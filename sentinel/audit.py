import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    dest_ip TEXT,
    classification TEXT NOT NULL,
    threat_category TEXT,
    risk_score INTEGER NOT NULL,
    anomaly_score REAL,
    class_probabilities TEXT,
    evidence_features TEXT,
    model_version TEXT,
    record_ids TEXT,
    status TEXT DEFAULT 'new',
    created_at TEXT NOT NULL
);
"""

CREATE_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_alerts_classification ON alerts(classification);
CREATE INDEX IF NOT EXISTS idx_alerts_threat_category ON alerts(threat_category);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_risk_score ON alerts(risk_score);
"""


def init_db(path: str):
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    conn.executescript(CREATE_INDEXES)
    conn.commit()
    return conn


@contextmanager
def get_connection(path: str):
    conn = init_db(path)
    try:
        yield conn
    finally:
        conn.close()


def insert_alert(conn, alert: dict, commit: bool = True):
    # Keep repeated runs byte-stable for the same deterministic alert.
    now = alert.get("created_at", alert["timestamp"])
    evidence = json.dumps(alert.get("evidence", []))
    class_probs = json.dumps(alert.get("class_probabilities", {}))
    record_ids = json.dumps(alert.get("record_ids", []))

    conn.execute(
        """INSERT OR REPLACE INTO alerts
           (alert_id, timestamp, source_ip, dest_ip, classification,
            threat_category, risk_score, anomaly_score, class_probabilities,
            evidence_features, model_version, record_ids, status, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            alert["alert_id"],
            alert["timestamp"],
            alert["source_ip"],
            alert.get("dest_ip", ""),
            alert["classification"],
            alert.get("threat_category", ""),
            alert["risk_score"],
            alert.get("anomaly_score", 0.0),
            class_probs,
            evidence,
            alert.get("model_version", ""),
            record_ids,
            alert.get("status", "new"),
            now,
        ),
    )
    if commit:
        conn.commit()


def list_alerts(conn, classification=None, threat_category=None, status=None, min_risk=None, limit=100):
    query = "SELECT * FROM alerts WHERE 1=1"
    params = []

    if classification:
        query += " AND classification = ?"
        params.append(classification)
    if threat_category:
        query += " AND threat_category = ?"
        params.append(threat_category)
    if status:
        query += " AND status = ?"
        params.append(status)
    if min_risk is not None:
        query += " AND risk_score >= ?"
        params.append(min_risk)

    query += " ORDER BY risk_score DESC LIMIT ?"
    params.append(limit)

    cursor = conn.execute(query, params)
    columns = [desc[0] for desc in cursor.description]
    rows = cursor.fetchall()

    results = []
    for row in rows:
        d = dict(zip(columns, row))
        d["class_probabilities"] = json.loads(d.get("class_probabilities", "{}"))
        d["evidence_features"] = json.loads(d.get("evidence_features", "[]"))
        d["record_ids"] = json.loads(d.get("record_ids", "[]"))
        results.append(d)

    return results


def update_status(conn, alert_id: str, new_status: str):
    if new_status not in {"new", "reviewed", "resolved"}:
        raise ValueError("status must be new, reviewed, or resolved")
    conn.execute(
        "UPDATE alerts SET status = ? WHERE alert_id = ?",
        (new_status, alert_id),
    )
    conn.commit()


def get_alert_count(conn) -> int:
    cursor = conn.execute("SELECT COUNT(*) FROM alerts")
    return cursor.fetchone()[0]


def get_counts_by_band(conn) -> dict:
    cursor = conn.execute(
        "SELECT classification, COUNT(*) FROM alerts GROUP BY classification"
    )
    return {row[0]: row[1] for row in cursor.fetchall()}
