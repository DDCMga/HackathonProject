import sqlite3
import pytest

from sentinel.audit import init_db, insert_alert, list_alerts, update_status, get_alert_count, get_counts_by_band


@pytest.fixture
def sample_alert():
    return {
        "alert_id": "test-alert-001",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "source_ip": "10.0.0.1",
        "dest_ip": "10.0.0.2",
        "classification": "Malicious",
        "threat_category": "PortScan",
        "risk_score": 88,
        "anomaly_score": 0.93,
        "class_probabilities": {"Normal": 0.02, "PortScan": 0.91, "BruteForce": 0.04, "LateralMovement": 0.02, "DataExfiltration": 0.01},
        "evidence": [{"feature": "unique_dest_ports", "value": 42, "zscore": 9.8, "contribution": 0.41}],
        "model_version": "anomaly-if-v1 / clf-rf-v1",
        "record_ids": ["r1", "r2"],
        "status": "new",
    }


def test_insert_and_read_back(sample_alert):
    conn = init_db(":memory:")
    insert_alert(conn, sample_alert)

    alerts = list_alerts(conn)
    assert len(alerts) == 1
    assert alerts[0]["alert_id"] == "test-alert-001"
    assert alerts[0]["source_ip"] == "10.0.0.1"
    assert alerts[0]["risk_score"] == 88
    assert alerts[0]["classification"] == "Malicious"
    conn.close()


def test_update_status(sample_alert):
    conn = init_db(":memory:")
    insert_alert(conn, sample_alert)

    update_status(conn, "test-alert-001", "reviewed")

    alerts = list_alerts(conn, status="reviewed")
    assert len(alerts) == 1
    assert alerts[0]["status"] == "reviewed"
    conn.close()


def test_persistence(tmp_path, sample_alert):
    db_path = str(tmp_path / "test.db")

    conn = init_db(db_path)
    insert_alert(conn, sample_alert)
    conn.close()

    conn2 = init_db(db_path)
    alerts = list_alerts(conn2)
    assert len(alerts) == 1
    assert alerts[0]["alert_id"] == "test-alert-001"
    conn2.close()


def test_idempotent_init(tmp_path):
    db_path = str(tmp_path / "test.db")
    conn1 = init_db(db_path)
    conn1.close()

    conn2 = init_db(db_path)
    count = get_alert_count(conn2)
    assert count == 0
    conn2.close()


def test_filter_by_classification(sample_alert):
    conn = init_db(":memory:")
    insert_alert(conn, sample_alert)

    malicious = list_alerts(conn, classification="Malicious")
    assert len(malicious) == 1

    normal = list_alerts(conn, classification="Normal")
    assert len(normal) == 0
    conn.close()


def test_filter_by_min_risk(sample_alert):
    conn = init_db(":memory:")
    insert_alert(conn, sample_alert)

    high = list_alerts(conn, min_risk=80)
    assert len(high) == 1

    low = list_alerts(conn, min_risk=90)
    assert len(low) == 0
    conn.close()


def test_counts_by_band(sample_alert):
    conn = init_db(":memory:")
    insert_alert(conn, sample_alert)

    counts = get_counts_by_band(conn)
    assert counts.get("Malicious") == 1
    conn.close()


def test_json_fields_roundtrip(sample_alert):
    conn = init_db(":memory:")
    insert_alert(conn, sample_alert)

    alerts = list_alerts(conn)
    assert isinstance(alerts[0]["class_probabilities"], dict)
    assert isinstance(alerts[0]["evidence_features"], list)
    assert isinstance(alerts[0]["record_ids"], list)
    assert alerts[0]["record_ids"] == ["r1", "r2"]
    conn.close()
