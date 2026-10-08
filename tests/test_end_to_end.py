import json
from datetime import datetime, timedelta, timezone

from sentinel import cli


def event(ts, source, dest, port, *, kind="flow", byte_count=200, auth=None, record_id=""):
    return {
        "timestamp": ts.isoformat(), "event_type": kind, "source_ip": source,
        "dest_ip": dest, "src_port": 40000, "dest_port": port, "protocol": "tcp",
        "bytes": byte_count, "packets": 1, "auth_status": auth, "record_id": record_id,
    }


def test_four_attack_signatures_flow_to_malicious_alerts(tmp_path, monkeypatch):
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    stream = []
    expected = {
        "10.0.0.1": "PortScan", "10.0.0.2": "BruteForce",
        "10.0.0.3": "LateralMovement", "10.0.0.4": "DataExfiltration",
    }
    for port in range(1, 31):
        stream.append(event(start + timedelta(seconds=port), "10.0.0.1", "10.0.1.1", port, record_id=f"scan-{port}"))
    for attempt in range(40):
        stream.append(event(start + timedelta(seconds=attempt), "10.0.0.2", "10.0.1.2", 22, kind="auth", auth="failure", record_id=f"auth-{attempt}"))
    for peer in range(10):
        stream.append(event(start + timedelta(seconds=peer), "10.0.0.3", f"10.0.2.{peer + 1}", 445, record_id=f"lateral-{peer}"))
    stream.append(event(start + timedelta(seconds=5), "10.0.0.4", "198.51.100.23", 443, byte_count=900_000_000, record_id="exfil"))
    stream.sort(key=lambda item: item["timestamp"])
    path = tmp_path / "attacks.jsonl"
    path.write_text("".join(json.dumps(item) + "\n" for item in stream), encoding="utf-8")

    class DummyModel: pass
    monkeypatch.setattr(cli, "load_models", lambda: (DummyModel(), DummyModel()))

    def fixture_score(vector, _anomaly, _classifier):
        if vector.failed_logins >= 30:
            category = "BruteForce"
        elif vector.bytes_out >= 800_000_000:
            category = "DataExfiltration"
        elif vector.unique_dest_ports >= 25:
            category = "PortScan"
        elif vector.unique_dest_ips >= 5:
            category = "LateralMovement"
        else:
            category = "Normal"
        probs = {name: (0.99 if name == category else 0.0025) for name in (
            "Normal", "PortScan", "BruteForce", "LateralMovement", "DataExfiltration"
        )}
        return {"anomaly_score": 0.99, "class_probs": probs, "predicted_class": category}

    monkeypatch.setattr(cli, "score_windows", lambda vectors, *_: [fixture_score(v, None, None) for v in vectors])
    alerts = list(cli.iter_pipeline(str(path), "config.yaml", str(tmp_path / "alerts.db")))
    for source, category in expected.items():
        matches = [alert for alert in alerts if alert["source_ip"] == source and alert["threat_category"] == category]
        assert matches, f"No {category} alert was emitted for {source}"
        assert all(alert["risk_score"] >= 71 for alert in matches)
        assert all(alert["classification"] == "Malicious" for alert in matches)
