from streamlit.testing.v1 import AppTest

from sentinel.audit import init_db, insert_alert, list_alerts


def test_dashboard_shows_friendly_empty_database_state(tmp_path, monkeypatch):
    db_path = tmp_path / "empty.db"
    connection = init_db(str(db_path))
    connection.close()
    monkeypatch.setenv("SENTINEL_DB", str(db_path))

    app = AppTest.from_file("sentinel/dashboard/app.py").run()
    assert not app.exception
    assert any("no alerts yet" in item.value.lower() for item in app.info)


def test_dashboard_can_mark_an_alert_reviewed(tmp_path, monkeypatch):
    db_path = tmp_path / "alerts.db"
    connection = init_db(str(db_path))
    insert_alert(connection, {
        "alert_id": "dashboard-alert", "timestamp": "2026-01-01T00:00:00+00:00",
        "source_ip": "10.0.0.1", "dest_ip": "10.0.0.2",
        "classification": "Malicious", "threat_category": "PortScan",
        "risk_score": 88, "anomaly_score": 0.9,
        "class_probabilities": {"PortScan": 0.99},
        "evidence": [{"feature": "unique_dest_ports", "value": 42, "zscore": 8.0}],
        "record_ids": ["r1"], "model_version": "test",
    })
    connection.close()
    monkeypatch.setenv("SENTINEL_DB", str(db_path))

    app = AppTest.from_file("sentinel/dashboard/app.py").run()
    assert not app.exception
    assert len(app.dataframe) == 1
    app.button[0].click().run()
    assert not app.exception

    connection = init_db(str(db_path))
    alerts = list_alerts(connection, status="reviewed")
    connection.close()
    assert len(alerts) == 1
    assert alerts[0]["alert_id"] == "dashboard-alert"
