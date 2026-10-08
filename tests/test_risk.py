from sentinel.risk import risk_score, get_band, build_evidence, build_alert
from sentinel.features import FeatureVector


CONFIG = {
    "risk_weights": {"anomaly": 0.40, "threat": 0.40, "evidence": 0.20},
    "risk_bands": {"normal": [0, 30], "suspicious": [31, 70], "malicious": [71, 100]},
}


def test_risk_formula_exact():
    anomaly = 0.5
    class_probs = {"Normal": 0.1, "PortScan": 0.8, "BruteForce": 0.05, "LateralMovement": 0.03, "DataExfiltration": 0.02}
    zscores = {"event_count": 4.0, "unique_dest_ports": 5.0, "bytes_out": 3.5, "failed_logins": 0.0}

    score = risk_score(anomaly, class_probs, zscores, CONFIG)
    expected = round(100 * (0.40 * 0.5 + 0.40 * 0.8 + 0.20 * 1.0))
    assert score == expected


def test_risk_clamp_at_100():
    anomaly = 1.0
    class_probs = {"Normal": 0.0, "PortScan": 1.0, "BruteForce": 0.0, "LateralMovement": 0.0, "DataExfiltration": 0.0}
    zscores = {"event_count": 10.0, "unique_dest_ports": 10.0, "bytes_out": 10.0}

    score = risk_score(anomaly, class_probs, zscores, CONFIG)
    assert score == 100


def test_risk_clamp_at_0():
    anomaly = 0.0
    class_probs = {"Normal": 0.0, "PortScan": 0.0, "BruteForce": 0.0, "LateralMovement": 0.0, "DataExfiltration": 0.0}
    zscores = {"event_count": 0.0, "unique_dest_ports": 0.0, "bytes_out": 0.0}

    score = risk_score(anomaly, class_probs, zscores, CONFIG)
    assert score == 0


def test_alert_id_deterministic():
    fv = FeatureVector(
        source_ip="10.0.0.1",
        window_start="2026-01-01T00:00:00+00:00",
        window_end="2026-01-01T01:00:00+00:00",
        event_count=50, unique_dest_ips=5, unique_dest_ports=30,
        failed_logins=0, success_fail_ratio=1.0,
        bytes_out=50000, bytes_in=0, bytes_per_conn=1000.0,
        new_peer_ratio=1.0, protocol_entropy=0.5, rate_vs_baseline=5.0,
        record_ids=["r1", "r2"],
    )
    class_probs = {"Normal": 0.1, "PortScan": 0.8, "BruteForce": 0.05, "LateralMovement": 0.03, "DataExfiltration": 0.02}
    zscores = {"event_count": 4.0, "unique_dest_ports": 5.0, "bytes_out": 3.5}

    alert1 = build_alert(fv, 0.7, class_probs, "PortScan", zscores, [], config=CONFIG)
    alert2 = build_alert(fv, 0.7, class_probs, "PortScan", zscores, [], config=CONFIG)

    assert alert1["alert_id"] == alert2["alert_id"]


def test_evidence_ranking():
    fv = FeatureVector(
        source_ip="10.0.0.1",
        window_start="2026-01-01T00:00:00+00:00",
        window_end="2026-01-01T01:00:00+00:00",
        event_count=50, unique_dest_ips=5, unique_dest_ports=42,
        failed_logins=0, success_fail_ratio=1.0,
        bytes_out=50000, bytes_in=0, bytes_per_conn=120.0,
        new_peer_ratio=1.0, protocol_entropy=0.5, rate_vs_baseline=5.0,
        record_ids=["r1"],
    )
    zscores = {"event_count": 4.0, "unique_dest_ports": 9.8, "bytes_out": 2.0, "bytes_per_conn": 1.5}
    class_probs = {"Normal": 0.1, "PortScan": 0.8, "BruteForce": 0.05, "LateralMovement": 0.03, "DataExfiltration": 0.02}

    evidence = build_evidence(fv, zscores, class_probs, top_n=3)
    assert evidence[0]["feature"] == "unique_dest_ports"
    assert evidence[0]["value"] == 42


def test_band_mapping():
    assert get_band(0, CONFIG) == "Normal"
    assert get_band(30, CONFIG) == "Normal"
    assert get_band(31, CONFIG) == "Suspicious"
    assert get_band(70, CONFIG) == "Suspicious"
    assert get_band(71, CONFIG) == "Malicious"
    assert get_band(100, CONFIG) == "Malicious"


def test_build_alert_full():
    fv = FeatureVector(
        source_ip="10.0.0.5",
        window_start="2026-01-01T00:00:00+00:00",
        window_end="2026-01-01T01:00:00+00:00",
        event_count=100, unique_dest_ips=10, unique_dest_ports=50,
        failed_logins=0, success_fail_ratio=1.0,
        bytes_out=100000, bytes_in=0, bytes_per_conn=1000.0,
        new_peer_ratio=1.0, protocol_entropy=0.5, rate_vs_baseline=10.0,
        record_ids=["r1", "r2"],
    )
    class_probs = {"Normal": 0.05, "PortScan": 0.9, "BruteForce": 0.02, "LateralMovement": 0.02, "DataExfiltration": 0.01}
    zscores = {"event_count": 6.0, "unique_dest_ports": 9.8, "bytes_out": 3.0}
    evidence = build_evidence(fv, zscores, class_probs)

    alert = build_alert(fv, 0.9, class_probs, "PortScan", zscores, evidence, config=CONFIG)

    assert alert["source_ip"] == "10.0.0.5"
    assert alert["classification"] == "Malicious"
    assert alert["threat_category"] == "PortScan"
    assert alert["status"] == "new"
    assert len(alert["record_ids"]) == 2
    assert "alert_id" in alert
