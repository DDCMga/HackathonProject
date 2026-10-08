from datetime import datetime, timezone, timedelta

from sentinel.features import build_windows, BaselineStore, compute_zscores
from sentinel.ingest import NormalizedEvent


def make_event(source_ip, dest_ip, dest_port, timestamp, event_type="flow", protocol="tcp", bytes_count=1000, auth_status=None):
    return NormalizedEvent(
        timestamp=timestamp,
        event_type=event_type,
        source_ip=source_ip,
        dest_ip=dest_ip,
        src_port=12345,
        dest_port=dest_port,
        protocol=protocol,
        bytes=bytes_count,
        packets=1,
        auth_status=auth_status,
    )


def test_port_scan_unique_dest_ports():
    base = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    events = []
    for i in range(30):
        events.append(make_event("10.0.0.1", "10.0.0.2", i + 1, base + timedelta(seconds=i)))

    windows = list(build_windows(events, window_seconds=60, hop_seconds=30))
    assert len(windows) >= 1
    port_scan_windows = [w for w in windows if w.unique_dest_ports >= 25]
    assert len(port_scan_windows) >= 1


def test_brute_force_failed_logins():
    base = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    events = []
    for i in range(42):
        events.append(make_event("10.0.0.1", "10.0.0.2", 22, base + timedelta(seconds=i), event_type="auth", auth_status="failure"))

    windows = list(build_windows(events, window_seconds=60, hop_seconds=30))
    bf_windows = [w for w in windows if w.failed_logins >= 42]
    assert len(bf_windows) >= 1


def test_new_peer_ratio_first_time():
    base = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    events = [
        make_event("10.0.0.1", "10.0.0.2", 80, base),
        make_event("10.0.0.1", "10.0.0.3", 80, base + timedelta(seconds=1)),
        make_event("10.0.0.1", "10.0.0.4", 80, base + timedelta(seconds=2)),
    ]

    windows = list(build_windows(events, window_seconds=60, hop_seconds=30))
    assert len(windows) >= 1
    assert windows[0].new_peer_ratio == 1.0


def test_new_peer_ratio_after_seen():
    base = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    events = [
        make_event("10.0.0.1", "10.0.0.2", 80, base),
        make_event("10.0.0.1", "10.0.0.2", 80, base + timedelta(seconds=60)),
        make_event("10.0.0.1", "10.0.0.3", 80, base + timedelta(seconds=61)),
    ]

    windows = list(build_windows(events, window_seconds=60, hop_seconds=30))
    assert len(windows) >= 2
    assert windows[0].new_peer_ratio == 1.0
    assert windows[1].new_peer_ratio < 1.0


def test_baseline_store_median():
    baseline = BaselineStore()
    baseline.update("10.0.0.1", {"event_count": 10})
    baseline.update("10.0.0.1", {"event_count": 20})
    baseline.update("10.0.0.1", {"event_count": 30})

    assert baseline.get_median("10.0.0.1", "event_count") == 20.0


def test_baseline_store_std():
    baseline = BaselineStore()
    baseline.update("10.0.0.1", {"event_count": 10})
    baseline.update("10.0.0.1", {"event_count": 20})
    baseline.update("10.0.0.1", {"event_count": 30})

    std = baseline.get_std("10.0.0.1", "event_count")
    assert std > 0


def test_zscores():
    baseline = BaselineStore()
    baseline.update("10.0.0.1", {"event_count": 10})
    baseline.update("10.0.0.1", {"event_count": 10})
    baseline.update("10.0.0.1", {"event_count": 10})

    fv = make_event("10.0.0.1", "10.0.0.2", 80, datetime(2026, 1, 1, tzinfo=timezone.utc))
    from sentinel.features import FeatureVector
    feature_vec = FeatureVector(
        source_ip="10.0.0.1",
        window_start="2026-01-01T00:00:00+00:00",
        window_end="2026-01-01T01:00:00+00:00",
        event_count=100,
        unique_dest_ips=5,
        unique_dest_ports=3,
        failed_logins=0,
        success_fail_ratio=1.0,
        bytes_out=10000,
        bytes_in=0,
        bytes_per_conn=100.0,
        new_peer_ratio=1.0,
        protocol_entropy=0.5,
        rate_vs_baseline=10.0,
    )

    zscores = compute_zscores(feature_vec, baseline)
    assert "event_count" in zscores
    assert zscores["event_count"] > 0


def test_protocol_entropy():
    base = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    events = [
        make_event("10.0.0.1", "10.0.0.2", 80, base, protocol="tcp"),
        make_event("10.0.0.1", "10.0.0.3", 80, base + timedelta(seconds=1), protocol="udp"),
        make_event("10.0.0.1", "10.0.0.4", 80, base + timedelta(seconds=2), protocol="icmp"),
    ]

    windows = list(build_windows(events, window_seconds=60, hop_seconds=30))
    assert windows[0].protocol_entropy > 0


def test_empty_events():
    windows = list(build_windows([], window_seconds=60, hop_seconds=30))
    assert len(windows) == 0


def test_record_ids_linkage():
    base = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    events = [
        make_event("10.0.0.1", "10.0.0.2", 80, base),
        make_event("10.0.0.1", "10.0.0.3", 80, base + timedelta(seconds=1)),
    ]
    events[0].record_id = "rec-001"
    events[1].record_id = "rec-002"

    windows = list(build_windows(events, window_seconds=60, hop_seconds=30))
    assert len(windows) >= 1
    assert "rec-001" in windows[0].record_ids
    assert "rec-002" in windows[0].record_ids
