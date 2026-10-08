import io
import json
import sys
from datetime import datetime, timezone

import pytest

from sentinel.ingest import iter_records, load_config, IngestResult


@pytest.fixture
def config():
    return load_config()


def make_line(**kwargs):
    base = {
        "timestamp": "2026-01-01T00:00:00Z",
        "event_type": "flow",
        "source_ip": "10.0.0.1",
        "dest_ip": "10.0.0.2",
        "src_port": 12345,
        "dest_port": 80,
        "protocol": "tcp",
        "bytes": 1000,
        "packets": 2,
        "auth_status": None,
    }
    base.update(kwargs)
    return json.dumps(base)


def test_valid_file(config, tmp_path):
    f = tmp_path / "valid.jsonl"
    f.write_text(make_line() + "\n" + make_line(source_ip="10.0.0.3") + "\n")

    events = list(iter_records(str(f), config))
    assert len(events) == 2
    assert events[0].source_ip == "10.0.0.1"
    assert events[1].source_ip == "10.0.0.3"
    assert events[0].record_id == "line-1"
    assert events[1].record_id == "line-2"


def test_stdin(config):
    stdin_data = make_line() + "\n" + make_line(event_type="auth", auth_status="failure") + "\n"
    old_stdin = sys.stdin
    sys.stdin = io.StringIO(stdin_data)
    try:
        events = list(iter_records(sys.stdin, config))
        assert len(events) == 2
        assert events[1].auth_status == "failure"
    finally:
        sys.stdin = old_stdin


def test_empty_file(config, tmp_path):
    f = tmp_path / "empty.jsonl"
    f.write_text("")
    events = list(iter_records(str(f), config))
    assert len(events) == 0


def test_only_garbage(config, tmp_path):
    f = tmp_path / "garbage.jsonl"
    f.write_text("not json\n{bad\n\nnull\n[]\n")
    events = list(iter_records(str(f), config))
    assert len(events) == 0


def test_malformed_types(config, tmp_path):
    f = tmp_path / "malformed.jsonl"
    lines = [
        make_line(bytes="abc"),
        make_line(src_port=99999),
        make_line(timestamp="not-a-date"),
        make_line(event_type="unknown_xyz"),
        make_line(source_ip=12345),
    ]
    f.write_text("\n".join(lines) + "\n")
    events = list(iter_records(str(f), config))
    assert len(events) == 0


def test_unknown_event_type_skipped(config, tmp_path):
    f = tmp_path / "unknown.jsonl"
    f.write_text(make_line(event_type="telnet") + "\n")
    events = list(iter_records(str(f), config))
    assert len(events) == 0


def test_noise_tagged(config, tmp_path):
    f = tmp_path / "noise.jsonl"
    lines = [
        make_line(event_type="dhcp"),
        make_line(event_type="arp"),
        make_line(dest_ip="224.0.0.1"),
        make_line(event_type="flow"),
    ]
    f.write_text("\n".join(lines) + "\n")
    events = list(iter_records(str(f), config))
    assert len(events) == 4
    assert events[0].is_noise is True
    assert events[1].is_noise is True
    assert events[2].is_noise is True
    assert events[3].is_noise is False


def test_normalization(config, tmp_path):
    f = tmp_path / "norm.jsonl"
    f.write_text(make_line(protocol="TCP", auth_status="SUCCESS") + "\n")
    events = list(iter_records(str(f), config))
    assert events[0].protocol == "tcp"
    assert events[0].auth_status == "success"


def test_missing_required_field(config, tmp_path):
    f = tmp_path / "missing.jsonl"
    rec = json.loads(make_line())
    del rec["source_ip"]
    f.write_text(json.dumps(rec) + "\n")
    events = list(iter_records(str(f), config))
    assert len(events) == 0
