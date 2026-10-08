import io
import json
import random
import tracemalloc
from datetime import datetime, timezone

from sentinel.ingest import NormalizedEvent, iter_records, load_config
from sentinel.features import build_windows
from sentinel import cli
import typer


def record(**updates):
    value = {
        "timestamp": "2026-01-01T00:00:00Z", "event_type": "flow",
        "source_ip": "10.0.0.1", "dest_ip": "10.0.0.2",
        "src_port": 12345, "dest_port": 443, "protocol": "tcp",
        "bytes": 128, "packets": 1, "auth_status": None,
    }
    value.update(updates)
    return json.dumps(value)


class GeneratedLines:
    def __init__(self, count):
        self.count = count
        self.index = 0

    def readline(self, _limit=-1):
        if self.index >= self.count:
            return ""
        self.index += 1
        return record(record_id=str(self.index)) + "\n"


def test_500_random_invalid_lines_do_not_stop_good_records(capsys):
    rng = random.Random(19)
    cases = ["{", "null", "[]", "\x00", "not-json", record(timestamp="bad"), record(bytes=-1)]
    payload = "\n".join(rng.choice(cases) for _ in range(500)) + "\n" + record() + "\n"
    events = list(iter_records(io.StringIO(payload), load_config()))
    assert len(events) == 1
    assert "processed 1, skipped 500" in capsys.readouterr().err


def test_oversized_and_hostile_numeric_lines_are_skipped(capsys):
    payload = "x" * (1_048_577) + "\n" + "\n".join([
        record(bytes="NaN"), record(bytes=1e309), record(bytes=-99999),
        record(packets=0, bytes=1), record(dest_port=65536),
    ]) + "\n" + record(source_ip="2001:db8::1") + "\n"
    events = list(iter_records(io.StringIO(payload), load_config()))
    assert len(events) == 2  # zero packets is valid; IPv6 addresses remain strings
    assert events[-1].source_ip == "2001:db8::1"
    assert "line exceeds" in capsys.readouterr().err


def test_ingestion_memory_stays_bounded_for_200k_records(capsys):
    source = GeneratedLines(200_000)
    tracemalloc.start()
    count = sum(1 for _ in iter_records(source, load_config()))
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert count == 200_000
    assert peak < 12 * 1024 * 1024
    assert "processed 200000, skipped 0" in capsys.readouterr().err


def test_noise_events_never_form_detection_windows():
    noise = NormalizedEvent(
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc), event_type="dhcp",
        source_ip="10.0.0.1", dest_ip="255.255.255.255", src_port=0,
        dest_port=67, protocol="udp", bytes=128, packets=1, auth_status=None, is_noise=True,
    )
    assert list(build_windows([noise])) == []


def test_cli_processes_200k_stdin_records_with_bounded_memory(tmp_path, monkeypatch, capsys):
    class DummyModel:
        pass

    monkeypatch.setattr(cli, "load_models", lambda: (DummyModel(), DummyModel()))
    monkeypatch.setattr(cli, "score_windows", lambda vectors, *_: [{
        "anomaly_score": 0.0, "class_probs": {"Normal": 1.0}, "predicted_class": "Normal"
    } for _ in vectors])
    monkeypatch.setattr(cli.sys, "stdin", GeneratedLines(200_000))
    tracemalloc.start()
    try:
        cli.run("-", 100, "config.yaml", str(tmp_path / "stream.db"))
    except typer.Exit as result:
        assert result.exit_code == 0
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert peak < 256 * 1024 * 1024
    captured = capsys.readouterr()
    assert "Total alerts: 1" in captured.out
    assert "processed 200000, skipped 0" in captured.err
