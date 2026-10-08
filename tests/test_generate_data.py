import json
from pathlib import Path

REQUIRED_FIELDS = {"timestamp", "event_type", "source_ip", "dest_ip", "src_port", "dest_port", "protocol", "bytes", "packets", "auth_status"}


def test_train_schema_and_counts():
    train_file = Path("data/train/train.jsonl")
    assert train_file.exists()

    count = 0
    with open(train_file) as f:
        for line in f:
            rec = json.loads(line)
            assert REQUIRED_FIELDS.issubset(rec.keys()), f"Missing fields in record: {rec}"
            assert rec["event_type"] in ("flow", "auth", "audit", "dhcp", "arp", "multicast", "dns")
            assert rec["protocol"] in ("tcp", "udp", "icmp")
            count += 1

    assert count >= 38000


def test_train_labels():
    labels_file = Path("data/train/labels.jsonl")
    assert labels_file.exists()

    labels = []
    with open(labels_file) as f:
        for line in f:
            label = json.loads(line)
            assert "record_ids" in label
            assert "label" in label
            assert label["label"] in ("port_scan", "brute_force", "lateral_movement", "data_exfiltration")
            labels.append(label)

    assert len(labels) >= 8


def test_demo_stream_exists():
    demo_file = Path("data/demo/stream.jsonl")
    assert demo_file.exists()

    count = 0
    with open(demo_file) as f:
        for line in f:
            count += 1

    assert count >= 4500


def test_demo_has_malformed():
    demo_file = Path("data/demo/stream.jsonl")
    malformed_count = 0
    with open(demo_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                malformed_count += 1
                continue
            try:
                rec = json.loads(line)
                if not REQUIRED_FIELDS.issubset(rec.keys()):
                    malformed_count += 1
            except json.JSONDecodeError:
                malformed_count += 1

    assert malformed_count > 0


def test_demo_generation_is_seeded_and_covers_every_attack(tmp_path):
    from argparse import Namespace
    from scripts.generate_data import run_demo

    first = tmp_path / "first"
    second = tmp_path / "second"
    run_demo(Namespace(seed=17, out=str(first)))
    run_demo(Namespace(seed=17, out=str(second)))
    first_stream = (first / "stream.jsonl").read_bytes()
    second_stream = (second / "stream.jsonl").read_bytes()
    assert first_stream == second_stream
    labels = [json.loads(line)["label"] for line in (first / "labels.jsonl").read_text().splitlines()]
    assert set(labels) == {"port_scan", "brute_force", "lateral_movement", "data_exfiltration"}
    exfil_ids = [entry["record_ids"] for entry in map(json.loads, (first / "labels.jsonl").read_text().splitlines()) if entry["label"] == "data_exfiltration"]
    assert all(len(ids) == 1 for ids in exfil_ids)
