import argparse
import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

INTERNAL_SUBNETS = [f"10.0.{i}" for i in range(1, 11)]
DNS_RESOLVER = "10.0.0.53"
EXTERNAL_IPS = ["203.0.113.50", "198.51.100.23", "192.0.2.100"]

PROTOCOLS = ["tcp", "udp", "icmp"]
EVENT_TYPES = ["flow", "auth", "audit"]
NOISE_TYPES = ["dhcp", "arp", "multicast", "dns"]


def random_internal_ip(rng):
    subnet = rng.choice(INTERNAL_SUBNETS)
    return f"{subnet}.{rng.randint(2, 254)}"


def random_port(rng):
    common = [80, 443, 22, 53, 8080, 3306, 5432, 25, 21, 3389]
    return rng.choice(common) if rng.random() < 0.7 else rng.randint(1024, 65535)


def make_record(timestamp, event_type, source_ip, dest_ip, src_port, dest_port, protocol, bytes_count, packets, auth_status):
    return {
        "timestamp": timestamp.isoformat(),
        "event_type": event_type,
        "source_ip": source_ip,
        "dest_ip": dest_ip,
        "src_port": src_port,
        "dest_port": dest_port,
        "protocol": protocol,
        "bytes": bytes_count,
        "packets": packets,
        "auth_status": auth_status,
    }


def gen_benign_record(rng, ts):
    event_type = rng.choices(EVENT_TYPES, weights=[70, 15, 15])[0]
    source_ip = random_internal_ip(rng)
    dest_ip = random_internal_ip(rng) if rng.random() < 0.8 else rng.choice(EXTERNAL_IPS)
    src_port = rng.randint(1024, 65535)
    dest_port = random_port(rng)
    protocol = rng.choices(PROTOCOLS, weights=[60, 30, 10])[0]
    bytes_count = rng.randint(64, 65536)
    packets = max(1, bytes_count // rng.randint(500, 1500))
    auth_status = None
    if event_type == "auth":
        auth_status = "success" if rng.random() < 0.85 else "failure"
    return make_record(ts, event_type, source_ip, dest_ip, src_port, dest_port, protocol, bytes_count, packets, auth_status)


def gen_noise_record(rng, ts):
    source_ip = random_internal_ip(rng)
    dest_ip = rng.choice(["224.0.0.1", "255.255.255.255", DNS_RESOLVER])
    return make_record(ts, rng.choice(NOISE_TYPES), source_ip, dest_ip, 0, rng.choice([53, 67, 68]), "udp", rng.randint(64, 512), 1, None)


def gen_port_scan(rng, ts_start, duration=30):
    records = []
    source_ip = random_internal_ip(rng)
    target_ip = random_internal_ip(rng)
    record_ids = []
    for i in range(rng.randint(25, 40)):
        ts = ts_start + timedelta(seconds=rng.uniform(0, duration))
        rec = make_record(ts, "flow", source_ip, target_ip, rng.randint(40000, 60000), rng.randint(1, 10000), "tcp", rng.randint(40, 120), 1, None)
        records.append(rec)
        record_ids.append(rec.get("record_id", ""))
    return records, record_ids


def gen_brute_force(rng, ts_start, duration=60):
    records = []
    source_ip = random_internal_ip(rng)
    target_ip = random_internal_ip(rng)
    record_ids = []
    for i in range(rng.randint(30, 50)):
        ts = ts_start + timedelta(seconds=rng.uniform(0, duration))
        rec = make_record(ts, "auth", source_ip, target_ip, rng.randint(40000, 60000), rng.choice([22, 3389, 21]), "tcp", rng.randint(100, 500), rng.randint(1, 3), "failure")
        records.append(rec)
        record_ids.append(rec.get("record_id", ""))
    return records, record_ids


def gen_lateral_movement(rng, ts_start, duration=60):
    records = []
    source_ip = random_internal_ip(rng)
    new_peers = set()
    record_ids = []
    for i in range(rng.randint(5, 15)):
        ts = ts_start + timedelta(seconds=rng.uniform(0, duration))
        peer = random_internal_ip(rng)
        while peer == source_ip or peer in new_peers:
            peer = random_internal_ip(rng)
        new_peers.add(peer)
        rec = make_record(ts, "flow", source_ip, peer, rng.randint(1024, 65535), rng.choice([445, 135, 3389, 5985, 22]), "tcp", rng.randint(200, 2000), rng.randint(1, 5), None)
        records.append(rec)
        record_ids.append(rec.get("record_id", ""))
    return records, record_ids


def gen_data_exfiltration(rng, ts_start, duration=10):
    records = []
    source_ip = random_internal_ip(rng)
    dest_ip = rng.choice(EXTERNAL_IPS)
    record_ids = []
    total_bytes = rng.randint(800_000_000, 2_000_000_000)
    ts = ts_start + timedelta(seconds=rng.uniform(0, duration))
    rec = make_record(ts, "flow", source_ip, dest_ip, rng.randint(40000, 60000), rng.choice([443, 8080, 22]), "tcp", total_bytes, total_bytes // 500, None)
    records.append(rec)
    record_ids.append("")
    return records, record_ids


def gen_malformed(rng, ts):
    kind = rng.randint(0, 4)
    if kind == 0:
        return '{"timestamp": "2026-01-01T00:00:00Z", "event_type": "flow", "source_ip": "10.0.0.1", "dest_ip": "10.0.0.2", "src_port": 12345, "dest_port": 80, "protocol": "tcp", "bytes": 100, "packets": 1, "auth_status": null'
    elif kind == 1:
        return '{"timestamp": "not-a-date", "event_type": "flow", "source_ip": "10.0.0.1", "dest_ip": "10.0.0.2", "src_port": 12345, "dest_port": 80, "protocol": "tcp", "bytes": 100, "packets": 1, "auth_status": null}'
    elif kind == 2:
        return '{"timestamp": "2026-01-01T00:00:00Z", "event_type": "unknown_type", "source_ip": "10.0.0.1", "dest_ip": "10.0.0.2", "src_port": 12345, "dest_port": 80, "protocol": "tcp", "bytes": 100, "packets": 1, "auth_status": null}'
    elif kind == 3:
        return '{"timestamp": "2026-01-01T00:00:00Z", "event_type": "flow", "source_ip": 12345, "dest_ip": "10.0.0.2", "src_port": "abc", "dest_port": 80, "protocol": "tcp", "bytes": 100, "packets": 1, "auth_status": null}'
    else:
        return ''


def run_train(args):
    rng = random.Random(args.seed)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    start_time = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    total_seconds = 7200
    total_records = 40000
    noise_ratio = 0.15

    all_records = []
    labels = []

    num_attacks = 12
    attack_interval = total_seconds // (num_attacks + 1)
    attack_types = ["port_scan", "brute_force", "lateral_movement", "data_exfiltration"]
    rng.shuffle(attack_types)

    for i in range(num_attacks):
        attack_type = attack_types[i % len(attack_types)]
        attack_start = start_time + timedelta(seconds=attack_interval * (i + 1))

        if attack_type == "port_scan":
            recs, ids = gen_port_scan(rng, attack_start)
        elif attack_type == "brute_force":
            recs, ids = gen_brute_force(rng, attack_start)
        elif attack_type == "lateral_movement":
            recs, ids = gen_lateral_movement(rng, attack_start)
        else:
            recs, ids = gen_data_exfiltration(rng, attack_start)

        for record_index, rec in enumerate(recs):
            rec["record_id"] = str(uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"{args.seed}:train:{i}:{record_index}:{attack_type}",
            ))
        all_records.extend(recs)
        labels.append({"record_ids": [r["record_id"] for r in recs], "label": attack_type})

    benign_count = total_records - len(all_records)
    for _ in range(benign_count):
        ts = start_time + timedelta(seconds=rng.uniform(0, total_seconds))
        if rng.random() < noise_ratio:
            all_records.append(gen_noise_record(rng, ts))
        else:
            all_records.append(gen_benign_record(rng, ts))

    all_records.sort(key=lambda r: r["timestamp"])

    with open(out_dir / "train.jsonl", "w") as f:
        for rec in all_records:
            f.write(json.dumps(rec) + "\n")

    with open(out_dir / "labels.jsonl", "w") as f:
        for label in labels:
            f.write(json.dumps(label) + "\n")

    print(f"Generated {len(all_records)} records ({len(labels)} attack episodes) in {out_dir}")


def run_demo(args):
    rng = random.Random(args.seed)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    start_time = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    total_seconds = 1800

    all_records = []
    labels = []

    num_attacks = 8
    attack_interval = total_seconds // (num_attacks + 1)
    attack_types = ["port_scan", "brute_force", "lateral_movement", "data_exfiltration"]
    rng.shuffle(attack_types)

    for i in range(num_attacks):
        attack_type = attack_types[i % len(attack_types)]
        attack_start = start_time + timedelta(seconds=attack_interval * (i + 1))

        if attack_type == "port_scan":
            recs, ids = gen_port_scan(rng, attack_start)
        elif attack_type == "brute_force":
            recs, ids = gen_brute_force(rng, attack_start)
        elif attack_type == "lateral_movement":
            recs, ids = gen_lateral_movement(rng, attack_start)
        else:
            recs, ids = gen_data_exfiltration(rng, attack_start)

        for record_index, rec in enumerate(recs):
            rec["record_id"] = str(uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"{args.seed}:demo:{i}:{record_index}:{attack_type}",
            ))
        all_records.extend(recs)
        labels.append({"record_ids": [r["record_id"] for r in recs], "label": attack_type})

    total_expected = 5000
    benign_count = total_expected - len(all_records)
    for _ in range(benign_count):
        ts = start_time + timedelta(seconds=rng.uniform(0, total_seconds))
        if rng.random() < 0.20:
            all_records.append(gen_noise_record(rng, ts))
        else:
            all_records.append(gen_benign_record(rng, ts))

    all_records.sort(key=lambda r: r["timestamp"])

    with open(out_dir / "stream.jsonl", "w") as f:
        for rec in all_records:
            f.write(json.dumps(rec) + "\n")
        for _ in range(int(len(all_records) * 0.1)):
            ts = start_time + timedelta(seconds=rng.uniform(0, total_seconds))
            f.write(gen_malformed(rng, ts) + "\n")

    with open(out_dir / "labels.jsonl", "w") as f:
        for label in labels:
            f.write(json.dumps(label) + "\n")

    print(f"Generated {len(all_records)} records + malformed lines in {out_dir}")


def main():
    parser = argparse.ArgumentParser(description="Synthetic telemetry generator")
    parser.add_argument("--mode", choices=["train", "demo"], required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    if args.mode == "train":
        run_train(args)
    else:
        run_demo(args)


if __name__ == "__main__":
    main()
