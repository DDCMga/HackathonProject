import json
import math
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

MAX_LINE_CHARS = 1_048_576
MAX_INTEGER = (1 << 63) - 1

import yaml


@dataclass
class NormalizedEvent:
    timestamp: datetime
    event_type: str
    source_ip: str
    dest_ip: str
    src_port: int
    dest_port: int
    protocol: str
    bytes: int
    packets: int
    auth_status: Optional[str]
    is_noise: bool = False
    record_id: str = ""


@dataclass
class SkipEntry:
    line_number: int
    raw_snippet: str
    reason: str


@dataclass
class IngestResult:
    events: list = field(default_factory=list)
    skip_log: list = field(default_factory=list)
    processed: int = 0
    skipped: int = 0
    noise_count: int = 0


def load_config(config_path: str = "config.yaml") -> dict:
    with open(config_path) as f:
        return yaml.safe_load(f)


def _parse_timestamp(value) -> Optional[datetime]:
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


def _coerce_int(value, min_val=None, max_val=None) -> Optional[int]:
    try:
        if isinstance(value, float) and (not math.isfinite(value) or not value.is_integer()):
            return None
        if isinstance(value, bool):
            return None
        v = int(value)
        if abs(v) > MAX_INTEGER:
            return None
        if min_val is not None and v < min_val:
            return None
        if max_val is not None and v > max_val:
            return None
        return v
    except (ValueError, TypeError, OverflowError):
        return None


def _is_noise(event_type: str, dest_ip: str, config: dict) -> bool:
    noise_cfg = config.get("noise_filter", {})
    noise_types = {t.lower() for t in noise_cfg.get("event_types", [])}
    ignored_ips = set(noise_cfg.get("ignored_dest_ips", []))
    return event_type.lower() in noise_types or dest_ip in ignored_ips


def _validate_record(raw: dict, line_number: int, config: dict) -> tuple:
    required = ["timestamp", "source_ip", "dest_ip", "event_type"]
    for field_name in required:
        if field_name not in raw or raw[field_name] is None:
            return None, f"missing required field: {field_name}"

    ts = _parse_timestamp(raw["timestamp"])
    if ts is None:
        return None, f"invalid timestamp: {raw['timestamp']}"

    source_ip = raw["source_ip"]
    dest_ip = raw["dest_ip"]
    if not isinstance(source_ip, str) or not isinstance(dest_ip, str):
        return None, "source_ip/dest_ip must be strings"

    event_type = str(raw["event_type"]).lower()
    valid_types = {"flow", "auth", "audit", "dhcp", "arp", "multicast", "dns"}
    if event_type not in valid_types:
        return None, f"unknown event_type: {event_type}"

    src_port = _coerce_int(raw.get("src_port", 0), 0, 65535)
    dest_port = _coerce_int(raw.get("dest_port", 0), 0, 65535)
    if src_port is None or dest_port is None:
        return None, "invalid port number"

    bytes_val = _coerce_int(raw.get("bytes", 0), 0)
    if bytes_val is None:
        return None, "invalid bytes value"

    packets = _coerce_int(raw.get("packets", 1), 0)
    if packets is None:
        return None, "invalid packets value"

    protocol = str(raw.get("protocol", "tcp")).lower()
    if protocol not in ("tcp", "udp", "icmp"):
        protocol = "tcp"

    auth_status = raw.get("auth_status")
    if auth_status is not None:
        auth_status = str(auth_status).lower()
        if auth_status not in ("success", "failure"):
            auth_status = None

    is_noise = _is_noise(event_type, dest_ip, config)

    event = NormalizedEvent(
        timestamp=ts,
        event_type=event_type,
        source_ip=source_ip,
        dest_ip=dest_ip,
        src_port=src_port,
        dest_port=dest_port,
        protocol=protocol,
        bytes=bytes_val,
        packets=packets,
        auth_status=auth_status,
        is_noise=is_noise,
        record_id=(
            raw.get("record_id")
            if isinstance(raw.get("record_id"), str) and raw.get("record_id")
            else f"line-{line_number}"
        ),
    )

    return event, None


def iter_records(source, config: dict = None) -> Iterator[NormalizedEvent]:
    if config is None:
        config = load_config()

    if isinstance(source, (str, Path)):
        f = open(source, "r", encoding="utf-8", errors="replace")
        should_close = True
    else:
        f = source
        should_close = False

    processed = skipped = noise_count = 0
    line_number = 0
    try:
        while True:
            line = f.readline(MAX_LINE_CHARS + 1)
            if not line:
                break
            line_number += 1
            if len(line) > MAX_LINE_CHARS:
                while line and not line.endswith("\n"):
                    line = f.readline(MAX_LINE_CHARS + 1)
                skipped += 1
                print(f"SKIP line {line_number}: line exceeds {MAX_LINE_CHARS} characters", file=sys.stderr)
                continue
            line = line.strip()
            if not line:
                skipped += 1
                print(f"SKIP line {line_number}: empty line", file=sys.stderr)
                continue

            try:
                raw = json.loads(line)
            except (json.JSONDecodeError, ValueError) as error:
                skipped += 1
                print(f"SKIP line {line_number}: invalid JSON - {error}", file=sys.stderr)
                continue
            if not isinstance(raw, dict):
                skipped += 1
                print(f"SKIP line {line_number}: not a JSON object", file=sys.stderr)
                continue

            event, error = _validate_record(raw, line_number, config)
            if error:
                skipped += 1
                print(f"SKIP line {line_number}: {error}", file=sys.stderr)
                continue
            processed += 1
            noise_count += int(event.is_noise)
            yield event
    finally:
        print(f"processed {processed}, skipped {skipped}, noise {noise_count}", file=sys.stderr)
        if should_close:
            f.close()


def ingest(source, config: dict = None) -> IngestResult:
    if config is None:
        config = load_config()

    result = IngestResult()
    for event in iter_records(source, config):
        result.events.append(event)
        result.processed += 1
        if event.is_noise:
            result.noise_count += 1

    return result
