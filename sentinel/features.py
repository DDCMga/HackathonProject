"""Bounded-memory sliding-window feature extraction."""

import math
import sys
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Iterable, Iterator

from sentinel.ingest import NormalizedEvent

MAX_EVENTS_PER_WINDOW = 100_000


@dataclass
class FeatureVector:
    source_ip: str
    window_start: str
    window_end: str
    event_count: int
    unique_dest_ips: int
    unique_dest_ports: int
    failed_logins: int
    success_fail_ratio: float
    bytes_out: int
    bytes_in: int
    bytes_per_conn: float
    new_peer_ratio: float
    protocol_entropy: float
    rate_vs_baseline: float
    record_ids: list = field(default_factory=list)
    baseline_zscores: dict = field(default_factory=dict, repr=False)
    dest_ip: str = ""

    def to_dict(self):
        return {
            "source_ip": self.source_ip, "window_start": self.window_start,
            "window_end": self.window_end, "dest_ip": self.dest_ip,
            "event_count": self.event_count, "unique_dest_ips": self.unique_dest_ips,
            "unique_dest_ports": self.unique_dest_ports, "failed_logins": self.failed_logins,
            "success_fail_ratio": self.success_fail_ratio, "bytes_out": self.bytes_out,
            "bytes_in": self.bytes_in, "bytes_per_conn": self.bytes_per_conn,
            "new_peer_ratio": self.new_peer_ratio, "protocol_entropy": self.protocol_entropy,
            "rate_vs_baseline": self.rate_vs_baseline, "record_ids": self.record_ids,
        }


@dataclass
class BaselineStore:
    max_history: int = 50
    max_sources: int = 10000
    max_peers_per_source: int = 2048
    _history: dict = field(default_factory=dict)
    _seen_peers: dict = field(default_factory=dict)
    _source_order: OrderedDict = field(default_factory=OrderedDict)

    def _touch_source(self, source_ip: str):
        if source_ip not in self._source_order:
            if len(self._source_order) >= self.max_sources:
                expired, _ = self._source_order.popitem(last=False)
                for key in [key for key in self._history if key[0] == expired]:
                    del self._history[key]
                self._seen_peers.pop(expired, None)
            self._source_order[source_ip] = None
        else:
            self._source_order.move_to_end(source_ip)

    def update(self, source_ip: str, features: dict):
        self._touch_source(source_ip)
        for key, value in features.items():
            values = self._history.setdefault((source_ip, key), [])
            values.append(float(value))
            if len(values) > self.max_history:
                del values[0]

    def get_median(self, source_ip: str, feature_name: str) -> float:
        values = self._history.get((source_ip, feature_name), [])
        if not values:
            return 0.0
        values = sorted(values)
        n = len(values)
        if n % 2:
            return float(values[n // 2])
        return (values[n // 2 - 1] + values[n // 2]) / 2.0

    def get_std(self, source_ip: str, feature_name: str) -> float:
        values = self._history.get((source_ip, feature_name), [])
        if len(values) < 2:
            return 1.0
        mean = sum(values) / len(values)
        variance = sum((value - mean) ** 2 for value in values) / (len(values) - 1)
        return math.sqrt(variance) if variance > 0 else 1.0

    def add_peer(self, source_ip: str, dest_ip: str):
        self._touch_source(source_ip)
        peers = self._seen_peers.setdefault(source_ip, OrderedDict())
        peers[dest_ip] = None
        peers.move_to_end(dest_ip)
        if len(peers) > self.max_peers_per_source:
            peers.popitem(last=False)

    def has_seen_peer(self, source_ip: str, dest_ip: str) -> bool:
        self._touch_source(source_ip)
        return dest_ip in self._seen_peers.get(source_ip, {})

    def peer_history_size(self, source_ip: str) -> int:
        return len(self._seen_peers.get(source_ip, {}))


def _shannon_entropy(protocols: list) -> float:
    if not protocols:
        return 0.0
    counts = defaultdict(int)
    for protocol in protocols:
        counts[protocol] += 1
    total = len(protocols)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def compute_window_features(source_ip, window_start, window_end, events, baseline):
    event_count = len(events)
    dest_ips = {event.dest_ip for event in events}
    dest_ports = {event.dest_port for event in events}
    bytes_by_dest = defaultdict(int)
    failed_logins = success_logins = bytes_out = 0
    protocols, record_ids = [], []
    for event in events:
        protocols.append(event.protocol)
        bytes_out += event.bytes
        bytes_by_dest[event.dest_ip] += event.bytes
        if event.record_id:
            record_ids.append(event.record_id)
        if event.event_type == "auth":
            failed_logins += int(event.auth_status == "failure")
            success_logins += int(event.auth_status == "success")

    unseen = {peer for peer in dest_ips if not baseline.has_seen_peer(source_ip, peer)}
    new_peer_ratio = len(unseen) / len(dest_ips) if dest_ips else 0.0
    for peer in dest_ips:
        baseline.add_peer(source_ip, peer)

    success_fail_ratio = success_logins / (success_logins + failed_logins) if success_logins + failed_logins else 1.0
    bytes_per_conn = bytes_out / event_count if event_count else 0.0
    protocol_entropy = _shannon_entropy(protocols)
    prior_median = baseline.get_median(source_ip, "event_count")
    rate_vs_baseline = event_count / prior_median if prior_median > 0 else 1.0
    values = {
        "event_count": event_count, "unique_dest_ips": len(dest_ips),
        "unique_dest_ports": len(dest_ports), "failed_logins": failed_logins,
        "bytes_out": bytes_out, "bytes_per_conn": bytes_per_conn,
        "new_peer_ratio": new_peer_ratio, "protocol_entropy": protocol_entropy,
    }
    zscores = {}
    for name, value in values.items():
        if baseline._history.get((source_ip, name)):
            median = baseline.get_median(source_ip, name)
            zscores[name] = (value - median) / baseline.get_std(source_ip, name)
        else:
            zscores[name] = 0.0

    vector = FeatureVector(
        source_ip=source_ip, window_start=window_start.isoformat(), window_end=window_end.isoformat(),
        event_count=event_count, unique_dest_ips=len(dest_ips), unique_dest_ports=len(dest_ports),
        failed_logins=failed_logins, success_fail_ratio=success_fail_ratio, bytes_out=bytes_out,
        bytes_in=0, bytes_per_conn=bytes_per_conn, new_peer_ratio=new_peer_ratio,
        protocol_entropy=protocol_entropy, rate_vs_baseline=rate_vs_baseline,
        record_ids=record_ids, baseline_zscores=zscores,
        dest_ip=max(bytes_by_dest, key=bytes_by_dest.get) if bytes_by_dest else "",
    )
    baseline.update(source_ip, values)
    return vector


def build_windows(events: Iterable[NormalizedEvent], window_seconds=60, hop_seconds=30) -> Iterator[FeatureVector]:
    """Yield sliding windows using bounded active-window buffers. Input timestamps must be ordered.

    Noise remains counted by ingestion but is excluded from behavioral detection. Late records are
    logged and skipped because their windows may already have been emitted.
    """
    if window_seconds <= 0 or hop_seconds <= 0:
        raise ValueError("window_seconds and hop_seconds must be positive")
    baseline = BaselineStore()
    pending = {}
    first_start = next_start = last_timestamp = None
    dropped_memberships = 0
    window_delta = timedelta(seconds=window_seconds)
    hop_delta = timedelta(seconds=hop_seconds)

    def emit(start):
        window_events = pending.pop(start, [])
        by_source = defaultdict(list)
        for event in window_events:
            by_source[event.source_ip].append(event)
        end = start + window_delta
        for source, source_events in by_source.items():
            yield compute_window_features(source, start, end, source_events, baseline)

    for event in events:
        if event.is_noise:
            continue
        if last_timestamp is not None and event.timestamp < last_timestamp:
            print(f"SKIP out-of-order event at {event.timestamp.isoformat()}", file=sys.stderr)
            continue
        if first_start is None:
            aligned = int(event.timestamp.timestamp())
            aligned -= aligned % hop_seconds
            first_start = datetime.fromtimestamp(aligned, tz=timezone.utc)
            next_start = first_start
        while next_start + window_delta <= event.timestamp:
            yield from emit(next_start)
            next_start += hop_delta
        timestamp_epoch = int(event.timestamp.timestamp())
        candidate = datetime.fromtimestamp(timestamp_epoch - timestamp_epoch % hop_seconds, tz=timezone.utc)
        while candidate >= next_start and event.timestamp < candidate + window_delta:
            bucket = pending.setdefault(candidate, [])
            if len(bucket) < MAX_EVENTS_PER_WINDOW:
                bucket.append(event)
            else:
                dropped_memberships += 1
            candidate -= hop_delta
        last_timestamp = event.timestamp

    if next_start is not None:
        while next_start <= last_timestamp:
            yield from emit(next_start)
            next_start += hop_delta
    if dropped_memberships:
        print(f"SKIP {dropped_memberships} event-window memberships after the per-window buffer cap", file=sys.stderr)


def compute_zscores(feature_vector: FeatureVector, baseline: BaselineStore) -> dict:
    if feature_vector.baseline_zscores:
        return dict(feature_vector.baseline_zscores)
    names = ("event_count", "unique_dest_ips", "unique_dest_ports", "failed_logins",
             "bytes_out", "bytes_per_conn", "new_peer_ratio", "protocol_entropy")
    result = {}
    for name in names:
        value = getattr(feature_vector, name)
        median, std = baseline.get_median(feature_vector.source_ip, name), baseline.get_std(feature_vector.source_ip, name)
        result[name] = (value - median) / std if std else 0.0
    return result
