"""Typer commands for running and operating Sentinel."""

import sys

import numpy as np
import typer

from sentinel.audit import get_counts_by_band, init_db, insert_alert
from sentinel.features import BaselineStore, build_windows, compute_zscores
from sentinel.ingest import iter_records, load_config
from sentinel.models import FEATURE_COLUMNS, load_models, score_windows
from sentinel.policy import is_breach
from sentinel.risk import build_alert, build_evidence

app = typer.Typer(name="sentinel", help="Intelligent Cyber Threat & Network Anomaly Detection Sentinel")


def iter_pipeline(source, config_path="config.yaml", db_path="sentinel.db", config=None):
    """Yield alerts as they are scored and persist them incrementally."""
    config = config or load_config(config_path)
    anomaly_model, classifier_model = load_models()
    conn = init_db(db_path)
    count = 0

    def score_batch(batch):
        nonlocal count
        matrix = np.asarray([
            [window.to_dict()[name] for name in FEATURE_COLUMNS]
            for window in batch
        ], dtype=np.float64)
        finite = np.isfinite(matrix).all(axis=1)
        valid_windows = []
        for window, is_finite in zip(batch, finite):
            if is_finite:
                valid_windows.append(window)
            else:
                print("SKIP non-finite feature window", file=sys.stderr)
        scores_batch = score_windows(valid_windows, anomaly_model, classifier_model)
        for window, scores in zip(valid_windows, scores_batch):
            zscores = compute_zscores(window, None)
            evidence = build_evidence(window, zscores, scores["class_probs"])
            alert = build_alert(
                window, scores["anomaly_score"], scores["class_probs"],
                scores["predicted_class"], zscores, evidence, config=config,
            )
            insert_alert(conn, alert, commit=False)
            count += 1
            if count % 250 == 0:
                conn.commit()
            yield alert

    try:
        events = iter_records(source, config)
        windows = build_windows(events, config["window_seconds"], config["hop_seconds"])
        batch = []
        for window in windows:
            batch.append(window)
            if len(batch) >= 256:
                yield from score_batch(batch)
                batch.clear()
        if batch:
            yield from score_batch(batch)
        conn.commit()
    finally:
        conn.close()


def run_pipeline(source, config_path="config.yaml", db_path="sentinel.db"):
    """Compatibility wrapper that returns all alerts; CLI uses iter_pipeline."""
    config = load_config(config_path)
    return list(iter_pipeline(source, config_path, db_path, config)), config


def print_alert(alert, attention_floor=31):
    if alert["risk_score"] < attention_floor:
        return
    band, score = alert["classification"], alert["risk_score"]
    category, source = alert["threat_category"], alert["source_ip"]
    top_evidence = alert["evidence"][0]["feature"] if alert["evidence"] else "N/A"
    color = {"Malicious": "\033[91m", "Suspicious": "\033[93m", "Normal": "\033[92m"}.get(band, "")
    reset = "\033[0m" if color else ""
    print(f"{color}[{band:10s}] Score: {score:3d} | {category:20s} | {source:15s} | {top_evidence}{reset}")


@app.command()
def run(
    source: str = typer.Argument(..., help="JSONL path or '-' to read stdin"),
    max_risk: int = typer.Option(70, "--max-risk", min=0, max=100, help="Maximum allowed risk score (0-100)"),
    config: str = typer.Option("config.yaml", "--config", help="Path to config.yaml"),
    db: str = typer.Option("sentinel.db", "--db", help="Path to SQLite database"),
):
    """Run detection, persist alerts, and return 1 when policy is breached."""
    cfg = load_config(config)
    input_source = sys.stdin if source == "-" else source
    attention_floor = cfg.get("attention_floor", 31)
    total = printed = 0
    breach_alert = None
    for alert in iter_pipeline(input_source, config, db, cfg):
        total += 1
        print_alert(alert, attention_floor)
        printed += int(alert["risk_score"] >= attention_floor)
        if breach_alert is None and is_breach(alert, max_risk):
            breach_alert = alert
    print(f"\n{'=' * 70}")
    print(f"Total alerts: {total} | Printed: {printed} | Max risk threshold: {max_risk}")
    if breach_alert:
        print(f"\nPOLICY BREACH: max risk {max_risk} exceeded by alert {breach_alert['alert_id']} (score {breach_alert['risk_score']})")
        raise typer.Exit(code=1)
    print("Policy check PASSED.")
    raise typer.Exit(code=0)


@app.command()
def train():
    """Train models on generated telemetry."""
    from scripts.train import main as train_main
    train_main()


@app.command()
def baseline_stats(db: str = typer.Option("sentinel.db", "--db", help="Path to SQLite database")):
    """Show alert counts grouped by risk band."""
    conn = init_db(db)
    try:
        counts = get_counts_by_band(conn)
        total = sum(counts.values())
        print(f"\nAlert Summary (total: {total})")
        for band in ("Malicious", "Suspicious", "Normal"):
            print(f"  {band:12s}: {counts.get(band, 0)}")
    finally:
        conn.close()


if __name__ == "__main__":
    app()
