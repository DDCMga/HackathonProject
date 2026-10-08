# Sentinel: intelligent cyber threat and network anomaly detection

Sentinel reads JSONL network telemetry, validates records, builds sliding behavioral windows per source IP, combines an Isolation Forest anomaly score with a Random Forest threat classification, creates a deterministic 0?100 risk score with evidence, and stores alerts in SQLite. A Streamlit dashboard supports alert review. The `--max-risk` policy gate returns exit code 1 when any alert is above the limit and 0 otherwise.

## Architecture

```text
JSONL file or stdin
  -> validation, normalization, noise tagging, malformed-line logging
  -> 60-second windows with a 30-second hop, per-source rolling baseline
  -> Isolation Forest anomaly scoring + Random Forest threat probabilities
  -> deterministic risk score, evidence, and source-record links
  -> SQLite audit log, policy exit code, and Streamlit operator dashboard
```

The streaming feature builder expects events in timestamp order. It holds active overlapping windows and capped per-source history rather than collecting the full input. Each window stores up to 100,000 event memberships; additional memberships are skipped with a stderr notice. Out-of-order events are logged and skipped because their windows may already have been emitted. Records without a supplied ID receive a deterministic line-based ID for alert traceability.

## Quickstart

Python 3.11 or newer is required.

```bash
pip install -e .
python scripts/generate_data.py --mode train --out data/train/ --seed 42
python scripts/generate_data.py --mode demo --out data/demo/ --seed 42
python scripts/train.py
python -m sentinel.cli run data/demo/stream.jsonl --max-risk 70
streamlit run sentinel/dashboard/app.py
python -m pytest -q
```

The run command intentionally exits with code 1 when the demo contains a score above 70. Set `SENTINEL_DB` to choose a database path for the dashboard, or enter the path in the dashboard sidebar. For a one-command walkthrough, run `bash scripts/demo.sh`. To use live telemetry, pipe JSONL into `python -m sentinel.cli run - --max-risk 70` while the dashboard is open.

## CLI commands

- `sentinel run <file|-> [--max-risk 0..100] [--config config.yaml] [--db sentinel.db]` processes telemetry, saves each alert, and enforces the risk ceiling.
- `sentinel train` trains models using `data/train/`.
- `sentinel baseline-stats [--db sentinel.db]` summarizes saved counts by risk band.

Each malformed line is skipped with a line-numbered reason. At end of input, stderr reports processed, skipped, and noise counts. Noise records are counted during ingestion and excluded from behavioral scoring.

## Risk and evidence

The deterministic formula is:

```text
risk = clamp(round(100 * (0.40 * anomaly_score
                          + 0.40 * max_class_probability
                          + 0.20 * evidence_boost)), 0, 100)
evidence_boost = min(1, strong_feature_count / 3)
strong feature: absolute z-score >= 3 against the source's prior-window baseline
```

Bands are Normal (0?30), Suspicious (31?70), and Malicious (71?100). Evidence lists observed feature values and their baseline deviations, ranked by absolute z-score. Alert IDs use UUID5 over source and window start, so identical input produces stable alert identities. `max_class_probability` currently includes the Normal class; this can make a confidently Normal prediction contribute to the risk score and is a known calibration limitation.

Example evidence entry:

```json
{
  "feature": "unique_dest_ports",
  "value": 42,
  "zscore": 9.8,
  "contribution": 9.8
}
```

## Evaluation snapshot

`docs/metrics.json` is produced by `scripts/train.py`. The current saved snapshot reports:

| Class | Precision | Recall | F1 | Support |
|---|---:|---:|---:|---:|
| Normal | 1.00 | 1.00 | 1.00 | 14,722 |
| PortScan | 1.00 | 1.00 | 1.00 | 1 |
| BruteForce | 1.00 | 1.00 | 1.00 | 5 |
| LateralMovement | 1.00 | 1.00 | 1.00 | 2 |
| DataExfiltration | 1.00 | 1.00 | 1.00 | 1 |
| Overall accuracy |  |  | 1.00 | 14,731 |

Confusion matrix row and column order is `Normal, PortScan, BruteForce, LateralMovement, DataExfiltration`; the saved matrix is diagonal with counts `14,722, 1, 5, 2, 1`. This is an optimistic synthetic-data result: overlapping windows from the same generated episodes can appear in both training and held-out folds, and attack-class support is small. Treat it as a pipeline smoke check, not a field-performance estimate.

The suite covers ingestion, bounded streaming input, hostile values, model determinism and score bounds, risk and policy behavior, audit persistence, feature windows, and four attack-signature-to-alert paths. Latest run: 50 tests passed. The demo stream includes malformed lines and all four attack types; noise is excluded from detections. `scripts/demo.sh` was also run from a clean temporary copy, including data generation, training, and detection.

## Design decisions and limitations

- Synthetic telemetry provides controlled labels and repeatable scan, brute-force, lateral-movement, and exfiltration scenarios without external data downloads.
- Isolation Forest catches unusual behavior; Random Forest supplies probabilities for the five classes. Both use fixed random seeds.
- Evidence is deterministic and based on prior-window z-scores. SHAP can later replace or supplement the ranking in `sentinel/risk.py`.
- The baseline and peer history have per-source caps. Very high-cardinality sources can therefore age out of history.
- The pipeline skips out-of-order events and does not perform packet-level direction inference; `bytes_in` remains zero because the event schema has no explicit direction.
- The synthetic evaluation does not establish performance on real network traffic.

## Configuration reference

| Setting | Meaning | Current value |
|---|---|---:|
| `window_seconds` | Duration of each feature window | 60 |
| `hop_seconds` | Step between window starts | 30 |
| `noise_filter.event_types` | Event types tagged as noise | dhcp, arp, multicast, dns |
| `noise_filter.ignored_dest_ips` | Destinations tagged as noise | 224.0.0.1, 255.255.255.255 |
| `risk_weights` | Anomaly, classifier, and evidence weights | 0.40, 0.40, 0.20 |
| `risk_bands` | Score boundaries for Normal, Suspicious, Malicious | 0?30, 31?70, 71?100 |
| `attention_floor` | Minimum score printed as an alert line | 31 |

