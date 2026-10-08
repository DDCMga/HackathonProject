# IT HAPPENS @ RAALE #11 — Solution Approach Report
**Intelligent Cyber Threat & Network Anomaly Detection Sentinel**

---

## 1. What the judges actually want

The problem statement is written in academic language, but the rubric (Part 9.3, page 10) is the real contract:

| Rubric component | Weight | What wins points |
|---|---|---|
| Telemetry ingestion & features | 15 | Clean parsing, sliding windows, malformed-record tolerance |
| Anomaly detection | 20 | Isolation Forest / One-Class SVM on **behavioral** features |
| Threat classification | 15 | Multi-class model (Port Scan, Brute Force, Lateral Movement, Exfil, Normal) |
| Risk scoring & explainability | 15 | Deterministic 0–100 score + **feature-level evidence** |
| Audit log & dashboard | 10 | SQLite schema + Streamlit operator view |
| Policy guardrail | 10 | `--max-risk N` → exit 0/1 |
| Noise/hostile-input resilience | 10 | Never crash; filter DHCP/ARP/multicast; log skips |
| Documentation & demo | 5 | Concise README + working demo |

**Key insight:** 60 of the 100 points are *not* model accuracy. Most teams will train a decent model and lose points on explainability, determinism, resilience, and the policy gate. Build those first-class, not as afterthoughts.

---

## 2. Recommended architecture

```
telemetry (stdin / file, JSONL)
        │
        ▼
┌───────────────────┐   Normalized events (validated, typed,
│ 1. INGESTION       │   timestamps normalized, malformed → skip+log)
│    ingest.py       │
└─────────┬─────────┘
          ▼
┌───────────────────┐   Per-(source_ip, window) feature vectors:
│ 2. FEATURE ENGINE  │   event_count, unique_dest_ips, unique_dest_ports,
│    features.py     │   failed_logins, success_ratio, bytes_out/in,
│    60s window,     │   new_peer_ratio, protocol entropy, rate-of-change
│    30s hop         │
└─────────┬─────────┘
          ▼
┌───────────────────────────────┐   Anomaly score [0,1] (Isolation Forest
│ 3. DUAL-LAYER DETECTION        │   trained on normal-only windows)
│    models.py                   │        +
│    IsolationForest +           │   Class probabilities [Normal, PortScan,
│    RandomForest/XGBoost        │   BruteForce, LateralMovement, Exfil]
└─────────┬─────────────────────┘
          ▼
┌───────────────────┐   Deterministic risk 0–100
│ 4. RISK & EVIDENCE │   Top-N contributing features with real values
│    risk.py         │   → Alert object {source, ts, class, score, evidence[]}
└─────────┬─────────┘
          ▼
┌───────────────────┐   SQLite audit table   +   Streamlit dashboard
│ 5. POLICY & AUDIT  │   --max-risk 70 → exit 1 on breach, else 0
│    audit.py, cli.py│
└───────────────────┘
```

### Module layout

```
sentinel/
├── cli.py            # Typer entrypoint: ingest, train, run, policy gate
├── ingest.py         # stdin/file reader, validation, normalization, skip-log
├── features.py       # sliding-window aggregation
├── models.py         # anomaly model + classifier (train/load)
├── risk.py           # risk formula + evidence extraction
├── policy.py         # threshold evaluation + exit codes
├── audit.py          # SQLite persistence
├── config.py         # YAML config: windows, noise filter, thresholds
├── dashboard/
│   └── app.py        # Streamlit operator view
├── scripts/
│   └── generate_data.py   # synthetic telemetry generator
├── data/
│   ├── train/             # generated training windows (with labels)
│   └── demo/              # demo stream incl. attacks + noise + malformed
└── tests/              # pytest suite
```

---

## 3. Critical design decisions (and why)

### 3.1 Data strategy — build a synthetic generator FIRST
This is the single most important decision.

- **Option A: public dataset (CIC-IDS2017, UNSW-NB15, NSL-KDD).** Real labels, but heavy downloads, field formats that don't match the handout's schema (`event_type`, `auth_status`...), and you spend half the hackathon on ETL instead of the pipeline.
- **Option B (recommended): synthetic JSONL generator.** You control the schema to match the handout exactly, you can generate **labeled** training data, and — crucially — you can generate the *benign noise* (DHCP, ARP, multicast, DNS, backups, monitoring probes) that Part 6 demands you filter. You can also emit deliberately malformed records to prove resilience.
- **Best of both:** generate synthetic data for the full pipeline + demo, and optionally fine-tune/validate the classifier on a public dataset if time permits.

The generator must produce four attack patterns with **window-level signatures**:
- **Port scan:** one source → 25+ unique dest ports in 30s, low bytes per flow
- **Brute force:** 30+ failed `auth_status` from one source in 60s
- **Lateral movement:** internal host talking to many *new* internal peers on services it never uses (track peer history)
- **Data exfiltration:** large outbound bytes to a rare external destination right after other suspicious events

### 3.2 Feature engineering — windows per source, not per flow
Single events are meaningless (Part 3.3 says this explicitly). Use **tumbling/sliding windows keyed by source_ip** (e.g., 60 s window, 30 s hop). Each window becomes one feature vector:

| Feature | Detects |
|---|---|
| `event_count` | volume anomalies |
| `unique_dest_ips`, `unique_dest_ports` | port scan, lateral movement |
| `failed_logins`, `success_fail_ratio` | brute force, password spraying |
| `bytes_out`, `bytes_in`, `bytes_per_conn` | exfiltration |
| `new_peer_ratio` (peers never seen from this source before) | lateral movement |
| `protocol_entropy` | unusual protocol mix |
| `rate_vs_baseline` (events vs trailing average) | bursts |

Keep a **baseline store** (rolling per-source medians) — you need it both for the `new_peer_ratio` feature and for the explanation layer (z-scores vs baseline).

### 3.3 Dual-layer detection — how the two models complement each other
- **Isolation Forest** trained **only on normal windows**. Output: anomaly score ∈ [0,1] (map `score_samples` linearly — document the mapping). It catches "weird but unlabeled" behavior.
- **Random Forest** (start here; XGBoost only if time allows — RF has `feature_importances_` for free and is harder to misconfigure) trained on **labeled windows** from your generator. Output: probability vector over 5 classes.
- Set `random_state` **everywhere**. The rubric demands "same input → same result."

### 3.4 Risk score — deterministic and documented
A defensible formula (state it in the README and config):

```
risk = clamp( round( 100 * ( 0.40 * anomaly_score
                           + 0.40 * max_threat_class_prob
                           + 0.20 * evidence_boost ) ), 0, 100 )
```

where `evidence_boost` ∈ [0,1] counts how many features exceed, say, 3σ from baseline (normalized: boost = min(1, n_strong_features / 3)).

Bands: **0–30 Normal · 31–70 Suspicious · 71–100 Malicious** (per the handout). Because the formula is a pure function of model outputs + config, it is deterministic and unit-testable.

### 3.5 Explainability — the highest-leverage rubric item
Every alert carries an `evidence[]` list of the **top 3–5 features, ranked**, each with the *actual observed value* and *why it matters*:

```json
{
  "alert_id": "a3f9...",
  "timestamp": "2026-10-08T17:52:11Z",
  "source_ip": "10.0.3.41",
  "classification": "Malicious",
  "threat_category": "PortScan",
  "risk_score": 88,
  "evidence": [
    {"feature": "unique_dest_ports", "value": 42, "baseline": "median 3 (z=9.8)", "contribution": 0.41},
    {"feature": "event_count", "value": 61, "baseline": "median 8 (z=6.2)", "contribution": 0.27},
    {"feature": "bytes_per_conn", "value": 120, "note": "tiny payloads = probe, not transfer", "contribution": 0.14}
  ],
  "anomaly_score": 0.93,
  "class_probabilities": {"Normal": 0.02, "PortScan": 0.91, "BruteForce": 0.04, "LateralMovement": 0.02, "Exfiltration": 0.01},
  "model_version": "anomaly-if-v1 / clf-rf-v1"
}
```

**How to rank features without SHAP (simpler, deterministic):** rank by |z-score| of each feature against the per-source baseline, blended with the classifier's `feature_importances_` for the predicted class. Both are deterministic and cheap. Mention in docs that SHAP could replace this.

### 3.6 Noise & hostile-input resilience (10 rubric points, easy to win)
- Config-driven **noise filter**: event types / destination IPs to de-prioritize (DHCP, ARP, multicast 224.0.0.0/4, DNS resolvers, monitoring probes).
- **Validation layer:** every record checked for required fields + types; timestamps parsed defensively; malformed → write to `skip_log` (with reason) and continue. Never raise to top level.
- **Bounded resources:** cap in-memory window buffers; handle unbounded stdin.
- Prove it: ship a `demo/noisy_stream.jsonl` containing ~10% garbage lines, and show the system processing 100% of the good ones.

### 3.7 Policy guardrail
CLI contract (exactly as the handout's example):

```
python -m sentinel.cli run data/demo/stream.jsonl --max-risk 70
echo $?   # 0 = no alert above 70, 1 = policy breach
```

### 3.8 Audit & dashboard
SQLite table per the handout schema (`alert_id, timestamp, source_ip, dest_ip, classification, risk_score, evidence_features, status`) plus `model_version` and `class_probabilities` columns for full reproducibility. `status` starts as `new`; dashboard allows marking `reviewed`/`resolved` (human-in-the-loop, Part 7.5).

Streamlit dashboard, clarity over beauty: alert table with risk-colored rows, risk distribution histogram, top source IPs bar chart, threat-category breakdown, expandable per-alert evidence.

---

## 4. Suggested build order (fits a 1–2 day hackathon)

| Phase | Deliverable |
|---|---|
| 1 | Project scaffold + config + synthetic data generator |
| 2 | Ingestion + feature engine (unit-tested) |
| 3 | Training script + both models |
| 4 | Risk score + evidence + audit (SQLite) |
| 5 | CLI + policy gate |
| 6 | Streamlit dashboard |
| 7 | Resilience hardening + noisy-stream demo + README |
| 8 | (Stretch) validate on public dataset, SHAP, retrain endpoint |

## 5. Evaluation you should run and report
- **Classification:** per-class precision/recall/F1 + confusion matrix (not just accuracy — imbalance is guaranteed). Report on a held-out generated set.
- **False-positive rate** on a pure-benign noisy stream — target the alert stream stays dominated by true findings.
- **Determinism test:** run the same input twice → byte-identical alerts and exit codes.
- **Resilience test:** inject malformed/truncated/hostile records → 0 crashes, all logged.
- **Explainability check:** for 5 sample alerts, hand-verify the top evidence features against raw records (this is exactly what judges will do).

## 6. Why this design wins
1. **Generator-first** removes the biggest hackathon risk (data ETL) and directly serves the noise-resilience rubric.
2. **Baseline store** gives you both a better lateral-movement feature and free, deterministic explanations.
3. **Pure-function risk scoring** makes the policy gate trivially correct and testable.
4. **Every rubric row maps to a concrete module**, so nothing is forgotten and the README can mirror the rubric.
