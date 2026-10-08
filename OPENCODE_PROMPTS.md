# Opencode Prompt Pack — Cybersecurity Sentinel Prototype
**How to use this file:**
1. Create the project folder, `cd` into it, run `opencode`.
2. **First**, paste the original problem statement PDF into the repo as `docs/PROBLEM_STATEMENT.md` (convert to text or just paste key sections) so the agent always has the full spec in context. Opencode agents read your repo, so anything you want it to honor must live in files, not just chat.
3. Work through the prompts **in order**. Each prompt ends with acceptance criteria — do not move on until the agent meets them.
4. After each milestone: review the diff, run the acceptance checks yourself, then commit. Tell the agent to commit at the end of each milestone.
5. Keep answers tight: if opencode asks clarifying questions, answer with decisions, not options.
6. If the agent goes off track, revert and re-issue the prompt with "Read docs/PROBLEM_STATEMENT.md section X first."

> Golden rule for agentic coding: **one milestone per prompt, small surface area, explicit acceptance criteria.** Never say "build the whole thing" in one prompt.

---

## Prompt 0 — Project scaffold
```
Read docs/PROBLEM_STATEMENT.md fully before doing anything. This project is an
intelligent cybersecurity sentinel: a Python 3.11+ CLI that ingests JSONL
network telemetry (stdin or file), builds sliding-window behavioral features per
source IP, runs an Isolation Forest anomaly detector plus a Random Forest
multi-class threat classifier, combines them into a deterministic 0-100 risk
score with feature-level evidence, persists alerts to SQLite, serves a Streamlit
dashboard, and enforces a --max-risk threshold via exit codes (0 = pass, 1 = breach).

Scaffold the project:
- pyproject.toml with deps: pandas, numpy, scikit-learn, typer, pyyaml, streamlit, pytest
- Package layout: sentinel/{cli,ingest,features,models,risk,policy,audit,config}.py,
  sentinel/dashboard/app.py, scripts/generate_data.py, tests/, data/, docs/
- config.yaml with: window_seconds=60, hop_seconds=30, noise_filter (event_types
  [dhcp, arp, multicast, dns], ignored destination IPs), risk weights
  (anomaly=0.40, threat=0.40, evidence=0.20), risk bands (normal 0-30,
  suspicious 31-70, malicious 71-100)
- Empty __init__.py files, a README.md skeleton, .gitignore for Python.

Do NOT implement logic yet — scaffold only. Commit as "scaffold".
```

## Prompt 1 — Synthetic telemetry generator
```
Implement scripts/generate_data.py. This generator is our ONLY data source for
training and demos, so it must produce labeled, schema-faithful telemetry.

Input schema per record (JSONL): timestamp (ISO8601), event_type
(flow|auth|audit), source_ip, dest_ip, src_port, dest_port, protocol
(tcp|udp|icmp), bytes, packets, auth_status (success|failure|null).

Behavior:
- --mode train --out data/train/ : ~40k records over 2 hours of simulated time.
  85% benign background: normal web/app traffic between plausible internal
  10.x subnets, DNS lookups to a resolver, plus CONFIGURABLE noise volume of
  dhcp/arp/multicast events. Inject clearly separated attack episodes with a
  "label" sidecar file (one JSONL of {record_ids, label} per episode):
  port_scan (one source -> 25+ unique dest ports in 30s, tiny payloads),
  brute_force (30+ failed auth_status from one source in 60s),
  lateral_movement (internal host contacts 5+ NEW internal peers on services
  it never used before), data_exfiltration (single connection, 800MB+ outbound
  to a rare external IP, optionally right after another attack episode).
- --mode demo --out data/demo/ : a 30-minute replayable stream stream.jsonl
  containing: normal traffic, all four attack types at random times, heavy
  benign noise, AND ~10% malformed records (truncated lines, wrong types,
  invalid timestamps, unknown event_type) for resilience testing.
- Deterministic: accept --seed, default 42.

Acceptance: running with default args produces both datasets; records match the
schema; label sidecar correctly identifies every injected attack episode; demo
stream contains malformed lines. Add a smoke test in tests/ asserting record
counts and schema validity. Commit.
```

## Prompt 2 — Ingestion layer
```
Implement sentinel/ingest.py. Contract:
- iter_records(source) -> Iterator[NormalizedEvent]; source is a file path or
  sys.stdin. Reads JSONL line by line (works for unbounded streams).
- Validation: required fields timestamp, source_ip, dest_ip, event_type;
  numeric fields coerced defensively; timestamps parsed to UTC datetime.
- A record that fails validation must NOT raise. It goes to a skip log:
  {line_number, raw_snippet, reason}. Expose skip_log as a returned structure
  and print a one-line summary to stderr at end of stream ("processed N, skipped M").
- Normalization: stable lowercase representations for protocol, event_type,
  auth_status; IPs kept as strings.
- De-prioritization: records matching config.noise_filter are tagged is_noise=True
  but still counted (do not drop silently — log the count).
- Bounded memory: do not buffer the whole stream.

Acceptance: tests/ingest tests — valid file, stdin, empty file, file with only
garbage (0 crashes, all skipped with reasons), malformed types, unknown
event_type is skipped-and-logged, noise records tagged. Commit.
```

## Prompt 3 — Feature engine
```
Implement sentinel/features.py — the heart of the system.

Windowed aggregation keyed by source_ip: tumbling windows of
config.window_seconds with hop config.hop_seconds. For each (source_ip, window)
produce a feature vector:
  event_count, unique_dest_ips, unique_dest_ports, failed_logins,
  success_fail_ratio, bytes_out, bytes_in, bytes_per_conn, new_peer_ratio,
  protocol_entropy (Shannon entropy of protocol distribution),
  rate_vs_baseline (event_count / trailing median event_count for that source).

Maintain a per-source rolling baseline store (median + std per feature over a
bounded trailing history, e.g. last 50 windows) so we can compute z-scores later.
Expose both the feature vector and the z-scores.

Every feature vector keeps linkage: {source_ip, window_start, window_end,
record_ids} so any alert can be traced back to raw records (hard requirement
from the spec).

Acceptance: unit tests with hand-crafted small streams where I can verify
window math by hand — e.g. 42 failed auths in 60s from one source yields
failed_logins=42 in exactly one window; a source touching 25 ports yields
unique_dest_ports=25; new_peer_ratio is 1.0 the first time a peer is seen and
<1.0 after. No pandas groupby shortcuts that obscure the math — clear code,
documented in docstrings. Commit.
```

## Prompt 4 — Models & training
```
Implement sentinel/models.py and scripts/train.py.

scripts/train.py:
- Load data/train/ records + label sidecar.
- Build windowed feature vectors via sentinel.features, attach window labels
  from the sidecar (a window inherits a label if any of its records is labeled;
  multi-label windows take the highest-severity label with this order:
  DataExfiltration > LateralMovement > BruteForce > PortScan > Normal).
- Train IsolationForest (random_state=42, contamination=0.05) on NORMAL-only
  windows. Save to models/anomaly.joblib.
- Train RandomForestClassifier (random_state=42, class_weight="balanced")
  on all labeled windows, 5 classes: Normal, PortScan, BruteForce,
  LateralMovement, DataExfiltration. Save to models/classifier.joblib plus a
  label-order manifest.
- Print per-class precision/recall/F1 and a confusion matrix on a held-out
  20% split. Save metrics to docs/metrics.json.

sentinel/models.py: load_models() returning both; score_window(features) ->
{anomaly_score: float 0-1 (document the linear mapping from score_samples),
class_probs: dict, predicted_class: str}.

Set random_state everywhere and say so in docstrings — determinism is a graded
requirement (same input -> same output).

Acceptance: train.py runs end-to-end on generated data; F1 for each attack
class >= 0.85 (regenerate data with a different seed and confirm stability);
loading models twice gives identical scores on a fixed feature vector. Commit.
```

## Prompt 5 — Risk scoring & evidence
```
Implement sentinel/risk.py. Pure functions only — no I/O, no randomness.

risk_score(anomaly_score, class_probs, evidence_features) -> int 0-100:
  risk = clamp(round(100 * (0.40*anomaly + 0.40*max_class_prob + 0.20*boost)), 0, 100)
  boost = min(1.0, n_strong_features/3) where a feature is "strong" if its
  |z-score| >= 3 vs baseline.
Band mapping: 0-30 Normal, 31-70 Suspicious, 71-100 Malicious (from config).

build_evidence(feature_vector, zscores, class_probs, top_n=5) -> list of
{feature, value, baseline, contribution} dicts, ranked by
0.6*|zscore| + 0.4*classifier_feature_importance for the predicted class.
Values must be actual observed values, never vague statements.

build_alert(...) -> the full alert dict per the schema in the spec: alert_id
(uuid5 over source_ip+window_start — deterministic), timestamp, source_ip,
dest_ip (top destination by bytes), classification (band), threat_category,
risk_score, evidence, anomaly_score, class_probabilities, model_version,
record_ids (traceability), status="new".

Acceptance: unit tests — risk formula exact values for known inputs; clamping at
0 and 100; identical inputs give identical alert_id; evidence ranks a
42-unique-port feature above a routine byte-volume feature in a port-scan
fixture. Document the formula in the README too. Commit.
```

## Prompt 6 — SQLite audit log
```
Implement sentinel/audit.py per the spec's schema, extended:
  alert_id TEXT PRIMARY KEY, timestamp TEXT, source_ip TEXT, dest_ip TEXT,
  classification TEXT, threat_category TEXT, risk_score INTEGER,
  anomaly_score REAL, class_probabilities TEXT (JSON),
  evidence_features TEXT (JSON), model_version TEXT, record_ids TEXT (JSON),
  status TEXT DEFAULT 'new', created_at TEXT.
- init_db(path), insert_alert(conn, alert), list_alerts(conn, ...filters),
  update_status(conn, alert_id, status) for operator review workflow.
- Context-manager connection handling; works with :memory: for tests.

Acceptance: round-trip tests — insert an alert, read it back, fields match;
update status new->reviewed; reopening the DB file persists data; schema is
created idempotently (init twice = no error). Commit.
```

## Prompt 7 — CLI + policy gate
```
Implement sentinel/cli.py with Typer, wired end-to-end:
- `sentinel run <source.(file|->stdin)> [--max-risk N] [--config path]
  [--db path]` : full pipeline — ingest -> features -> models -> risk/evidence
  -> audit -> console report. Console report: one color-coded line per alert
  (band, score, category, source, top evidence feature) using rich-free plain
  output, plus a summary. Alerts below the configured attention floor
  (e.g. risk < 31) are stored but not printed.
- POLICY GATE: if any alert's risk_score > --max-risk, print "POLICY BREACH:
  max risk <N> exceeded by alert <id> (score <S>)" and exit 1; else exit 0.
  This must be the process exit code — automated pipelines depend on it.
- `sentinel train` : invokes scripts/train.py logic.
- `sentinel baseline-stats --db path` : quick operator summary (counts by band).

Acceptance: run against data/demo/stream.jsonl with --max-risk 70 — exit code 1
and a breach line naming the alert; run with --max-risk 100 — exit 0; piping the
same stream via stdin gives identical results to reading the file (determinism);
no traceback on the malformed records (skips summarized on stderr). Commit.
```

## Prompt 8 — Streamlit dashboard
```
Implement sentinel/dashboard/app.py. Reads the SQLite DB (path via env var or
sidebar input). Prioritize clarity:
- Header: total alerts, counts per band, latest alert time.
- Alert table: filterable by band/threat_category/status; risk_score
  color-coded (green/amber/red); click a row to expand and see the full
  evidence list with observed values and baselines.
- Charts: risk distribution histogram, top-10 source IPs by max risk, threat
  category breakdown.
- Operator actions: buttons to mark an alert reviewed/resolved (writes back
  via sentinel.audit.update_status), with a refresh button.
- Auto-refresh every 10s when a run is in progress (st.experimental rerun /
  st_autorefresh is fine).

Acceptance: `streamlit run sentinel/dashboard/app.py` shows all sections with
demo data; marking an alert reviewed persists after refresh; app never crashes
on an empty DB (show friendly empty state). Add a one-line note in README on
how to launch it alongside a live run. Commit.
```

## Prompt 9 — Resilience hardening
```
Harden the pipeline per the spec's hostile-input requirements. Write adversarial
tests first, then fix what fails:
- tests/fuzz_ingest.py: 500 random garbage lines (truncated JSON, null bytes,
  huge lines 1MB+, wrong field types, timestamps like "not-a-date",
  IPv6-vs-IPv4 mix) — assert: zero exceptions escape ingest, every bad line
  appears in the skip log with a reason, good lines still processed.
- Unbounded-stream test: pipe 200k records via stdin, assert bounded memory
  growth (ingest must not accumulate the whole stream) and correct exit code.
- Hostile-value test: bytes=-99999, packets=0 with bytes>0, ports > 65535 —
  coerce or skip with reason, never feed NaN/inf into the models.
- Add a defensive guard in features/models: if a feature vector contains NaN
  or inf, skip scoring that window and log it.
- Confirm noise records (dhcp/arp/multicast) produce no alerts above
  Suspicious in the demo stream.

Acceptance: all tests green; run the full demo twice and diff the SQLite dumps
— byte-identical (determinism proof). Commit.
```

## Prompt 10 — Test suite & CI-ready quality gate
```
Complete tests/ so `pytest` covers: ingest (valid/malformed/stdin/noise),
features (window math, baselines, z-scores), models (determinism, score
ranges), risk (formula, clamping, evidence ranking), policy (exit codes),
audit (persistence). Target: the four attack types each have at least one
end-to-end test — fixture stream in, correct threat_category alert out with
risk above the Malicious band where the fixture is unambiguous.
Add a Makefile or just document in README: setup, generate data, train, run,
dashboard, test. Commit.
```

## Prompt 11 — Documentation & demo
```
Write README.md as the submission document, mirroring the rubric:
1. One-paragraph what-it-does + architecture diagram (ASCII, the 5 stages).
2. Quickstart: commands to generate data, train, run the demo stream, open
   the dashboard — each copy-pasteable.
3. Risk formula and evidence method, stated explicitly with the weights.
4. Evaluation section: paste docs/metrics.json results + determinism +
   resilience test outcomes + a worked example alert with its evidence.
5. Design decisions: why synthetic data, why IsolationForest+RandomForest,
   why no SHAP (and where it would plug in), known limitations.
6. Config reference for config.yaml.

Then create scripts/demo.sh that runs the whole story in one command:
generate -> train -> run demo stream with --max-risk 70 -> prints exit code ->
tells the user how to open the dashboard. Make it executable and verify it
runs clean from a fresh clone state (delete data/ and models/ first, rerun).
Commit.
```

---

## General opencode operating tips
- **Review every diff** before accepting; agents drift on long sessions. Revert early, re-prompt with the acceptance criteria restated.
- **Force small commits** per milestone — it makes agent mistakes cheap to undo.
- If opencode picks the wrong abstraction (e.g., pandas magic you can't explain to judges), say: "rewrite X so the window math is explicit and explainable — judges will ask about it."
- Save your answers to its questions in `docs/DECISIONS.md` so later prompts stay consistent.
- For the demo, rehearse `scripts/demo.sh` end-to-end at least twice; have a pre-trained `models/` and pre-generated `data/demo/` folder as a fallback in case of venue Wi-Fi issues.
