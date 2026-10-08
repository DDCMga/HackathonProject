#!/usr/bin/env bash
set -euo pipefail

python scripts/generate_data.py --mode train --out data/train/ --seed 42
python scripts/generate_data.py --mode demo --out data/demo/ --seed 42
python scripts/train.py

set +e
python -m sentinel.cli run data/demo/stream.jsonl --max-risk 70
run_status=$?
set -e

printf "\nDemo detector exit code: %s\n" "$run_status"
printf "A value of 1 means the policy gate found an alert above risk 70.\n"
printf "Start the dashboard with: streamlit run sentinel/dashboard/app.py\n"
