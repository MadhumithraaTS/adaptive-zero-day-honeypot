#!/usr/bin/env bash
# Task 13B: 7 profiles x 3 sessions through the unmodified generator 2.1 against the isolated Cowrie (127.0.0.1:2223).
# Seeds come from configs/session_plan.json (plan_smoke_sessions.py). Run from the repository root.
set -u
HERE=reports/revised_profile_cowrie_smoke_test
PY=.venv/Scripts/python.exe
mkdir -p "$HERE/runs" "$HERE/evidence"
CONSOLE="$HERE/evidence/generator_console.txt"
: > "$CONSOLE"
for name in benign_admin reconnaissance brute_force botnet privilege_escalation lateral_movement data_exfiltration; do
  read -r seed pacing held <<<"$($PY -c "import json;c=json.load(open('$HERE/configs/session_plan.json'))['chosen']['$name'];print(c['seed'],c['pacing_seed'],int(c['include_held_out']))")"
  extra=""; [ "$held" = "1" ] && extra="--include-held-out"
  cmd="$PY -W ignore dataset_builder/generate_labelled_traffic.py --config $HERE/configs/$name.json --host 127.0.0.1 --port 2223 --sessions 3 --seed $seed --pacing-seed $pacing --output-dir $HERE/runs/$name --runs-root $HERE/runs --container cowrie-project $extra"
  echo "===== $name $(date -u +%FT%TZ)" >> "$CONSOLE"
  echo "\$ $cmd" >> "$CONSOLE"
  $cmd >> "$CONSOLE" 2>&1
  echo "exit=$?" >> "$CONSOLE"
done
echo "===== done $(date -u +%FT%TZ)" >> "$CONSOLE"
