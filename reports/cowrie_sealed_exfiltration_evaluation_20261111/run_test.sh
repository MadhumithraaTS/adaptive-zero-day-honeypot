#!/usr/bin/env bash
# Task 19B: generate the single sealed data_exfiltration test run (approved design: 600 interactions, exfiltration
# only, disjoint IP/domain pools, planning seed 14103, pacing seed 9403, speed 1) with the unmodified generator 2.1,
# following the Task 14B procedure (run_split.sh). Run ONCE from the repository root:
#   bash reports/cowrie_sealed_exfiltration_evaluation_20261111/run_test.sh
# Immediately afterwards the raw evidence is sealed (SHA-256) before any feature is extracted or read.
set -u
HERE=reports/cowrie_sealed_exfiltration_evaluation_20261111
PY=.venv/Scripts/python.exe
OUT=$HERE/runs/test
RAW=$HERE/raw/test
LOCK=$HERE/evidence/GENERATION_DONE.lock
if [ -e "$LOCK" ] || [ -e "$OUT/manifest.jsonl" ]; then echo "test run already generated; refusing (single approved run)"; exit 2; fi
mkdir -p "$HERE/runs" "$RAW" "$HERE/logs" "$HERE/evidence"
CONSOLE="$HERE/logs/generator_console_test.txt"
LOG=/cowrie/cowrie-git/var/log/cowrie/cowrie.json
snapshot() { MSYS_NO_PATHCONV=1 docker cp "cowrie-project:$LOG" "$1"; }

snapshot "$RAW/cowrie_before.json"
before_lines=$(wc -l < "$RAW/cowrie_before.json")
cmd="$PY -W ignore dataset_builder/generate_labelled_traffic.py --config $HERE/config/profiles_v2_sealed_exfiltration.json --include-held-out --host 127.0.0.1 --port 2223 --sessions 600 --seed 14103 --pacing-seed 9403 --speed 1 --output-dir $OUT --runs-root reports --container cowrie-project"
{
  echo "split=test start_utc=$(date -u +%FT%TZ) cowrie_lines_before=$before_lines sha256_before=$(sha256sum "$RAW/cowrie_before.json" | cut -c1-64)"
  echo "\$ $cmd"
} > "$CONSOLE"
$cmd >> "$CONSOLE" 2>&1
rc=$?
snapshot "$RAW/cowrie_after.json"
after_lines=$(wc -l < "$RAW/cowrie_after.json")
prefix=$(head -n "$before_lines" "$RAW/cowrie_after.json" | sha256sum | cut -c1-64)
tail -n +"$((before_lines + 1))" "$RAW/cowrie_after.json" > "$RAW/cowrie_slice.json"
{
  echo "exit=$rc end_utc=$(date -u +%FT%TZ) cowrie_lines_after=$after_lines sha256_after=$(sha256sum "$RAW/cowrie_after.json" | cut -c1-64)"
  echo "prefix_sha256(first $before_lines lines of after)=$prefix"
  echo "slice_lines=$(wc -l < "$RAW/cowrie_slice.json") slice_sha256=$(sha256sum "$RAW/cowrie_slice.json" | cut -c1-64)"
} >> "$CONSOLE"
# seal the raw evidence immediately (protocol section 6.2), before extraction or scoring
{
  echo "# sealed raw test evidence, $(date -u +%FT%TZ); recorded before any feature extraction or scoring"
  sha256sum "$RAW/cowrie_before.json" "$RAW/cowrie_after.json" "$RAW/cowrie_slice.json" "$OUT/manifest.jsonl" "$OUT/run_meta.json" "$OUT/terminal_output.jsonl" "$CONSOLE"
} > "$HERE/evidence/sealed_raw_hashes.txt"
date -u +%FT%TZ > "$LOCK"
tail -5 "$CONSOLE"
