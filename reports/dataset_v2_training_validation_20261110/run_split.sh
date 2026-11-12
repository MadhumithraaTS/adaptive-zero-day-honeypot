#!/usr/bin/env bash
# Task 14B: generate one Dataset V2 split with the unmodified generator 2.1 against the isolated Cowrie.
#   bash reports/dataset_v2_training_validation_20261110/run_split.sh <split> <sessions> <planning_seed> <pacing_seed>
# Run from the repository root. Approved design: design_proposal.md section 4 (speed 1, held-out excluded).
set -u
split=$1; sessions=$2; seed=$3; pacing=$4
HERE=reports/dataset_v2_training_validation_20261110
PY=.venv/Scripts/python.exe
OUT=$HERE/runs/$split
RAW=$HERE/raw/$split
mkdir -p "$HERE/runs" "$RAW" "$HERE/logs"
CONSOLE="$HERE/logs/generator_console_$split.txt"
LOG=/cowrie/cowrie-git/var/log/cowrie/cowrie.json

snapshot() {  # $1 = destination file (docker cp of the cumulative Cowrie log, read-only)
  MSYS_NO_PATHCONV=1 docker cp "cowrie-project:$LOG" "$1"
}

snapshot "$RAW/cowrie_before.json"
before_lines=$(wc -l < "$RAW/cowrie_before.json")
cmd="$PY -W ignore dataset_builder/generate_labelled_traffic.py --config dataset_builder/profiles_v2_revised.json --host 127.0.0.1 --port 2223 --sessions $sessions --seed $seed --pacing-seed $pacing --speed 1 --output-dir $OUT --runs-root $HERE/runs --container cowrie-project"
{
  echo "split=$split start_utc=$(date -u +%FT%TZ) cowrie_lines_before=$before_lines sha256_before=$(sha256sum "$RAW/cowrie_before.json" | cut -c1-64)"
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
tail -5 "$CONSOLE"
