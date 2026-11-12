"""Collect Cowrie logs for a generated run, attach ground-truth labels, and build the feature CSV.

Pipeline, all under the run's --output-dir (never touching data/ or the tracked scripts' defaults):

  1. Obtain raw Cowrie logs: --raw-input <cowrie.json>, or `docker cp` via scripts/collect_logs.py.
  2. Parse them into sessions with scripts/parse_logs.py (reused as-is).
  3. Label sessions with dataset_builder/labelling.py (labelling v2): assign each session to its
     manifest entry by aligning Cowrie's sessions with the manifest's authentication attempts, and
     give it a behaviour label (failed_login, login_no_commands, the source profile's category when
     its commands support it, or ambiguous/unassigned). Inject attack_cat/label onto every event.
  4. Run scripts/extract_features.py (reused as-is) on the labelled sessions to get behavior_features.csv.

Output: <output-dir>/labelled/{sessions_labelled.json, label_assignments.csv, label_report.json,
behavior_features.csv, session_details.json}. To correct an existing run without rebuilding it, use
relabel_run.py, which writes a new directory instead.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, '..'))
SCRIPTS = os.path.join(REPO_ROOT, 'scripts')
sys.path.insert(0, REPO_ROOT)
from dataset_builder import labelling  # noqa: E402
from session_exclusions import load_exclusions  # noqa: E402


def parse_iso(ts):
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace('Z', '+00:00'))
    except ValueError:
        return None


def load_manifest(path):
    entries = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    if not entries:
        raise SystemExit(f"Manifest {path} is empty.")
    for e in entries:
        e['_start'] = parse_iso(e.get('start_utc'))
        e['_end'] = parse_iso(e.get('end_utc'))
    return entries


def session_bounds(events):
    """First/last event timestamps and the set of command inputs for one parsed session."""
    times, commands = [], []
    for ev in events:
        dt = parse_iso(ev.get('timestamp'))
        if dt:
            times.append(dt)
        if ev.get('eventid') == 'cowrie.command.input':
            commands.append((ev.get('input') or '').strip())
    return (min(times) if times else None, max(times) if times else None, commands)


def run_script(name, args, python=None):
    cmd = [python or sys.executable, os.path.join(SCRIPTS, name), *args]
    print(f"  -> {name} {' '.join(args)}")
    subprocess.run(cmd, check=True)


def main():
    parser = argparse.ArgumentParser(description='Attach labels to a Cowrie run and build the feature CSV.')
    parser.add_argument('--output-dir', required=True, help='The run dir produced by generate_labelled_traffic.py.')
    parser.add_argument('--raw-input', help='Existing cowrie.json. If omitted, collect via docker cp.')
    parser.add_argument('--container', default='cowrie-project', help='Cowrie container name for docker cp.')
    parser.add_argument('--clock-tolerance', type=float, default=5.0,
                        help='Seconds of host/Cowrie clock difference allowed when a time window is used '
                             'to choose between otherwise equal candidate entries.')
    parser.add_argument('--min-block', type=int, default=3,
                        help='Minimum consecutive matching attempts for an alignment block to be trusted.')
    parser.add_argument('--allow-overwrite', action='store_true',
                        help='Allow replacing an existing raw/, parsed/ or labelled/ output in --output-dir.')
    parser.add_argument('--cap-empty', action='store_true',
                        help='Reduce zero-command (failed-login) sessions: keep up to --brute-empty-cap '
                             'for brute_force and drop them from other categories. Command-bearing '
                             'sessions are always kept. Off by default (keeps every session).')
    parser.add_argument('--brute-empty-cap', type=int, default=150,
                        help='With --cap-empty, how many empty brute_force sessions to keep (default 150).')
    parser.add_argument('--window-margin', type=float, default=15.0,
                        help='Seconds of clock-skew slack around the run window; sessions outside it '
                             'are dropped. Keep small: generate with --reset-cowrie-log so the log is '
                             'already clean, since runs <1s apart cannot be separated by time alone.')
    args = parser.parse_args()

    out = args.output_dir
    manifest_path = os.path.join(out, 'manifest.jsonl')
    if not os.path.isfile(manifest_path):
        raise SystemExit(f"No manifest at {manifest_path}; run generate_labelled_traffic.py first.")

    labelled_dir = os.path.join(out, 'labelled')
    raw_path = os.path.join(out, 'raw', 'cowrie.json')
    sessions_path = os.path.join(out, 'parsed', 'sessions.json')
    features_path = os.path.join(labelled_dir, 'behavior_features.csv')

    # Never replace an already-built run (its raw log, parsed sessions or labels) by accident.
    existing = [p for p in (raw_path, sessions_path, os.path.join(out, 'raw', 'cowrie_thisrun.json'),
                            os.path.join(labelled_dir, 'sessions_labelled.json'), features_path)
                if os.path.exists(p)]
    if existing and not args.allow_overwrite:
        raise SystemExit("Refusing to overwrite existing outputs (use relabel_run.py to correct a built run, "
                         "or pass --allow-overwrite):\n  " + "\n  ".join(existing))
    os.makedirs(labelled_dir, exist_ok=True)

    # Baseline captured by the generator: how many log lines predate this run. We parse only the
    # lines after it, which isolates this run even from a run that started a fraction of a second
    # earlier (time windows cannot). None/absent means the generator skipped it (--no-baseline).
    baseline = None
    meta_path = os.path.join(out, 'run_meta.json')
    if os.path.isfile(meta_path):
        with open(meta_path, encoding='utf-8') as f:
            baseline = json.load(f).get('log_baseline_lines')

    print("1. Obtaining raw Cowrie logs")
    if args.raw_input:
        # Byte-for-byte copy: the raw log is never decoded or re-encoded here, so nothing is replaced.
        # Invalid UTF-8, if any, is reported with its line number by parse_logs.py in step 2.
        os.makedirs(os.path.dirname(raw_path), exist_ok=True)
        shutil.copyfile(args.raw_input, raw_path)
        print(f"  copied {args.raw_input} -> {raw_path}")
    else:
        run_script('collect_logs.py', ['--container', args.container, '--dest', raw_path])

    parse_input = raw_path
    if baseline:
        with open(raw_path, 'rb') as f:
            lines = f.readlines()
        if len(lines) >= baseline:
            parse_input = os.path.join(out, 'raw', 'cowrie_thisrun.json')
            with open(parse_input, 'wb') as f:
                f.writelines(lines[baseline:])
            print(f"  trimmed {baseline} pre-run lines; {len(lines) - baseline} lines belong to this run")
        else:
            print(f"  WARNING: log has {len(lines)} lines < baseline {baseline} (rotation?); "
                  f"parsing full log and relying on the time-window filter")

    print("2. Parsing sessions")
    run_script('parse_logs.py', ['--input', parse_input, '--output', sessions_path])

    print("3. Attaching labels from manifest (labelling v2)")
    entries = load_manifest(manifest_path)
    with open(sessions_path, 'r', encoding='utf-8') as f:
        sessions = json.load(f)

    # Registered diagnostic/demo sessions never enter a dataset (configs/session_exclusions_v1.json; Task 26C, F-7).
    exclusions = load_exclusions()
    sessions, excluded = exclusions.filter_sessions(sessions)
    print(f"  session exclusions {exclusions.version} ({exclusions.digest[:16]}): {len(excluded)} excluded {excluded}")

    # Cowrie's log is cumulative, so drop sessions that fall outside this run's time window
    # (plus a margin). They belong to earlier runs and have no entry in this manifest.
    starts = [e['_start'] for e in entries if e['_start']]
    ends = [e['_end'] for e in entries if e['_end']]
    margin = timedelta(seconds=args.window_margin)
    run_start, run_end = (min(starts) - margin), (max(ends) + margin)
    in_window, dropped = {}, 0
    for sid, events in sessions.items():
        connect_dt, _, _ = session_bounds(events)
        if connect_dt is None or run_start <= connect_dt <= run_end:
            in_window[sid] = events
        else:
            dropped += 1
    sessions = in_window

    # Labelling v2 (dataset_builder/labelling.py): source entries by attempt-sequence alignment,
    # behaviour labels from Cowrie events; unresolved cases stay ambiguous/unassigned.
    records, report = labelling.label_sessions(sessions, entries, clock_tolerance=args.clock_tolerance,
                                               min_block=args.min_block)
    report['session_exclusions'] = {**exclusions.summary(), 'sessions_excluded': excluded}
    report['parsed_sessions'] = len(sessions) + dropped
    report['out_of_window_dropped'] = dropped
    report['empty_dropped'] = 0

    # Optional cleanup of command-less sessions (failed logins and logins without commands). They
    # are legitimate but heavily over-represented and near-identical. With --cap-empty, keep up to
    # --brute-empty-cap of them from brute_force source entries and drop the rest. Command-bearing
    # sessions are always kept.
    if args.cap_empty:
        empties = {}
        for sid, rec in records.items():
            if rec['n_commands'] == 0:
                empties.setdefault(rec['source_attack_cat'], []).append((rec['connect_utc'], sid))
        drop = set()
        for cat, items in empties.items():
            limit = args.brute_empty_cap if cat == 'brute_force' else 0
            # Keep the earliest `limit` by connect time (stable, reproducible); drop the rest.
            for _, sid in sorted(items)[limit:]:
                drop.add(sid)
        if drop:
            sessions = {sid: ev for sid, ev in sessions.items() if sid not in drop}
            records = {sid: rec for sid, rec in records.items() if sid not in drop}
            report['empty_dropped'] = len(drop)
            report['sessions_after_cap'] = len(sessions)

    print("4. Writing labelled sessions and extracting features")
    labelling.write_outputs(labelled_dir, sessions, records, report)

    sa = report['source_assignment']
    print("\n=== Label report ===")
    print(f"  parsed:          {report['parsed_sessions']}")
    print(f"  out-of-window:   {report['out_of_window_dropped']} (dropped: other runs in cumulative log)")
    if report['empty_dropped']:
        print(f"  empty dropped:   {report['empty_dropped']} (command-less sessions, --cap-empty)")
    print(f"  sessions:        {len(sessions)}")
    print(f"  source assigned: {sa['confidently_assigned']}  ambiguous: {sa['ambiguous']}  "
          f"unassigned: {sa['unassigned']}  inconsistent: {sa['inconsistent_source_evidence']}")
    print("  behaviour labels:")
    for cat, n in sorted(report['label_distribution_after'].items(), key=lambda kv: -kv[1]):
        print(f"    {cat:<22} {n}")
    print(f"\nFeatures: {features_path}")


if __name__ == '__main__':
    main()
