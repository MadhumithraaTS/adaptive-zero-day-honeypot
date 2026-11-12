"""Build a corrected (labelling v2) copy of an existing labelled run without modifying it.

Reads from --source-run (never written):
  manifest.jsonl, run_meta.json      generation ground truth
  parsed/sessions.json               unmodified Cowrie sessions
  labelled/sessions_labelled.json    the run's session set and its version-1 labels (for comparison)

Writes to --output-dir, which must not exist yet:
  sessions_labelled.json, behavior_features.csv, session_details.json   corrected dataset
  label_assignments.csv              per-session behaviour label, source entry and evidence
  label_report.json                  quality counts and before/after label distributions
  comparison_report.md               human-readable version-1 vs version-2 comparison
  provenance.json                    source paths, input SHA-256 hashes, parameters
  manifest.jsonl, run_meta.json      copies of the source generation records

The session set is the source run's labelled set: version 1 already removed sessions belonging to
other runs, and the corrected labels are compared session by session.
"""
import argparse
import hashlib
import json
import os
import shutil
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from dataset_builder import labelling  # noqa: E402

INPUTS = ('manifest.jsonl', 'run_meta.json', os.path.join('parsed', 'sessions.json'),
          os.path.join('labelled', 'sessions_labelled.json'))
INJECTED_KEYS = ('attack_cat', 'label')


def sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def load_manifest(path):
    with open(path, 'r', encoding='utf-8') as f:
        entries = [json.loads(line) for line in f if line.strip()]
    if not entries:
        raise SystemExit(f"Manifest {path} is empty.")
    indices = [e.get('index') for e in entries]
    if indices != sorted(indices):
        raise SystemExit(f"Manifest {path} is not in generation order.")
    return entries


def comparison_markdown(name, report):
    before, after = report.get('label_distribution_before', {}), report['label_distribution_after']
    rows = [f"| {cat} | {before.get(cat, 0)} | {after.get(cat, 0)} |" for cat in sorted(set(before) | set(after))]
    sa, ties = report['source_assignment'], report['command_overlap_ties']
    transitions = sorted(report.get('label_transitions', {}).items(), key=lambda kv: -kv[1])
    lines = [
        f"# Label correction report: {name}",
        "",
        "Labels are behaviour labels inferred from Cowrie events and the generation manifest "
        "(labelling version 2). They are not independently verified ground truth.",
        "",
        "## Label distribution",
        "",
        "| Label | Version 1 | Version 2 |",
        "|---|---|---|",
        *rows,
        "",
        "## Quality counts",
        "",
        f"- Sessions: {report['sessions_total']} (manifest attempts expected: {report['manifest_attempts_expected']})",
        f"- Failed-login sessions: {report['failed_login_sessions']}",
        f"- Command-bearing sessions: {report['command_bearing_sessions']}",
        f"- Successful logins without commands: {report['login_no_command_sessions']}",
        f"- Source entry confidently assigned: {sa['confidently_assigned']} (by method: {sa['by_method']})",
        f"- Ambiguous source: {sa['ambiguous']}; unassigned: {sa['unassigned']}; "
        f"inconsistent evidence: {sa['inconsistent_source_evidence']}",
        f"- Time-based assignments: {report['time_based_assignments']}",
        f"- Command-overlap ties: {ties['sessions_with_tie']} "
        f"({ties['ties_spanning_multiple_categories']} spanning several categories); "
        f"resolved {ties['resolved']}, unresolved {ties['unresolved']}",
        f"- Behaviour label `ambiguous`: {report['behaviour_labels_ambiguous']}; "
        f"`unassigned`: {report['behaviour_labels_unassigned']}",
        f"- Version-1 label differs from the assigned source entry's category: "
        f"{report.get('previous_label_differs_from_assigned_source_category', 'n/a')}",
        f"- Of those, profile-labelled (command) sessions whose version-1 label was wrong: "
        f"{report.get('previous_label_wrong_for_profile_labelled_sessions', 'n/a')}",
        "",
        "## Label transitions (version 1 -> version 2)",
        "",
        "| Transition | Sessions |",
        "|---|---|",
        *[f"| {t} | {n} |" for t, n in transitions],
        "",
    ]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description='Write a labelling-v2 corrected copy of a labelled run.')
    parser.add_argument('--source-run', required=True, help='Existing run directory (read only).')
    parser.add_argument('--output-dir', required=True, help='New directory for the corrected dataset; must not exist.')
    parser.add_argument('--clock-tolerance', type=float, default=5.0,
                        help='Seconds of host/Cowrie clock difference allowed when a time window is used.')
    parser.add_argument('--min-block', type=int, default=3,
                        help='Minimum consecutive matching attempts for an alignment block to be trusted.')
    args = parser.parse_args()

    source = os.path.abspath(args.source_run)
    out = os.path.abspath(args.output_dir)
    if os.path.exists(out):
        raise SystemExit(f"Refusing to write: {out} already exists.")
    if os.path.commonpath([source, out]) == source:
        raise SystemExit("Refusing to write inside the source run directory.")
    paths = {name: os.path.join(source, name) for name in INPUTS}
    missing = [p for p in paths.values() if not os.path.isfile(p)]
    if missing:
        raise SystemExit(f"Missing source files: {missing}")
    hashes_before = {name: sha256(p) for name, p in paths.items()}

    entries = load_manifest(paths['manifest.jsonl'])
    with open(paths[os.path.join('parsed', 'sessions.json')], 'r', encoding='utf-8') as f:
        parsed = json.load(f)
    with open(paths[os.path.join('labelled', 'sessions_labelled.json')], 'r', encoding='utf-8') as f:
        v1 = json.load(f)

    # Take the unmodified events from parsed/ and check they are the version-1 events minus labels.
    missing_ids = [sid for sid in v1 if sid not in parsed]
    if missing_ids:
        raise SystemExit(f"{len(missing_ids)} labelled sessions are absent from parsed/sessions.json.")
    sessions, mismatched = {}, []
    for sid, events in v1.items():
        stripped = [{k: v for k, v in ev.items() if k not in INJECTED_KEYS} for ev in events]
        if stripped != parsed[sid]:
            mismatched.append(sid)
        sessions[sid] = parsed[sid]
    if mismatched:
        raise SystemExit(f"{len(mismatched)} sessions differ between parsed and labelled files; not relabelling.")
    previous = {sid: events[0].get('attack_cat', '') for sid, events in v1.items()}

    records, report = labelling.label_sessions(sessions, entries, previous_labels=previous,
                                               clock_tolerance=args.clock_tolerance, min_block=args.min_block)
    report['source_run'] = os.path.basename(source)
    report['parsed_sessions_not_in_labelled_set'] = len(set(parsed) - set(v1))

    labelling.write_outputs(out, sessions, records, report)
    shutil.copyfile(paths['manifest.jsonl'], os.path.join(out, 'manifest.jsonl'))
    shutil.copyfile(paths['run_meta.json'], os.path.join(out, 'run_meta.json'))
    with open(os.path.join(out, 'comparison_report.md'), 'w', encoding='utf-8', newline='\n') as f:
        f.write(comparison_markdown(f"{os.path.basename(source)} (labelling v{labelling.LABELLING_VERSION})", report))

    hashes_after = {name: sha256(p) for name, p in paths.items()}
    if hashes_after != hashes_before:
        raise SystemExit("Source run files changed during relabelling.")
    with open(os.path.join(out, 'provenance.json'), 'w', encoding='utf-8') as f:
        json.dump({
            'labelling_version': labelling.LABELLING_VERSION,
            'source_run': os.path.basename(source),
            'input_sha256': {name.replace(os.sep, '/'): h for name, h in sorted(hashes_before.items())},
            'parameters': {'clock_tolerance_s': args.clock_tolerance, 'min_alignment_block': args.min_block},
        }, f, indent=2)

    sa = report['source_assignment']
    print(f"Relabelled {report['sessions_total']} sessions from {os.path.basename(source)} -> {out}")
    print(f"  failed_login={report['failed_login_sessions']}  command-bearing={report['command_bearing_sessions']}  "
          f"login_no_commands={report['login_no_command_sessions']}")
    print(f"  source assigned={sa['confidently_assigned']} ambiguous={sa['ambiguous']} "
          f"unassigned={sa['unassigned']} inconsistent={sa['inconsistent_source_evidence']}")
    print(f"  labels: {dict(Counter(r['behaviour_label'] for r in records.values()))}")


if __name__ == '__main__':
    main()
