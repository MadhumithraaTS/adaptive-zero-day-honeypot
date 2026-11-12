"""Dataset V2 feature extractor: Cowrie JSON event logs -> the feature representation of configs/feature_spec_v2.json.

    python scripts/extract_features_v2.py --input <cowrie.json> [--input ...] --output-dir <dir> [--allow-malformed]

Independent of the V1 extractor (scripts/extract_features.py), which it neither imports nor changes. It reads
only the Cowrie JSONL files given with --input and the specification file; never a generation manifest, the
generator's terminal_output.jsonl, labels, profile names or any other prohibited input
(feature_spec_v2.json -> forbidden_inputs). Design: docs/extractor_v2_design.md. Output: docs/extractor_v2_output_schema.md.

Outputs in --output-dir:
  model_features.csv      exactly the 13 model features, one row per session, in session_metadata.csv row order
  session_metadata.csv    row, session_ref, spec version, extraction status, warnings and the descriptive fields
  extraction_summary.json counts, input hashes, warnings with line numbers, column types
"""
import argparse
import csv
import hashlib
import json
import math
import os
import statistics
import sys
from datetime import datetime, timezone

SPEC_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'configs', 'feature_spec_v2.json')
IMPLEMENTED_SPEC_VERSION = '2.0.0-draft.3'
MODEL_FEATURES = [
    'login_success', 'login_failed_count', 'session_duration_s', 'input_line_count', 'input_bytes_total',
    'input_line_max_bytes', 'unique_command_names', 'shell_operator_lines', 'download_command_lines',
    'time_to_first_input_s', 'inter_input_mean_s', 'inter_input_std_s', 'tty_output_bytes',
]
DESCRIPTIVE_FIELDS = [
    'unknown_command_events', 'url_download_events', 'download_failed_events', 'redirect_write_events',
    'scp_stdin_events', 'event_count', 'session_closed_observed', 'timestamp_order_mismatch',
]
# Formula constants, copied verbatim from the specification.
EXCLUDED_INPUT_LINES = ('exit', 'logout')
SHELL_OPERATORS = ('|', ';', '&&', '>', '<', '`', '$(')
DOWNLOAD_COMMANDS = frozenset({'wget', 'curl', 'tftp', 'ftp', 'ftpget', 'scp'})
RESERVED_MARKER_PREFIXES = ('PILOT_',)
# Event types seen in this Cowrie build; anything else is counted and reported, never dropped.
KNOWN_EVENTS = frozenset({
    'cowrie.session.connect', 'cowrie.client.version', 'cowrie.client.kex', 'cowrie.client.size',
    'cowrie.client.var', 'cowrie.session.params', 'cowrie.login.success', 'cowrie.login.failed',
    'cowrie.command.input', 'cowrie.command.failed', 'cowrie.log.closed', 'cowrie.session.closed',
    'cowrie.session.file_download', 'cowrie.session.file_download.failed', 'cowrie.session.file_upload',
})
DURATION_TOLERANCE_S = 1.0  # spec validation: duration ~ last event - connect (tolerance 1 s)
NAN = float('nan')


class ExtractionError(Exception):
    """Input that cannot be processed under the chosen policy (invalid UTF-8, or malformed JSON in strict mode)."""


# --- reading ----------------------------------------------------------------------------------------

def read_events(paths, allow_malformed=False):
    """Read Cowrie JSONL files in order. Returns (events, file_warnings, input_info).

    Every event gets `_order` (global position) and `_source` ('file:line'). Malformed JSON stops the run unless
    allow_malformed, in which case the line is reported in file_warnings and skipped. Invalid UTF-8 always stops it.
    """
    events, warnings, inputs, order = [], [], [], 0
    for path in paths:
        with open(path, 'rb') as f:
            raw = f.read()
        inputs.append({'path': path, 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)})
        for line_no, line in enumerate(raw.split(b'\n'), start=1):
            if not line.strip():
                continue
            where = f"{path}:{line_no}"
            try:
                text = line.decode('utf-8')
            except UnicodeDecodeError as exc:
                raise ExtractionError(f"{where} is not valid UTF-8 (byte 0x{line[exc.start]:02x} at column "
                                      f"{exc.start + 1}); the input was not changed") from exc
            try:
                event = json.loads(text)
                if not isinstance(event, dict):
                    raise ValueError("not a JSON object")
            except ValueError as exc:
                if not allow_malformed:
                    raise ExtractionError(f"{where}: malformed JSON record ({exc}); use --allow-malformed to "
                                          f"skip and report such lines") from exc
                warnings.append({'where': where, 'warning': 'malformed_json_skipped', 'detail': str(exc)[:200]})
                continue
            event['_order'], event['_source'] = order, where
            order += 1
            events.append(event)
    return events, warnings, inputs


def parse_timestamp(value):
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _canonical(event):
    return json.dumps({k: v for k, v in event.items() if not k.startswith('_')}, sort_keys=True, ensure_ascii=False)


def group_sessions(events):
    """Group by Cowrie session id; remove exact duplicate records; sort by (timestamp, log order).

    Returns (sessions, file_warnings). Events without a session id are reported, not assigned.
    """
    sessions, warnings, seen = {}, [], {}
    for event in events:
        sid = event.get('session')
        if not isinstance(sid, str) or not sid:
            warnings.append({'where': event['_source'], 'warning': 'event_without_session_id',
                             'detail': str(event.get('eventid'))})
            continue
        session = sessions.setdefault(sid, {'events': [], 'warnings': [], 'duplicates': 0})
        key = _canonical(event)
        if key in seen.setdefault(sid, set()):
            session['duplicates'] += 1
            continue
        seen[sid].add(key)
        event['_ts'] = parse_timestamp(event.get('timestamp'))
        if event['_ts'] is None:
            session['warnings'].append(f"missing_or_invalid_timestamp@{event['_source']}")
        session['events'].append(event)
    far_future = datetime.max.replace(tzinfo=timezone.utc)
    for session in sessions.values():
        session['events'].sort(key=lambda e: (e['_ts'] or far_future, e['_order']))
        if session['duplicates']:
            session['warnings'].append(f"duplicate_records_removed={session['duplicates']}")
    return sessions, warnings


# --- features -----------------------------------------------------------------------------------------

def command_name(line):
    tokens = line.strip().split()
    return tokens[0] if tokens else None


def _num(value):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def compute_session(sid, session):
    """All 13 model features and 8 descriptive fields of one session, plus its warnings."""
    events, warn = session['events'], list(session['warnings'])
    by_type = {}
    for event in events:
        eid = event.get('eventid')
        if not isinstance(eid, str):
            warn.append(f"missing_eventid@{event['_source']}")
            eid = '<missing>'
        elif eid not in KNOWN_EVENTS:
            warn.append(f"unknown_event_type:{eid}")
        by_type.setdefault(eid, []).append(event)
    get = lambda eid: by_type.get(eid, [])  # noqa: E731

    successes, failures = get('cowrie.login.success'), get('cowrie.login.failed')
    login_success = 1 if successes else 0
    if len(successes) > 1:
        warn.append('more_than_one_login_success')
    if not successes and not failures:
        warn.append('no_authentication_event')

    closed = get('cowrie.session.closed')
    session_duration = NAN
    if closed:
        if len(closed) > 1:
            warn.append('more_than_one_session_closed_first_used')
        value = _num(closed[0].get('duration'))
        if value is None:
            warn.append('session_closed_duration_unparsable')
        else:
            session_duration = value
            connect = next((e['_ts'] for e in get('cowrie.session.connect') if e['_ts']), None)
            last = max((e['_ts'] for e in events if e['_ts']), default=None)
            if value < 0:
                warn.append('negative_session_duration')
            if connect and last and abs((last - connect).total_seconds() - value) > DURATION_TOLERANCE_S:
                warn.append('session_duration_differs_from_event_span')

    # Recorded input lines (not verified client typing): command.input minus exact 'exit'/'logout'.
    raw_inputs = get('cowrie.command.input')
    for event in raw_inputs:
        if not isinstance(event.get('input'), str):
            warn.append(f"command_input_without_text@{event['_source']}")
    inputs = [e for e in raw_inputs if (e.get('input') if isinstance(e.get('input'), str) else '').strip()
              not in EXCLUDED_INPUT_LINES]
    texts = [e.get('input') if isinstance(e.get('input'), str) else '' for e in inputs]
    sizes = [len(t.encode('utf-8')) for t in texts]
    names = {n for n in (command_name(t) for t in texts) if n is not None}
    if any(not t.isascii() for t in texts):
        warn.append('non_ascii_recorded_input')
    if any(t.strip().startswith(RESERVED_MARKER_PREFIXES) for t in texts):
        warn.append('reserved_test_marker_present')
    if inputs and not login_success:
        warn.append('recorded_input_without_login_success')

    # Timing over recorded input events. Undefined (NaN) if any needed timestamp is missing.
    stamps = [e['_ts'] for e in inputs]
    timing_ok = all(s is not None for s in stamps)
    if inputs and not timing_ok:
        warn.append('recorded_input_without_timestamp_timing_undefined')
    first_success = next((e['_ts'] for e in successes if e['_ts']), None)
    time_to_first = NAN
    if login_success and inputs and timing_ok and first_success is not None:
        time_to_first = (stamps[0] - first_success).total_seconds()
        if time_to_first < 0:
            warn.append('negative_time_to_first_input')
    gaps = [(b - a).total_seconds() for a, b in zip(stamps, stamps[1:])] if timing_ok else []
    inter_mean = statistics.fmean(gaps) if timing_ok and len(inputs) >= 2 else NAN
    inter_std = statistics.pstdev(gaps) if timing_ok and len(inputs) >= 3 else NAN

    log_closed = get('cowrie.log.closed')
    if not login_success:
        tty = 0.0  # structural zero: no terminal channel exists without a successful login
        if log_closed:
            warn.append('log_closed_without_login_success')
    elif not log_closed:
        tty = NAN
        warn.append('logged_in_without_log_closed')
    else:
        values = [_num(e.get('size')) for e in log_closed]
        if any(v is None for v in values):
            tty = NAN
            warn.append('log_closed_size_unparsable')
        else:
            tty = float(sum(values))
            if tty < sum(sizes):
                warn.append('tty_output_below_recorded_input_bytes')

    order_by_log = [e['_order'] for e in sorted(raw_inputs, key=lambda e: e['_order'])]
    order_by_time = [e['_order'] for e in raw_inputs]  # raw_inputs follow the (timestamp, log order) sort
    downloads = get('cowrie.session.file_download')

    features = {
        'login_success': login_success,
        'login_failed_count': len(failures),
        'session_duration_s': session_duration,
        'input_line_count': len(inputs),
        'input_bytes_total': sum(sizes),
        'input_line_max_bytes': float(max(sizes)) if sizes else NAN,
        'unique_command_names': len(names),
        'shell_operator_lines': sum(1 for t in texts if any(op in t for op in SHELL_OPERATORS)),
        'download_command_lines': sum(1 for t in texts if command_name(t) in DOWNLOAD_COMMANDS),
        'time_to_first_input_s': time_to_first,
        'inter_input_mean_s': inter_mean,
        'inter_input_std_s': inter_std,
        'tty_output_bytes': tty,
    }
    descriptive = {
        'unknown_command_events': len(get('cowrie.command.failed')),
        'url_download_events': sum(1 for e in downloads if 'url' in e),
        'download_failed_events': len(get('cowrie.session.file_download.failed')),
        'redirect_write_events': sum(1 for e in downloads if 'destfile' in e and 'url' not in e),
        'scp_stdin_events': sum(1 for e in downloads if e.get('realm') == 'scp'),
        'event_count': len(events),
        'session_closed_observed': 1 if closed else 0,
        'timestamp_order_mismatch': 1 if order_by_log != order_by_time else 0,
    }
    if not closed:
        warn.append('no_session_closed')
    validate_session(features, descriptive, warn)
    return features, descriptive, sorted(set(warn))


def validate_session(f, d, warn):
    """Specification validation rules; a violation is a warning on the session, never a silent change."""
    checks = [
        (f['login_success'] in (0, 1), 'login_success_not_binary'),
        (f['login_failed_count'] >= 0, 'login_failed_count_negative'),
        (f['input_line_count'] >= 0, 'input_line_count_negative'),
        (not (f['login_success'] == 0 and f['input_line_count'] > 0), 'input_lines_without_login'),
        (math.isnan(f['input_line_max_bytes']) or f['input_line_max_bytes'] <= f['input_bytes_total'],
         'max_line_bytes_exceeds_total'),
        (f['unique_command_names'] <= f['input_line_count'], 'unique_names_exceed_lines'),
        (f['shell_operator_lines'] <= f['input_line_count'], 'operator_lines_exceed_lines'),
        (f['download_command_lines'] <= f['input_line_count'], 'download_lines_exceed_lines'),
        (math.isnan(f['inter_input_std_s']) or f['inter_input_std_s'] >= 0, 'negative_std'),
        (math.isnan(f['tty_output_bytes']) or f['tty_output_bytes'] >= 0, 'negative_tty_output'),
        (d['event_count'] > 0, 'empty_session'),
    ]
    warn.extend(name for ok, name in checks if not ok)


# --- spec binding and output -------------------------------------------------------------------------

def load_spec(path=SPEC_PATH):
    with open(path, 'r', encoding='utf-8') as f:
        spec = json.load(f)
    names = [x['name'] for x in spec['features']]
    descriptive = [x['name'] for x in spec['descriptive_fields']]
    if spec.get('spec_version') != IMPLEMENTED_SPEC_VERSION or names != MODEL_FEATURES or descriptive != DESCRIPTIVE_FIELDS:
        raise ExtractionError(f"{path} (spec_version {spec.get('spec_version')}) does not match the implemented "
                              f"specification {IMPLEMENTED_SPEC_VERSION}; update the extractor before use")
    return spec


def _sha256_file(path):
    with open(path, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()


def _cell(value):
    if isinstance(value, float):
        return 'NaN' if math.isnan(value) else repr(value)
    return str(value)


def _load_exclusions(path):
    """Registered diagnostic/demo sessions (configs/session_exclusions_v1.json). Used only to select sessions, never as a
    feature input; see session_exclusions/ (Task 26C, F-7)."""
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if repo not in sys.path:
        sys.path.insert(0, repo)
    from session_exclusions import load_exclusions
    return load_exclusions(path)


def extract(paths, output_dir, allow_malformed=False, spec_path=SPEC_PATH, exclusions_path=None):
    """Run the extraction and write the three outputs. Returns the summary dict."""
    spec = load_spec(spec_path)
    exclusions = _load_exclusions(exclusions_path)
    events, file_warnings, inputs = read_events(paths, allow_malformed)
    sessions, group_warnings = group_sessions(events)
    sessions, excluded = exclusions.filter_sessions(sessions)
    rows = []
    for sid in sorted(sessions):
        features, descriptive, warnings = compute_session(sid, sessions[sid])
        rows.append((sid, features, descriptive, warnings))

    os.makedirs(output_dir, exist_ok=True)
    with open(os.path.join(output_dir, 'model_features.csv'), 'w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f, lineterminator='\n')
        writer.writerow(MODEL_FEATURES)
        for _, features, _, _ in rows:
            writer.writerow([_cell(features[name]) for name in MODEL_FEATURES])
    meta_columns = ['row', 'session_ref', 'feature_spec_version', 'extraction_status', 'warnings'] + DESCRIPTIVE_FIELDS
    with open(os.path.join(output_dir, 'session_metadata.csv'), 'w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f, lineterminator='\n')
        writer.writerow(meta_columns)
        for i, (sid, _, descriptive, warnings) in enumerate(rows):
            writer.writerow([i, sid, IMPLEMENTED_SPEC_VERSION, 'ok_with_warnings' if warnings else 'ok',
                             ';'.join(warnings)] + [_cell(descriptive[name]) for name in DESCRIPTIVE_FIELDS])

    warning_counts = {}
    for _, _, _, warnings in rows:
        for w in warnings:
            key = w.split('@')[0].split('=')[0]
            warning_counts[key] = warning_counts.get(key, 0) + 1
    summary = {
        'extractor': 'scripts/extract_features_v2.py', 'feature_spec_version': IMPLEMENTED_SPEC_VERSION,
        'spec_sha256': _sha256_file(spec_path),
        'inputs': inputs, 'events_read': len(events), 'sessions': len(rows),
        'sessions_with_warnings': sum(1 for r in rows if r[3]),
        'duplicate_records_removed': sum(s['duplicates'] for s in sessions.values()),
        'file_level_warnings': file_warnings + group_warnings,
        'session_warning_counts': dict(sorted(warning_counts.items())),
        'nan_counts': {name: sum(1 for r in rows if isinstance(r[1][name], float) and math.isnan(r[1][name]))
                       for name in MODEL_FEATURES},
        'model_feature_dtypes': {x['name']: x['dtype'] for x in spec['features']},
        'model_feature_status': {x['name']: x['status'] for x in spec['features']},
        'missing_value_encoding': "'NaN' in CSV",
        'outputs': ['model_features.csv', 'session_metadata.csv', 'extraction_summary.json'],
        'session_exclusions': {**exclusions.summary(), 'sessions_excluded': excluded},
    }
    with open(os.path.join(output_dir, 'extraction_summary.json'), 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description='Extract Dataset V2 features from Cowrie JSON event logs.')
    parser.add_argument('--input', action='append', required=True, help='Cowrie JSONL file (repeatable; read in order).')
    parser.add_argument('--output-dir', required=True)
    parser.add_argument('--allow-malformed', action='store_true',
                        help='Skip malformed JSON lines and report them (default: stop at the first one).')
    args = parser.parse_args(argv)
    try:
        summary = extract(args.input, args.output_dir, args.allow_malformed)
    except (ExtractionError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(f"{summary['sessions']} sessions from {summary['events_read']} events "
          f"({summary['sessions_with_warnings']} with warnings) -> {args.output_dir}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
