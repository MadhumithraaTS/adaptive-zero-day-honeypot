"""Behaviour labelling of Cowrie sessions against a generation manifest (labelling version 2).

Version 1 (the original build_labelled_dataset.py) labelled every session with the category of the
manifest entry it was matched to: command-bearing sessions by best command overlap (ties went to the
first entry in the run) and command-less sessions by host-clock time window. That put attack labels
on failed-login sessions and mislabelled sessions near entry boundaries.

Version 2 separates two things:

* Source assignment: which manifest entry produced the session. The generator runs sessions one at
  a time and records every authentication attempt (username, password, outcome order), and Cowrie
  logs one session per SSH connection. So Cowrie's sessions in connect order should reproduce the
  manifest's attempt sequence exactly. The sequences are aligned on (outcome, username, password);
  only alignment blocks of at least `min_block` consecutive attempts are trusted. Sessions outside
  trusted blocks fall back to credential and command evidence restricted to the unaligned region,
  then to the entry's generation window widened by `clock_tolerance` seconds (host and Cowrie clocks
  differ). Anything still unresolved is recorded as ambiguous or unassigned, never forced.

* Behaviour label: what the session itself shows, from Cowrie events.
    failed_login       failed authentication only, no successful login
    login_no_commands  successful login with no commands (other than `exit`)
    <attack_cat>       the source profile's category, only when every command the session ran was
                       sent by its source entry (or by every candidate entry, when they share a category)
    ambiguous          commands consistent with several candidate entries of different categories
    unassigned         no reliable source, or commands the source entry never sent

The binary `label` is the source profile's label for profile-labelled sessions and -1 (not
applicable) for every other behaviour label. These are behaviour labels inferred from Cowrie events
and the generation manifest, not independently verified ground truth.
"""
import csv
import difflib
import json
import os
import statistics
import subprocess
import sys
from collections import Counter
from datetime import datetime

LABELLING_VERSION = '2.0'
FAILED_LOGIN = 'failed_login'
LOGIN_NO_COMMANDS = 'login_no_commands'
AMBIGUOUS = 'ambiguous'
UNASSIGNED = 'unassigned'
NOT_APPLICABLE_LABEL = -1

ASSIGNED, STATUS_AMBIGUOUS, STATUS_UNASSIGNED, INCONSISTENT = 'assigned', 'ambiguous', 'unassigned', 'inconsistent'

ASSIGNMENT_FIELDS = [
    'session_id', 'connect_utc', 'auth_outcome', 'username', 'n_commands', 'behaviour_label', 'label',
    'source_status', 'assignment_method', 'source_index', 'source_profile', 'source_attack_cat',
    'candidate_count', 'candidate_categories', 'commands_supported', 'overlap_tie', 'clock_offset_s',
    'previous_attack_cat',
]


def parse_iso(ts):
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace('Z', '+00:00'))
    except ValueError:
        return None


def session_evidence(session_id, events):
    """Observed facts for one Cowrie session: connect time, authentication outcome, commands."""
    times = [t for t in (parse_iso(ev.get('timestamp')) for ev in events) if t is not None]
    logins = [ev for ev in events if ev.get('eventid') in ('cowrie.login.success', 'cowrie.login.failed')]
    if any(ev['eventid'] == 'cowrie.login.success' for ev in logins):
        outcome = 'success'
    elif logins:
        outcome = 'failed'
    else:
        outcome = 'none'
    last = logins[-1] if logins else {}
    commands = [(ev.get('input') or '').strip() for ev in events if ev.get('eventid') == 'cowrie.command.input']
    return {
        'session_id': session_id,
        'connect': min(times) if times else None,
        'outcome': outcome,
        'username': last.get('username'),
        'password': last.get('password'),
        'commands': [c for c in commands if c and c != 'exit'],
    }


def _token(kind, username, password):
    return f'{kind}\x1f{username}\x1f{password}'


def manifest_tokens(entries):
    """Expected Cowrie sessions in order: one per authentication attempt in each entry."""
    tokens = []
    for pos, entry in enumerate(entries):
        attempts = entry.get('auth_attempts') or []
        for username, password in attempts[:-1]:
            tokens.append(('failed', username, password, pos))
        if attempts:
            username, password = attempts[-1]
            tokens.append(('success' if entry.get('auth_success') else 'failed', username, password, pos))
    return tokens


def align(observations, tokens, min_block=3):
    """Align observed sessions to expected attempts.

    Returns ({observation index: entry position} for trusted blocks, [(observation indices, candidate
    entry positions)] for everything else). Untrusted stretches between two trusted blocks form one
    region, so short coincidental matches inside it do not narrow the candidates.
    """
    expected = [_token(kind, user, pwd) for kind, user, pwd, _ in tokens]
    observed = [_token(o['outcome'], o['username'], o['password']) for o in observations]
    matcher = difflib.SequenceMatcher(None, expected, observed, autojunk=False)
    aligned, regions = {}, []
    pending_obs, pending_pos = [], set()

    def flush():
        if pending_obs:
            regions.append((list(pending_obs), sorted(pending_pos)))
        pending_obs.clear()
        pending_pos.clear()

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == 'equal' and (j2 - j1) >= min_block:
            flush()
            for k in range(j2 - j1):
                aligned[j1 + k] = tokens[i1 + k][3]
        else:
            pending_obs.extend(range(j1, j2))
            pending_pos.update(tokens[i][3] for i in range(i1, i2))
    flush()
    return aligned, regions


def _overlap(commands, entry):
    session_set = set(commands)
    return len(session_set & set(entry.get('commands_sent', []))) / len(session_set) if session_set else 0.0


def region_candidates(obs, positions, entries):
    """Entries in an unaligned region that could have produced this session."""
    if obs['outcome'] == 'none':
        return []
    cred = [obs['username'], obs['password']]
    candidates = []
    for pos in positions:
        attempts = entries[pos].get('auth_attempts') or []
        if obs['outcome'] == 'failed':
            failed = attempts[:-1] if entries[pos].get('auth_success') else attempts
            if cred in [list(a) for a in failed]:
                candidates.append(pos)
        elif entries[pos].get('auth_success') and attempts and list(attempts[-1]) == cred:
            candidates.append(pos)
    if obs['commands'] and candidates:
        scores = {pos: _overlap(obs['commands'], entries[pos]) for pos in candidates}
        best = max(scores.values())
        candidates = [pos for pos in candidates if best > 0 and scores[pos] == best]
    return candidates


def resolve(obs, candidates, entries, clock_tolerance):
    """Pick a source entry only when the evidence supports one. Returns (position, status, method)."""
    if not candidates:
        return None, STATUS_UNASSIGNED, 'none'
    if len(candidates) == 1:
        return candidates[0], ASSIGNED, 'region_unique'
    connect = obs['connect']
    if connect is not None:
        within = []
        for pos in candidates:
            start, end = parse_iso(entries[pos].get('start_utc')), parse_iso(entries[pos].get('end_utc'))
            if start and end and (start - connect).total_seconds() <= clock_tolerance \
                    and (connect - end).total_seconds() <= clock_tolerance:
                within.append(pos)
        if len(within) == 1:
            return within[0], ASSIGNED, 'time_window'
    return None, STATUS_AMBIGUOUS, 'none'


def _behaviour(obs, status, pos, candidates, entries):
    """Behaviour label, binary label and final source status for one session."""
    if obs['outcome'] == 'failed':
        return FAILED_LOGIN, NOT_APPLICABLE_LABEL, status, None
    if obs['outcome'] == 'none':
        return UNASSIGNED, NOT_APPLICABLE_LABEL, status, None
    if not obs['commands']:
        return LOGIN_NO_COMMANDS, NOT_APPLICABLE_LABEL, status, None
    commands = set(obs['commands'])
    if status == ASSIGNED:
        entry = entries[pos]
        if commands <= set(entry.get('commands_sent', [])):
            return entry['attack_cat'], entry['label'], status, True
        return UNASSIGNED, NOT_APPLICABLE_LABEL, INCONSISTENT, False
    supporting = [p for p in candidates if commands <= set(entries[p].get('commands_sent', []))]
    categories = {(entries[p]['attack_cat'], entries[p]['label']) for p in supporting}
    if status == STATUS_AMBIGUOUS and len(categories) == 1:
        attack_cat, label = categories.pop()
        return attack_cat, label, status, True
    return (AMBIGUOUS if status == STATUS_AMBIGUOUS else UNASSIGNED), NOT_APPLICABLE_LABEL, status, None


def _overlap_tie(commands, entries):
    """Version-1-style tie: several manifest entries share the best command overlap."""
    if not commands:
        return False, set()
    scores = [(_overlap(commands, e), pos) for pos, e in enumerate(entries) if e.get('commands_sent')]
    best = max((s for s, _ in scores), default=0.0)
    tied = {pos for s, pos in scores if best > 0 and s == best}
    return len(tied) > 1, tied


def label_sessions(sessions, entries, previous_labels=None, clock_tolerance=5.0, min_block=3):
    """Label sessions {session_id: events} against manifest entries (in generation order).

    Returns (records ordered as `sessions`, report). `previous_labels` ({session_id: attack_cat}) is
    only used for the before/after comparison.
    """
    previous_labels = previous_labels or {}
    evidence = {sid: session_evidence(sid, events) for sid, events in sessions.items()}
    ordered = sorted(evidence.values(), key=lambda o: (o['connect'] is None, o['connect'] or datetime.min, o['session_id']))
    tokens = manifest_tokens(entries)
    aligned, regions = align(ordered, tokens, min_block=min_block)

    decisions = {}
    for idx, pos in aligned.items():
        decisions[ordered[idx]['session_id']] = (pos, ASSIGNED, 'sequence_alignment', [pos])
    for obs_indices, positions in regions:
        for idx in obs_indices:
            obs = ordered[idx]
            candidates = region_candidates(obs, positions, entries)
            pos, status, method = resolve(obs, candidates, entries, clock_tolerance)
            decisions[obs['session_id']] = (pos, status, method, candidates)

    records, offsets = {}, []
    counts = Counter()
    for sid in sessions:
        obs = evidence[sid]
        pos, status, method, candidates = decisions[sid]
        behaviour, label, status, supported = _behaviour(obs, status, pos, candidates, entries)
        tie, tied = _overlap_tie(obs['commands'], entries) if obs['outcome'] == 'success' else (False, set())
        entry = entries[pos] if pos is not None and status in (ASSIGNED, INCONSISTENT) else None
        offset = None
        if entry and obs['connect'] and parse_iso(entry.get('start_utc')):
            offset = round((obs['connect'] - parse_iso(entry['start_utc'])).total_seconds(), 3)
            offsets.append(offset)
        records[sid] = {
            'session_id': sid,
            'connect_utc': obs['connect'].isoformat().replace('+00:00', 'Z') if obs['connect'] else '',
            'auth_outcome': obs['outcome'],
            'username': obs['username'] or '',
            'n_commands': len(obs['commands']),
            'behaviour_label': behaviour,
            'label': label,
            'source_status': status,
            'assignment_method': method if status in (ASSIGNED, INCONSISTENT) else 'none',
            'source_index': entry.get('index', pos) if entry else '',
            'source_profile': entry.get('profile', '') if entry else '',
            'source_attack_cat': entry.get('attack_cat', '') if entry else '',
            'candidate_count': len(candidates),
            'candidate_categories': '|'.join(sorted({entries[p]['attack_cat'] for p in candidates})),
            'commands_supported': '' if supported is None else supported,
            'overlap_tie': tie,
            'clock_offset_s': '' if offset is None else offset,
            'previous_attack_cat': previous_labels.get(sid, ''),
        }
        counts['tie'] += tie
        counts['tie_resolved'] += tie and status == ASSIGNED
        counts['tie_unresolved'] += tie and status != ASSIGNED
        counts['tie_multi_category'] += tie and len({entries[p]['attack_cat'] for p in tied}) > 1

    statuses = Counter(r['source_status'] for r in records.values())
    methods = Counter(r['assignment_method'] for r in records.values() if r['source_status'] in (ASSIGNED, INCONSISTENT))
    outcomes = Counter(r['auth_outcome'] for r in records.values())
    after = Counter(r['behaviour_label'] for r in records.values())
    report = {
        'labelling_version': LABELLING_VERSION,
        'parameters': {'clock_tolerance_s': clock_tolerance, 'min_alignment_block': min_block},
        'sessions_total': len(records),
        'manifest_entries': len(entries),
        'manifest_attempts_expected': len(tokens),
        'failed_login_sessions': outcomes.get('failed', 0),
        'successful_login_sessions': outcomes.get('success', 0),
        'no_authentication_sessions': outcomes.get('none', 0),
        'command_bearing_sessions': sum(1 for r in records.values() if r['n_commands'] > 0),
        'login_no_command_sessions': after.get(LOGIN_NO_COMMANDS, 0),
        'source_assignment': {
            'confidently_assigned': statuses.get(ASSIGNED, 0),
            'ambiguous': statuses.get(STATUS_AMBIGUOUS, 0),
            'unassigned': statuses.get(STATUS_UNASSIGNED, 0),
            'inconsistent_source_evidence': statuses.get(INCONSISTENT, 0),
            'by_method': dict(sorted(methods.items())),
        },
        'time_based_assignments': methods.get('time_window', 0),
        'alignment': {
            'sessions_in_trusted_blocks': len(aligned),
            'sessions_in_unaligned_regions': sum(len(o) for o, _ in regions),
            'unaligned_regions': len(regions),
        },
        'command_overlap_ties': {
            'sessions_with_tie': counts['tie'],
            'ties_spanning_multiple_categories': counts['tie_multi_category'],
            'resolved': counts['tie_resolved'],
            'unresolved': counts['tie_unresolved'],
        },
        'behaviour_labels_ambiguous': after.get(AMBIGUOUS, 0),
        'behaviour_labels_unassigned': after.get(UNASSIGNED, 0),
        'missing_or_inconsistent_source_evidence': statuses.get(STATUS_UNASSIGNED, 0) + statuses.get(INCONSISTENT, 0),
        'clock_offset_s': ({'min': min(offsets), 'median': statistics.median(offsets), 'max': max(offsets),
                            'definition': 'Cowrie connect time minus manifest entry start (host clock)'}
                           if offsets else None),
        'label_distribution_after': dict(sorted(after.items())),
        'binary_label_convention': 'source profile label for profile-labelled sessions; -1 (not applicable) '
                                   'for failed_login, login_no_commands, ambiguous and unassigned',
    }
    if previous_labels:
        before = Counter(previous_labels.get(sid, '') for sid in records)
        transitions = Counter(f"{previous_labels.get(sid, '')} -> {r['behaviour_label']}" for sid, r in records.items())
        changed_source = sum(1 for sid, r in records.items()
                             if r['source_status'] == ASSIGNED and r['behaviour_label'] not in (FAILED_LOGIN, LOGIN_NO_COMMANDS)
                             and previous_labels.get(sid) != r['source_attack_cat'])
        report['label_distribution_before'] = dict(sorted(before.items()))
        report['label_transitions'] = dict(sorted(transitions.items()))
        report['previous_label_differs_from_assigned_source_category'] = sum(
            1 for sid, r in records.items() if r['source_attack_cat'] and previous_labels.get(sid) != r['source_attack_cat'])
        report['previous_label_wrong_for_profile_labelled_sessions'] = changed_source
    return records, report


def write_outputs(out_dir, sessions, records, report, python=None):
    """Write labelled sessions, per-session assignments, the report and the feature CSV into out_dir."""
    os.makedirs(out_dir, exist_ok=True)
    labelled = {}
    for sid, events in sessions.items():
        rec = records[sid]
        labelled[sid] = [dict(ev, attack_cat=rec['behaviour_label'], label=rec['label']) for ev in events]
    sessions_path = os.path.join(out_dir, 'sessions_labelled.json')
    with open(sessions_path, 'w', encoding='utf-8') as f:
        json.dump(labelled, f, indent=2)
    with open(os.path.join(out_dir, 'label_assignments.csv'), 'w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=ASSIGNMENT_FIELDS, lineterminator='\n')
        writer.writeheader()
        for sid in sessions:
            writer.writerow(records[sid])
    with open(os.path.join(out_dir, 'label_report.json'), 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
    extractor = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'scripts', 'extract_features.py')
    subprocess.run([python or sys.executable, extractor, '--input', sessions_path,
                    '--output', os.path.join(out_dir, 'behavior_features.csv'),
                    '--details', os.path.join(out_dir, 'session_details.json')], check=True)
