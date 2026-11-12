"""Generate labelled SSH sessions against the Cowrie honeypot and record ground truth per session.

This reuses the approach of scripts/attack_generator.py (paramiko SSH to Cowrie) but adds the two
things the released dataset needs: scale (many randomised sessions per category) and labels. Every
session attempt is appended to <output-dir>/manifest.jsonl the moment it finishes, recording the
profile, category, label, credentials tried, the exact commands sent, and UTC start/end times.
build_labelled_dataset.py later matches Cowrie's own session records to these manifest entries to
attach the correct attack_cat/label.

Nothing here touches the existing scripts/ or configs/ files. It only talks to the honeypot and
writes under its own --output-dir.

Pacing and sequencing (generator 2.1, docs/generator_pacing_and_sequencing.md):
- Every profile and category uses one PacingPolicy. A profile's own `delay_range` is ignored, so
  timing features cannot encode the category.
- Each command is sent only after Cowrie's shell prompt has returned (ReadinessPolicy). If the prompt
  does not return in time, the session is terminated and every remaining command is recorded as not sent.
- The manifest records per command what was sent, when, and whether the prompt came back
  (docs/generation_manifest_schema.md). It is audit evidence and a label source, never a model input.
"""
import argparse
import codecs
import json
import math
import os
import random
import re
import string
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

import paramiko

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG = os.path.join(HERE, 'profiles_v2.json')
CONTAINER_LOG = '/cowrie/cowrie-git/var/log/cowrie/cowrie.json'
GENERATOR_VERSION = '2.1'


@dataclass(frozen=True)
class PacingPolicy:
    """The single pacing distribution shared by every profile and category.

    Think time before each command (including the first, after the prompt appears) and before `exit`
    is log-normal with the given median and sigma, clipped to [min, max], then divided by `speed`.
    The gap between authentication attempts is uniform. No parameter depends on a profile, category
    or command. These defaults are documented choices, not values fitted to real attackers.
    """
    think_median_s: float = 1.5
    think_sigma: float = 0.75
    think_min_s: float = 0.2
    think_max_s: float = 15.0
    auth_gap_min_s: float = 0.2
    auth_gap_max_s: float = 0.8
    speed: float = 1.0

    def think_time(self, rng):
        value = rng.lognormvariate(math.log(self.think_median_s), self.think_sigma)
        return min(max(value, self.think_min_s), self.think_max_s) / self.speed

    def auth_gap(self, rng):
        return rng.uniform(self.auth_gap_min_s, self.auth_gap_max_s) / self.speed

    def describe(self):
        return dict(asdict(self), think_distribution='lognormal(ln(median), sigma) clipped to [min, max], / speed',
                    auth_gap_distribution='uniform(min, max) / speed')


def session_pacing_rng(pacing_seed, session_index):
    """Pacing stream for one session: depends only on the run's pacing seed and the session index.

    It is separate from the planning RNG, so a session's pacing never depends on which profile it
    (or any earlier session) used. String seeds are hashed with SHA-512 by `random`, so this is
    reproducible across processes and platforms.
    """
    return random.Random(f"pacing:{pacing_seed}:{session_index}")


def find_pacing_seed_reuse(runs_root, pacing_seed, exclude=None):
    """Run directories under runs_root whose run_meta.json records the same pacing seed.

    Reusing a pacing seed in two runs gives their sessions identical pacing streams (session i of
    each run gets the same think times), so Dataset V2 runs must each use a new seed.
    """
    if not os.path.isdir(runs_root):
        return []
    excluded = os.path.abspath(exclude) if exclude else None
    hits = []
    for dirpath, _dirnames, filenames in os.walk(runs_root):
        if 'run_meta.json' not in filenames or os.path.abspath(dirpath) == excluded:
            continue
        try:
            with open(os.path.join(dirpath, 'run_meta.json'), encoding='utf-8') as f:
                meta = json.load(f)
        except (OSError, ValueError):
            continue
        if meta.get('pacing_seed') == pacing_seed:
            hits.append(dirpath)
    return sorted(hits)


# Cowrie's prompt is "user@host:path$ " or "user@host:path# ", preceded by terminal control sequences.
PROMPT_RE = re.compile(r'[^\s@]+@[^\s:]+:[^\r\n]*[#$] $')
ANSI_RE = re.compile(r'\x1b\[[0-9;?]*[A-Za-z]')
# Command names that may keep the emulated shell busy (network or stdin). Used only to annotate the
# manifest; every command gets the same readiness timeout.
BLOCKING_COMMANDS = frozenset({'wget', 'curl', 'scp', 'sftp', 'tftp', 'ftp', 'ftpget', 'nc', 'ncat',
                               'ping', 'ssh', 'sleep'})


@dataclass(frozen=True)
class ReadinessPolicy:
    """When the shell counts as ready, how long to wait for it, and what to do when it is not."""
    prompt_timeout_s: float = 20.0
    exit_timeout_s: float = 5.0
    poll_interval_s: float = 0.05
    on_timeout: str = 'terminate_session'  # the only policy: send nothing more, record the rest as not sent

    def describe(self):
        return dict(asdict(self), prompt_regex=PROMPT_RE.pattern,
                    readiness_condition='terminal output (control sequences and CR removed) ends with the prompt')


# Diagnostic terminal-output capture: at most this many characters per wait (head and tail halves).
OUTPUT_CAPTURE_CHARS = 2048
# A typed secret shorter than this is not replaced: as a whole token it is too likely to be ordinary
# text, and the command containing it is already in the manifest. The decision is recorded.
REDACT_MIN_LENGTH = 4
TRUNCATION_MARKER = '\n[...truncated...]\n'
_SURROGATE_RE = re.compile('[\udc80-\udcff]')


def secrets_typed_in(command, secrets):
    """Secrets that appear as whole tokens in a command the client typed.

    SSH authentication never passes through the terminal, so a password can only appear in terminal
    output if the client typed it in a command. This is the only evidence on which output is redacted.
    """
    return tuple(s for s in dict.fromkeys(secrets) if s and _token_re(s).search(command))


def _token_re(secret):
    return re.compile(r'(?<![A-Za-z0-9_])' + re.escape(secret) + r'(?![A-Za-z0-9_])')


class _Utf8Stream:
    """Incremental UTF-8 decoding across received chunks.

    Valid multi-byte characters split between chunks are reassembled. Invalid bytes are never replaced
    silently: they are rendered as an explicit '\\xNN' escape and counted.
    """

    def __init__(self):
        self._decoder = codecs.getincrementaldecoder('utf-8')(errors='surrogateescape')
        self.invalid_bytes = 0

    def _render(self, text):
        self.invalid_bytes += len(_SURROGATE_RE.findall(text))
        return _SURROGATE_RE.sub(lambda m: '\\x%02x' % (ord(m.group()) - 0xDC00), text)

    def decode(self, data):
        return self._render(self._decoder.decode(data))

    def flush(self):
        return self._render(self._decoder.decode(b'', final=True))


class _OutputCapture:
    """Bounded record of the (control-sequence-stripped) terminal output seen during one wait.

    Keeps the first and last `limit // 2` characters plus a margin (the longest secret being redacted),
    so a secret straddling a cut is still seen whole before the final cut is made.
    """

    def __init__(self, limit=OUTPUT_CAPTURE_CHARS, margin=0):
        self.half = limit // 2
        self.keep = self.half + margin
        self.head, self.tail, self.total_chars, self.total_bytes = '', '', 0, 0

    def add_bytes(self, n):
        self.total_bytes += n

    def add_text(self, text):
        self.total_chars += len(text)
        if len(self.head) < self.keep:
            take = self.keep - len(self.head)
            self.head, text = self.head + text[:take], text[take:]
        self.tail = (self.tail + text)[-self.keep:]

    def result(self, prompt_match=None, typed_secrets=()):
        """Bounded diagnostic text and redaction record.

        Redaction happens only for secrets the client typed in this step (typed_secrets), only for whole
        tokens, never inside the trailing prompt, and never for secrets shorter than REDACT_MIN_LENGTH.
        """
        candidates = [s for s in typed_secrets if len(s) >= REDACT_MIN_LENGTH]
        occurrences = 0

        def redact(text):
            nonlocal occurrences
            for secret in candidates:
                text, n = _token_re(secret).subn('[REDACTED]', text)
                occurrences += n
            return text

        def redact_keep_prompt(text):
            if prompt_match and text.endswith(prompt_match):
                return redact(text[:-len(prompt_match)]) + prompt_match
            return redact(text)

        limit = 2 * self.half
        if self.total_chars <= len(self.head) + len(self.tail):      # everything was kept
            text = redact_keep_prompt(self.head + self.tail)
            truncated = len(text) > limit
            if truncated:
                text = text[:self.half] + TRUNCATION_MARKER + text[len(text) - self.half:]
        else:
            truncated = True
            text = redact(self.head)[:self.half] + TRUNCATION_MARKER
            tail = redact_keep_prompt(self.tail)
            text += tail[len(tail) - self.half:]

        if not typed_secrets:
            reason = 'no_secret_typed'
        elif not candidates:
            reason = 'typed_secret_too_short_not_redacted'
        elif occurrences:
            reason = 'typed_secret_echoed_and_redacted'
        else:
            reason = 'typed_secret_not_found_in_output'
        return {'output': text, 'output_chars': self.total_chars, 'output_bytes': self.total_bytes,
                'output_truncated': truncated,
                'redaction': {'applied': occurrences > 0, 'reason': reason, 'occurrences': occurrences}}


def wait_for_prompt(channel, timeout_s, poll_s, typed_secrets=()):
    """Read shell output until it ends with a prompt, the channel closes, or the timeout passes.

    Returns {'ready', 'reason', 'waited_s', 'prompt_match', 'output', 'output_chars', 'output_bytes',
    'output_truncated', 'redaction', 'invalid_utf8_bytes'}; reason is 'prompt', 'channel_closed' or
    'timeout'. Prompt detection always runs on the unredacted text. The bounded output is the evidence
    behind the readiness decision; it is diagnostic only and never telemetry for features.
    """
    start = time.monotonic()
    buffer = ''
    stream = _Utf8Stream()
    capture = _OutputCapture(margin=max((len(s) for s in typed_secrets), default=0))
    while True:
        while channel.recv_ready():
            data = channel.recv(65535)
            if not data:
                break
            capture.add_bytes(len(data))
            text = ANSI_RE.sub('', stream.decode(data)).replace('\r', '')
            capture.add_text(text)
            buffer = (buffer + text)[-4096:]
        waited = round(time.monotonic() - start, 3)
        match = PROMPT_RE.search(buffer)
        if match:
            reason, ready = 'prompt', True
        elif channel.closed or channel.exit_status_ready():
            reason, ready = 'channel_closed', False
        elif waited >= timeout_s:
            reason, ready = 'timeout', False
        else:
            time.sleep(poll_s)
            continue
        leftover = stream.flush()  # an incomplete sequence at the end is reported, not dropped
        if leftover:
            capture.add_text(ANSI_RE.sub('', leftover).replace('\r', ''))
        prompt_match = match.group(0) if match else None
        result = {'ready': ready, 'reason': reason, 'waited_s': waited, 'prompt_match': prompt_match,
                  'invalid_utf8_bytes': stream.invalid_bytes}
        result.update(capture.result(prompt_match, typed_secrets))
        return result


def wait_for_close(channel, timeout_s, poll_s):
    """After `exit`: True if the channel closed (or reported an exit status) within the timeout."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if channel.closed or channel.exit_status_ready():
            return True
        while channel.recv_ready():
            if not channel.recv(65535):
                break
        time.sleep(poll_s)
    return channel.closed or channel.exit_status_ready()


def capture_log_baseline(container):
    """Count the lines already in the container's cumulative Cowrie log, without modifying it.

    Cowrie appends every session to one log that is never cleared between runs, and consecutive runs
    can be <1s apart, so no time filter can separate them. Instead we remember how many lines exist
    now; the builder parses only the lines this run appends after. This never touches the container
    (overwriting the open log file corrupts Cowrie's logging), so it is safe and reproducible.
    """
    tmp = tempfile.NamedTemporaryFile(suffix='.json', delete=False)
    tmp.close()
    try:
        result = subprocess.run(['docker', 'cp', f'{container}:{CONTAINER_LOG}', tmp.name],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode != 0:
            # No log yet (fresh container) counts as a zero baseline, which is correct.
            if b'Could not find' in result.stderr or b'No such' in result.stderr:
                return 0
            raise SystemExit(f"Could not read Cowrie log baseline: {result.stderr.decode(errors='replace').strip()}")
        with open(tmp.name, 'rb') as f:
            return sum(1 for _ in f)
    except FileNotFoundError:
        raise SystemExit("docker not found; run with --no-baseline if the honeypot is elsewhere.")
    finally:
        os.unlink(tmp.name)


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def load_config(config_path):
    with open(config_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def fill_placeholders(command, placeholders, chosen, rng):
    """Fill {name} slots. A name keeps one value within a session so steps stay internally consistent."""
    for name, pool in placeholders.items():
        token = '{' + name + '}'
        if token in command:
            chosen.setdefault(name, rng.choice(pool))
            command = command.replace(token, chosen[name])
    if '{rand}' in command:
        chosen.setdefault('rand', ''.join(rng.choices(string.ascii_letters + string.digits, k=12)))
        command = command.replace('{rand}', chosen['rand'])
    return command


def plan_commands(profile, placeholders, rng):
    """Resolve a profile's steps into one concrete command list for a single session."""
    chosen, commands = {}, []
    for step in profile['steps']:
        if isinstance(step, dict):
            if rng.random() >= step.get('p', 1.0):
                continue
            step = step['cmd']
        command = rng.choice(step) if isinstance(step, list) else step
        commands.append(fill_placeholders(command, placeholders, chosen, rng))

    noise_min, noise_max = profile.get('noise_count', [0, 0])
    for _ in range(rng.randint(noise_min, noise_max)):
        if profile.get('noise_pool') and commands:
            commands.insert(rng.randint(0, len(commands)), rng.choice(profile['noise_pool']))
    return commands


# Failed guesses use the reserved "scan" account, which userdb.txt denies and no profile ever uses
# for a real login. This keeps the failed-login space from ever colliding with an accepted credential.
WRONG_POOL = [['scan', '123456'], ['scan', 'password'], ['scan', 'admin'], ['scan', 'root']]


def plan_credentials(profile, rng):
    """A few wrong guesses (so Cowrie logs failed logins) followed by one accepted pair."""
    creds = profile['credentials']
    fail_min, fail_max = creds.get('failed_attempts', [0, 0])
    attempts = [list(rng.choice(WRONG_POOL)) for _ in range(rng.randint(fail_min, fail_max))]
    attempts.append([rng.choice(creds['usernames']), rng.choice(creds['passwords'])])
    return attempts


def _connect(host, port, username, password):
    """Return a connected client, or close the half-open connection and re-raise the original error.

    Without the close, a rejected login left the SSH transport open until Cowrie's 120 s
    authentication_timeout dropped it (reports/cowrie_payload_observability_pilot/report.md, section 8).
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host, port=port, username=username, password=password,
            timeout=15, banner_timeout=20, auth_timeout=15,
            look_for_keys=False, allow_agent=False,
            disabled_algorithms={"pubkeys": ["rsa-sha2-256", "rsa-sha2-512"]},
        )
    except BaseException:
        client.close()
        raise
    return client


def _command_entry(seq, command):
    name = command.strip().split()[0] if command.strip() else ''
    return {'seq': seq, 'command': command, 'blocking_expected': name in BLOCKING_COMMANDS,
            'sent': False, 'think_time_s': None, 'sent_utc': None, 'ready_before_send': None,
            'prompt_returned': None, 'wait_s': None, 'readiness_reason': None, 'prompt_match': None,
            'output_chars': None, 'output_truncated': None, 'status': 'not_sent', 'action': None}


def _terminal_record(step, wait):
    """Diagnostic output for one wait; kept out of the manifest (written to terminal_output.jsonl)."""
    return {'step': step, 'readiness_reason': wait['reason'], 'prompt_match': wait['prompt_match'],
            'waited_s': wait['waited_s'], 'output': wait['output'], 'output_chars': wait['output_chars'],
            'output_bytes': wait['output_bytes'], 'output_truncated': wait['output_truncated'],
            'redaction': wait['redaction'], 'invalid_utf8_bytes': wait['invalid_utf8_bytes']}


def run_session(host, port, attempts, commands, pacing, pacing_rng, readiness=ReadinessPolicy()):
    """Run one planned session. Cowrie accepts almost any password, so the last attempt logs in.

    Pacing comes only from `pacing` (shared by all profiles) and `pacing_rng` (the session's own stream);
    nothing about the profile or category is passed in. Each command is sent only after the prompt has
    returned; on a readiness failure the session is terminated and the remaining commands are recorded
    as not sent. `commands_sent` lists exactly the commands transmitted - not that they succeeded.
    """
    record = {'auth_attempts': attempts, 'auth_log': [], 'auth_success': False,
              'commands_planned': list(commands), 'commands_sent': [],
              'command_log': [_command_entry(seq, cmd) for seq, cmd in enumerate(commands, start=1)],
              'shell_ready_initial': None, 'shell_initial_wait_s': None, 'exit_sent': False,
              'exit_confirmed': None, 'termination': None,
              'guess_errors': [], 'status': 'ok', 'error': None,
              # Diagnostic only: main() moves this to terminal_output.jsonl; it never enters the manifest.
              'terminal_output': []}
    secrets = tuple(password for _, password in attempts)

    def log_auth(username, outcome, error=None):
        record['auth_log'].append({'attempt': len(record['auth_log']) + 1, 'username': username,
                                   'outcome': outcome, 'utc': utc_now(), 'error': error})

    # Wrong guesses first: connect and immediately drop, so Cowrie records a failed login.
    # _connect closes the connection itself when the guess is rejected.
    for username, password in attempts[:-1]:
        try:
            _connect(host, port, username, password).close()
            log_auth(username, 'accepted_unexpectedly')
        except paramiko.AuthenticationException:
            log_auth(username, 'rejected')  # the expected outcome of a wrong guess
        except Exception as exc:
            # Anything else (refused connection, timeout, protocol error) is kept for the manifest.
            record['guess_errors'].append(f"{username}: {type(exc).__name__}: {exc}")
            log_auth(username, 'error', f"{type(exc).__name__}: {exc}")
        time.sleep(pacing.auth_gap(pacing_rng))

    username, password = attempts[-1]
    client = None
    try:
        try:
            client = _connect(host, port, username, password)
        except paramiko.AuthenticationException as exc:
            log_auth(username, 'rejected', f"{type(exc).__name__}: {exc}")
            record['termination'] = 'auth_failed'
            raise
        log_auth(username, 'accepted')
        record['auth_success'] = True
        channel = client.invoke_shell()

        # Nothing has been typed yet, so nothing can have been echoed: no redaction for the initial wait.
        initial = wait_for_prompt(channel, readiness.prompt_timeout_s, readiness.poll_interval_s)
        record['terminal_output'].append(_terminal_record('initial', initial))
        record['shell_ready_initial'] = initial['ready']
        record['shell_initial_wait_s'] = initial['waited_s']
        if not initial['ready']:
            record['termination'] = 'shell_not_ready'
            record['status'] = 'incomplete'
            record['error'] = f"initial prompt: {initial['reason']} after {initial['waited_s']} s"
            return record

        for entry in record['command_log']:
            entry['think_time_s'] = round(pacing.think_time(pacing_rng), 4)
            time.sleep(entry['think_time_s'])
            entry['ready_before_send'] = True  # every send follows a confirmed prompt
            channel.sendall((entry['command'] + "\n").encode('utf-8'))
            entry['sent'], entry['sent_utc'] = True, utc_now()
            record['commands_sent'].append(entry['command'])

            result = wait_for_prompt(channel, readiness.prompt_timeout_s, readiness.poll_interval_s,
                                     secrets_typed_in(entry['command'], secrets))
            record['terminal_output'].append(_terminal_record(entry['seq'], result))
            entry['prompt_returned'], entry['wait_s'] = result['ready'], result['waited_s']
            entry['readiness_reason'], entry['prompt_match'] = result['reason'], result['prompt_match']
            entry['output_chars'], entry['output_truncated'] = result['output_chars'], result['output_truncated']
            if result['ready']:
                entry['status'], entry['action'] = 'prompt_returned', 'continue'
                continue
            entry['status'] = 'readiness_' + result['reason']
            entry['action'] = readiness.on_timeout
            record['termination'] = entry['status']
            record['status'] = 'incomplete'
            record['error'] = f"command {entry['seq']}: {result['reason']} after {result['waited_s']} s"
            for later in record['command_log'][entry['seq']:]:
                later['status'] = 'not_sent_after_termination'
            return record

        time.sleep(pacing.think_time(pacing_rng))
        channel.sendall(b"exit\n")
        record['exit_sent'] = True
        record['exit_confirmed'] = wait_for_close(channel, readiness.exit_timeout_s, readiness.poll_interval_s)
        record['termination'] = 'clean_exit' if record['exit_confirmed'] else 'exit_unconfirmed'
    except Exception as exc:
        record['status'] = 'error'
        record['error'] = f"{type(exc).__name__}: {exc}"
        record['termination'] = record['termination'] or 'error'
    finally:
        if client:
            try:
                client.close()
            except Exception:
                pass
    return record


def weighted_profile_order(profiles, count, rng, include_held_out):
    """Build the run order. Benign is up-weighted so the dataset is not all-attack."""
    pool = [p for p in profiles if include_held_out or not p.get('held_out')]
    weights = [3 if p['attack_cat'] == 'benign' else 1 for p in pool]
    return rng.choices(pool, weights=weights, k=count)


def main():
    parser = argparse.ArgumentParser(description='Generate labelled honeypot traffic and a ground-truth manifest.')
    parser.add_argument('--config', default=DEFAULT_CONFIG)
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=2223, help='Cowrie SSH port (docker-compose maps 2223).')
    parser.add_argument('--sessions', type=int, default=400, help='Total sessions to generate.')
    parser.add_argument('--output-dir', default=os.path.join(HERE, 'runs', 'run_' + datetime.now().strftime('%Y%m%d_%H%M%S')))
    parser.add_argument('--seed', type=int, default=None, help='Set for a reproducible run.')
    parser.add_argument('--include-held-out', action='store_true',
                        help='Also generate the held-out/novel categories (default: skip, so they stay unseen).')
    parser.add_argument('--inter-session-delay', type=float, default=0.8)
    parser.add_argument('--speed', type=float, default=1.0,
                        help='Divide every pacing delay by this to compress runtime (e.g. 5 = ~5x faster). '
                             'It applies equally to all profiles; keep it fixed across runs that are combined.')
    parser.add_argument('--pacing-seed', type=int, required=True,
                        help='Required. Seed of the per-session pacing streams. Must differ from every other '
                             'run under --runs-root (checked before any connection). Independent of --seed, '
                             'which only plans profiles, commands and credentials.')
    parser.add_argument('--runs-root', default=None,
                        help='Directory whose run_meta.json files are checked for pacing-seed reuse '
                             '(default: the parent of --output-dir).')
    parser.add_argument('--allow-pacing-seed-reuse', action='store_true',
                        help='Diagnostics only: permit a pacing seed already used under --runs-root. '
                             'Recorded in run_meta.json; never use for Dataset V2 runs.')
    parser.add_argument('--prompt-timeout', type=float, default=ReadinessPolicy.prompt_timeout_s,
                        help='Seconds to wait for the shell prompt before terminating a session.')
    parser.add_argument('--container', default='cowrie-project',
                        help='Cowrie container name, used to read the log baseline.')
    parser.add_argument('--no-baseline', action='store_true',
                        help='Skip reading the container log baseline (use when the honeypot is not a '
                             'local docker container; the builder then falls back to time-window filtering).')
    args = parser.parse_args()

    runs_root = args.runs_root or os.path.dirname(os.path.abspath(args.output_dir))
    reused = find_pacing_seed_reuse(runs_root, args.pacing_seed, exclude=args.output_dir)
    if reused and not args.allow_pacing_seed_reuse:
        raise SystemExit(f"--pacing-seed {args.pacing_seed} was already used by: " + ", ".join(reused)
                         + ". Choose a new pacing seed (or --allow-pacing-seed-reuse for diagnostics only).")

    log_baseline = None if args.no_baseline else capture_log_baseline(args.container)
    if log_baseline is not None:
        print(f"Cowrie log baseline: {log_baseline} existing lines (this run's events come after).")

    rng = random.Random(args.seed)
    pacing_seed = args.pacing_seed
    pacing = PacingPolicy(speed=args.speed)
    readiness = ReadinessPolicy(prompt_timeout_s=args.prompt_timeout)
    config = load_config(args.config)
    placeholders = config.get('placeholders', {})

    os.makedirs(args.output_dir, exist_ok=True)
    manifest_path = os.path.join(args.output_dir, 'manifest.jsonl')

    run_meta = {
        'generated_at': utc_now(), 'host': args.host, 'port': args.port,
        'sessions_requested': args.sessions, 'seed': args.seed,
        'config_version': config.get('version'), 'include_held_out': args.include_held_out,
        'container': args.container, 'log_baseline_lines': log_baseline, 'speed': args.speed,
        'generator_version': GENERATOR_VERSION, 'config_path': os.path.abspath(args.config),
        'pacing_seed': pacing_seed, 'pacing_seed_source': 'explicit --pacing-seed',
        'pacing_seed_reuse': {'runs_root': runs_root, 'reused_by': reused, 'allowed': args.allow_pacing_seed_reuse},
        'terminal_output_file': 'terminal_output.jsonl (diagnostic only; not a feature source)',
        'output_capture_chars': OUTPUT_CAPTURE_CHARS, 'output_redact_min_length': REDACT_MIN_LENGTH,
        'output_redaction_policy': 'whole-token session passwords, only in a step whose sent command contains them; '
                                   'never the trailing prompt; never the initial wait',
        'output_decoding': 'incremental UTF-8; invalid bytes rendered as \\xNN and counted',
        'pacing_policy': pacing.describe(), 'readiness_policy': readiness.describe(),
        'profile_delay_range': 'ignored: pacing is category-independent (PacingPolicy)',
        'inter_session_delay_s': args.inter_session_delay / args.speed,
    }
    with open(os.path.join(args.output_dir, 'run_meta.json'), 'w', encoding='utf-8') as f:
        json.dump(run_meta, f, indent=2)

    order = weighted_profile_order(config['profiles'], args.sessions, rng, args.include_held_out)
    print(f"Writing manifest to {manifest_path}")
    print(f"Target: {args.sessions} sessions across {len({p['name'] for p in order})} profiles "
          f"-> {args.host}:{args.port}")

    ok = 0
    terminal_path = os.path.join(args.output_dir, 'terminal_output.jsonl')
    with open(manifest_path, 'w', encoding='utf-8') as manifest, \
            open(terminal_path, 'w', encoding='utf-8') as terminal_log:
        for i, profile in enumerate(order, start=1):
            attempts = plan_credentials(profile, rng)
            commands = plan_commands(profile, placeholders, rng)
            start = utc_now()
            # The profile chooses what is sent; it has no influence on when (pacing) or on readiness.
            result = run_session(args.host, args.port, attempts, commands, pacing,
                                 session_pacing_rng(pacing_seed, i), readiness)
            for item in result.pop('terminal_output'):
                terminal_log.write(json.dumps({'index': i, **item}) + "\n")
            terminal_log.flush()
            entry = {
                'index': i,
                'profile': profile['name'],
                'attack_cat': profile['attack_cat'],
                'label': profile['label'],
                'held_out': profile.get('held_out', False),
                'username': attempts[-1][0],
                'start_utc': start,
                'end_utc': utc_now(),
                'pacing_stream': f"pacing:{pacing_seed}:{i}",
                **result,
            }
            manifest.write(json.dumps(entry) + "\n")
            manifest.flush()
            ok += result['status'] == 'ok'
            print(f"[{i}/{len(order)}] {profile['name']:<22} {result['status']}"
                  + (f"  ({result['error']})" if result['error'] else ""))
            time.sleep(args.inter_session_delay / args.speed)

    print(f"\nDone. {ok}/{len(order)} sessions completed cleanly.")
    print(f"Manifest: {manifest_path}")
    print("Next: run build_labelled_dataset.py to collect Cowrie logs and attach these labels.")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted; manifest holds every session completed so far.", file=sys.stderr)
        sys.exit(130)
