"""Test doubles for dataset_builder/generate_labelled_traffic.py: no network, no Cowrie.

FakeShell imitates Cowrie's interactive shell closely enough for the generator's readiness logic:
it prints a prompt like "\\x1b[4hroot@svr04:~# ", echoes each line, and per command name can answer
at once ('normal'), after a few polls ('slow'), never ('hang', like emulated scp waiting on stdin),
or close the channel ('close'). For every line received it records whether the client had already
read the prompt, i.e. whether the shell was ready.
"""

PROMPT = b"\x1b[4hroot@svr04:~# "


class FakeShell:
    """prompt: prompt bytes; responses: {line: output bytes after the echo}; chunk_size: deliver output
    in pieces of at most this many bytes (to split multi-byte characters across recv calls)."""

    def __init__(self, behaviours=None, initial_prompt=True, close_on_exit=True, slow_polls=5,
                 prompt=PROMPT, responses=None, chunk_size=None):
        self.behaviours = behaviours or {}
        self.close_on_exit = close_on_exit
        self.slow_polls = slow_polls
        self.prompt = prompt
        self.responses = responses or {}
        self.chunk_size = chunk_size
        self.pending = []          # (bytes, is_prompt) not yet read by the client
        self.countdown = None      # polls left before a slow command answers
        self.ready = False         # True once the client has read a prompt
        self.received = []         # (line, shell_was_ready) for every line sent by the client
        self.closed = False
        if initial_prompt:
            self.pending += [(b"\nWelcome to the fake shell\n", False), (self.prompt, True)]

    def _answer(self, line):
        output = self.responses.get(line, b"ok\r\n")
        self.pending += [(line.encode() + b"\r\n" + output, False), (self.prompt, True)]

    def recv_ready(self):
        if self.countdown is not None:
            self.countdown -= 1
            if self.countdown <= 0:
                self.countdown = None
                self._answer(self._slow_line)
        return bool(self.pending)

    def recv(self, n):
        data, is_prompt = self.pending.pop(0)
        if self.chunk_size and len(data) > self.chunk_size:
            self.pending.insert(0, (data[self.chunk_size:], is_prompt))
            return data[:self.chunk_size]
        if is_prompt:
            self.ready = True
        return data

    def sendall(self, data):
        line = data.decode().rstrip("\n")
        self.received.append((line, self.ready))
        self.ready = False
        name = line.split()[0] if line.strip() else ""
        if line == "exit":
            self.closed = self.closed or self.close_on_exit
            return
        # behaviours: {command name: behaviour} or a function(line) -> behaviour
        behaviour = self.behaviours(line) if callable(self.behaviours) else self.behaviours.get(name, "normal")
        if behaviour == "normal":
            self._answer(line)
        elif behaviour == "big":
            self.pending += [(line.encode() + b"\r\n" + b"x" * 10000 + b"\r\n", False), (self.prompt, True)]
        elif behaviour == "slow":
            self._slow_line, self.countdown = line, self.slow_polls
            self.pending.append((line.encode() + b"\r\n", False))
        elif behaviour == "hang":
            self.pending.append((line.encode() + b"\r\n", False))
        elif behaviour == "close":
            self.closed = True

    def exit_status_ready(self):
        return self.closed

    def close(self):
        self.closed = True


class FakeClient:
    """Stands in for paramiko.SSHClient; each instance takes the next queued connect outcome."""

    outcomes = []
    instances = []
    shell_factory = FakeShell

    def __init__(self):
        self.closed = 0
        self.shell = None
        self.username = None
        FakeClient.instances.append(self)

    def set_missing_host_key_policy(self, policy):
        pass

    def connect(self, **kwargs):
        self.username = kwargs["username"]
        outcome = FakeClient.outcomes.pop(0) if FakeClient.outcomes else None
        if outcome is not None:
            raise outcome

    def invoke_shell(self):
        self.shell = FakeClient.shell_factory()
        return self.shell

    def close(self):
        self.closed += 1


def install(monkeypatch, glt, outcomes=None, shell_factory=FakeShell):
    """Patch the generator module to use FakeClient and a no-op sleep. Returns FakeClient."""
    FakeClient.outcomes = list(outcomes or [])
    FakeClient.instances = []
    FakeClient.shell_factory = shell_factory
    monkeypatch.setattr(glt.paramiko, "SSHClient", FakeClient)
    monkeypatch.setattr(glt.time, "sleep", lambda seconds: None)
    return FakeClient
