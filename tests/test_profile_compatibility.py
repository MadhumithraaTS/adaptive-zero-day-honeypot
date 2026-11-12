"""Dataset V2 profile compatibility with Cowrie's emulated shell (reports/cowrie_profile_compatibility_v2/report.md).

COWRIE_MODEL encodes the audited Cowrie behaviour of this pinned build in the isolated lab:
- ssh: interactive (yes/no, password) -> never returns a prompt
- scp: reads stdin as file data -> never returns a prompt
- wget to an IP address: connection failure reaches wget.py's reference to the missing
  twisted.internet.error.ConnectingDone -> never returns a prompt (smoke test: botnet #2)
Everything else returned a prompt in the smoke test or the historical runs.
"""
import hashlib
import ipaddress
import itertools
import json
import random
import re
from pathlib import Path

import pytest

from dataset_builder import generate_labelled_traffic as glt
from generator_fakes import FakeShell, install

REPO = Path(__file__).resolve().parents[1]
ISOLATED = REPO / "dataset_builder" / "profiles_v2_isolated.json"
COMPAT = REPO / "dataset_builder" / "profiles_v2_compat.json"
URL_HOST = re.compile(r"https?://([^/\s]+)")
FAST = glt.ReadinessPolicy(prompt_timeout_s=0.2, exit_timeout_s=0.2, poll_interval_s=0.001)


def cowrie_model(line):
    name = line.split()[0] if line.strip() else ""
    if name in ("ssh", "scp"):
        return "hang"
    if name == "wget":
        host = URL_HOST.search(line)
        if host and re.fullmatch(r"[0-9.]+", host.group(1)):
            return "hang"
    return "normal"


def _load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def all_commands(config):
    """Every concrete command any profile can emit: all alternatives x all placeholder values, plus noise."""
    pools = config["placeholders"]
    out = {}
    for profile in config["profiles"]:
        templates = []
        for step in profile["steps"]:
            options = step["cmd"] if isinstance(step, dict) else step
            templates += options if isinstance(options, list) else [options]
        templates += profile.get("noise_pool", [])
        cmds = set()
        for t in templates:
            names = [n for n in pools if "{" + n + "}" in t]
            for values in itertools.product(*(pools[n] for n in names)):
                c = t
                for n, v in zip(names, values):
                    c = c.replace("{" + n + "}", v)
                cmds.add(c)
        out[profile["name"]] = cmds
    return out


def test_original_and_isolated_profiles_are_unchanged():
    digests = {
        "dataset_builder/profiles_v2.json": "182afa5f282031fc8414be07bbafe3ae205c145031afa59d83346d3576e7c60e",
        "dataset_builder/profiles_v2_isolated.json": "385af93690cbaf0242130873f7da57b699e1d2e92ec6220f13dfa5c009780f63",
        "configs/attack_profiles.json": "f3cc54a95315467e2f753eb56799db00487635c3b00d28c27762a69e8da364d0",
        "configs/attack_profiles_isolated.json": "cce960082d20992337dafbb4b6ade11170510df7012750b7b3ef263bbee5946e",
    }
    for rel, digest in digests.items():
        assert hashlib.sha256((REPO / rel).read_bytes()).hexdigest() == digest, rel


def test_compat_profiles_differ_from_isolated_only_in_the_three_documented_steps():
    iso, compat = _load(ISOLATED), _load(COMPAT)
    assert compat["placeholders"] == iso["placeholders"]
    assert compat["derived_from"]["version"] == iso["version"]
    for a, b in zip(iso["profiles"], compat["profiles"]):
        changed = {k for k in set(a) | set(b) if a.get(k) != b.get(k)}
        expected = {"steps", "compat_notes"} if a["name"] in ("botnet", "data_exfiltration", "lateral_movement") else set()
        assert changed == expected, a["name"]
        # labels, categories, credentials and held-out status are untouched
        for key in ("attack_cat", "label", "held_out", "credentials", "noise_pool", "noise_count"):
            assert a.get(key) == b.get(key)


def test_isolated_profiles_contain_the_blocking_commands_that_compat_removes():
    blocking = {name: {c for c in cmds if cowrie_model(c) == "hang"} for name, cmds in all_commands(_load(ISOLATED)).items()}
    assert {n for n, cmds in blocking.items() if cmds} == {"botnet", "data_exfiltration", "lateral_movement"}


def test_compat_profiles_contain_no_command_that_blocks_cowrie():
    for name, cmds in all_commands(_load(COMPAT)).items():
        assert not [c for c in cmds if cowrie_model(c) == "hang"], name
        assert not [c for c in cmds if c.split()[0] in ("ssh", "scp", "sftp", "telnet")], name


def test_compat_profiles_have_no_external_network_dependency():
    for name, cmds in all_commands(_load(COMPAT)).items():
        for cmd in cmds:
            for token in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d+)?\b", cmd):
                net = ipaddress.ip_network(token.split("/")[0])
                assert any(net.subnet_of(ipaddress.ip_network(d)) for d in
                           ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")), (name, cmd)
            for host in URL_HOST.findall(cmd):
                assert host.endswith(".example") or re.fullmatch(r"[0-9.]+", host), (name, cmd)
            if cmd.startswith("wget "):
                assert URL_HOST.search(cmd).group(1).endswith(".example"), cmd


@pytest.mark.parametrize("profile_name", ["benign_admin", "reconnaissance", "brute_force", "botnet",
                                          "privilege_escalation", "lateral_movement", "data_exfiltration"])
def test_every_compat_profile_completes_under_the_audited_cowrie_model(monkeypatch, profile_name):
    config = _load(COMPAT)
    profile = next(p for p in config["profiles"] if p["name"] == profile_name)
    for seed in range(40):
        install(monkeypatch, glt, shell_factory=lambda: FakeShell(behaviours=cowrie_model))
        rng = random.Random(seed)
        commands = glt.plan_commands(profile, config["placeholders"], rng)
        record = glt.run_session("h", 1, [["root", "x"]], commands, glt.PacingPolicy(),
                                 glt.session_pacing_rng(seed, 1), FAST)
        assert record["termination"] == "clean_exit", (profile_name, seed, record["error"])
        assert record["commands_sent"] == commands


def test_isolated_lateral_movement_terminates_under_the_same_model(monkeypatch):
    install(monkeypatch, glt, shell_factory=lambda: FakeShell(behaviours=cowrie_model))
    record = glt.run_session("h", 1, [["root", "x"]], ["arp -a", "ssh root@192.0.2.5", "whoami"], glt.PacingPolicy(),
                             glt.session_pacing_rng(1, 1), FAST)
    assert record["termination"] == "readiness_timeout"
    assert record["commands_sent"] == ["arp -a", "ssh root@192.0.2.5"]
