"""Dataset V2 revised profiles (dataset_builder/profiles_v2_revised.json; docs/profile_redesign_v2.md).

Offline only: structure, Cowrie compatibility under the audited model from test_profile_compatibility, network
restrictions, and the static design properties the redesign claims. No test here sends traffic to Cowrie, and the
static properties are not evidence that model-level leakage is gone.
"""
import hashlib
import json
import random
import re
from pathlib import Path

import pytest

from dataset_builder import generate_labelled_traffic as glt
from generator_fakes import FakeShell, install
from test_profile_compatibility import FAST, all_commands, cowrie_model

REPO = Path(__file__).resolve().parents[1]
COMPAT = REPO / "dataset_builder" / "profiles_v2_compat.json"
REVISED = REPO / "dataset_builder" / "profiles_v2_revised.json"
NAMES = ["benign_admin", "reconnaissance", "brute_force", "botnet", "privilege_escalation", "lateral_movement",
         "data_exfiltration"]
SHELL_OPERATORS = ('|', ';', '&&', '>', '<', '`', '$(')
DOWNLOAD_COMMANDS = {'wget', 'curl', 'tftp', 'ftp', 'ftpget', 'scp'}
INTERACTIVE = {"ssh", "scp", "sftp", "telnet", "vi", "vim", "nano", "pico", "emacs", "vipw", "top", "less", "more"}


def _load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def revised_model(line):
    """test_profile_compatibility.cowrie_model plus the other known non-returning forms."""
    name = line.split()[0] if line.strip() else ""
    if name in INTERACTIVE or (name == "ping" and "-c" not in line.split()):
        return "hang"
    return cowrie_model(line)


def _options(step):
    options = step["cmd"] if isinstance(step, dict) else step
    return options if isinstance(options, list) else [options]


def test_compat_profiles_are_unchanged():
    assert hashlib.sha256(COMPAT.read_bytes()).hexdigest() == \
        "27c4f96416c8733ffd12df008cbd456ddf052501233243d903c57a98b55dfb23"


def test_revised_file_keeps_labels_order_credentials_and_placeholders():
    compat, revised = _load(COMPAT), _load(REVISED)
    assert revised["version"] == "2.3.0-revised"
    assert revised["derived_from"] == {"file": "dataset_builder/profiles_v2_compat.json", "version": compat["version"]}
    assert revised["placeholders"] == compat["placeholders"]
    assert [p["name"] for p in revised["profiles"]] == NAMES
    for a, b in zip(compat["profiles"], revised["profiles"]):
        for key in ("name", "attack_cat", "label", "held_out", "credentials", "weight"):
            assert a.get(key) == b.get(key), (a["name"], key)
        assert "delay_range" not in b and "compat_notes" not in b
        assert b["redesign_notes"]
    brute = [p for p in revised["profiles"] if p["name"] == "brute_force"][0]
    assert brute["steps"] == [p for p in compat["profiles"] if p["name"] == "brute_force"][0]["steps"]


def test_steps_and_noise_are_well_formed():
    config = _load(REVISED)
    pools = set(config["placeholders"]) | {"rand"}
    for profile in config["profiles"]:
        assert profile["steps"], profile["name"]
        lo, hi = profile.get("noise_count", [0, 0])
        assert 0 <= lo <= hi
        assert (hi == 0) or profile["noise_pool"]
        groups = [_options(s) for s in profile["steps"]] + [profile.get("noise_pool", [])]
        for step in profile["steps"]:
            if isinstance(step, dict):
                assert set(step) == {"p", "cmd"} and 0 < step["p"] <= 1, profile["name"]
        for options in groups:
            assert len(options) == len(set(options)), (profile["name"], options)
            for cmd in options:
                assert isinstance(cmd, str) and cmd == cmd.strip() and cmd, (profile["name"], cmd)
                assert "\n" not in cmd and "\r" not in cmd and cmd.isascii(), cmd
                assert set(re.findall(r"\{(\w+)\}", cmd)) <= pools, cmd
                assert cmd.count("'") % 2 == 0 and cmd.count('"') % 2 == 0, cmd


def test_revised_profiles_contain_no_command_that_blocks_cowrie():
    for name, cmds in all_commands(_load(REVISED)).items():
        assert not [c for c in cmds if revised_model(c) == "hang"], name


def test_revised_profiles_have_no_external_network_dependency():
    import ipaddress
    docnets = [ipaddress.ip_network(d) for d in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
    for name, cmds in all_commands(_load(REVISED)).items():
        for cmd in cmds:
            for token in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d+)?\b", cmd):
                assert any(ipaddress.ip_network(token, strict=False).subnet_of(d) for d in docnets), (name, cmd)
            for host in re.findall(r"https?://([^/\s]+)", cmd):
                assert host.endswith(".example") or re.fullmatch(r"[0-9.]+", host), (name, cmd)


def test_benign_profile_has_no_attack_commands():
    suspicious = re.compile(r"chmod|\./|/etc/shadow|sudo|-perm|\bnc\b|nmap|history -c|HISTFILE|\brm\b|tar |wget |"
                            r"curl -(O|T)|id_rsa|known_hosts|bash_history|/tmp|/dev/shm")
    benign = all_commands(_load(REVISED))["benign_admin"]
    assert not [c for c in benign if suspicious.search(c)]


@pytest.mark.parametrize("profile_name", NAMES)
def test_every_revised_profile_completes_under_the_audited_cowrie_model(monkeypatch, profile_name):
    config = glt.load_config(REVISED)
    profile = next(p for p in config["profiles"] if p["name"] == profile_name)
    for seed in range(40):
        install(monkeypatch, glt, shell_factory=lambda: FakeShell(behaviours=revised_model))
        commands = glt.plan_commands(profile, config["placeholders"], random.Random(seed))
        record = glt.run_session("h", 1, [["root", "x"]], commands, glt.PacingPolicy(),
                                 glt.session_pacing_rng(seed, 1), FAST)
        assert record["termination"] == "clean_exit", (profile_name, seed, record["error"])
        assert record["commands_sent"] == commands


def test_operator_and_download_vocabulary_is_no_longer_single_category():
    """Static design property only (task 11 C4 criterion b): each indicator occurs in >= 2 non-held-out categories."""
    config = _load(REVISED)
    cmds = all_commands(config)
    trained = [p["name"] for p in config["profiles"] if not p.get("held_out")]
    with_ops = {n for n in trained if any(any(op in c for op in SHELL_OPERATORS) for c in cmds[n])}
    with_dl = {n for n in trained if any(c.split()[0] in DOWNLOAD_COMMANDS for c in cmds[n])}
    assert len(with_ops) >= 4 and len(with_dl) >= 2
    # benign never downloads to disk: its only download-family command is a header check
    assert all(c.startswith("curl -I ") for c in cmds["benign_admin"] if c.split()[0] in DOWNLOAD_COMMANDS)
