from datetime import timedelta
from pathlib import Path

from logsentry.engine import Engine
from logsentry.rules.ssh_bruteforce import SshBruteforce

CONFIG = Path(__file__).parent.parent / "config" / "rules.yaml"


def engine(cooldown_seconds=300):
    rule = SshBruteforce(SshBruteforce.Config(threshold=10, window_seconds=60))
    return Engine([rule], cooldown_seconds)


def run(eng, events):
    return [a for e in events for a in eng.process(e)]


def shifted(events, seconds):
    return [e.model_copy(update={"ts": e.ts + timedelta(seconds=seconds)}) for e in events]


def test_one_bruteforce_gives_one_alert(load_events):
    alerts = run(engine(), load_events("auth_bruteforce.log"))
    assert len(alerts) == 1
    assert alerts[0].event_count == 10


def test_same_attack_after_cooldown_alerts_again(load_events):
    events = load_events("auth_bruteforce.log")
    eng = engine(cooldown_seconds=300)
    assert len(run(eng, events)) == 1
    assert run(eng, shifted(events, 200)) == []  # still inside the cooldown
    assert len(run(eng, shifted(events, 600))) == 1


def test_cooldown_is_per_ip(load_events):
    events = load_events("auth_bruteforce.log")
    other = [e.model_copy(update={"src_ip": "198.51.100.99"}) for e in events]
    alerts = run(engine(), events + other)
    assert sorted(str(a.src_ip) for a in alerts) == ["198.51.100.99", "203.0.113.7"]


def test_events_only_reach_rules_for_their_source(load_events):
    # nginx events never reach the sshd-only rule
    nginx = load_events("nginx_attacks.log")
    assert run(engine(), nginx) == []


def test_from_repo_config_with_benign_logs(load_events):
    eng = Engine.from_config(CONFIG)
    assert run(eng, load_events("auth_benign.log") + load_events("nginx_benign.log")) == []
