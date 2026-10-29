from datetime import timedelta

from logsentry.models import Severity
from logsentry.rules.ssh_bruteforce import SshBruteforce


def make_rule(threshold=10, window_seconds=60):
    return SshBruteforce(SshBruteforce.Config(threshold=threshold, window_seconds=window_seconds))


def run(rule, events):
    return [a for e in events for a in rule.process(e)]


def test_fires_on_bruteforce_fixture(load_events):
    events = load_events("auth_bruteforce.log")
    alerts = run(make_rule(), events)
    # 12 failures: the 10th, 11th and 12th each cross the threshold (the engine dedupes)
    assert [a.event_count for a in alerts] == [10, 11, 12]
    first = alerts[0]
    assert (first.rule_id, first.technique_id, first.severity) == (
        "ssh_bruteforce",
        "T1110.001",
        Severity.MEDIUM,
    )
    assert str(first.src_ip) == "203.0.113.7"
    assert first.first_seen == events[0].ts
    assert first.summary == "10 failed SSH logins from 203.0.113.7 within 60s"
    assert all("Failed password" in line for line in first.evidence)


def test_invalid_user_lines_are_not_double_counted(load_events):
    # the fixture has 12 attempts; counting "Invalid user" too would reach 10 much earlier
    alerts = run(make_rule(threshold=13), load_events("auth_bruteforce.log"))
    assert alerts == []


def test_slow_attack_outside_window_does_not_fire(load_events):
    # fixture failures are 4 s apart, so a 30 s window never holds 10 of them
    assert run(make_rule(window_seconds=30), load_events("auth_bruteforce.log")) == []


def test_benign_fixture_does_not_fire(load_events):
    # one real typo (bob fails once, then logs in) must not look like an attack
    assert run(make_rule(), load_events("auth_benign.log")) == []


def test_evidence_is_capped(load_events):
    failure = next(e for e in load_events("auth_bruteforce.log") if e.event_type == "auth_failure")
    events = [
        failure.model_copy(update={"ts": failure.ts + timedelta(seconds=i)}) for i in range(30)
    ]
    alert = run(make_rule(), events)[-1]
    assert alert.event_count == 30
    assert len(alert.evidence) == 20
