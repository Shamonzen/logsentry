from datetime import timedelta

from logsentry.models import Severity
from logsentry.rules.success_after_failures import SuccessAfterFailures


def make_rule(threshold=5, window_seconds=600):
    return SuccessAfterFailures(
        SuccessAfterFailures.Config(threshold=threshold, window_seconds=window_seconds)
    )


def run(rule, events):
    return [a for e in events for a in rule.process(e)]


def test_fires_on_success_after_failures_fixture(load_events):
    events = load_events("auth_success_after_fail.log")
    [alert] = run(make_rule(), events)
    assert (alert.rule_id, alert.technique_id, alert.severity) == (
        "success_after_failures",
        "T1078",
        Severity.HIGH,
    )
    assert str(alert.src_ip) == "203.0.113.80"
    assert alert.event_count == 7  # 6 failures + the success
    assert alert.first_seen == events[0].ts
    assert alert.last_seen == events[-1].ts
    assert alert.summary == (
        "Successful SSH login as labuser from 203.0.113.80 after 6 failed attempts within 600s"
    )
    assert "Accepted password" in alert.evidence[-1]


def test_failures_alone_do_not_fire(load_events):
    assert run(make_rule(), load_events("auth_bruteforce.log")) == []


def test_failures_older_than_window_are_forgotten(load_events):
    events = load_events("auth_success_after_fail.log")
    success = events[-1].model_copy(update={"ts": events[-1].ts + timedelta(seconds=600)})
    assert run(make_rule(), [*events[:-1], success]) == []


def test_failures_from_another_ip_do_not_count(load_events):
    events = load_events("auth_success_after_fail.log")
    success = events[-1].model_copy(update={"src_ip": "198.51.100.99"})
    assert run(make_rule(), [*events[:-1], success]) == []


def test_benign_fixture_does_not_fire(load_events):
    # bob mistypes once, then logs in: one failure is far below the threshold
    assert run(make_rule(), load_events("auth_benign.log")) == []
