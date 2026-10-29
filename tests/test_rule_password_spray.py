from logsentry.models import Severity
from logsentry.rules.password_spray import PasswordSpray


def make_rule(threshold=5, window_seconds=300):
    return PasswordSpray(PasswordSpray.Config(threshold=threshold, window_seconds=window_seconds))


def run(rule, events):
    return [a for e in events for a in rule.process(e)]


def test_fires_on_spray_fixture(load_events):
    events = load_events("auth_spray.log")
    alerts = run(make_rule(), events)
    # 6 users, one attempt each: the 5th and 6th users cross the threshold (the engine dedupes)
    assert [a.event_count for a in alerts] == [5, 6]
    first = alerts[0]
    assert (first.rule_id, first.technique_id, first.severity) == (
        "password_spray",
        "T1110.003",
        Severity.MEDIUM,
    )
    assert str(first.src_ip) == "203.0.113.50"
    assert first.first_seen == events[0].ts
    assert (
        first.summary == "5 failed SSH logins for 5 different users from 203.0.113.50 within 300s"
    )
    assert all("Failed password" in line for line in first.evidence)


def test_many_failures_for_one_user_is_not_a_spray(load_events):
    # 6 failures, all for labuser: brute force territory, not spraying
    assert run(make_rule(), load_events("auth_success_after_fail.log")) == []


def test_invalid_user_lines_are_not_counted_as_extra_users(load_events):
    # each user appears on two lines ("Invalid user" + "Failed password"); 6 users, not 12 events
    assert run(make_rule(threshold=7), load_events("auth_spray.log")) == []


def test_slow_spray_outside_window_does_not_fire(load_events):
    # attempts are 20 s apart, so a 60 s window never holds 5 users
    assert run(make_rule(window_seconds=60), load_events("auth_spray.log")) == []


def test_benign_fixture_does_not_fire(load_events):
    assert run(make_rule(), load_events("auth_benign.log")) == []
