from datetime import UTC, datetime, timedelta

from logsentry.models import Event
from logsentry.rules.base import SlidingWindow

T0 = datetime(2026, 10, 22, 14, 0, tzinfo=UTC)


def event(seconds: float, ip: str = "203.0.113.7") -> Event:
    return Event(
        ts=T0 + timedelta(seconds=seconds),
        source="sshd",
        event_type="auth_failure",
        src_ip=ip,
        host="target",
        raw=f"line at {seconds}",
    )


def test_window_drops_events_older_than_span():
    window = SlidingWindow(seconds=60)
    for s in (0, 30, 60):
        window.add("k", event(s))
    # 61 s after the first event: it falls out, the one at exactly 60 s before stays
    assert [e.raw for e in window.add("k", event(61))] == ["line at 30", "line at 60", "line at 61"]


def test_window_uses_event_time_not_arrival_order():
    window = SlidingWindow(seconds=60)
    window.add("k", event(0))
    # replaying an old file hours later gives the same result as live
    assert len(window.add("k", event(3600))) == 1


def test_window_keys_are_independent():
    window = SlidingWindow(seconds=60)
    window.add("a", event(0))
    assert len(window.add("b", event(1))) == 1


def test_window_caps_number_of_keys():
    window = SlidingWindow(seconds=60, max_keys=3)
    for i in range(10):
        window.add(f"ip{i}", event(i))
    assert len(window) == 3
    assert len(window.add("ip9", event(10))) == 2  # newest key kept its history
