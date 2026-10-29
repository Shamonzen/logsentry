from collections import Counter
from datetime import UTC, datetime
from ipaddress import IPv6Address
from pathlib import Path

import pytest

from logsentry.models import MAX_LINE, EventType
from logsentry.parsers.sshd import parse_line

FIXTURES = Path(__file__).parent / "fixtures"
ISO = "2026-10-22T14:03:00+00:00 target sshd-session[42]: "


def parse_fixture(name: str) -> list:
    lines = (FIXTURES / name).read_text().splitlines()
    return [e for line in lines if (e := parse_line(line, year=2026))]


@pytest.mark.parametrize(
    ("msg", "event_type", "user"),
    [
        ("Failed password for root from 203.0.113.7 port 22 ssh2", "auth_failure", "root"),
        (
            "Failed password for invalid user admin from 203.0.113.7 port 22 ssh2",
            "auth_failure",
            "admin",
        ),
        (
            "Failed publickey for bob from 203.0.113.7 port 22 ssh2: RSA SHA256:abc",
            "auth_failure",
            "bob",
        ),
        ("Accepted password for bob from 203.0.113.7 port 22 ssh2", "auth_success", "bob"),
        (
            "Accepted publickey for bob from 203.0.113.7 port 22 ssh2: ED25519 SHA256:x",
            "auth_success",
            "bob",
        ),
        ("Invalid user oracle from 203.0.113.7 port 22", "invalid_user", "oracle"),
        ("Invalid user  from 203.0.113.7 port 22", "invalid_user", ""),
    ],
)
def test_auth_messages(msg, event_type, user):
    event = parse_line(ISO + msg)
    assert event is not None
    assert (event.event_type, event.user_name, str(event.src_ip)) == (
        event_type,
        user,
        "203.0.113.7",
    )
    assert (event.source, event.host, event.raw) == ("sshd", "target", ISO + msg)


def test_rfc3339_timestamp_is_converted_to_utc():
    line = "2026-10-22T16:03:00.5+02:00 target sshd[1]: Invalid user x from 203.0.113.7 port 22"
    assert parse_line(line).ts == datetime(2026, 10, 22, 14, 3, 0, 500000, tzinfo=UTC)


def test_bsd_timestamp_uses_given_year_and_utc():
    line = (
        "Oct  2 09:14:40 web01 sshd[1290]: Failed password for bob from 198.51.100.31 port 1 ssh2"
    )
    event = parse_line(line, year=2025)
    assert event.ts == datetime(2025, 10, 2, 9, 14, 40, tzinfo=UTC)
    assert event.host == "web01"


def test_ipv6_source():
    event = parse_line(ISO + "Failed password for root from 2001:db8::bad:1 port 22 ssh2")
    assert event.src_ip == IPv6Address("2001:db8::bad:1")


def test_username_cannot_spoof_source_ip():
    msg = "Failed password for invalid user x from 192.0.2.66 port 1 from 203.0.113.7 port 22 ssh2"
    event = parse_line(ISO + msg)
    assert str(event.src_ip) == "203.0.113.7"
    assert event.user_name == "x from 192.0.2.66 port 1"


def test_username_control_chars_stripped_and_capped():
    user = "\x1b[31mevil\rFAKE" + "a" * 100
    event = parse_line(ISO + f"Invalid user {user} from 203.0.113.7 port 22")
    assert event.user_name.startswith("[31mevilFAKE")
    assert len(event.user_name) == 64


@pytest.mark.parametrize(
    "line",
    [
        "",
        "garbage",
        ISO + "Connection closed by authenticating user root 203.0.113.7 port 22 [preauth]",
        ISO + "Failed password for root from 999.1.1.1 port 22 ssh2",
        ISO + "Failed password for root from not-an-ip port 22 ssh2",
        "2026-10-22T14:03:00 target sshd[1]: Invalid user x from 203.0.113.7 port 22",  # no tz
        "Feb 30 10:00:00 web01 sshd[1]: Invalid user x from 203.0.113.7 port 22",
        "Oct 22 10:00:00 web01 CRON[1]: Invalid user x from 203.0.113.7 port 22",
        ISO + "Invalid user " + "a" * MAX_LINE + " from 203.0.113.7 port 22",
    ],
)
def test_junk_lines_are_ignored(line):
    assert parse_line(line, year=2026) is None


def test_bruteforce_fixture():
    events = parse_fixture("auth_bruteforce.log")
    counts = Counter(e.event_type for e in events)
    assert counts == {EventType.AUTH_FAILURE: 12, EventType.INVALID_USER: 6}
    assert {str(e.src_ip) for e in events} == {"203.0.113.7"}
    assert (events[-1].ts - events[0].ts).total_seconds() < 60


def test_benign_fixture():
    events = parse_fixture("auth_benign.log")
    assert [(e.event_type, e.user_name) for e in events] == [
        (EventType.AUTH_SUCCESS, "alice"),
        (EventType.AUTH_FAILURE, "bob"),
        (EventType.AUTH_SUCCESS, "bob"),
        (EventType.AUTH_SUCCESS, "deploy"),
    ]
