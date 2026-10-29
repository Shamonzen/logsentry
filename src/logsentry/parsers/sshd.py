"""Parse OpenSSH auth log lines into Events."""

import re
from datetime import UTC, datetime

from logsentry.models import MAX_LINE, Event, EventType

# Timestamp is RFC 3339 (rsyslog in the lab) or classic BSD syslog ("Oct  2 10:00:00").
# OpenSSH >= 9.8 logs auth results from "sshd-session" instead of "sshd".
_HEADER = re.compile(
    r"^(?:(?P<iso>\d{4}-\d{2}-\d{2}T\S+)|(?P<bsd>[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}))"
    r" (?P<host>\S+) sshd(?:-session)?\[\d+\]: (?P<msg>.*)$"
)
# The user name is attacker-chosen and may itself contain " from x port y"; the greedy (.*)
# makes the last match win, which is the one sshd appended.
_AUTH = re.compile(
    r"^(?P<result>Failed|Accepted) \S+ for (?:invalid user )?(?P<user>.*) from (?P<ip>\S+) port \d+"
)
_INVALID_USER = re.compile(r"^Invalid user (?P<user>.*) from (?P<ip>\S+) port \d+")


def parse_line(line: str, *, year: int | None = None) -> Event | None:
    """Return an Event for an sshd auth line, or None for unrelated, malformed or overlong lines.

    BSD syslog timestamps have no year or timezone: they are read as UTC in `year`
    (default: the current UTC year).
    """
    line = line.rstrip("\r\n")
    if len(line) > MAX_LINE or not (head := _HEADER.match(line)):
        return None
    if m := _AUTH.match(head["msg"]):
        is_success = m["result"] == "Accepted"
        event_type = EventType.AUTH_SUCCESS if is_success else EventType.AUTH_FAILURE
    elif m := _INVALID_USER.match(head["msg"]):
        event_type = EventType.INVALID_USER
    else:
        return None
    try:
        return Event(
            ts=_parse_ts(head["iso"], head["bsd"], year),
            source="sshd",
            event_type=event_type,
            src_ip=m["ip"],
            host=head["host"],
            user_name=m["user"],
            raw=line,
        )
    except ValueError:  # bad date, naive timestamp or bad IP (pydantic errors are ValueErrors)
        return None


def _parse_ts(iso: str | None, bsd: str | None, year: int | None) -> datetime:
    if iso:
        return datetime.fromisoformat(iso)
    # shortcut: BSD syslog has no year, so a December log replayed in January gets the wrong
    # year; pass `year` or use RFC 3339 timestamps (the lab does).
    year = year or datetime.now(UTC).year
    return datetime.strptime(f"{year} {bsd}", "%Y %b %d %H:%M:%S").replace(tzinfo=UTC)
