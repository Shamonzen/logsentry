"""Judge whether a file-inclusion attack worked, from the Apache error_log written after it.

PHP logs a warning when include() can't open its target, so a matching warning means the
attack failed, and silence over a window the error_log covers means it succeeded.
"""

import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Literal
from urllib.parse import parse_qsl

from logsentry.models import Alert, Event
from logsentry.parsers.apache_error import ErrorLine, parse_line

Outcome = Literal["succeeded", "failed", "unknown"]
# the web_attack categories whose success shows (or not) in the error_log
INCLUSION_CATEGORIES = {"rfi", "path_traversal"}
MAX_EVIDENCE = 25  # Alert.outcome_evidence's cap
_PHP = re.compile(r"\.php\d?$", re.IGNORECASE)
_ACCESS_TZ = re.compile(r"\[[^\]]* (?P<offset>[+-]\d{4})\]")


def read_error_log(path: Path) -> tuple[list[ErrorLine], int]:
    """Return (parsed lines oldest first, number of malformed lines). Blank lines don't count."""
    # shortcut: the whole error_log is held in memory; fine for lab-sized files, stream it
    # alongside the access log if multi-GB logs ever need judging.
    lines, malformed = [], 0
    with path.open(encoding="utf-8", errors="replace") as f:
        for raw in f:
            if (parsed := parse_line(raw)) is not None:
                lines.append(parsed)
            elif raw.strip():
                malformed += 1
    return sorted(lines, key=lambda e: e.ts), malformed


def _local_time(event: Event) -> datetime | None:
    """The request time as naive local time, in the offset its access log line was written in."""
    if not (m := _ACCESS_TZ.search(event.raw)):
        return None
    tz = datetime.strptime(m["offset"], "%z").tzinfo
    return event.ts.astimezone(tz).replace(tzinfo=None)


def _size_note(event: Event, usual_size: int | None, outcome: str) -> str | None:
    if event.http_bytes is None or usual_size is None:
        return None
    note = f"response {event.http_bytes} B vs usual {usual_size} B for {event.url_path}"
    # PHP prints the include warning into the page, so a failed include changes the size;
    # a successful one may too (an LFI prints the file), so only a failure can be contradicted
    if outcome == "failed" and event.http_bytes == usual_size:
        note += " (contradicts the verdict)"
    return note


def judge(
    event: Event, errors: list[ErrorLine] | None, window: timedelta, usual_size: int | None
) -> tuple[Outcome, list[str]]:
    """The outcome of one file-inclusion request, and the evidence for it."""
    outcome: Outcome = "unknown"
    evidence: list[str] = []
    req = _local_time(event)
    if errors is None:
        evidence.append("no error_log given")
    elif not _PHP.search(event.url_path or ""):
        # shortcut: a directory index (/rfi/) may be PHP too; judge it if real logs show that
        evidence.append(f"{event.url_path} isn't a PHP script, so its failures don't reach the log")
    elif req is None:
        evidence.append("access log line has no time zone to line up with the error_log")
    else:
        failures = [
            e
            for e in errors
            if e.client_ip == event.src_ip and req <= e.ts <= req + window and e.failed_include
        ]
        values = [v for _, v in parse_qsl(event.url_query or "", keep_blank_values=True) if v]
        by_url = [e for e in failures if e.target and any(e.target.endswith(v) for v in values)]
        if failures:
            outcome = "failed"
            signal = "URL match" if by_url else "same IP and time only"
            reasons = "; ".join(sorted({e.reason for e in failures if e.reason}))
            evidence.append(f"error_log ({signal}): {reasons or 'include failed'}")
            evidence += [e.raw for e in by_url or failures]
        # a log still being written at request time covers it, even if it stops soon after
        elif errors and errors[0].ts <= req <= errors[-1].ts:
            outcome = "succeeded"
            seconds = int(window.total_seconds())
            evidence.append(f"error_log: no error logged within {seconds} s of the request")
            if (left := errors[-1].ts - req) < window:
                evidence.append(f"error_log ends {left.seconds} s after the request")
        else:
            evidence.append("error_log doesn't cover the time of the request")
    if note := _size_note(event, usual_size, outcome):
        evidence.append(note)
    return outcome, evidence


def verdict(
    alert: Alert,
    events: list[Event],
    errors: list[ErrorLine] | None,
    window: timedelta,
    usual_sizes: dict[str | None, int],
) -> Alert:
    """Return `alert` with the error_log outcome of its file-inclusion requests, `events`.

    The alert succeeded if any of them did, failed only if all failed; with no events it
    comes back unchanged. `errors` is None when no error_log was given. The response size is
    supporting evidence only. Severity is the rule's job (WebAttack.alert_for, which takes
    the same per-request verdicts from `judge`).
    """
    if not events:
        return alert
    judged = [
        (event, *judge(event, errors, window, usual_sizes.get(event.url_path))) for event in events
    ]
    outcomes = {o for _, o, _ in judged}
    outcome: Outcome = (
        "succeeded"
        if "succeeded" in outcomes
        else "failed"
        if outcomes == {"failed"}
        else "unknown"
    )
    evidence = []
    for event, o, lines in judged:
        when = _local_time(event) or event.ts
        target = event.url_path + (f"?{event.url_query}" if event.url_query else "")
        evidence += [f"{when:%H:%M:%S} {target}: {o}", *(f"  {line}" for line in lines)]
    if len(evidence) > MAX_EVIDENCE:
        cut = len(evidence) - MAX_EVIDENCE + 1
        evidence = [*evidence[: MAX_EVIDENCE - 1], f"... {cut} more line(s) not shown"]
    return alert.model_copy(
        update={
            "outcome": outcome,
            "outcome_evidence": evidence,
        }
    )
