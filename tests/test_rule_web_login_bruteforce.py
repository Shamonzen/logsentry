from datetime import timedelta

from logsentry.models import Severity
from logsentry.parsers import nginx
from logsentry.rules.web_login_bruteforce import WebLoginBruteforce

LOGIN = (
    '203.0.113.50 - - [22/Oct/2026:14:10:00 +0000] "POST /wp-login.php HTTP/1.1" 200 4890 "-" "-"'
)


def make_rule(threshold=5, window_seconds=60):
    config = WebLoginBruteforce.Config(
        threshold=threshold,
        window_seconds=window_seconds,
        login_paths=[r"wp-login\.php$", r"/login$"],
    )
    return WebLoginBruteforce(config)


def burst(n, seconds_apart=2, raw=LOGIN):
    first = nginx.parse_line(raw)
    return [
        first.model_copy(update={"ts": first.ts + timedelta(seconds=i * seconds_apart)})
        for i in range(n)
    ]


def run(rule, events):
    return [a for e in events for a in rule.process(e)]


def test_fires_on_a_burst_of_login_posts():
    alerts = run(make_rule(), burst(5))
    (alert,) = alerts
    assert (alert.rule_id, alert.technique_id, alert.severity, alert.event_count) == (
        "web_login_bruteforce",
        "T1110",
        Severity.MEDIUM,  # a 200 isn't a successful login on a form
        5,
    )
    assert alert.summary == "5 POSTs to login pages from 203.0.113.50 within 60s"


def test_login_page_match_ignores_case():
    assert run(make_rule(), burst(5, raw=LOGIN.replace("/wp-login.php", "/WP-Login.PHP")))


def test_get_requests_do_not_count():
    assert run(make_rule(), burst(10, raw=LOGIN.replace("POST", "GET"))) == []


def test_other_pages_do_not_count():
    assert run(make_rule(), burst(10, raw=LOGIN.replace("/wp-login.php", "/comments"))) == []


def test_slow_attempts_outside_the_window_do_not_fire():
    assert run(make_rule(), burst(10, seconds_apart=20)) == []
