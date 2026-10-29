from logsentry.models import Severity
from logsentry.rules.web_scan import WebScan


def make_rule(threshold=20, window_seconds=60):
    return WebScan(WebScan.Config(threshold=threshold, window_seconds=window_seconds))


def run(rule, events):
    return [a for e in events for a in rule.process(e)]


def from_ip(alerts, ip):
    return [a for a in alerts if str(a.src_ip) == ip]


def test_fires_on_404_burst(load_events):
    alerts = from_ip(run(make_rule(), load_events("nginx_scan.log")), "203.0.113.12")
    # 22 404s: the 20th, 21st and 22nd each cross the threshold (the engine dedupes)
    assert [a.event_count for a in alerts] == [20, 21, 22]
    first = alerts[0]
    assert (first.rule_id, first.technique_id, first.severity) == (
        "web_scan",
        "T1595.003",
        Severity.LOW,
    )
    assert first.summary == "Web scanning from 203.0.113.12: 20 404 responses within 60s"
    assert all('" 404 ' in line for line in first.evidence)  # the 200 for robots.txt isn't counted


def test_scanner_user_agent_alone_is_not_a_scan(load_events):
    # Nikto's 2 404s are under the threshold; its User-Agent is a web_attack category now
    assert from_ip(run(make_rule(), load_events("nginx_scan.log")), "203.0.113.13") == []


def test_fewer_404s_than_threshold_do_not_fire(load_events):
    alerts = run(make_rule(threshold=23), load_events("nginx_scan.log"))
    assert from_ip(alerts, "203.0.113.12") == []


def test_slow_scan_outside_window_does_not_fire(load_events):
    # 404s are 2 s apart, so a 30 s window never holds 20 of them
    alerts = run(make_rule(window_seconds=30), load_events("nginx_scan.log"))
    assert from_ip(alerts, "203.0.113.12") == []


def test_benign_fixture_does_not_fire(load_events):
    # a browser's favicon 404, a health check and a UA-less HEAD must not look like a scan
    assert run(make_rule(), load_events("nginx_benign.log")) == []
