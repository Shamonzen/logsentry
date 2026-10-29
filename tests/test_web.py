import re
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from logsentry import store
from logsentry.campaigns import rebuild
from logsentry.models import Alert, CategoryResult, Match, Severity, Technique
from logsentry.web.app import create_app

XSS = "<script>alert(1)</script>"


def make_alert(severity: Severity, summary: str = "10 failures", evidence: str = "line") -> Alert:
    ts = datetime(2026, 10, 22, 14, 0, tzinfo=UTC)
    return Alert(
        rule_id="ssh_bruteforce",
        rule_name="SSH brute force",
        technique_id="T1110.001",
        tactic="Credential Access",
        severity=severity,
        src_ip="203.0.113.9",
        first_seen=ts,
        last_seen=ts,
        event_count=10,
        summary=summary,
        evidence=[evidence],
    )


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "t.db"
    conn = store.connect(path)
    store.insert_alert(conn, make_alert(Severity.MEDIUM))
    store.insert_alert(conn, make_alert(Severity.HIGH, summary=XSS, evidence=XSS))
    conn.close()
    return path


@pytest.fixture
def client(db):
    return TestClient(create_app(db))


def test_list_shows_alerts_with_security_headers(client):
    r = client.get("/")
    assert r.status_code == 200
    assert r.text.count('class="rowlink"') == 2
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["x-content-type-options"] == "nosniff"


def test_severity_filter(client):
    assert len(client.get("/api/alerts?severity=high").json()) == 1
    assert len(client.get("/api/alerts").json()) == 2
    assert client.get("/rows?severity=low").text.count("No alerts match") == 1
    assert client.get("/api/alerts?severity=bogus").status_code == 422


def test_api_returns_decoded_evidence(client):
    alerts = client.get("/api/alerts").json()
    assert alerts[0]["evidence"] == [XSS]  # newest first
    assert alerts[0]["technique_id"] == "T1110.001"


def test_detail_page_and_missing_alert(client):
    assert "Raw log lines" in client.get("/alerts/1").text
    assert client.get("/alerts/999").status_code == 404


def test_xss_payload_is_escaped(client):
    r = client.get("/alerts/2")
    assert XSS not in r.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in r.text


def test_web_cannot_write(db):
    conn = store.connect_readonly(db)
    with pytest.raises(Exception, match="readonly"):
        conn.execute("DELETE FROM alerts")


def test_missing_database_is_503(tmp_path):
    assert TestClient(create_app(tmp_path / "none.db")).get("/").status_code == 503


def test_detail_page_shows_matches_escaped(db):
    conn = store.connect(db)
    match = Match(
        ts=datetime(2026, 10, 22, 14, 0, tzinfo=UTC),
        http_status=200,
        category="xss",
        pattern="script_tag",
        matched=XSS,
    )
    alert_id = store.insert_alert(
        conn, make_alert(Severity.HIGH).model_copy(update={"matches": [match]})
    )
    conn.close()
    text = TestClient(create_app(db)).get(f"/alerts/{alert_id}").text
    assert "Matched requests" in text and 'title="pattern script_tag"' in text
    # stored before matches kept the request: only the matched text is shown
    assert "<mark>&lt;script&gt;alert(1)&lt;/script&gt;</mark>" in text
    assert XSS not in text
    assert "Matched" not in TestClient(create_app(db)).get("/alerts/1").text


def test_detail_page_shows_outcome_evidence_escaped(db):
    conn = store.connect(db)
    alert = make_alert(Severity.LOW).model_copy(
        update={"outcome": "failed", "outcome_evidence": [f"include({XSS}) failed"]}
    )
    alert_id = store.insert_alert(conn, alert)
    conn.close()
    text = TestClient(create_app(db)).get(f"/alerts/{alert_id}").text
    assert "Outcome evidence" in text
    assert "include(&lt;script&gt;" in text
    assert "Outcome evidence" not in TestClient(create_app(db)).get("/alerts/1").text


def test_list_and_detail_show_categories_and_campaign(tmp_path):
    db = tmp_path / "c.db"
    conn = store.connect(db)
    for ip in ("203.0.113.1", "203.0.113.2"):
        alert = make_alert(Severity.HIGH).model_copy(
            update={"src_ip": ip, "rule_id": "web_attack", "categories": ["XSS", XSS]}
        )
        store.insert_alert(conn, alert)
    rebuild(conn, timedelta(minutes=30))
    conn.close()
    client = TestClient(create_app(db))
    page = client.get("/").text
    assert '<span class="tag">&lt;script&gt;alert(1)&lt;/script&gt;</span>' in page
    assert XSS not in page
    assert page.count("#1 · 2 IPs") == 2
    detail = client.get("/alerts/1").text
    assert '<a href="/campaigns?open=1#c1">#1</a> · 203.0.113.0/24 · 2 IPs' in detail


def web_alert(ip, severity, statuses, categories=("XSS",), **update):
    """A stored web alert whose requests got `statuses`; times in minutes after 14:00."""
    ts = datetime(2024, 7, 28, 14, 0, tzinfo=UTC)
    matches = [
        Match(
            ts=ts + timedelta(minutes=i),
            http_status=s,
            category="xss",
            pattern="script_tag",
            matched="<script",
            name="XSS",
            request=f"/search?q=<script>alert({i})</script>",
            user_agent="Mozilla/5.0 <b>",
        )
        for i, s in enumerate(statuses)
    ]
    ok = [200 <= s < 300 for s in statuses]
    result = "succeeded" if all(ok) else "blocked" if not any(ok) else "mixed"
    return Alert(
        rule_id="web_attack",
        rule_name="Web attack",
        technique_id="T1190, T1595.003",
        tactic="Initial Access",
        severity=severity,
        src_ip=ip,
        first_seen=ts,
        last_seen=ts + timedelta(minutes=len(statuses) - 1),
        event_count=len(statuses),
        summary="x",
        evidence=["line"],
        categories=list(categories),
        matches=matches,
        result=result,
        confidence=None if result == "blocked" else "likely",
        results=[
            CategoryResult(
                name=c,
                result=result,
                confidence=None if result == "blocked" else "likely",
                severity=severity,
            )
            for c in categories
        ],
    ).model_copy(update=update)


@pytest.fixture
def web_db(tmp_path):
    path = tmp_path / "w.db"
    conn = store.connect(path)
    store.insert_alert(conn, web_alert("203.0.113.1", Severity.HIGH, [200, 404]))
    store.insert_alert(
        conn,
        web_alert("203.0.113.2", Severity.CRITICAL, [404], categories=["Command injection"]),
    )
    store.insert_alert(conn, web_alert("198.51.100.7", Severity.HIGH, [200, 200, 200]))
    # an RFI answered 302 that the error_log proved worked
    store.insert_alert(
        conn,
        web_alert(
            "198.51.100.8",
            Severity.HIGH,
            [302],
            categories=["Remote file inclusion"],
            outcome="succeeded",
            result="succeeded",
            confidence="confirmed",
        ),
    )
    # an internal attacker
    store.insert_alert(conn, web_alert("10.0.0.50", Severity.LOW, [404], internal=True))
    store.insert_alert(conn, make_alert(Severity.MEDIUM))  # an SSH alert, no categories
    rebuild(conn, timedelta(minutes=30))
    conn.close()
    return TestClient(create_app(path))


def ips(response):
    return [a["src_ip"] for a in response.json()]


def test_sorted_by_severity_then_most_recent(web_db):
    assert ips(web_db.get("/api/alerts")) == [
        "203.0.113.2",  # critical
        "198.51.100.7",  # high, last seen 14:02
        "203.0.113.1",  # high, 14:01
        "198.51.100.8",  # high, 14:00
        "203.0.113.9",  # medium (SSH)
        "10.0.0.50",  # low
    ]


def test_filters(web_db):
    assert ips(web_db.get("/api/alerts?type=Command injection")) == ["203.0.113.2"]
    assert ips(web_db.get("/api/alerts?type=SSH brute force")) == ["203.0.113.9"]
    assert ips(web_db.get("/api/alerts?outcome=mixed")) == ["203.0.113.1"]
    assert ips(web_db.get("/api/alerts?outcome=blocked")) == ["203.0.113.2", "10.0.0.50"]
    # the error_log verdict wins over the 302
    assert set(ips(web_db.get("/api/alerts?outcome=succeeded"))) == {
        "198.51.100.7",
        "198.51.100.8",
    }
    assert set(ips(web_db.get("/api/alerts?campaign=1"))) == {"203.0.113.1", "203.0.113.2"}
    assert ips(web_db.get("/api/alerts?campaign=1&severity=critical&type=Command injection")) == [
        "203.0.113.2"
    ]
    assert ips(web_db.get("/api/alerts?ip=198.51.100.8")) == ["198.51.100.8"]
    assert ips(web_db.get("/api/alerts?type=<nope>")) == []


@pytest.mark.parametrize(
    "query", ["outcome=won", "campaign=1;drop", "ip=not-an-ip", "severity=urgent"]
)
def test_bad_filter_values_are_rejected(web_db, query):
    assert web_db.get(f"/api/alerts?{query}").status_code == 422
    assert web_db.get(f"/rows?{query}").status_code == 422


def test_summary_strip(web_db):
    page = web_db.get("/").text
    assert "Data:</strong> 2024-07-28 14:00–2026-10-22 14:00 UTC" in page
    assert ">1 critical</a>" in page and ">3 high</a>" in page and ">1 medium</a>" in page
    # 203.0.113.0/24 and 198.51.100.0/24 each have 2 IPs within 30 min
    assert '<p class="big"><a href="/campaigns">2</a></p>' in page
    assert "203.0.113.0/24" in page and "198.51.100.0/24" in page
    assert 'href="/?type=Remote%20file%20inclusion"' in page


def test_table_has_tags_attack_links_and_short_times(web_db):
    rows = web_db.get("/rows").text
    assert ">Command injection <small>blocked</small></span>" in rows
    assert 'href="https://attack.mitre.org/techniques/T1595/003/"' in rows
    assert "2024-07-28 14:02:00 UTC" in rows and "+00:00" not in rows
    assert '<span class="pill out-mixed">mixed</span>' in rows
    assert "#1 · 2 IPs" in rows


def test_detail_highlights_the_match_and_escapes_everything(web_db):
    page = web_db.get("/alerts/1").text
    assert "/search?q=<mark>&lt;script</mark>&gt;alert(0)&lt;/script&gt;" in page
    assert "Mozilla/5.0 &lt;b&gt;" in page
    assert "<script>alert" not in page and "<b>" not in page
    assert page.count('<circle cx="') == 2  # one timeline dot per request
    assert 'class="dot dot-ok"' in page and 'class="dot dot-error"' in page
    assert '<span class="pill out-mixed">mixed</span> <small class="muted">likely</small>' in page
    assert "XSS <small>mixed</small>" in page  # per attack type
    detail = web_db.get("/alerts/4").text
    assert (
        '<span class="pill out-succeeded">succeeded</span> <small class="muted">confirmed</small>'
        in detail
    )


def test_campaigns_page_expands_to_its_ips(web_db):
    page = web_db.get("/campaigns").text
    assert page.count('<details class="campaign"') == 2  # 203.0.113.0/24, 198.51.100.0/24
    assert "203.0.113.0/24" in page and "2 IPs" in page
    assert (
        '<td class="mono">203.0.113.1</td>' in page and '<td class="mono">203.0.113.2</td>' in page
    )
    assert " open>" not in page
    assert " open>" in web_db.get("/campaigns?open=1").text


def test_pages_need_no_inline_script_or_style(web_db):
    assert web_db.get("/static/theme.js").status_code == 200
    for url in ("/", "/alerts/1", "/campaigns"):
        r = web_db.get(url)
        assert "default-src 'self'" in r.headers["content-security-policy"]
        assert "style=" not in r.text and "<style" not in r.text
        assert all(
            tag.startswith('<script src="/static/')
            for tag in r.text.split("<script")[1:]
            for tag in ["<script" + tag]
        )


def test_internal_sources_have_a_badge_and_a_filter(web_db):
    rows = web_db.get("/rows").text
    assert rows.count('class="badge-internal"') == 1
    assert ips(web_db.get("/api/alerts?source=internal")) == ["10.0.0.50"]
    assert "10.0.0.50" not in ips(web_db.get("/api/alerts?source=external"))
    assert web_db.get("/api/alerts?source=inside").status_code == 422


def test_no_campaign_is_explained_on_the_alert_page(web_db):
    lone = web_db.get("/alerts/5").text  # 10.0.0.50, alone in its /24
    assert "none: no other IP from 10.0.0.0/24 had alerts within the campaign window" in lone


def test_campaigns_page_shows_the_time_span(web_db):
    page = web_db.get("/campaigns").text
    assert "2024-07-28 14:00:00 UTC → 2024-07-28 14:01:00 UTC</span> (1 min)" in page


def test_pages_link_versioned_assets(web_db):
    # a changed stylesheet gets a new URL, so browsers can't keep showing an old cached copy
    page = web_db.get("/").text
    assert re.search(r'href="/static/style\.css\?v=[0-9a-f]{10}"', page)
    assert re.search(r'src="/static/theme\.js\?v=[0-9a-f]{10}"', page)
    assert web_db.get(re.search(r"/static/style\.css\?v=\w+", page).group()).status_code == 200


def test_attack_column_shows_the_chain_and_cwe_links(tmp_path):
    db = tmp_path / "chain.db"
    conn = store.connect(db)
    alert = web_alert(
        "203.0.113.5", Severity.CRITICAL, [200], categories=["Remote file inclusion"]
    ).model_copy(
        update={
            "results": [
                CategoryResult(
                    name="Remote file inclusion",
                    result="succeeded",
                    confidence="confirmed",
                    severity=Severity.CRITICAL,
                    cwe="CWE-98",
                    follow_on=["T1105"],
                )
            ],
            "tactic": "Initial Access, Command and Control",
            "techniques": [
                Technique(
                    id="T1190", name="Exploit Public-Facing Application", tactic="Initial Access"
                ),
                Technique(
                    id="T1105",
                    name="Ingress Tool Transfer",
                    tactic="Command and Control",
                    follow_on=True,
                ),
            ],
        }
    )
    store.insert_alert(conn, alert)
    store.insert_alert(conn, make_alert(Severity.LOW))  # SSH: no chain, plain link
    conn.close()
    client = TestClient(create_app(db))
    rows = client.get("/rows").text
    assert re.search(
        r'title="T1190 Exploit Public-Facing Application \(Initial Access\)">T1190</a>'
        r' <span class="arrow" aria-label="led to">→</span> '
        r'<a [^>]*href="https://attack.mitre.org/techniques/T1105/"[^>]*'
        r'title="T1105 Ingress Tool Transfer \(Command and Control\)">T1105</a>',
        rows,
    )
    assert 'href="https://cwe.mitre.org/data/definitions/98.html"' in rows and ">CWE-98</a>" in rows
    assert 'href="https://attack.mitre.org/techniques/T1110/001/"' in rows  # the SSH alert
    detail = client.get("/alerts/1").text
    assert "Ingress Tool Transfer</span>" in detail  # the "Led to" column
    assert "Initial Access → Command and Control" in detail
