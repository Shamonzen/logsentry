from datetime import UTC, datetime, timedelta

from logsentry import store
from logsentry.campaigns import group, rebuild, subnet
from logsentry.models import Alert, Severity

GAP = timedelta(minutes=30)
T0 = datetime(2026, 10, 22, 14, 0, tzinfo=UTC)


def alert(id_, ip, start, minutes=5, categories=("Path traversal / LFI",)):
    """A stored-alert dict as campaigns.group sees it; times in minutes after T0."""
    return {
        "id": id_,
        "src_ip": ip,
        "rule_name": "Web attack",
        "first_seen": T0 + timedelta(minutes=start),
        "last_seen": T0 + timedelta(minutes=start + minutes),
        "categories": list(categories),
    }


def test_overlapping_ips_in_one_slash24_are_one_campaign():
    (c,) = group(
        [
            alert(1, "24.122.48.210", 0, 20),
            alert(2, "24.122.48.218", 10, categories=["Command injection"]),
            alert(3, "24.122.48.219", 40),  # 15 min after .210 stopped
            alert(4, "24.122.48.219", 50),  # same IP again: counted once
        ],
        GAP,
    )
    assert c.subnet == "24.122.48.0/24"
    assert (c.ip_count, c.alert_ids) == (3, [1, 2, 3, 4])
    assert c.categories == ["Path traversal / LFI", "Command injection"]
    assert (c.first_seen, c.last_seen) == (T0, T0 + timedelta(minutes=55))


def test_a_quiet_gap_longer_than_the_window_splits_campaigns():
    alerts = [alert(1, "203.0.113.1", 0), alert(2, "203.0.113.2", 36)]  # 31 min quiet
    assert group(alerts, GAP) == []
    assert len(group(alerts, timedelta(minutes=31))) == 1  # the window is configurable


def test_a_lone_ip_is_not_a_campaign():
    assert group([alert(1, "203.0.113.1", 0), alert(2, "203.0.113.1", 10)], GAP) == []


def test_different_slash24s_are_not_a_campaign():
    assert group([alert(1, "203.0.113.1", 0), alert(2, "203.0.114.1", 0)], GAP) == []


def test_ipv6_uses_a_slash64():
    assert str(subnet("2001:db8:0:1::5")) == "2001:db8:0:1::/64"
    alerts = [alert(1, "2001:db8:0:1::5", 0), alert(2, "2001:db8:0:1::9", 1)]
    assert group(alerts, GAP)[0].subnet == "2001:db8:0:1::/64"


def test_other_rules_contribute_their_rule_name():
    ssh = {**alert(2, "203.0.113.2", 1), "rule_name": "SSH brute force", "categories": []}
    (c,) = group([alert(1, "203.0.113.1", 0), ssh], GAP)
    assert c.categories == ["Path traversal / LFI", "SSH brute force"]


def stored(ip, start):
    ts = T0 + timedelta(minutes=start)
    return Alert(
        rule_id="web_attack",
        rule_name="Web attack",
        technique_id="T1190",
        tactic="Initial Access",
        severity=Severity.HIGH,
        src_ip=ip,
        first_seen=ts,
        last_seen=ts,
        event_count=1,
        summary="x",
        evidence=["line"],
        categories=["XSS"],
    )


def test_rebuild_links_alerts_and_replaces_old_campaigns(tmp_path):
    conn = store.connect(tmp_path / "t.db")
    ids = [store.insert_alert(conn, stored(ip, 0)) for ip in ("203.0.113.1", "203.0.113.2")]
    lone = store.insert_alert(conn, stored("198.51.100.1", 0))
    (c,) = rebuild(conn, GAP)
    rows = {a["id"]: a["campaign_id"] for a in store.list_alerts(conn)}
    (campaign_id,) = {rows[i] for i in ids}
    assert rows[lone] is None
    saved = store.get_campaign(conn, campaign_id)
    assert (saved["subnet"], saved["ip_count"], saved["alert_count"], saved["categories"]) == (
        "203.0.113.0/24",
        2,
        2,
        ["XSS"],
    )
    rebuild(conn, GAP)  # rebuilding again doesn't pile up campaigns
    assert conn.execute("SELECT count(*) FROM campaigns").fetchone()[0] == 1
