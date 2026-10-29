import json
import sqlite3
from datetime import UTC, datetime

from logsentry import store
from logsentry.models import Alert, Match, Severity


def make_alert(summary: str) -> Alert:
    ts = datetime(2026, 10, 22, 14, 0, tzinfo=UTC)
    return Alert(
        rule_id="web_attack",
        rule_name="Web attack",
        technique_id="T1190",
        tactic="Initial Access",
        severity=Severity.HIGH,
        src_ip="203.0.113.9",
        first_seen=ts,
        last_seen=ts,
        event_count=1,
        summary=summary,
        evidence=["GET /?q=1' OR '1'='1 HTTP/1.1"],
    )


def test_insert_round_trips_attacker_text_literally(tmp_path):
    conn = store.connect(tmp_path / "t.db")
    payload = "x'); DROP TABLE alerts; --"
    alert_id = store.insert_alert(conn, make_alert(payload))
    row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    assert row["summary"] == payload
    assert row["severity"] == "high"
    assert row["src_ip"] == "203.0.113.9"
    assert json.loads(row["evidence"]) == ["GET /?q=1' OR '1'='1 HTTP/1.1"]
    assert row["created_at"]


def test_connect_is_idempotent_and_uses_wal(tmp_path):
    path = tmp_path / "t.db"
    store.insert_alert(store.connect(path), make_alert("one"))
    conn = store.connect(path)
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert conn.execute("SELECT count(*) FROM alerts").fetchone()[0] == 1


def test_connect_adds_new_columns_to_an_old_database(tmp_path):
    path = tmp_path / "old.db"
    old = sqlite3.connect(path)
    old.executescript(store._SCHEMA)  # the schema before outcomes and matches existed
    old.close()
    conn = store.connect(path)
    match = Match(
        ts=datetime(2026, 10, 22, 14, 0, tzinfo=UTC),
        http_status=302,
        category="rfi",
        pattern="remote_script_param",
        matched="=http://198.51.100.5/x.php",
    )
    alert = make_alert("rfi").model_copy(
        update={"outcome": "failed", "outcome_evidence": ["error_log: 404"], "matches": [match]}
    )
    alert_id = store.insert_alert(conn, alert)
    stored = store.get_alert(conn, alert_id)
    assert (stored["outcome"], stored["outcome_evidence"]) == ("failed", ["error_log: 404"])
    assert Match.model_validate(stored["matches"][0]) == match
    plain = store.get_alert(conn, store.insert_alert(conn, make_alert("x")))
    assert (plain["outcome"], plain["matches"]) == (None, [])


def test_upsert_updates_an_alert_with_the_same_rule_ip_and_start(tmp_path):
    conn = store.connect(tmp_path / "t.db")
    first = make_alert("1 request").model_copy(update={"severity": Severity.MEDIUM})
    alert_id, before = store.upsert_alert(conn, first)
    assert before is None
    grown = first.model_copy(
        update={"summary": "3 requests", "event_count": 3, "severity": Severity.HIGH}
    )
    assert store.upsert_alert(conn, grown) == (alert_id, Severity.MEDIUM)
    (row,) = conn.execute("SELECT * FROM alerts").fetchall()
    assert (row["summary"], row["event_count"], row["severity"]) == ("3 requests", 3, "high")
    later = first.model_copy(update={"first_seen": first.first_seen.replace(hour=15)})
    assert store.upsert_alert(conn, later)[1] is None  # another start: a new alert
