"""SQLite storage for alerts. All SQL lives here, and every value goes in as a parameter."""

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from logsentry.models import Alert, Severity

_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    technique_id TEXT NOT NULL,
    tactic TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    src_ip TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    event_count INTEGER NOT NULL,
    summary TEXT NOT NULL,
    evidence TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS alerts_created_at ON alerts (created_at);
CREATE INDEX IF NOT EXISTS alerts_severity ON alerts (severity);
CREATE TABLE IF NOT EXISTS campaigns (
    id INTEGER PRIMARY KEY,
    subnet TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    ip_count INTEGER NOT NULL,
    alert_count INTEGER NOT NULL,
    categories TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ingest_offsets (
    path TEXT PRIMARY KEY,
    inode INTEGER NOT NULL,
    offset INTEGER NOT NULL
);
"""
_BY_RANK = ["critical", "high", "medium", "low"]  # the severity order the queries rank by
# columns added after the first release: connect() adds them to databases created before
_ADDED_COLUMNS = {
    "outcome": "TEXT CHECK (outcome IN ('succeeded', 'failed', 'unknown'))",
    "outcome_evidence": "TEXT NOT NULL DEFAULT '[]'",
    "matches": "TEXT NOT NULL DEFAULT '[]'",
    "categories": "TEXT NOT NULL DEFAULT '[]'",
    "campaign_id": "INTEGER",
    "result": "TEXT CHECK (result IN ('succeeded', 'mixed', 'blocked'))",
    "confidence": "TEXT CHECK (confidence IN ('confirmed', 'likely'))",
    "results": "TEXT NOT NULL DEFAULT '[]'",
    "internal": "INTEGER NOT NULL DEFAULT 0",
    "techniques": "TEXT NOT NULL DEFAULT '[]'",
}


def connect(path: Path | str) -> sqlite3.Connection:
    """Open the database (creating the schema if needed) in WAL mode: one writer, many readers."""
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_SCHEMA)
    existing = {row["name"] for row in conn.execute("PRAGMA table_info(alerts)")}
    for name, definition in _ADDED_COLUMNS.items():
        if name not in existing:  # names and definitions are constants above, not input
            conn.execute(f"ALTER TABLE alerts ADD COLUMN {name} {definition}")
    # an alert's identity while a rule grows it (see upsert_alert)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS alerts_identity ON alerts (rule_id, src_ip, first_seen)"
    )
    return conn


def _values(alert: Alert) -> tuple:
    return (
        alert.rule_id,
        alert.rule_name,
        alert.technique_id,
        alert.tactic,
        alert.severity.value,
        str(alert.src_ip),
        alert.first_seen.isoformat(),
        alert.last_seen.isoformat(),
        alert.event_count,
        alert.summary,
        json.dumps(alert.evidence),
        alert.outcome,
        json.dumps(alert.outcome_evidence),
        json.dumps([m.model_dump(mode="json") for m in alert.matches]),
        json.dumps(alert.categories),
        alert.result,
        alert.confidence,
        json.dumps([r.model_dump(mode="json") for r in alert.results]),
        int(alert.internal),
        json.dumps([t.model_dump(mode="json") for t in alert.techniques]),
    )


def insert_alert(conn: sqlite3.Connection, alert: Alert) -> int:
    """Store an alert and return its id."""
    cur = conn.execute(
        "INSERT INTO alerts (rule_id, rule_name, technique_id, tactic, severity, src_ip,"
        " first_seen, last_seen, event_count, summary, evidence, outcome, outcome_evidence,"
        " matches, categories, result, confidence, results, internal, techniques)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        _values(alert),
    )
    conn.commit()
    return cur.lastrowid  # type: ignore[return-value]  # always set after an INSERT


def upsert_alert(conn: sqlite3.Connection, alert: Alert) -> tuple[int, Severity | None]:
    """Store an alert, or update the stored one with the same rule, IP and first_seen.

    Returns its id and the severity it had before (None when it is new).
    """
    row = conn.execute(
        "SELECT id, severity FROM alerts WHERE rule_id = ? AND src_ip = ? AND first_seen = ?",
        (alert.rule_id, str(alert.src_ip), alert.first_seen.isoformat()),
    ).fetchone()
    if row is None:
        return insert_alert(conn, alert), None
    conn.execute(
        "UPDATE alerts SET rule_id = ?, rule_name = ?, technique_id = ?, tactic = ?,"
        " severity = ?, src_ip = ?, first_seen = ?, last_seen = ?, event_count = ?, summary = ?,"
        " evidence = ?, outcome = ?, outcome_evidence = ?, matches = ?, categories = ?,"
        " result = ?, confidence = ?, results = ?, internal = ?, techniques = ?"
        " WHERE id = ?",
        (*_values(alert), row["id"]),
    )
    conn.commit()
    return row["id"], Severity(row["severity"])


def get_offset(conn: sqlite3.Connection, path: str) -> tuple[int, int] | None:
    """Return the saved (inode, byte offset) for a tailed file, or None if never seen."""
    row = conn.execute(
        "SELECT inode, offset FROM ingest_offsets WHERE path = ?", (path,)
    ).fetchone()
    return (row["inode"], row["offset"]) if row else None


def set_offset(conn: sqlite3.Connection, path: str, inode: int, offset: int) -> None:
    conn.execute(
        "INSERT INTO ingest_offsets (path, inode, offset) VALUES (?, ?, ?)"
        " ON CONFLICT (path) DO UPDATE SET inode = excluded.inode, offset = excluded.offset",
        (path, inode, offset),
    )
    conn.commit()


def connect_readonly(path: Path | str) -> sqlite3.Connection:
    """Open an existing database read-only, so the web process can never write to it."""
    conn = sqlite3.connect(f"{Path(path).resolve().as_uri()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def count_alerts_since(conn: sqlite3.Connection, since: datetime) -> list[sqlite3.Row]:
    """Alerts stored at or after `since`, counted per rule and severity, most severe first."""
    return conn.execute(
        "SELECT rule_name, severity, count(*) AS n FROM alerts WHERE created_at >= ?"
        " GROUP BY rule_id, rule_name, severity"
        " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1"
        " WHEN 'medium' THEN 2 ELSE 3 END, n DESC, rule_name",
        # same text format as created_at, so the comparison is chronological
        (since.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z"),),
    ).fetchall()


def _alert_dict(row: sqlite3.Row) -> dict:
    return {
        **dict(row),
        "evidence": json.loads(row["evidence"]),
        "outcome_evidence": json.loads(row["outcome_evidence"]),
        "matches": json.loads(row["matches"]),
        "categories": json.loads(row["categories"]),
        "results": json.loads(row["results"]),
        "internal": bool(row["internal"]),
        "techniques": json.loads(row["techniques"]),
    }


RESULTS = ("succeeded", "mixed", "blocked")


def list_alerts(
    conn: sqlite3.Connection,
    severity: Severity | None = None,
    limit: int = 200,
    *,
    attack_type: str | None = None,
    outcome: str | None = None,
    campaign_id: int | None = None,
    src_ip: str | None = None,
    alert_id: int | None = None,
    internal: bool | None = None,
) -> list[dict]:
    """Most severe first, then most recent. Every filter is optional.

    `attack_type` is a web category name, or the rule name of an alert without categories.
    `outcome` is the web alert's result (succeeded / mixed / blocked).
    """
    rows = conn.execute(
        "SELECT * FROM ("
        "  SELECT alerts.*, campaigns.ip_count AS campaign_ips"
        "  FROM alerts LEFT JOIN campaigns ON campaigns.id = alerts.campaign_id"
        ") WHERE (?1 IS NULL OR severity = ?1)"
        " AND (?2 IS NULL OR EXISTS (SELECT 1 FROM json_each(categories) WHERE value = ?2)"
        "  OR (categories = '[]' AND rule_name = ?2))"
        " AND (?3 IS NULL OR result = ?3)"
        " AND (?4 IS NULL OR campaign_id = ?4)"
        " AND (?5 IS NULL OR src_ip = ?5)"
        " AND (?6 IS NULL OR id = ?6)"
        " AND (?8 IS NULL OR internal = ?8)"
        " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1"
        " WHEN 'medium' THEN 2 ELSE 3 END, last_seen DESC, id DESC LIMIT ?7",
        (
            severity and severity.value,
            attack_type,
            outcome,
            campaign_id,
            src_ip,
            alert_id,
            limit,
            None if internal is None else int(internal),
        ),
    )
    return [_alert_dict(r) for r in rows]


def summary(conn: sqlite3.Connection) -> dict:
    """What the whole database holds: counts, top sources and categories, time range."""
    by_severity = dict(conn.execute("SELECT severity, count(*) FROM alerts GROUP BY severity"))
    first, last = conn.execute("SELECT min(first_seen), max(last_seen) FROM alerts").fetchone()
    return {
        "total": sum(by_severity.values()),
        "by_severity": by_severity,
        "campaigns": conn.execute("SELECT count(*) FROM campaigns").fetchone()[0],
        # every IP, busiest first: the caller groups them into subnets too
        "ips": conn.execute(
            "SELECT src_ip, count(*) AS alerts, sum(event_count) AS events FROM alerts"
            " GROUP BY src_ip ORDER BY events DESC, src_ip"
        ).fetchall(),
        "attack_types": conn.execute(
            "SELECT coalesce(j.value, alerts.rule_name) AS name, count(*) AS alerts"
            " FROM alerts LEFT JOIN json_each(alerts.categories) AS j"
            " GROUP BY name ORDER BY alerts DESC, name"
        ).fetchall(),
        "first_seen": first,
        "last_seen": last,
    }


def list_campaigns(conn: sqlite3.Connection) -> list[dict]:
    """Every campaign, latest first, with its IPs (alerts, events, worst severity each)."""
    ips: dict[int, list[dict]] = {}
    for r in conn.execute(
        "SELECT campaign_id, src_ip, count(*) AS alerts, sum(event_count) AS events,"
        " min(CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2"
        " ELSE 3 END) AS worst FROM alerts WHERE campaign_id IS NOT NULL"
        " GROUP BY campaign_id, src_ip ORDER BY events DESC, src_ip"
    ):
        ip = {**dict(r), "severity": _BY_RANK[r["worst"]]}
        ips.setdefault(r["campaign_id"], []).append(ip)
    campaigns = conn.execute("SELECT * FROM campaigns ORDER BY first_seen DESC, id").fetchall()
    result = []
    for c in campaigns:
        members = ips.get(c["id"], [])
        worst = min((_BY_RANK.index(m["severity"]) for m in members), default=3)
        result.append(
            {
                **dict(c),
                "categories": json.loads(c["categories"]),
                "ips": members,
                "events": sum(m["events"] for m in members),
                "severity": _BY_RANK[worst],
            }
        )
    return result


def get_alert(conn: sqlite3.Connection, alert_id: int) -> dict | None:
    """One alert, with the same extra fields as list_alerts (campaign_ips)."""
    found = list_alerts(conn, alert_id=alert_id, limit=1)
    return found[0] if found else None


def campaign_inputs(conn: sqlite3.Connection) -> list[dict]:
    """Every alert's id, IP, time span and categories, with times parsed, for campaigns.group."""
    return [
        {
            **dict(r),
            "first_seen": datetime.fromisoformat(r["first_seen"]),
            "last_seen": datetime.fromisoformat(r["last_seen"]),
            "categories": json.loads(r["categories"]),
        }
        for r in conn.execute(
            "SELECT id, src_ip, rule_name, first_seen, last_seen, categories FROM alerts"
        )
    ]


def save_campaigns(conn: sqlite3.Connection, campaigns: list) -> None:
    """Replace every campaign (campaigns.Campaign tuples) and the alerts' links to them."""
    with conn:  # one transaction: readers never see alerts pointing at missing campaigns
        conn.execute("UPDATE alerts SET campaign_id = NULL")
        conn.execute("DELETE FROM campaigns")
        for c in campaigns:
            cur = conn.execute(
                "INSERT INTO campaigns (subnet, first_seen, last_seen, ip_count, alert_count,"
                " categories) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    c.subnet,
                    c.first_seen.isoformat(),
                    c.last_seen.isoformat(),
                    c.ip_count,
                    len(c.alert_ids),
                    json.dumps(c.categories),
                ),
            )
            conn.executemany(
                "UPDATE alerts SET campaign_id = ? WHERE id = ?",
                [(cur.lastrowid, alert_id) for alert_id in c.alert_ids],
            )


def get_campaign(conn: sqlite3.Connection, campaign_id: int) -> dict | None:
    row = conn.execute("SELECT * FROM campaigns WHERE id = ?", (campaign_id,)).fetchone()
    return {**dict(row), "categories": json.loads(row["categories"])} if row else None
