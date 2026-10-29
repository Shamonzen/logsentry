"""`logsentry summary`: one phone message with the last day's alerts, sent by a daily timer."""

import sqlite3
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from logsentry import notify, store


def build(rows: list[sqlite3.Row], hours: int) -> tuple[str, str, str]:
    """Return the title, body and ntfy priority for alert counts from count_alerts_since."""
    if not rows:
        return "LogSentry: all quiet", f"No alerts in the last {hours} hours.", "low"
    total = sum(r["n"] for r in rows)
    high = sum(r["n"] for r in rows if r["severity"] in ("high", "critical"))
    lines = [f"{r['n']} x {r['rule_name']} ({r['severity'].upper()})" for r in rows]
    if high:
        # each HIGH alert was already pushed when it happened; this is the reminder
        verdict, priority = f"{high} HIGH: check them on the dashboard.", "default"
    else:
        verdict, priority = "Nothing serious: no HIGH alerts.", "low"
    title = f"LogSentry: {total} alert{'s' * (total != 1)} in {hours} hours"
    return title, "\n".join([*lines, verdict]), priority


def run(db: Path, hours: int, url: str | None, now: datetime | None = None) -> int:
    """Print the summary and push it when `url` is set. Returns 1 if the push failed."""
    since = (now or datetime.now(UTC)) - timedelta(hours=hours)
    rows = []
    if db.exists():
        conn = store.connect_readonly(db)
        try:
            rows = store.count_alerts_since(conn, since)
        finally:
            conn.close()
    title, body, priority = build(rows, hours)
    print(f"{title}\n{body}")
    if url and (error := notify.send(url, title, body, priority, tags="bar_chart")):
        print(f"ntfy push failed: {error}", file=sys.stderr)
        return 1
    return 0
