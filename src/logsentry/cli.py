import argparse
import contextlib
import functools
import os
import sqlite3
import time
from collections import Counter, defaultdict
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path

from logsentry import __version__, campaigns, doctor, notify, outcome, store, summary
from logsentry.config import load_config
from logsentry.engine import Engine
from logsentry.ingest import read_new_lines
from logsentry.models import Alert, Event, Severity
from logsentry.parsers import iis, nginx, sshd
from logsentry.rules.web_attack import WebAttack

PARSERS = {"sshd": sshd.parse_line, "nginx": nginx.parse_line, "iis": iis.parse_line}
NTFY_ENV = notify.NTFY_ENV
LEVELS = list(Severity)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logsentry",
        description="Detect attacks in sshd, nginx and IIS logs and map them to MITRE ATT&CK.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")
    ingest = sub.add_parser("ingest", help="run a log file through the rules once and store alerts")
    ingest.add_argument("file", type=Path)
    ingest.add_argument("--source", choices=PARSERS, required=True)
    ingest.add_argument("--config", type=Path, default=Path("config/rules.yaml"))
    ingest.add_argument("--db", type=Path, default=Path("logsentry.db"))
    ingest.add_argument(
        "--error-log",
        type=Path,
        help="Apache error_log paired with an nginx-format access log: judge if inclusions worked",
    )
    tail = sub.add_parser("tail", help="follow live log files, resuming where the last run stopped")
    tail.add_argument("--sshd", type=Path, help="sshd auth log to follow")
    tail.add_argument("--nginx", type=Path, help="nginx access log to follow")
    tail.add_argument("--interval", type=float, default=1.0, help="seconds between polls")
    tail.add_argument("--config", type=Path, default=Path("config/rules.yaml"))
    tail.add_argument("--db", type=Path, default=Path("logsentry.db"))
    web = sub.add_parser("web", help="serve the read-only dashboard")
    web.add_argument("--db", type=Path, default=Path("logsentry.db"))
    web.add_argument("--host", default="127.0.0.1")
    web.add_argument("--port", type=int, default=8000)
    # defaults are where install.sh puts things
    check = sub.add_parser("doctor", help="check a server install and send a test phone alert")
    check.add_argument("--sshd", type=Path, default=Path("/var/log/auth.log"))
    check.add_argument("--nginx", type=Path, default=Path("/var/log/nginx/access.log"))
    check.add_argument("--config", type=Path, default=Path("/opt/logsentry/config/rules.yaml"))
    check.add_argument("--db", type=Path, default=Path("/var/lib/logsentry/logsentry.db"))
    check.add_argument("--env-file", type=Path, default=Path("/etc/logsentry/logsentry.env"))
    daily = sub.add_parser("summary", help="print the last day's alerts and push them to the phone")
    daily.add_argument("--db", type=Path, default=Path("/var/lib/logsentry/logsentry.db"))
    daily.add_argument("--hours", type=int, default=24, help="how far back to count")
    daily.add_argument("--env-file", type=Path, default=Path("/etc/logsentry/logsentry.env"))
    return parser


def handle_line(
    line: str,
    parse_line: Callable[[str], Event | None],
    engine: Engine,
    conn: sqlite3.Connection,
    on_alert: Callable[[Alert], None] | None = None,
) -> int:
    """Parse one line, run it through the rules, store and print alerts. Returns the alert count."""
    if (event := parse_line(line)) is None:
        return 0
    alerts = engine.process(event)
    for alert in alerts:
        emit(alert, conn, on_alert)
    return len(alerts)


def emit(
    alert: Alert, conn: sqlite3.Connection, on_alert: Callable[[Alert], None] | None = None
) -> None:
    """Store one alert (or update it as it grows); print it and hand it to `on_alert` when
    it is new or its severity went up, so a growing alert doesn't repeat itself."""
    _, before = store.upsert_alert(conn, alert)
    if before is not None and LEVELS.index(alert.severity) <= LEVELS.index(before):
        return
    text = (
        f"[{alert.severity.upper()}] {alert.rule_id} {alert.technique_id} "
        f"{alert.src_ip}: {alert.summary}"
    )
    if alert.outcome:
        text += f" outcome={alert.outcome}" + "".join(f"\n    {e}" for e in alert.outcome_evidence)
    print(text, flush=True)
    if on_alert:
        on_alert(alert)


def ingest(file: Path, source: str, config: Path, db: Path, error_log: Path | None = None) -> int:
    """Parse, detect, judge outcomes, store and print. Returns the number of alerts.

    Alerts are held until the whole file is read: the usual response size of a page and
    the error_log lines written after a request are only known then.
    """
    parse_line = PARSERS[source]
    settings, rules = load_config(config)
    engine = Engine(rules, settings.cooldown_seconds)
    web = next((r for r in rules if isinstance(r, WebAttack)), None)
    # the latest version of each alert (web_attack returns its IP's alert again as it
    # grows, with the same first_seen) and the requests it covers
    found: dict[tuple, tuple[Alert, list[Event]]] = {}
    sizes: defaultdict[str | None, Counter[int]] = defaultdict(Counter)
    with file.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            if (event := parse_line(line)) is None:
                continue
            alerts = engine.process(event)
            for alert in alerts:
                key = (alert.rule_id, alert.src_ip, alert.first_seen)
                events = found[key][1] if key in found else []
                found[key] = (alert, [*events, event])
            if event.http_bytes is not None and not any(a.rule_id == WebAttack.id for a in alerts):
                sizes[event.url_path][event.http_bytes] += 1
    usual_sizes = {path: c.most_common(1)[0][0] for path, c in sizes.items()}
    errors = None
    if error_log:
        errors, malformed = outcome.read_error_log(error_log)
        if malformed:
            print(f"{error_log}: {malformed} malformed line(s) skipped")
    window = timedelta(seconds=settings.outcome_window_seconds)
    conn = store.connect(db)
    try:
        for alert, events in found.values():
            if web and alert.rule_id == web.id:
                hits = [(e, web.classify(e)) for e in events]
                judged = [e for e, m in hits if outcome.INCLUSION_CATEGORIES & m.keys()]
                # each inclusion request's own error_log verdict, for the severity
                confirmed = {
                    (e.ts, e.raw): outcome.judge(e, errors, window, usual_sizes.get(e.url_path))[0]
                    for e in judged
                }
                # rebuilt now the usual page sizes and the error_log verdicts are known
                alert = web.alert_for(hits, usual_sizes, confirmed)
                alert = outcome.verdict(alert, judged, errors, window, usual_sizes)
            emit(alert, conn)
        grouped = campaigns.rebuild(conn, timedelta(seconds=settings.campaign_gap_seconds))
    finally:
        conn.close()
    print(f"{len(grouped)} campaign(s)")
    print(f"{len(found)} alert(s)")
    return len(found)


def poll(
    conn: sqlite3.Connection,
    engine: Engine,
    files: dict[str, Path],
    on_alert: Callable[[Alert], None] | None = None,
) -> int:
    """Process what was appended to each file since its saved offset. Returns the alert count."""
    count = 0
    for source, path in files.items():
        if (new := read_new_lines(conn, path)) is None:
            continue
        lines, inode, offset = new
        for line in lines:
            count += handle_line(line, PARSERS[source], engine, conn, on_alert)
        store.set_offset(conn, str(path), inode, offset)
    return count


def tail(
    files: dict[str, Path], config: Path, db: Path, interval: float, ntfy_url: str | None
) -> None:
    """Poll the files forever. This process is the only writer to the database."""
    settings, rules = load_config(config)
    engine = Engine(rules, settings.cooldown_seconds)
    gap = timedelta(seconds=settings.campaign_gap_seconds)
    conn = store.connect(db)
    on_alert = functools.partial(notify.push, ntfy_url) if ntfy_url else None
    try:
        while True:
            if poll(conn, engine, files, on_alert):
                campaigns.rebuild(conn, gap)
            time.sleep(interval)
    finally:
        conn.close()


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "ingest":
        if args.error_log and args.source != "nginx":
            parser.error("--error-log needs --source nginx (an Apache or nginx access log)")
        ingest(args.file, args.source, args.config, args.db, args.error_log)
        return 0
    if args.command == "tail":
        files = {src: p for src, p in (("sshd", args.sshd), ("nginx", args.nginx)) if p}
        if not files:
            parser.error("tail needs --sshd and/or --nginx")
        ntfy_url = os.environ.get(NTFY_ENV) or None
        if ntfy_url and not notify.is_web_url(ntfy_url):
            parser.error(f"{NTFY_ENV} must be an http(s) URL")
        with contextlib.suppress(KeyboardInterrupt):
            tail(files, args.config, args.db, args.interval, ntfy_url)
        return 0
    if args.command == "doctor":
        ntfy_url = os.environ.get(NTFY_ENV) or None
        return doctor.run(args.sshd, args.nginx, args.config, args.db, ntfy_url, args.env_file)
    if args.command == "summary":
        if args.hours < 1:
            parser.error("--hours must be at least 1")
        try:
            ntfy_url = os.environ.get(NTFY_ENV) or notify.read_env_file(args.env_file).get(NTFY_ENV)
        except PermissionError:
            parser.error(f"can't read {args.env_file}: run it with sudo")
        if ntfy_url and not notify.is_web_url(ntfy_url):
            parser.error(f"{NTFY_ENV} must be an http(s) URL")
        return summary.run(args.db, args.hours, ntfy_url)
    if args.command == "web":
        import uvicorn  # imported here so ingest/tail don't load the web stack

        from logsentry.web.app import create_app

        uvicorn.run(create_app(args.db), host=args.host, port=args.port)
        return 0
    parser.print_help()
    return 0
