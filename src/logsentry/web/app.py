"""Read-only dashboard: alert list, alert detail, campaigns and a JSON API over the store."""

import hashlib
import sqlite3
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader

from logsentry import store
from logsentry.campaigns import subnet
from logsentry.models import Severity

HERE = Path(__file__).parent
SECURITY_HEADERS = {
    # htmx and theme.js are served from /static, so no inline script, inline style or CDN
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; base-uri 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}
TIMELINE_WIDTH = 1200  # the detail page's SVG timeline, in SVG units


def _severity(value: str) -> Severity | None:
    """'' means all severities (the "All" option of the filter); anything else must be valid."""
    if not value:
        return None
    try:
        return Severity(value)
    except ValueError:
        raise HTTPException(422, f"unknown severity: {value!r}") from None


SOURCES = {"internal": True, "external": False}  # the Source filter → Alert.internal


def list_filters(
    severity: str = "",
    type: str = "",
    outcome: str = "",
    campaign: str = "",
    ip: str = "",
    source: str = "",
) -> dict:
    """The list filters from the query string; '' means "all". Bad values are a 422."""
    if outcome and outcome not in store.RESULTS:
        raise HTTPException(422, f"unknown outcome: {outcome!r}")
    if source and source not in SOURCES:
        raise HTTPException(422, f"unknown source: {source!r}")
    if campaign and not campaign.isdigit():
        raise HTTPException(422, f"bad campaign: {campaign!r}")
    try:
        ip = str(ip_address(ip)) if ip else ""
    except ValueError:
        raise HTTPException(422, f"bad IP: {ip!r}") from None
    return {
        "severity": _severity(severity),
        "attack_type": type or None,  # a bound parameter: an unknown name just matches nothing
        "outcome": outcome or None,
        "campaign_id": int(campaign) if campaign else None,
        "src_ip": ip or None,
        "internal": SOURCES.get(source),
    }


Filters = Annotated[dict, Depends(list_filters)]


def short_ts(value: str | None) -> str:
    """'2024-07-28T15:08:40+00:00' → '2024-07-28 15:08:40 UTC'."""
    if not value:
        return ""
    return datetime.fromisoformat(value).astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def data_range(first: str | None, last: str | None) -> str:
    """'2024-07-28 14:48–17:17 UTC', with the second date only when it differs."""
    if not first or not last:
        return "no data yet"
    start, end = (datetime.fromisoformat(v).astimezone(UTC) for v in (first, last))
    tail = f"{end:%H:%M}" if start.date() == end.date() else f"{end:%Y-%m-%d %H:%M}"
    return f"{start:%Y-%m-%d %H:%M}–{tail} UTC"


def duration(first: str, last: str) -> str:
    """'22 min' or '1 h 37 min' between two ISO timestamps."""
    minutes = round(
        (datetime.fromisoformat(last) - datetime.fromisoformat(first)).total_seconds() / 60
    )
    return f"{minutes // 60} h {minutes % 60} min" if minutes >= 60 else f"{minutes} min"


def attack_url(technique: str) -> str:
    """T1595.003 → https://attack.mitre.org/techniques/T1595/003/"""
    return f"https://attack.mitre.org/techniques/{technique.strip().replace('.', '/')}/"


def cwe_url(cwe: str) -> str:
    """CWE-22 → https://cwe.mitre.org/data/definitions/22.html"""
    return f"https://cwe.mitre.org/data/definitions/{cwe.removeprefix('CWE-')}.html"


def status_class(status: int | None) -> str:
    if status is None:
        return "unknown"
    return "ok" if 200 <= status < 300 else "redirect" if status < 400 else "error"


def timeline(alert: dict) -> list[dict]:
    """One dot per matched request, placed between the alert's first and last seen."""
    start = datetime.fromisoformat(alert["first_seen"])
    span = (datetime.fromisoformat(alert["last_seen"]) - start).total_seconds()
    dots = {}
    for m in alert["matches"]:  # a request in two categories is still one dot
        ts = datetime.fromisoformat(m["ts"])
        offset = (ts - start).total_seconds() / span if span else 0.5
        dots[(m["ts"], m.get("request"))] = {
            "x": round(10 + offset * (TIMELINE_WIDTH - 20), 1),
            "status": status_class(m["http_status"]),
            "label": f"{short_ts(m['ts'])} · HTTP {m['http_status']}",
        }
    return list(dots.values())


def top_subnets(ips: list[sqlite3.Row], n: int = 5) -> list[tuple[str, int]]:
    events: Counter[str] = Counter()
    for row in ips:
        events[str(subnet(row["src_ip"]))] += row["events"]
    return events.most_common(n)


def create_app(db: Path) -> FastAPI:
    app = FastAPI(title="LogSentry", docs_url=None, redoc_url=None, openapi_url=None)
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    env = Environment(loader=FileSystemLoader(HERE / "templates"), autoescape=True)
    env.filters.update(
        ts=short_ts, attack_url=attack_url, cwe_url=cwe_url, status_class=status_class
    )
    # /static/style.css?v=<hash>: a changed file gets a new URL, so no browser keeps an old copy
    versions = {
        f.name: hashlib.sha256(f.read_bytes()).hexdigest()[:10] for f in (HERE / "static").iterdir()
    }
    env.globals["duration"] = duration
    env.globals["asset"] = lambda name: f"/static/{name}?v={versions[name]}"
    templates = Jinja2Templates(env=env)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.update(SECURITY_HEADERS)
        return response

    @contextmanager
    def conn() -> Iterator[sqlite3.Connection]:
        if not db.exists():
            raise HTTPException(503, "no alerts database yet: start `logsentry tail` first")
        c = store.connect_readonly(db)
        try:
            yield c
        finally:
            c.close()

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request, filters: Filters):
        with conn() as c:
            rows = store.list_alerts(c, **filters)
            summary = store.summary(c)
            campaigns = store.list_campaigns(c)
        context = {
            "alerts": rows,
            "summary": summary,
            "top_ips": summary["ips"][:5],
            "top_subnets": top_subnets(summary["ips"]),
            "data_range": data_range(summary["first_seen"], summary["last_seen"]),
            "campaigns": campaigns,
            "chosen": request.query_params,
            "severities": list(Severity),
            "outcomes": store.RESULTS,
        }
        return templates.TemplateResponse(request, "alerts.html", context)

    @app.get("/rows", response_class=HTMLResponse)
    def rows(request: Request, filters: Filters):
        with conn() as c:
            context = {"alerts": store.list_alerts(c, **filters)}
        return templates.TemplateResponse(request, "_rows.html", context)

    @app.get("/alerts/{alert_id}", response_class=HTMLResponse)
    def alert_detail(request: Request, alert_id: int):
        with conn() as c:
            alert = store.get_alert(c, alert_id)
            if alert is None:
                raise HTTPException(404, "alert not found")
            campaign = alert["campaign_id"] and store.get_campaign(c, alert["campaign_id"])
        context = {
            "alert": alert,
            "subnet": subnet(alert["src_ip"]),
            "campaign": campaign,
            "timeline": timeline(alert),
            "timeline_width": TIMELINE_WIDTH,
        }
        return templates.TemplateResponse(request, "alert.html", context)

    @app.get("/campaigns", response_class=HTMLResponse)
    def campaigns_page(request: Request, open: int | None = None):
        """`open`: a campaign id to show expanded, for links from the alerts."""
        with conn() as c:
            campaigns = store.list_campaigns(c)
        context = {"campaigns": campaigns, "open": open}
        return templates.TemplateResponse(request, "campaigns.html", context)

    @app.get("/api/alerts")
    def api_alerts(filters: Filters) -> list[dict]:
        with conn() as c:
            return store.list_alerts(c, **filters)

    return app
