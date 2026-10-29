"""Push HIGH and CRITICAL alerts to a phone through ntfy (https://ntfy.sh)."""

import sys
import urllib.request
from pathlib import Path

from logsentry.models import Alert, Severity

PUSHED = {Severity.HIGH, Severity.CRITICAL}
NTFY_ENV = "LOGSENTRY_NTFY_URL"


def read_env_file(path: Path) -> dict[str, str]:
    """KEY=VALUE lines as systemd's EnvironmentFile reads them; a missing file is empty.

    PermissionError is raised: the file is root-only, and "can't read" is not "not set".
    """
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (FileNotFoundError, NotADirectoryError):
        return {}
    pairs = (ln.split("=", 1) for ln in lines if "=" in ln and not ln.lstrip().startswith("#"))
    return {key.strip(): value.strip().strip("\"'") for key, value in pairs}


def is_web_url(url: str) -> bool:
    """urllib would also open file:// and ftp:// URLs, so only http(s) is accepted."""
    return url.startswith(("https://", "http://"))


def send(url: str, title: str, body: str, priority: str, tags: str) -> str | None:
    """POST one message to an ntfy topic URL. Returns None on success, else the error."""
    request = urllib.request.Request(  # noqa: S310 - scheme checked by is_web_url at startup
        url,
        data=body.encode(),
        headers={"Title": title, "Priority": priority, "Tags": tags},
    )
    try:
        urllib.request.urlopen(request, timeout=5).close()  # noqa: S310 - see above
    except OSError as exc:  # URLError, HTTPError, timeouts and resets are all OSErrors
        return str(exc)
    return None


def push(url: str, alert: Alert) -> None:
    """Send an alert if it is HIGH or CRITICAL. Failures are printed, never raised."""
    if alert.severity not in PUSHED:
        return
    error = send(
        url,
        title=f"LogSentry {alert.severity.upper()}: {alert.rule_id}",
        # the summary may hold an attacker-chosen user name, so it goes in the body, not a header
        body=f"{alert.summary}\n{alert.technique_id} {alert.rule_name}",
        priority="urgent" if alert.severity == Severity.CRITICAL else "high",
        tags="rotating_light",
    )
    if error:
        print(f"ntfy push failed: {error}", file=sys.stderr, flush=True)
