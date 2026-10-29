"""`logsentry doctor`: a plain-language health check of a server install."""

import os
import shutil
import sqlite3
import subprocess
from pathlib import Path

import yaml

from logsentry import notify, store
from logsentry.config import load_config

OK, WARN, FAIL = "[ OK ]", "[WARN]", "[FAIL]"
SERVICE = "logsentry-tail"
TIMER = "logsentry-summary.timer"


def systemctl(*args: str) -> str | None:
    """Output of a systemctl query, or None where there is no systemd."""
    path = shutil.which("systemctl")
    if path is None:
        return None
    # fixed arguments, no user input
    return subprocess.run([path, *args], capture_output=True, text=True).stdout.strip()  # noqa: S603


def check_service() -> tuple[str, str]:
    state = systemctl("is-active", SERVICE)
    if state is None:
        return WARN, "Detector service: systemd not found, so it isn't running as a service"
    if state == "active":
        return OK, "Detector service: running"
    return FAIL, f"Detector service: {state or 'not installed'} (details: journalctl -u {SERVICE})"


def check_timer() -> tuple[str, str]:
    state = systemctl("is-active", TIMER)
    if state is None:
        return WARN, "Daily summary: systemd not found, so there is no daily summary"
    if state != "active":
        # a missing timer also reports "inactive"; reinstalling puts it back either way
        return WARN, f"Daily summary: timer is {state or 'missing'} (fix: sudo ./install.sh)"
    when = systemctl("show", TIMER, "--property=NextElapseUSecRealtime", "--value")
    return OK, f"Daily summary: next one {when}" if when else "Daily summary: scheduled"


def check_log(path: Path, what: str, required: bool) -> tuple[str, str]:
    if not path.exists():
        if required:
            return FAIL, f"{what}: {path} not found (install rsyslog: sudo apt install rsyslog)"
        return WARN, f"{what}: {path} not found (fine if this server has no website)"
    if not os.access(path, os.R_OK):
        return FAIL, f"{what}: {path} can't be read (run the check with sudo)"
    return OK, f"{what}: {path} found"


def check_config(path: Path) -> tuple[str, str]:
    try:
        _, rules = load_config(path)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        return FAIL, f"Rules: {path} is broken: {exc}"
    return OK, f"Rules: {len(rules)} detections enabled"


def check_db(path: Path) -> tuple[str, str]:
    if not path.exists():
        return WARN, "Alerts: no database yet (it appears once the detector has started)"
    try:
        conn = store.connect_readonly(path)
        total, high, last = conn.execute(
            "SELECT count(*), count(*) FILTER (WHERE severity IN ('high', 'critical')),"
            " max(created_at) FROM alerts"
        ).fetchone()
        conn.close()
    except sqlite3.Error as exc:
        return FAIL, f"Alerts: {path} can't be read: {exc}"
    if total == 0:
        return OK, "Alerts: none yet (that's good)"
    return OK, f"Alerts: {total} stored, {high} of them HIGH, latest {last[:16].replace('T', ' ')}"


def check_phone(url: str | None, env_file: Path) -> tuple[str, str]:
    if not url:
        try:
            url = notify.read_env_file(env_file).get(notify.NTFY_ENV)
        except PermissionError:
            return WARN, f"Phone alerts: {env_file} can't be read (run the check with sudo)"
    if not url:
        return WARN, "Phone alerts: off (turn them on with: sudo ./install.sh --phone)"
    if not notify.is_web_url(url):
        return FAIL, f"Phone alerts: {url} is not an http(s) URL"
    error = notify.send(
        url,
        title="LogSentry test",
        body="Phone alerts work. HIGH alerts from your server will arrive here.",
        priority="default",
        tags="white_check_mark",
    )
    if error:
        return FAIL, f"Phone alerts: test notification failed: {error}"
    return OK, "Phone alerts: test notification sent, check your phone"


def run(
    sshd: Path, nginx: Path, config: Path, db: Path, ntfy_url: str | None, env_file: Path
) -> int:
    """Print every check and return 1 if any failed, else 0. `ntfy_url` overrides `env_file`."""
    checks = [
        check_service(),
        check_timer(),
        check_log(sshd, "SSH log", required=True),
        check_log(nginx, "Web log", required=False),
        check_config(config),
        check_db(db),
        check_phone(ntfy_url, env_file),
    ]
    print("LogSentry health check\n")
    for status, message in checks:
        print(f"  {status} {message}")
    failed = sum(status == FAIL for status, _ in checks)
    print("\nAll good." if not failed else f"\n{failed} problem(s) found, see [FAIL] above.")
    return 1 if failed else 0
