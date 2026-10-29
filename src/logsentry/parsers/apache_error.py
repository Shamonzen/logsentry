"""Parse Apache error_log lines (2.2 and 2.4 formats).

Not an Event source: these lines only judge the outcome of web attacks found in the access log.
"""

import re
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import NamedTuple

from logsentry.models import _CONTROL_CHARS, MAX_LINE

# 2.2: [Sun Jul 28 12:49:44 2024] [error] [client 203.0.113.22] msg
# 2.4: [Sun Jul 28 12:49:44.123456 2024] [php7:warn] [pid 12:tid 34] [client 203.0.113.22:5555]
#      AH01071: msg
_LINE = re.compile(
    r"^\[(?P<ts>\w{3} \w{3} \d\d \d\d:\d\d:\d\d)(?:\.\d+)? (?P<year>\d{4})\]"
    r" \[(?:[\w.-]+:)?(?P<level>\w+)\](?: \[pid [^\]]*\])?(?: \[client (?P<ip>[^\]\s]+)\])?"
    r" (?:AH\d{5}: )?(?P<msg>.*)$"
)
_INCLUDE = re.compile(r"\b(?P<func>(?:include|require)(?:_once)?)\((?P<target>[^)]*)\)")
_FAILED_OPENING = re.compile(r"Failed opening '(?P<target>[^']*)' for inclusion")
_SCRIPT = re.compile(r" in (?P<script>/\S+) on line (?P<line>\d+)$")
_STREAM = "failed to open stream: "


class ErrorLine(NamedTuple):
    ts: datetime  # naive: error_log has no time zone
    level: str
    client_ip: IPv4Address | IPv6Address | None  # None for server messages
    message: str
    php_func: str | None
    target: str | None  # URL or path PHP tried to include
    reason: str | None  # why the include failed, e.g. "HTTP request failed! ... 404 ..."
    script: str | None
    script_line: int | None
    raw: str

    @property
    def failed_include(self) -> bool:
        return self.reason is not None or _FAILED_OPENING.search(self.message) is not None


def _client(text: str) -> IPv4Address | IPv6Address:
    try:
        return ip_address(text)
    except ValueError:  # 2.4 appends the port: 203.0.113.22:5555 or ::1:5555
        return ip_address(text.rpartition(":")[0])


def parse_line(line: str) -> ErrorLine | None:
    """Return an ErrorLine, or None for malformed or overlong lines."""
    line = _CONTROL_CHARS.sub("", line.rstrip("\r\n"))
    if len(line) > MAX_LINE or not (m := _LINE.match(line)):
        return None
    try:
        ts = datetime.strptime(f"{m['ts']} {m['year']}", "%a %b %d %H:%M:%S %Y")
        ip = _client(m["ip"]) if m["ip"] else None
    except ValueError:
        return None
    msg = m["msg"]
    inc = _INCLUDE.search(msg)
    target = inc["target"] if inc and inc["target"] else None
    if target is None and (failed := _FAILED_OPENING.search(msg)):
        target = failed["target"]
    reason = None
    if _STREAM in msg:
        # PHP logs the HTTP status line with a literal "\r\n" after it
        reason = msg.partition(_STREAM)[2].rsplit(" in /", 1)[0].replace("\\r\\n", "").strip()
    script = _SCRIPT.search(msg)
    return ErrorLine(
        ts=ts,
        level=m["level"],
        client_ip=ip,
        message=msg,
        php_func=inc["func"] if inc else None,
        target=target,
        reason=reason,
        script=script["script"] if script else None,
        script_line=int(script["line"]) if script else None,
        raw=line,
    )
