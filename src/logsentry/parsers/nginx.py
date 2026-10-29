"""Parse nginx access log lines (the default "combined" format) into Events."""

import re
from datetime import datetime

from logsentry.models import MAX_LINE, Event, EventType

# $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent
# "$http_referer" "$http_user_agent"
# nginx escapes '"' inside quoted fields as \x22, so [^"]* cannot be ended early by a client.
_COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d{3}) (?P<bytes>\S+)'
    r' "[^"]*" "(?P<ua>[^"]*)"'
)
# HTTP/0.9 requests have no version; anything else (TLS on port 80, junk) keeps method/path None.
_REQUEST = re.compile(r"^(?P<method>[A-Z]+) (?P<target>\S+)(?: HTTP/\d(?:\.\d)?)?$")


def parse_line(line: str) -> Event | None:
    """Return an Event for a combined-format access line, or None for malformed or overlong lines.

    The URL is kept exactly as logged (still percent-encoded); rules decode it themselves.
    """
    line = line.rstrip("\r\n")
    # shortcut: an attacker can pad a URL past MAX_LINE to have the request ignored; raise the
    # cap (regexes here are linear) if that matters more than the memory per line.
    if len(line) > MAX_LINE or not (m := _COMBINED.match(line)):
        return None
    method = path = query = None
    if req := _REQUEST.match(m["request"]):
        method = req["method"]
        path, _, query = req["target"].partition("?")
    try:
        return Event(
            ts=datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z"),
            source="nginx",
            event_type=EventType.HTTP_REQUEST,
            src_ip=m["ip"],
            host="-",  # the combined format doesn't log a host
            http_method=method,
            url_path=path,
            url_query=query or None,
            http_status=int(m["status"]),
            http_bytes=int(m["bytes"]) if m["bytes"].isdigit() else None,
            user_agent=None if m["ua"] == "-" else m["ua"],
            raw=line,
        )
    except ValueError:  # bad date or bad IP (pydantic errors are ValueErrors)
        return None
