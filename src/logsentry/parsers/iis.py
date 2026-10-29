"""Parse IIS logs in W3C extended format into Events."""

from datetime import UTC, datetime

from logsentry.models import MAX_LINE, Event, EventType

# IIS's default field set, used until a #Fields directive says otherwise.
DEFAULT_FIELDS = [
    "date",
    "time",
    "s-ip",
    "cs-method",
    "cs-uri-stem",
    "cs-uri-query",
    "s-port",
    "cs-username",
    "c-ip",
    "cs(User-Agent)",
    "sc-status",
    "sc-substatus",
    "sc-win32-status",
    "time-taken",
]
REQUIRED = {"date", "time", "c-ip", "cs-method", "cs-uri-stem", "sc-status"}


class W3CParser:
    """W3C columns are declared by a `#Fields:` header, so the parser remembers the last one."""

    def __init__(self) -> None:
        self.fields = DEFAULT_FIELDS

    def parse_line(self, line: str) -> Event | None:
        """Return an Event for a request line, or None for directives and malformed lines.

        The URL is kept exactly as logged; rules decode it themselves.
        """
        line = line.rstrip("\r\n")
        if len(line) > MAX_LINE:
            return None
        if line.startswith("#Fields:"):
            fields = line.removeprefix("#Fields:").split()
            # a header missing a required field would make every following line unreadable
            self.fields = fields if set(fields) >= REQUIRED else DEFAULT_FIELDS
            return None
        # values never contain spaces: IIS writes them as '+', so a client can't shift columns
        values = line.split(" ")
        if line.startswith("#") or len(values) != len(self.fields):
            return None
        row = {k: None if v == "-" else v for k, v in zip(self.fields, values, strict=True)}
        ua = row.get("cs(User-Agent)")
        try:
            return Event(
                # W3C extended logs are always written in UTC
                ts=datetime.fromisoformat(f"{row['date']}T{row['time']}").replace(tzinfo=UTC),
                source="iis",
                event_type=EventType.HTTP_REQUEST,
                src_ip=row["c-ip"],
                host=row.get("cs-host") or row.get("s-ip") or "-",
                http_method=row["cs-method"],
                url_path=row["cs-uri-stem"],
                url_query=row.get("cs-uri-query"),
                http_status=int(row["sc-status"] or ""),
                user_agent=None if ua is None else ua.replace("+", " "),
                raw=line,
            )
        except (TypeError, ValueError):  # missing or bad date, IP or status
            return None


# shortcut: one parser shared by the CLI; every IIS log file opens with a #Fields header that
# resets it, so it only goes wrong for a headerless file read after one with other columns.
parse_line = W3CParser().parse_line
