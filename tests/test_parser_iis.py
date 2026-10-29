from datetime import UTC, datetime
from ipaddress import IPv6Address
from pathlib import Path

import pytest

from logsentry.models import MAX_LINE, EventType
from logsentry.parsers.iis import W3CParser

FIXTURES = Path(__file__).parent / "fixtures"
HEADER = "#Fields: date time c-ip cs-method cs-uri-stem cs-uri-query sc-status cs(User-Agent)"


def parse_fixture(name: str) -> list:
    parser = W3CParser()
    lines = (FIXTURES / name).read_text().splitlines()
    return [e for raw in lines if (e := parser.parse_line(raw))]


def parse(*lines: str):
    parser = W3CParser()
    return [parser.parse_line(raw) for raw in lines][-1]


def test_request_line_follows_fields_header():
    raw = "2026-10-22 14:03:00 203.0.113.7 GET /search q=a%20b&x=1 404 Mozilla/5.0+(X11)\r\n"
    event = parse(HEADER, raw)
    assert (event.source, event.event_type, str(event.src_ip)) == (
        "iis",
        EventType.HTTP_REQUEST,
        "203.0.113.7",
    )
    assert (event.http_method, event.url_path, event.url_query) == ("GET", "/search", "q=a%20b&x=1")
    assert (event.http_status, event.user_agent) == (404, "Mozilla/5.0 (X11)")
    assert event.ts == datetime(2026, 10, 22, 14, 3, tzinfo=UTC)
    assert event.raw == raw.rstrip()


def test_dash_means_empty():
    event = parse(HEADER, "2026-10-22 14:03:00 2001:db8::1 GET / - 200 -")
    assert (event.url_query, event.user_agent) == (None, None)
    assert event.src_ip == IPv6Address("2001:db8::1")


def test_default_fields_without_header():
    raw = "2026-10-22 09:01:12 192.0.2.10 GET / - 80 - 198.51.100.20 UA 200 0 0 15"
    assert str(parse(raw).src_ip) == "198.51.100.20"


def test_header_missing_required_field_falls_back_to_default():
    parser = W3CParser()
    parser.parse_line("#Fields: date time cs-uri-stem")
    assert parser.parse_line("2026-10-22 14:03:00 /") is None


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "#Software: Microsoft Internet Information Services 5.0",
        "garbage",
        "2026-10-22 14:03:00 203.0.113.7 GET / - 200",  # column missing
        "2026-10-22 14:03:00 203.0.113.7 GET / - 200 UA extra",  # column added
        "2026-10-22 14:03:00 999.1.1.1 GET / - 200 UA",
        "2026-02-30 14:03:00 203.0.113.7 GET / - 200 UA",
        "2026-10-22 14:03:00 203.0.113.7 GET / - - UA",  # no status
        "2026-10-22 14:03:00 203.0.113.7 GET /" + "a" * MAX_LINE + " - 200 UA",
    ],
)
def test_junk_lines_are_ignored(raw):
    assert parse(HEADER, raw) is None


def test_benign_fixture():
    events = parse_fixture("iis_benign.log")
    assert [(e.http_method, e.url_path, e.http_status) for e in events] == [
        ("GET", "/", 200),
        ("GET", "/favicon.ico", 404),
        ("GET", "/login.aspx", 200),
        ("POST", "/login.aspx", 302),
        ("GET", "/healthz", 200),
    ]
    assert events[-1].user_agent is None


def test_attacks_fixture():
    events = parse_fixture("iis_attacks.log")
    assert len(events) == 3
    assert {(str(e.src_ip), e.host) for e in events} == {("203.0.113.21", "www.example.test")}
    assert events[1].url_path == "/scripts/..%5c../winnt/system32/cmd.exe"
