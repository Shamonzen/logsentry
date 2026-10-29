from datetime import UTC, datetime
from ipaddress import IPv6Address
from pathlib import Path

import pytest

from logsentry.models import MAX_LINE, EventType
from logsentry.parsers.nginx import parse_line

FIXTURES = Path(__file__).parent / "fixtures"
UA = "Mozilla/5.0 (X11; Linux x86_64)"


def line(request: str, status: int = 200, ua: str = UA, ts: str = "22/Oct/2026:14:03:00 +0000"):
    return f'203.0.113.7 - - [{ts}] "{request}" {status} 512 "-" "{ua}"'


def parse_fixture(name: str) -> list:
    lines = (FIXTURES / name).read_text().splitlines()
    return [e for raw in lines if (e := parse_line(raw))]


def test_combined_line():
    raw = line("GET /search?q=a%20b&x=1 HTTP/1.1", status=404)
    event = parse_line(raw)
    assert (event.source, event.event_type, str(event.src_ip)) == (
        "nginx",
        EventType.HTTP_REQUEST,
        "203.0.113.7",
    )
    assert (event.http_method, event.url_path, event.url_query) == ("GET", "/search", "q=a%20b&x=1")
    assert (event.http_status, event.user_agent, event.raw) == (404, UA, raw)
    assert event.ts == datetime(2026, 10, 22, 14, 3, tzinfo=UTC)


def test_time_local_offset_is_converted_to_utc():
    event = parse_line(line("GET / HTTP/1.1", ts="22/Oct/2026:16:03:00 +0200"))
    assert event.ts == datetime(2026, 10, 22, 14, 3, tzinfo=UTC)


def test_ipv6_source():
    event = parse_line(line("GET / HTTP/1.1").replace("203.0.113.7", "2001:db8::bad:1"))
    assert event.src_ip == IPv6Address("2001:db8::bad:1")


@pytest.mark.parametrize(
    ("request_", "path", "query"),
    [
        ("GET / HTTP/1.1", "/", None),
        ("GET /a? HTTP/1.1", "/a", None),
        ("GET /a?b?c HTTP/2.0", "/a", "b?c"),
        ("GET /old", "/old", None),  # HTTP/0.9
    ],
)
def test_request_target_split(request_, path, query):
    event = parse_line(line(request_))
    assert (event.url_path, event.url_query) == (path, query)


@pytest.mark.parametrize("request_", ["", "-", r"\x16\x03\x01\x02\x00", "GET /a b HTTP/1.1"])
def test_unparseable_request_still_yields_event(request_):
    event = parse_line(line(request_, status=400))
    assert (event.http_method, event.url_path, event.http_status) == (None, None, 400)


def test_escaped_quote_cannot_spoof_fields():
    # nginx writes a client's '"' as \x22, so the payload stays inside its field
    event = parse_line(line(r"GET /?q=\x22%20200%20 HTTP/1.1", ua=r"\x22 999 1 \x22-\x22 \x22x"))
    assert event.http_status == 200
    assert event.url_query == r"q=\x22%20200%20"
    assert event.user_agent == r"\x22 999 1 \x22-\x22 \x22x"


def test_missing_user_agent_is_none():
    assert parse_line(line("GET / HTTP/1.1", ua="-")).user_agent is None


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "garbage",
        "Oct 22 10:00:00 web01 sshd[1]: Invalid user x from 203.0.113.7 port 22",
        line("GET / HTTP/1.1").replace("203.0.113.7", "999.1.1.1"),
        line("GET / HTTP/1.1").replace("203.0.113.7", "unix:"),
        line("GET / HTTP/1.1", ts="30/Feb/2026:14:03:00 +0000"),
        line("GET / HTTP/1.1", ts="22/Oct/2026:14:03:00"),  # no offset
        line("GET /" + "a" * MAX_LINE + " HTTP/1.1"),
    ],
)
def test_junk_lines_are_ignored(raw):
    assert parse_line(raw) is None


def test_benign_fixture():
    events = parse_fixture("nginx_benign.log")
    assert [(e.http_method, e.url_path, e.http_status) for e in events] == [
        ("GET", "/", 200),
        ("GET", "/favicon.ico", 404),
        ("GET", "/search", 200),
        ("POST", "/login", 302),
        ("GET", "/healthz", 200),
        ("HEAD", "/robots.txt", 200),
    ]
    assert events[-1].user_agent is None


def test_attacks_fixture():
    events = parse_fixture("nginx_attacks.log")
    assert len(events) == 7
    assert {str(e.src_ip) for e in events} == {"203.0.113.9"}
    assert events[1].url_query == "file=../../../../etc/passwd"
    assert events[-1].url_path is None  # TLS handshake sent to the HTTP port


@pytest.mark.parametrize(("size", "expected"), [("512", 512), ("-", None)])
def test_body_bytes_sent(size, expected):
    raw = line("GET / HTTP/1.1").replace(" 512 ", f" {size} ")
    assert parse_line(raw).http_bytes == expected
