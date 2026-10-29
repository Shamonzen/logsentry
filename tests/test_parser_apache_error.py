from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path

import pytest

from logsentry.models import MAX_LINE
from logsentry.parsers.apache_error import parse_line

FIXTURES = Path(__file__).parent / "fixtures"
SPEC_LINES = (FIXTURES / "apache_error_rfi.log").read_text().splitlines()


def test_failed_to_open_stream():
    e = parse_line(SPEC_LINES[1])
    assert e.ts == datetime(2024, 7, 28, 12, 49, 44)
    assert (e.level, e.client_ip) == ("error", IPv4Address("203.0.113.22"))
    assert (e.php_func, e.target) == ("include", "http://198.51.100.5/dataex.php")
    assert e.reason == "HTTP request failed! HTTP/1.1 404 Undescribed"
    assert (e.script, e.script_line) == ("/var/www/html/rfi/view.php", 3)
    assert e.failed_include


def test_failed_opening_for_inclusion():
    e = parse_line(SPEC_LINES[2])
    assert (e.php_func, e.target, e.reason) == ("include", "http://198.51.100.5/dataex.php", None)
    assert e.failed_include


@pytest.mark.parametrize("index", [3, -1])
def test_other_errors_are_not_include_failures(index):
    e = parse_line(SPEC_LINES[index])
    assert e.client_ip == IPv4Address("203.0.113.22")
    assert (e.target, e.failed_include) == (None, False)


def test_server_message_has_no_client():
    assert parse_line(SPEC_LINES[0]).client_ip is None


def test_apache_24_format():
    e = parse_line(
        "[Sun Jul 28 12:49:44.123456 2024] [php7:warn] [pid 812:tid 140] [client ::1:51234]"
        " AH01071: PHP Warning:  require_once(../conf.php): failed to open stream:"
        " No such file or directory in /var/www/html/index.php on line 9"
    )
    assert (e.level, e.client_ip, e.php_func) == ("warn", IPv6Address("::1"), "require_once")
    assert (e.target, e.reason) == ("../conf.php", "No such file or directory")


@pytest.mark.parametrize(
    "raw",
    [
        "",
        SPEC_LINES[4],  # the cut-off line
        "[Sun Jul 99 12:49:44 2024] [error] [client 203.0.113.22] bad date",
        "[Sun Jul 28 12:49:44 2024] [error] [client not-an-ip] bad client",
        SPEC_LINES[1][:30] + "x" * MAX_LINE,
    ],
)
def test_malformed_lines_are_rejected(raw):
    assert parse_line(raw) is None


def test_control_characters_are_stripped():
    e = parse_line("[Sun Jul 28 12:49:44 2024] [error] [client 203.0.113.22] a\x1b[31mb\x07c")
    assert e.message == "a[31mbc"
