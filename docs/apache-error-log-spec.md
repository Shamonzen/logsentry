# Feature: Apache error_log ingestion and attack outcome verdicts

## Goal

LogSentry currently reads Apache/nginx access logs (`--source nginx`) and flags
web attacks, but it cannot tell whether an attack **worked**. A remote file
inclusion (RFI) returns HTTP 302 whether it succeeded or failed, so every RFI
alert gets the same MEDIUM rating.

Add support for Apache's `error_log` and use it to give each web-attack alert
an **outcome**: `succeeded`, `failed` or `unknown`.

## Current state (check in the code before changing anything)

- CLI: `uv run logsentry ingest <file> --source sshd|nginx|iis`, entry point in
  `src/logsentry/cli.py` (`ingest()` opens the file with
  `encoding="utf-8", errors="replace"`).
- Rules live in `config/rules.yaml`. Alerts are stored in SQLite and shown by
  `uv run logsentry web`.
- Sample logs live in `tests/fixtures/`.
- Unreadable lines are currently skipped silently.

## 1. Parse Apache error_log

Add a parser for the Apache 2.2 error log format, and 2.4 if simple:

```
[Sun Jul 28 12:49:44 2024] [error] [client 203.0.113.22] PHP Warning:  include(http://198.51.100.5/dataex.php) [<a href='function.include'>function.include</a>]: failed to open stream: HTTP request failed! HTTP/1.1 404 Undescribed\r\n in /var/www/html/rfi/view.php on line 3
[Sun Jul 28 12:49:44 2024] [error] [client 203.0.113.22] PHP Warning:  include() [<a href='function.include'>function.include</a>]: Failed opening 'http://198.51.100.5/dataex.php' for inclusion (include_path='.:/usr/share/pear:/usr/share/php') in /var/www/html/rfi/view.php on line 3
[Sun Jul 28 12:49:44 2024] [error] [client 203.0.113.22] PHP Notice:  Undefined variable: value in /var/www/html/rfi/view.php on line 4
[Sun Jul 28 13:13:14 2024] [error] [client 203.0.113.22] File does not exist: /var/www/html/rfi/yessir2345.html2345.html
```

Extract: timestamp, level, client IP, message, and, when present, the PHP
function (`include`, `require`, …), the target URL or path, and the script file
and line.

Note: error_log timestamps have **no time zone**. Access-log timestamps do
(`-0400`). Assume the error_log is in the same local time zone as the access
log it is paired with.

## 2. Correlate with the access log and set an outcome

Proposed CLI (adjust if the code suggests something cleaner):

```
uv run logsentry ingest access_log --source nginx --error-log error_log
```

For each web-attack alert from the access log, look for matching error_log
lines:

- **Match on:** same client IP, error time within 0 to 10 seconds after the
  request (PHP fetching a remote file can take a few seconds; one real case
  took 4 s), and, for inclusion attacks, the URL in `include(...)` /
  `Failed opening '...'` equals the URL in the request parameter. URL match is
  the strongest signal; use time and IP as fallback.
- **RFI / LFI verdict:**
  - `failed` if a matching `failed to open stream` or `Failed opening ... for
    inclusion` line exists. Store the reason (e.g. remote server answered 404).
  - `succeeded` if the error_log covers that time window and has no such line.
  - `unknown` if no error_log was given or it doesn't cover the time.
- **Backup heuristic (works without error_log):** compare the response size
  with the normal response size of the same script. In the sample data, normal
  and successful requests to `view.php` return 2 bytes, while failed RFI
  attempts return ~730 bytes (PHP printed the warning into the page). Use this
  only to support the verdict, and record which signal decided it.

Severity: `succeeded` → HIGH, `failed` → LOW, `unknown` → keep current level.

Show the outcome and the evidence (the matching error_log lines, or "no error
logged") in the CLI output and on the dashboard alert detail.

## 3. Tests

- Add fixtures with **synthetic** data only, using reserved IPs
  (203.0.113.0/24, 198.51.100.0/24). Don't commit real logs.
- Cases: failed RFI (remote 404), successful RFI (no include error), LFI with
  200, error_log missing → `unknown`, error_log not covering the time window →
  `unknown`, malformed error_log lines are counted and reported, not skipped
  silently.
- Existing tests must still pass.

## 4. Docs

Update the README and the user guide's command list with `--error-log` and
the outcome field.

## Out of scope (separate tasks later)

- Alert deduplication shows 25 alerts for 149 malicious requests in an IIS log
  and 3 alerts for 7 RFI requests. Add a count of grouped requests per alert
  rather than changing grouping now.
- A rule that labels `cmd.exe` / `/bin/sh` in a URL as **command execution**
  (critical) instead of "path traversal".
- Windows `.evtx` support.
