# Changelog

All notable changes to LogSentry are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-10-29

First public release: a lightweight IDS that reads sshd auth and nginx access
logs, maps detections to MITRE ATT&CK, stores them in SQLite and shows them on a
small web dashboard, with a Docker lab that demonstrates it catching real attacks.

### Added

- **Ingest and tail pipeline.** `logsentry ingest <file>` for offline runs and
  `logsentry tail` for live logs with saved offsets and rotation handling; `tail`
  is the only database writer, `web` reads only.
- **Parsers** for sshd auth logs (both timestamp formats, invalid users, IPv6),
  the nginx combined access log, and IIS W3C logs, each with fixture-based tests.
- **Six detection rules**, each with an ATT&CK technique, tactic, severity and a
  pydantic config with thresholds in `config/rules.yaml`: `ssh_bruteforce`,
  `password_spray`, `success_after_failures`, `web_scan`, `web_attack` and
  `web_login_bruteforce`.
- **Web attack classification** from `config/web_patterns.yaml` (eight categories,
  double URL decode, per-request evidence), with a CWE per category.
- **Outcome judging.** `ingest --error-log` pairs an Apache `error_log` with the
  access log to confirm whether an RFI / path-traversal request worked; a
  succeeded web attack raises severity and adds a follow-on ATT&CK chain
  (T1190 → T1059 / T1105 / T1505.003 / T1083 / T1552.001).
- **Campaigns.** Alerts from one /24 (IPv6 /64) within `campaign_gap_seconds`
  group into a campaign when two or more distinct IPs take part.
- **`internal` tag** (+1 severity) for RFC 1918 / IPv6 ULA sources.
- **Dashboard.** Summary cards, top sources / subnets / attack types, filters
  (severity, type, outcome, campaign, source), alert detail with evidence and
  timeline, a campaigns page, `/api/alerts` JSON, security headers (CSP) and an
  XSS-escaping test. HTMX refresh every 5 s; theme toggle.
- **Docker lab.** Hardened `target` (sshd + nginx), `logsentry-tail` and
  `logsentry-web` services, an attacker container with six lab-only scenarios
  (`make lab`, `make attack`), and an end-to-end test with its own CI job.
- **Operations.** `install.sh` with hardened systemd units, `logsentry doctor`,
  ntfy phone alerts and a daily `logsentry summary`.

[1.0.0]: https://github.com/Shamonzen/logsentry/releases/tag/v1.0.0
