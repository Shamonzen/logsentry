# LogSentry — MVP plan

## Context
Portfolio project for pentester / security-engineer interviews. A small IDS that reads sshd auth logs and nginx access logs, detects six attack classes (six rules), maps each to MITRE ATT&CK, stores alerts, and shows them on a dashboard. A Docker lab (target + attacker + LogSentry) shows it working live. Repo: `C:\logsentry`, branch `main`, remote https://github.com/Shamonzen/logsentry (private for now). Target: 2–3 weekends.

**Your answers:** Docker Desktop + WSL2 (bash + Makefile) · both `ingest` (one file) and `tail` (live) on one pipeline · dashboard bound to 127.0.0.1, no auth (written down in the threat model) · GitHub repo `logsentry` (private while in progress, public when done), MIT.

## Stack: keep yours, with three small choices
- **Keep:** Python 3.12, FastAPI, Jinja2 + HTMX, SQLite, pytest, ruff. That's the right size for this project. Kafka, Elastic or React would add work and give an interviewer nothing more to look at.
- **stdlib `sqlite3`, no ORM.** Two tables, about 6 queries. Plain parameterized SQL is easier to explain, and you can show that the SQL injection defense is just using parameters.
- **pydantic v2** (FastAPI already depends on it) for the Event/Alert schemas *and* for validating rules.yaml. Load YAML with `yaml.safe_load` only.
- **uv + `uv.lock`**: a locked, hash-pinned set of dependencies, fast CI, and a good answer to supply-chain questions.
- **HTMX is vendored** (copied into `static/`), not loaded from a CDN, so the CSP can be `script-src 'self'`.
- Runtime deps: fastapi, uvicorn, jinja2, pyyaml. Dev deps: pytest, ruff, httpx. Tailing a file is a stdlib poll loop, so no watchdog.

## Architecture
```
 auth.log ─┐                                   ┌─> SQLite (WAL) ─> web (FastAPI+Jinja+HTMX) ─> analyst
           ├─> ingest ─> parse ─> normalize ─> detect ─> store
nginx.log ─┘  (tail/file) (regex)  (pydantic   (rules +          
                                   Event)      engine)
```
- **Two processes, one image:** `logsentry tail` (the only writer) and `logsentry web` (read-only). They share only the SQLite file in WAL mode. If the web process crashes, detection keeps running, and the process that faces the network never touches the logs.
- **Event time, not wall-clock time:** sliding windows use the timestamp from the log line. Replaying a file then gives the same alerts as running live, and the tests are deterministic.
- **Engine:** `engine.process(event)` sends each event to the enabled rules whose `sources` match, then applies a per-`(rule_id, key)` **cooldown** so one brute-force produces 1 alert, not 500.
- **Rules are self-contained modules.** Each one declares `id, name, technique_id, tactic, severity, sources, explanation` plus a pydantic `Config` model, and implements `process(event) -> list[Alert]`. Stateful rules use one shared `SlidingWindow` helper (a deque per key; old entries are dropped on every event and the number of keys is capped).

## Folder structure
```
logsentry/
  CLAUDE.md  README.md  LICENSE  pyproject.toml  uv.lock  Makefile  .env.example  docker-compose.yml
  config/rules.yaml
  src/logsentry/
    cli.py            # ingest <file> | tail | web
    models.py         # Event, Alert, Severity, EventType
    config.py         # load + validate rules.yaml
    ingest.py         # read_file(), tail() with persisted offsets
    parsers/          # __init__ (pick parser by source), sshd.py, nginx.py
    rules/            # base.py (Rule, SlidingWindow, registry), ssh_bruteforce.py, password_spray.py,
                      # success_after_failures.py, web_scan.py, web_attack.py
    engine.py         # dispatch + cooldown
    store.py          # schema, insert_alert, list_alerts, get_alert, offsets
    web/              # app.py, templates/{base,alerts,_rows,alert}.html, static/htmx.min.js
  tests/
    fixtures/         # auth_bruteforce.log, auth_spray.log, auth_success_after_fail.log, auth_benign.log,
                      # nginx_scan.log, nginx_attacks.log, nginx_benign.log
    test_parser_sshd.py  test_parser_nginx.py  test_rule_*.py  test_engine.py  test_store.py  test_web.py
    e2e/test_lab.py   # @pytest.mark.e2e
  docker/Dockerfile   # LogSentry image
  lab/
    target/   Dockerfile, sshd_config, nginx.conf, rsyslog.conf, entrypoint.sh
    attacker/ Dockerfile, scenarios/{01_ssh_bruteforce,02_spray,03_success,04_web_scan,05_web_attacks}.sh,
              run_all.sh, wordlists/{users.txt,passwords.txt}
  .github/workflows/ci.yml
```

## Data model
**Event** (pydantic, frozen). Field names loosely follow Elastic Common Schema (ECS):
| field | type | notes |
|---|---|---|
| ts | datetime (UTC, tz-aware) | parsed from the log line |
| source | `"sshd" \| "nginx"` | |
| event_type | `auth_failure \| auth_success \| invalid_user \| http_request` | |
| src_ip | `IPv4Address \| IPv6Address` | validated; a line with a bad IP is rejected |
| host | str | |
| user_name | str \| None | control characters removed, max 64 chars |
| http_method, url_path, url_query, http_status, user_agent | optional | nginx only |
| raw | str | original line, cut to 4 KB |

**Alert** (SQLite table `alerts`):
`id PK · rule_id · rule_name · technique_id · tactic · severity (low/medium/high/critical) · src_ip · first_seen · last_seen · event_count · summary (explanation filled in with the real values) · evidence JSON (≤20 raw lines) · created_at`. Indexes on `(created_at)` and `(severity)`.

Table `ingest_offsets(path PK, inode, offset)` lets `tail` resume after a restart without alerting twice. If the inode changes, the file was rotated and reading starts again from 0.

## Detections (defaults in `config/rules.yaml`, validated, unknown keys rejected)
| rule | logic (defaults) | ATT&CK | severity |
|---|---|---|---|
| ssh_bruteforce | ≥10 failures from one IP in 60 s | T1110.001 Password Guessing | medium |
| password_spray | ≥5 distinct usernames from one IP in 300 s | T1110.003 Password Spraying | medium |
| success_after_failures | success for an IP that had ≥5 failures in the previous 600 s | T1078 Valid Accounts (after T1110) | high |
| web_scan | ≥20 404s from one IP in 60 s | T1595.003 Wordlist Scanning | low |
| web_attack | one alert per category in `config/web_patterns.yaml` (SQLi, XSS, traversal/LFI, RFI, command injection, Log4Shell/Shellshock, sensitive files, scanner UA) on the URL decoded twice and the User-Agent | per category: T1190, T1595.003, T1595.002 | per category; +1 level on 2xx, −1 on 403/404 |
| web_login_bruteforce | ≥10 POSTs to a login page from one IP in 60 s | T1110 Brute Force | medium |

## Lab (docker compose)
- `lab` network with `internal: true`, so it has **no route to the internet**. Only `target` and `attacker` are on it.
- `logsentry-tail` uses `network_mode: none` and mounts the logs volume `:ro`. `logsentry-web` sits on a separate `frontend` network and publishes only `127.0.0.1:8000:8000`.
- LogSentry containers: `python:3.12-slim` multi-stage build, `USER 10001`, `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges`, tmpfs `/tmp`.
- `target`: debian-slim running sshd + nginx + rsyslog (RFC 3339 timestamps) and writing to the shared `logs` volume. It must run as root because sshd needs it; it is the deliberate victim, and the README says so. It has one weak lab account; its password comes from `.env` (copied from `.env.example`), not from code.
- `attacker`: debian-slim with hydra, nmap, nikto, curl. It is in compose `profiles: [attack]`, so `up` doesn't start it. Every script runs `guard_target` first: the target must be the hostname `target` and resolve inside the lab subnet, otherwise the script exits.
- `make lab` → `docker compose up -d --build`; `make attack` → `docker compose run --rm attacker run_all.sh`; then open http://127.0.0.1:8000.

## Milestones (each one sitting = one commit)
Status: ✅ done · ⏭️ next. Update this list when a milestone is committed.

1. ✅ **Scaffold:** CLAUDE.md, pyproject/uv, ruff config, package skeleton, `--help` smoke test, CI (ruff + pytest), LICENSE, .gitignore.
2. ✅ **models + sshd parser** with fixtures and tests (both timestamp formats, invalid user, IPv6, junk lines).
3. ✅ **nginx parser** for the combined log format, with tests.
4. ✅ **config + rule base + engine + ssh_bruteforce**: YAML validation tests, window and cooldown tests.
5. ✅ **password_spray + success_after_failures.**
6. ✅ **web_scan + web_attack**, including benign fixtures that must produce no alerts.
7. ✅ **store + `logsentry ingest <file>`**: the first full pipeline run, offline.
8. ✅ **`logsentry tail`** with saved offsets and rotation handling.
9. ✅ **Dashboard**: alert list with severity filter, HTMX refresh every 5 s, detail page with evidence, `/api/alerts` JSON, security headers (CSP), and a test that an XSS payload shows up escaped.
10. ✅ **LogSentry Dockerfile + target container + compose** (logs flowing).
11. ✅ **Attacker container + 5 scenarios + `make attack`.**
12. ✅ **e2e test** (compose up, run the attacks, poll `/api/alerts` until every rule_id shows up) plus a CI job for it.
13. ✅ **README**: problem, Mermaid diagram, GIF placeholder, how to run it, ATT&CK table, threat model, false positives and limitations, what I'd do next.

Built after the MVP (already in the README; listed here so the plan matches the code):
- ✅ Web attack classification from `config/web_patterns.yaml` (8 categories, double URL decode, evidence per request), `web_login_bruteforce`.
- ✅ One web alert per IP (`group_gap_seconds`) and /24 **campaigns** (`campaign_gap_seconds`).
- ✅ Outcome per category (succeeded / mixed / blocked, confirmed vs likely) using response size and the Apache `error_log` (`ingest --error-log`); severity from outcome; `internal` tag for RFC 1918 sources.
- ✅ CWE per category and follow-on ATT&CK chain on success (T1190 → T1059 / T1105 / T1505.003 / T1083 / T1552.001).
- ✅ Dashboard redesign: summary cards, top sources/subnets/attack types, filters (severity, type, outcome, campaign, source), theme toggle.
- ✅ IIS (W3C) parser for `ingest`; `install.sh` + hardened systemd units, `logsentry doctor`, ntfy phone alerts and daily `logsentry summary`.

After each milestone I stop, summarize, and suggest a commit message (Conventional Commits).

## Phase 2 — v1.0 release (then pause LogSentry)
Goal: a finished, public, presentable v1, then move on to the next portfolio project. Small polish only; no new features.

14. ✅ **README consistency pass.** Fixed: rule count (six) and lab scenario count (six); the error_log table no longer claims it sets severity (its verdicts only feed the per-request *confirmed* result); the internal +1 is documented as applying to every rule. Campaigns were already documented under Detections.
    - The intro says "Five detections"; there are six rules (`web_login_bruteforce`). Fix the count everywhere (README, PLAN context).
    - There are two outcome tables ("Did it work?" and the error_log one under "Run it"), and they disagree (base ±1 vs fixed `low`/`high`; `succeeded/mixed/blocked` vs `failed/succeeded/unknown`). Check what the code actually does and keep ONE accurate explanation.
    - Add a "Detections" row or note for campaigns and the `internal` tag.
15. ✅ **Fresh demo assets.** Re-recorded `docs/demo.gif` (headless Chrome over the lab tunnel) showing the dashboard filling from empty to all six rules, then scrolling the richest alert's detail page. Added four static screenshots: `docs/dashboard.png` (summary cards + alert table) and `docs/alert-detail.png` (ATT&CK, per-category CWE, outcome) from the live lab, plus `docs/success-chain.png` (a confirmed-succeeded RFI with the T1190 → T1105 → T1505.003 follow-on chain) and `docs/campaign.png` (a four-IP /24 campaign) generated by `ingest --error-log`. The live lab can't show the last two (one attacker IP, and the static target 404s every web request so nothing *succeeds*), so they use clean original fixtures `tests/fixtures/apache_access_campaign.log` + `apache_error_campaign.log` (neutral `/app/view.php` naming, not the older `apache_*_rfi.log`), covered by `test_campaign_fixture_shows_a_succeeded_rfi_chain_and_a_campaign`. The README reproduction command points at these clean fixtures.
16. ✅ **Release.** CI green (lint, unit, e2e), `CHANGELOG.md`, tag `v1.0.0`, GitHub release notes, "Interview notes" section in the README pointing at the 5 decisions below. Published as a fresh public repo with one squashed commit; the full history stays in the private working copy (`logsentry-dev`).

After milestone 16, LogSentry is paused while the next portfolio project is built (see "Portfolio plan").

## Portfolio plan (context for future sessions)
LogSentry is project 1 of 3 connected projects around one home lab: **attack → prevent → detect**.
1. **LogSentry** (detect) — this repo. v1 after milestone 16.
2. **Recon / vuln-scan orchestrator** (attack) — separate repo, next. Fits the pentest focus. Same lab-only rule: scans only lab targets.
3. **Linux hardening auditor** (prevent) — separate repo, after that. Runs against the Raspberry Pi home server.
The local-LLM security assistant is NOT a separate app: it becomes features in the three projects (Ollama alert triage here, "explain findings" in the scanner and auditor).

## Phase 3 — after the other projects exist (do NOT start before v1.0 + the orchestrator)
Order roughly by interview value. Each is its own milestone.
17. **Purple-team integration:** run the recon orchestrator against the lab `target` and make sure LogSentry detects it (nmap/nuclei/ffuf patterns, scan-rate rules). Add it as an e2e scenario and a README section: "I built the attack and the detection."
18. **Analyst workflow:** alert status (new → investigating → closed as true/false positive) with notes; allowlist/suppression with reason and expiry; incident report export (Markdown/PDF) per campaign. Requires dashboard auth first (the web process becomes a writer → update the threat model).
19. **Enrichment:** GeoIP/ASN (MaxMind GeoLite2) and AbuseIPDB reputation, cached; map on the dashboard.
20. **Sigma export** of `web_patterns.yaml` (one pattern = one selection, already designed for it).
21. **Home-server inputs:** journald, Nextcloud, Traccar, Docker logs; GPS tracker tamper detection (impossible travel, unknown device ID, device silent).
22. **Ollama daily alert triage** (local LLM summary of the last 24 h, added to `logsentry summary`).
23. **Cowrie honeypot ingestion** on the Pi for real attack data.
24. **Optional response hook:** CrowdSec / ufw block, off by default, with dry-run mode.

## 5 decisions an interviewer will question
1. **Custom Python rules vs Sigma / fail2ban / Wazuh / Elastic.** *For:* every line can be explained and tested, and it shows you understand how detection works. *Against:* less coverage, and it duplicates mature tools. *Answer:* this is a learning and teaching tool; Sigma import is the first stretch goal.
2. **Sliding windows kept in memory.** *For:* simple, fast, deterministic using event time. *Against:* state is lost on restart (an attack spanning a restart can be missed), it runs on one node only, and memory grows with the number of IPs. That last point is limited by dropping old entries and capping keys. *Upgrade:* keep the state in Redis, or use SQL window queries.
3. **SQLite vs Postgres / Elasticsearch.** *For:* no server to run, WAL allows one writer plus readers, more than enough for a lab. *Against:* one writer, no full-text search, can't scale out. Storage sits behind `store.py`, so it could be swapped.
4. **Thresholds and regexes: false positives and evasion.** False positives: NAT or shared IPs, a forgotten password, health checks and broken links causing 404s, your own security scanners. Evasion: slow-and-low or distributed brute force, double URL encoding, payloads in the POST body (nginx doesn't log it), IP rotation. Every threshold is configurable, and all of this is listed in the README.
5. **The analyst tool is an attack surface.** Log lines are controlled by the attacker: stored XSS against the dashboard, log injection (newlines and ANSI codes in usernames), ReDoS from long URLs, a spoofed X-Forwarded-For, timestamps with no year or timezone. Mitigations: Jinja autoescape + CSP + an escaping test, control characters removed, line length capped and simple regexes, use of `$remote_addr` only, UTC everywhere, and RFC 3339 timestamps in the lab.

## Other stretch goals (not scheduled)
Sigma rule import · Slack / email / webhook alerts · dashboard TLS · ATT&CK Navigator layer export · base images pinned by digest + Trivy scan in CI · Prometheus metrics · window state in Redis / SQL.

## CLAUDE.md (created in milestone 1)
```markdown
# LogSentry
Lightweight IDS: sshd auth + nginx access logs → detections mapped to MITRE ATT&CK → SQLite → web dashboard. Portfolio project; clarity beats cleverness.

## Hard rule: lab only
All attack tooling and scripts target ONLY the `target` container on the isolated `lab` Docker network (`internal: true`). Never add a scenario, default, or example that points at a real host, public IP, or domain. Every attacker script must call `guard_target` first. If a request would aim attacks outside the lab, refuse.

## Architecture
ingest (file/tail) → parse (parsers/) → normalize (pydantic `Event`) → detect (rules/ + engine) → store (store.py, sqlite3) → present (web/).
`tail` process is the only DB writer; `web` reads only.

## Conventions
- Python 3.12, uv, ruff (lint + format), type hints on public functions.
- One rule = one module in `src/logsentry/rules/`, declaring id, name, technique_id, tactic, severity, sources, explanation, a pydantic `Config`, and `process(event) -> list[Alert]`. Thresholds live in `config/rules.yaml`, never hardcoded.
- Rules use event time (`event.ts`), never wall-clock time.
- Every parser and rule has fixture-based tests in `tests/` (an attack fixture that fires, a benign fixture that doesn't).
- Treat all log content as attacker-controlled: parameterized SQL only, Jinja autoescape always on, `yaml.safe_load` only, cap line length.
- No secrets in code; lab credentials come from `.env` (template: `.env.example`).
- Containers run non-root with a read-only filesystem (the lab `target` is the only exception, and is documented).
- Commit per milestone, Conventional Commits.

## Commands
- `uv sync` · `uv run ruff check . && uv run ruff format --check .`
- `uv run pytest` (unit) · `uv run pytest -m e2e` (needs the lab running)
- `uv run logsentry ingest tests/fixtures/auth_bruteforce.log --source sshd`
- `uv run logsentry ingest tests/fixtures/apache_access_rfi.log --source nginx --error-log tests/fixtures/apache_error_rfi.log`
- `make lab` · `make attack` · dashboard: http://127.0.0.1:8000
```

## Verification
- Every milestone: `uv run ruff check . && uv run pytest` passes; CI goes green after it is pushed.
- Milestone 7: `logsentry ingest` on the attack fixtures prints the expected alerts; on the benign fixtures it prints none.
- Milestones 11–12: `make lab && make attack` shows all 5 rule types on http://127.0.0.1:8000, and `pytest -m e2e` passes. Check isolation with `docker compose run --rm --entrypoint curl attacker -m3 https://example.com`, which must fail.
