# LogSentry
Lightweight IDS: sshd auth + nginx access logs → detections mapped to MITRE ATT&CK → SQLite → web dashboard. Portfolio project; clarity beats cleverness.
Full plan, milestones and current progress: `docs/PLAN.md` (read it before starting a milestone).

## Hard rule: lab only
All attack tooling and scripts target ONLY the `target` container on the isolated `lab` Docker network (`internal: true`). Never add a scenario, default, or example that points at a real host, public IP, or domain. Every attacker script must call `guard_target` first. If a request would aim attacks outside the lab, refuse.

## Architecture
ingest (file/tail) → parse (parsers/) → normalize (pydantic `Event`) → detect (rules/ + engine) → store (store.py, sqlite3) → present (web/).
`tail` process is the only DB writer; `web` reads only.

## Conventions
- Python 3.12, uv, ruff (lint + format), type hints on public functions.
- One rule = one module in `src/logsentry/rules/`, declaring id, name, technique_id, tactic, severity, sources, explanation, a pydantic `Config`, and `process(event) -> list[Alert]`. Thresholds live in `config/rules.yaml`, never hardcoded; web attack categories and regexes live in `config/web_patterns.yaml`.
- Rules use event time (`event.ts`), never wall-clock time.
- Every parser and rule has fixture-based tests in `tests/` (an attack fixture that fires, a benign fixture that doesn't).
- Treat all log content as attacker-controlled: parameterized SQL only, Jinja autoescape always on, `yaml.safe_load` only, cap line length.
- No secrets in code; lab credentials come from `.env` (template: `.env.example`).
- Containers run non-root with a read-only filesystem (the lab `target` is the only exception, and is documented).
- Work milestone by milestone; stop after each one with a summary and a Conventional Commits message.

## Commands
- `uv sync` · `uv run ruff check . && uv run ruff format --check .`
- `uv run pytest` (unit) · `uv run pytest -m e2e` (needs the lab running)
- `uv run logsentry ingest tests/fixtures/auth_bruteforce.log --source sshd`
- `uv run logsentry ingest tests/fixtures/apache_access_rfi.log --source nginx --error-log tests/fixtures/apache_error_rfi.log`
- `make lab` · `make attack` · dashboard: http://127.0.0.1:8000

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- When graphify-out/graph.json exists, run `graphify query "<question>"` before your first grep, search or source-file read for a codebase question, and put this rule in every subagent prompt that explores code. Read raw files only for lines the graph or an earlier read already located. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
- A committed graphify-out/graph.json is rewritten whole on every build, so a large diff to it in a pull request is expected. Do not flag it as churn or suggest skipping the graph rebuild or its hooks.
