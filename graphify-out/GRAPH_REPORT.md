# Graph Report - logsentry  (2026-10-29)

## Corpus Check
- 70 files · ~68,988 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 28 file(s) not represented in the graph (top: .log 13, (none) 8, .service 3)

## Summary
- 761 nodes · 1814 edges · 56 communities (31 shown, 25 thin omitted)
- Extraction: 89% EXTRACTED · 11% INFERRED · 0% AMBIGUOUS · INFERRED: 194 edges (avg confidence: 0.92)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `4654270c`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- campaigns.py
- store.py
- Rule Config and Plan
- pytest
- app.py
- Severity
- Rule Base Classes
- test_parser_iis.py
- lib.sh
- sshd Parser
- test_parser_nginx.py
- Password Spray Tests
- test_outcome.py
- Success-After-Failures Tests
- test_rule_web_login_bruteforce.py
- Event-Time Windowing
- test_web.py
- CI Pipeline
- Project Instructions
- Pipeline Overview
- Package Root
- 05_web_attacks.sh
- 01_ssh_bruteforce.sh
- 02_spray.sh
- 03_success.sh
- 04_web_scan.sh
- Engine
- main
- install.sh
- test_e2e.py
- outcome.py
- test_notify.py
- web_attack.py
- Event
- web_attack.py
- 06_web_login_bruteforce.sh
- pathlib
- test_rule_success_after_failures.py
- notify.py
- list_alerts
- test_engine.py
- parse_line
- cli.py
- test_rule_ssh_bruteforce.py
- ErrorLine
- [1.0.0] - 2026-10-29
- sshd.py
- _severity

## God Nodes (most connected - your core abstractions)
1. `Event` - 56 edges
2. `Severity` - 53 edges
3. `Alert` - 46 edges
4. `make_rule()` - 31 edges
5. `main()` - 30 edges
6. `SlidingWindow` - 26 edges
7. `create_app()` - 26 edges
8. `Rule` - 25 edges
9. `RuleConfig` - 22 edges
10. `run()` - 22 edges

## Surprising Connections (you probably didn't know these)
- `Current state (check in the code before changing anything)` --references--> `ingest()`  [INFERRED]
  docs/apache-error-log-spec.md → src/logsentry/cli.py
- `Added` --references--> `tail()`  [INFERRED]
  CHANGELOG.md → src/logsentry/cli.py
- `Goal` --references--> `succeeded()`  [INFERRED]
  docs/apache-error-log-spec.md → tests/test_rule_web_attack.py
- `2. Correlate with the access log and set an outcome` --references--> `succeeded()`  [INFERRED]
  docs/apache-error-log-spec.md → tests/test_rule_web_attack.py
- `test_ingest_groups_the_rfi_fixture_ips_into_one_campaign()` --calls--> `main()`  [INFERRED]
  tests/test_cli.py → src/logsentry/cli.py

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Dashboard templates (milestone 9: list, HTMX rows partial, detail, layout)** — src_logsentry_web_templates_base, src_logsentry_web_templates_alerts, src_logsentry_web_templates__rows, src_logsentry_web_templates_alert [EXTRACTED 1.00]
- **Five detection rule configs mapped to ATT&CK** — config_rules_ssh_bruteforce, config_rules_password_spray, config_rules_success_after_failures, config_rules_web_scan, config_rules_web_attack [EXTRACTED 1.00]
- **Defenses against attacker-controlled log content** — claude_attacker_controlled_logs [INFERRED 0.85]
- **Defenses against attacker-controlled log content** — docs_plan_analyst_tool_attack_surface, docs_plan_stdlib_sqlite3, src_logsentry_web_templates_base [INFERRED 0.85]

## Communities (56 total, 25 thin omitted)

### Community 0 - "campaigns.py"
Cohesion: 0.18
Nodes (12): Campaign, group(), rebuild(), alert(), stored(), test_a_lone_ip_is_not_a_campaign(), test_a_quiet_gap_longer_than_the_window_splits_campaigns(), test_different_slash24s_are_not_a_campaign() (+4 more)

### Community 1 - "store.py"
Cohesion: 0.07
Nodes (23): _alert_dict(), campaign_inputs(), connect(), connect_readonly(), count_alerts_since(), get_alert(), get_campaign(), get_offset() (+15 more)

### Community 2 - "Rule Config and Plan"
Cohesion: 0.07
Nodes (25): rules.yaml detection thresholds, cooldown_seconds: 300, password_spray config (5 users in 300s, T1110.003), ssh_bruteforce config (10 in 60s, T1110.001), success_after_failures config (5 in 600s, T1078), web_attack config (T1190), web_scan config (20 404s in 60s + scanner UAs, T1595), LogSentry MVP plan (+17 more)

### Community 3 - "pytest"
Cohesion: 0.09
Nodes (20): load_config(), Settings, check_config(), check_db(), check_log(), check_phone(), check_service(), check_timer() (+12 more)

### Community 4 - "app.py"
Cohesion: 0.10
Nodes (7): attack_url(), cwe_url(), data_range(), duration(), short_ts(), status_class(), timeline()

### Community 5 - "Severity"
Cohesion: 0.21
Nodes (10): Severity, client(), db(), make_alert(), test_attack_column_shows_the_chain_and_cwe_links(), test_detail_page_shows_matches_escaped(), test_detail_page_shows_outcome_evidence_escaped(), test_list_and_detail_show_categories_and_campaign() (+2 more)

### Community 6 - "Rule Base Classes"
Cohesion: 0.61
Nodes (8): from_ip(), make_rule(), run(), test_benign_fixture_does_not_fire(), test_fewer_404s_than_threshold_do_not_fire(), test_fires_on_404_burst(), test_scanner_user_agent_alone_is_not_a_scan(), test_slow_scan_outside_window_does_not_fire()

### Community 7 - "test_parser_iis.py"
Cohesion: 0.20
Nodes (11): W3CParser, parse(), parse_fixture(), test_attacks_fixture(), test_benign_fixture(), test_dash_means_empty(), test_default_fields_without_header(), test_header_missing_required_field_falls_back_to_default() (+3 more)

### Community 8 - "lib.sh"
Cohesion: 0.50
Nodes (3): guard_target(), lib.sh script, run_all.sh script

### Community 9 - "sshd Parser"
Cohesion: 0.23
Nodes (11): parse_line(), parse_fixture(), test_auth_messages(), test_benign_fixture(), test_bruteforce_fixture(), test_bsd_timestamp_uses_given_year_and_utc(), test_ipv6_source(), test_junk_lines_are_ignored() (+3 more)

### Community 10 - "test_parser_nginx.py"
Cohesion: 0.28
Nodes (14): parse_line(), line(), parse_fixture(), test_attacks_fixture(), test_benign_fixture(), test_body_bytes_sent(), test_combined_line(), test_escaped_quote_cannot_spoof_fields() (+6 more)

### Community 11 - "Password Spray Tests"
Cohesion: 0.61
Nodes (7): make_rule(), run(), test_benign_fixture_does_not_fire(), test_fires_on_spray_fixture(), test_invalid_user_lines_are_not_counted_as_extra_users(), test_many_failures_for_one_user_is_not_a_spray(), test_slow_spray_outside_window_does_not_fire()

### Community 12 - "test_outcome.py"
Cohesion: 0.11
Nodes (16): first_alert(), judge(), test_all_failed_burst_is_failed_and_evidence_is_capped(), test_error_log_ending_before_the_request_is_unknown(), test_error_log_ending_soon_after_the_request_still_covers_it(), test_failed_rfi_matches_by_url_in_local_time(), test_no_error_log_is_unknown_even_with_a_telling_size(), test_no_include_error_in_covered_window_means_succeeded() (+8 more)

### Community 13 - "Success-After-Failures Tests"
Cohesion: 0.10
Nodes (51): 1. Parse Apache error_log, 2. Correlate with the access log and set an outcome, 3. Tests, 4. Docs, Current state (check in the code before changing anything), Feature: Apache error_log ingestion and attack outcome verdicts, Goal, Out of scope (separate tasks later) (+43 more)

### Community 14 - "test_rule_web_login_bruteforce.py"
Cohesion: 0.22
Nodes (11): load_events(), load(), parse_any(), burst(), make_rule(), run(), test_fires_on_a_burst_of_login_posts(), test_get_requests_do_not_count() (+3 more)

### Community 16 - "test_web.py"
Cohesion: 0.10
Nodes (8): ips(), test_bad_filter_values_are_rejected(), test_filters(), test_internal_sources_have_a_badge_and_a_filter(), test_missing_database_is_503(), test_pages_link_versioned_assets(), test_sorted_by_severity_then_most_recent(), test_web_cannot_write()

### Community 31 - "Engine"
Cohesion: 0.20
Nodes (7): emit(), handle_line(), ingest(), poll(), Engine, test_restart_does_not_alert_twice(), test_tail_updates_a_growing_web_alert_in_place()

### Community 32 - "main"
Cohesion: 0.05
Nodes (38): main(), ingest_rfi(), test_campaign_fixture_shows_a_succeeded_rfi_chain_and_a_campaign(), test_error_log_needs_an_access_log_source(), test_help_exits_cleanly(), test_ingest_counts_the_requests_a_web_alert_grouped(), test_ingest_groups_the_rfi_fixture_ips_into_one_campaign(), test_ingest_stores_and_prints_expected_alerts() (+30 more)

### Community 33 - "install.sh"
Cohesion: 0.55
Nodes (10): apt_install(), ask(), check_ssh_log(), die(), install_app(), say(), setup_phone(), install.sh script (+2 more)

### Community 35 - "outcome.py"
Cohesion: 0.23
Nodes (4): judge(), _local_time(), _size_note(), verdict()

### Community 36 - "test_notify.py"
Cohesion: 0.24
Nodes (8): alerts_from(), FakeResponse, sent(), fake_urlopen(), test_high_alert_is_pushed(), test_medium_alert_is_not_pushed(), test_poll_hands_every_alert_to_the_callback(), test_push_failure_is_reported_not_raised()

### Community 37 - "web_attack.py"
Cohesion: 0.20
Nodes (4): Category, _compile(), FollowOn, Pattern

### Community 38 - "Event"
Cohesion: 0.06
Nodes (27): Alert, Event, EventType, is_internal(), Rule, RuleConfig, SlidingWindow, PasswordSpray (+19 more)

### Community 39 - "web_attack.py"
Cohesion: 0.28
Nodes (4): CategoryResult, Match, Technique, _clean()

### Community 41 - "pathlib"
Cohesion: 0.19
Nodes (6): read_new_lines(), read_and_save(), test_missing_file_is_skipped(), test_resumes_from_saved_offset_and_waits_for_partial_lines(), test_rotation_and_truncation_restart_from_zero(), test_tail_requires_a_file()

### Community 42 - "test_rule_success_after_failures.py"
Cohesion: 0.61
Nodes (7): make_rule(), run(), test_benign_fixture_does_not_fire(), test_failures_alone_do_not_fire(), test_failures_from_another_ip_do_not_count(), test_failures_older_than_window_are_forgotten(), test_fires_on_success_after_failures_fixture()

### Community 44 - "list_alerts"
Cohesion: 0.22
Nodes (9): subnet(), create_app(), alert_detail(), api_alerts(), campaigns_page(), conn(), index(), rows() (+1 more)

### Community 45 - "test_engine.py"
Cohesion: 0.50
Nodes (8): engine(), run(), shifted(), test_cooldown_is_per_ip(), test_events_only_reach_rules_for_their_source(), test_from_repo_config_with_benign_logs(), test_one_bruteforce_gives_one_alert(), test_same_attack_after_cooldown_alerts_again()

### Community 50 - "test_rule_ssh_bruteforce.py"
Cohesion: 0.61
Nodes (7): make_rule(), run(), test_benign_fixture_does_not_fire(), test_evidence_is_capped(), test_fires_on_bruteforce_fixture(), test_invalid_user_lines_are_not_double_counted(), test_slow_attack_outside_window_does_not_fire()

### Community 51 - "ErrorLine"
Cohesion: 0.20
Nodes (4): read_error_log(), _client(), ErrorLine, parse_line()

### Community 52 - "[1.0.0] - 2026-10-29"
Cohesion: 0.50
Nodes (3): [1.0.0] - 2026-10-29, Added, Changelog

## Knowledge Gaps
- **14 isolated node(s):** `logsentry`, `CI lint-test job (uv sync, ruff, pytest)`, `success_after_failures config (5 in 600s, T1078)`, `web_attack config (T1190)`, `web_scan config (20 404s in 60s + scanner UAs, T1595)` (+9 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 234 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **25 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Event` connect `Event` to `outcome.py`, `web_attack.py`, `test_parser_iis.py`, `sshd Parser`, `test_parser_nginx.py`, `models.py`, `test_rule_web_login_bruteforce.py`, `cli.py`, `sshd.py`, `Engine`?**
  _High betweenness centrality (0.093) - this node is a cross-community bridge._
- **Are the 21 inferred relationships involving `Event` (e.g. with `handle_line()` and `ingest()`) actually correct?**
  _`Event` has 21 INFERRED edges - model-reasoned connections that need verification._
- **What connects `logsentry`, `CI lint-test job (uv sync, ruff, pytest)`, `success_after_failures config (5 in 600s, T1078)` to the rest of the system?**
  _14 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `store.py` be split into smaller, more focused modules?**
  _Cohesion score 0.07227891156462585 - nodes in this community are weakly interconnected._
- **Why does `Severity` connect `Severity` to `campaigns.py`, `store.py`, `app.py`, `web_attack.py`, `Event`, `web_attack.py`, `test_notify.py`, `Rule Base Classes`, `test_rule_success_after_failures.py`, `notify.py`, `list_alerts`, `Password Spray Tests`, `models.py`, `Success-After-Failures Tests`, `test_rule_web_login_bruteforce.py`, `cli.py`, `test_rule_ssh_bruteforce.py`, `_severity`?**
  _High betweenness centrality (0.082) - this node is a cross-community bridge._
- **Are the 37 inferred relationships involving `Severity` (e.g. with `push()` and `Rule`) actually correct?**
  _`Severity` has 37 INFERRED edges - model-reasoned connections that need verification._
- **Should `Rule Config and Plan` be split into smaller, more focused modules?**
  _Cohesion score 0.06818181818181818 - nodes in this community are weakly interconnected._