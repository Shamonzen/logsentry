from pathlib import Path

import pytest
from pydantic import ValidationError

from logsentry.config import load_config
from logsentry.rules.ssh_bruteforce import SshBruteforce

CONFIG = Path(__file__).parent.parent / "config" / "rules.yaml"

VALID = """
cooldown_seconds: 300
outcome_window_seconds: 10
campaign_gap_seconds: 1800
rules:
  ssh_bruteforce: {threshold: 10, window_seconds: 60}
  password_spray: {threshold: 5, window_seconds: 300}
  success_after_failures: {threshold: 5, window_seconds: 600}
  web_scan: {threshold: 20, window_seconds: 60}
  web_attack: {patterns_file: web_patterns.yaml, group_gap_seconds: 1800}
  web_login_bruteforce: {threshold: 10, window_seconds: 60, login_paths: [/login$]}
"""


def write(tmp_path, text):
    path = tmp_path / "rules.yaml"
    path.write_text(text)
    # patterns_file is relative to rules.yaml
    (tmp_path / "web_patterns.yaml").write_text((CONFIG.parent / "web_patterns.yaml").read_text())
    return path


def test_repo_config_loads():
    settings, rules = load_config(CONFIG)
    assert settings.cooldown_seconds > 0
    assert {r.id for r in rules} == {
        "ssh_bruteforce",
        "password_spray",
        "success_after_failures",
        "web_scan",
        "web_attack",
        "web_login_bruteforce",
    }


def test_valid_config(tmp_path):
    settings, rules = load_config(write(tmp_path, VALID))
    rule = next(r for r in rules if r.id == "ssh_bruteforce")
    assert isinstance(rule, SshBruteforce)
    assert (rule.config.threshold, rule.config.window_seconds) == (10, 60)
    assert settings.cooldown_seconds == 300


def test_disabled_rule_is_dropped(tmp_path):
    text = VALID.replace("ssh_bruteforce: {", "ssh_bruteforce: {enabled: false, ")
    assert "ssh_bruteforce" not in {r.id for r in load_config(write(tmp_path, text))[1]}


@pytest.mark.parametrize(
    "text",
    [
        "",
        "cooldown_seconds: 300\nrules: {}",  # rule section missing: thresholds have no defaults
        VALID + "typo_key: 1",
        VALID.replace("window_seconds: 60", "window_seconds: 60, windw: 5"),
        VALID.replace("threshold: 10", "threshold: 0"),
        VALID.replace("threshold: 10", "threshold: ten"),
        VALID.replace("cooldown_seconds: 300", "cooldown_seconds: -1"),
        VALID.replace("login_paths: [/login$]", "login_paths: []"),
        VALID.replace("web_patterns.yaml", "missing.yaml"),
    ],
)
def test_invalid_config_is_rejected(tmp_path, text):
    with pytest.raises(ValidationError):
        load_config(write(tmp_path, text))


def test_unknown_rule_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="unknown rules.*no_such_rule"):
        load_config(write(tmp_path, VALID + "  no_such_rule: {}\n"))


def test_yaml_tags_are_not_executed(tmp_path):
    # safe_load refuses python-object tags instead of constructing them
    with pytest.raises(Exception, match="python/object"):
        load_config(write(tmp_path, "!!python/object/apply:os.system ['echo pwned']"))
