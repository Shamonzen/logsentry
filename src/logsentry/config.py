"""Load and validate config/rules.yaml."""

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, PositiveInt

from logsentry.rules import RULES, Rule


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cooldown_seconds: PositiveInt
    outcome_window_seconds: PositiveInt
    campaign_gap_seconds: PositiveInt
    rules: dict[str, dict[str, Any]]


def load_config(path: Path) -> tuple[Settings, list[Rule]]:
    """Return the settings and the enabled rules. Raises ValueError on invalid or unknown keys."""
    settings = Settings.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
    unknown = settings.rules.keys() - RULES.keys()
    if unknown:
        raise ValueError(f"unknown rules in {path}: {', '.join(sorted(unknown))}")
    rules = [
        # base_dir: files a rule names (web_attack's patterns_file) are relative to this one
        cls(
            cls.Config.model_validate(
                settings.rules.get(rule_id, {}), context={"base_dir": path.parent}
            )
        )
        for rule_id, cls in RULES.items()
    ]
    return settings, [r for r in rules if r.config.enabled]
