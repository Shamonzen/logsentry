"""End-to-end: the lab's attacks must surface every rule on the dashboard API.

Needs the lab up and the attacks run first: `make lab && make attack && uv run pytest -m e2e`.
"""

import contextlib
import json
import time
import urllib.request

import pytest

from logsentry.rules import RULES

API = "http://127.0.0.1:8000/api/alerts"


def fetch_rule_ids() -> set[str]:
    with urllib.request.urlopen(API, timeout=5) as resp:
        # web_attack alerts are named per category: web_attack.sqli, web_attack.xss, ...
        return {a["rule_id"].split(".")[0] for a in json.load(resp)}


@pytest.mark.e2e
def test_every_rule_fires_in_the_lab() -> None:
    expected = set(RULES)
    seen: set[str] = set()
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        with contextlib.suppress(OSError):  # web container may still be starting
            seen = fetch_rule_ids()
        if expected <= seen:
            return
        time.sleep(2)
    pytest.fail(f"missing rule_ids after 60s: {sorted(expected - seen)}")
