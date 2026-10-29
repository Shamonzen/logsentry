from collections.abc import Callable
from pathlib import Path

import pytest

from logsentry.models import Event
from logsentry.parsers import nginx, sshd

FIXTURES = Path(__file__).parent / "fixtures"


def parse_any(line: str) -> Event | None:
    return sshd.parse_line(line, year=2026) or nginx.parse_line(line)


@pytest.fixture
def load_events() -> Callable[[str], list[Event]]:
    """Parse a fixture file into events, skipping lines no parser understands."""

    def load(name: str) -> list[Event]:
        lines = (FIXTURES / name).read_text().splitlines()
        return [e for line in lines if (e := parse_any(line))]

    return load
