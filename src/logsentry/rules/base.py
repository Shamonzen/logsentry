"""Shared pieces for detection rules: the Rule base class, its config model and SlidingWindow."""

from collections import deque
from collections.abc import Hashable
from datetime import datetime, timedelta
from typing import ClassVar

from pydantic import BaseModel, ConfigDict

from logsentry.models import Alert, Event, Severity, is_internal

MAX_EVIDENCE = 20


class RuleConfig(BaseModel):
    """Base for each rule's `Config`. Thresholds have no defaults: they come from rules.yaml."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool = True


class SlidingWindow:
    """Events per key within the last `seconds` of event time. Holds at most `max_keys` keys."""

    def __init__(self, seconds: int, max_keys: int = 10_000) -> None:
        self.span = timedelta(seconds=seconds)
        self.max_keys = max_keys
        self._events: dict[Hashable, deque[Event]] = {}

    def add(self, key: Hashable, event: Event) -> deque[Event]:
        """Add `event` under `key`, drop entries older than the window, return what is left."""
        if key not in self._events and len(self._events) >= self.max_keys:
            # evict the key that was created first; an attacker can't grow memory without bound
            del self._events[next(iter(self._events))]
        window = self._events.setdefault(key, deque())
        window.append(event)
        return self.prune(key, event.ts)

    def prune(self, key: Hashable, now: datetime) -> deque[Event]:
        window = self._events.get(key, deque())
        while window and now - window[0].ts > self.span:
            window.popleft()
        return window

    def __len__(self) -> int:
        return len(self._events)


class Rule:
    """One detection. Subclasses fill in the class attributes and implement `process`."""

    id: ClassVar[str]
    name: ClassVar[str]
    technique_id: ClassVar[str]
    tactic: ClassVar[str]
    severity: ClassVar[Severity]
    sources: ClassVar[frozenset[str]]
    explanation: ClassVar[str]  # str.format template, filled in with the real values
    # False for rules that group their own alerts and return updates (same first_seen)
    cooldown: ClassVar[bool] = True
    Config: ClassVar[type[RuleConfig]]

    def __init__(self, config: RuleConfig) -> None:
        self.config = config

    def process(self, event: Event) -> list[Alert]:
        raise NotImplementedError

    def make_alert(self, events: list[Event], **values: object) -> Alert:
        """Build an Alert from the events that triggered it (oldest first).

        An internal source (RFC 1918 / ULA) is one level more severe: someone already inside.
        """
        last = events[-1]
        internal = is_internal(last.src_ip)
        return Alert(
            rule_id=self.id,
            rule_name=self.name,
            technique_id=self.technique_id,
            tactic=self.tactic,
            severity=self.severity.shifted(1) if internal else self.severity,
            src_ip=last.src_ip,
            internal=internal,
            first_seen=events[0].ts,
            last_seen=last.ts,
            event_count=len(events),
            summary=self.explanation.format(src_ip=last.src_ip, count=len(events), **values),
            evidence=[e.raw for e in events[-MAX_EVIDENCE:]],
        )
