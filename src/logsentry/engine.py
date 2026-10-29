"""Send each event to the rules that handle its source, and suppress repeat alerts."""

from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path

from logsentry.config import load_config
from logsentry.models import Alert, Event
from logsentry.rules import Rule


class Engine:
    def __init__(self, rules: list[Rule], cooldown_seconds: int) -> None:
        self.rules = rules
        self.cooldown = timedelta(seconds=cooldown_seconds)
        # shortcut: one entry per (rule, IP) that ever alerted, never pruned; fine for a lab,
        # prune entries older than the cooldown if this ever runs against internet traffic
        self._last_alert: dict[tuple[str, IPv4Address | IPv6Address], datetime] = {}

    @classmethod
    def from_config(cls, path: Path) -> "Engine":
        settings, rules = load_config(path)
        return cls(rules, settings.cooldown_seconds)

    def process(self, event: Event) -> list[Alert]:
        alerts = []
        for rule in self.rules:
            if event.source not in rule.sources:
                continue
            for alert in rule.process(event):
                if not rule.cooldown:
                    alerts.append(alert)
                    continue
                key = (alert.rule_id, alert.src_ip)
                last = self._last_alert.get(key)
                if last is not None and alert.last_seen - last < self.cooldown:
                    continue
                self._last_alert[key] = alert.last_seen
                alerts.append(alert)
        return alerts
