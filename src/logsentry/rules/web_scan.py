from pydantic import PositiveInt

from logsentry.models import Alert, Event, Severity
from logsentry.rules.base import Rule, RuleConfig, SlidingWindow


class WebScan(Rule):
    id = "web_scan"
    name = "Web scanning"
    technique_id = "T1595.003"  # Wordlist Scanning; scanner User-Agents are a web_attack category
    tactic = "Reconnaissance"
    severity = Severity.LOW
    sources = frozenset({"nginx", "iis"})
    explanation = "Web scanning from {src_ip}: {reason}"

    class Config(RuleConfig):
        threshold: PositiveInt  # 404 responses from one IP...
        window_seconds: PositiveInt

    config: Config

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self.window = SlidingWindow(config.window_seconds)

    def process(self, event: Event) -> list[Alert]:
        if event.http_status == 404:
            events = self.window.add(event.src_ip, event)
            if len(events) >= self.config.threshold:
                reason = f"{len(events)} 404 responses within {self.config.window_seconds}s"
                return [self.make_alert(list(events), reason=reason)]
        return []
