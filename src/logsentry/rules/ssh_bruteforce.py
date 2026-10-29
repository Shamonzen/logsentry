from pydantic import PositiveInt

from logsentry.models import Alert, Event, EventType, Severity
from logsentry.rules.base import Rule, RuleConfig, SlidingWindow


class SshBruteforce(Rule):
    id = "ssh_bruteforce"
    name = "SSH brute force"
    technique_id = "T1110.001"
    tactic = "Credential Access"
    severity = Severity.MEDIUM
    sources = frozenset({"sshd"})
    explanation = "{count} failed SSH logins from {src_ip} within {window_seconds}s"

    class Config(RuleConfig):
        threshold: PositiveInt
        window_seconds: PositiveInt

    config: Config

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self.window = SlidingWindow(config.window_seconds)

    def process(self, event: Event) -> list[Alert]:
        # sshd also logs "Invalid user" for the same attempt; counting it too would double-count
        if event.event_type != EventType.AUTH_FAILURE:
            return []
        events = self.window.add(event.src_ip, event)
        if len(events) < self.config.threshold:
            return []
        return [self.make_alert(list(events), window_seconds=self.config.window_seconds)]
