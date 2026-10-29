from pydantic import PositiveInt

from logsentry.models import Alert, Event, EventType, Severity
from logsentry.rules.base import Rule, RuleConfig, SlidingWindow


class PasswordSpray(Rule):
    id = "password_spray"
    name = "SSH password spray"
    technique_id = "T1110.003"
    tactic = "Credential Access"
    severity = Severity.MEDIUM
    sources = frozenset({"sshd"})
    explanation = (
        "{count} failed SSH logins for {user_count} different users from {src_ip}"
        " within {window_seconds}s"
    )

    class Config(RuleConfig):
        threshold: PositiveInt  # distinct user names
        window_seconds: PositiveInt

    config: Config

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self.window = SlidingWindow(config.window_seconds)

    def process(self, event: Event) -> list[Alert]:
        # same reason as ssh_bruteforce: "Invalid user" repeats a failure that is logged anyway
        if event.event_type != EventType.AUTH_FAILURE:
            return []
        events = self.window.add(event.src_ip, event)
        user_count = len({e.user_name for e in events})
        if user_count < self.config.threshold:
            return []
        return [
            self.make_alert(
                list(events), user_count=user_count, window_seconds=self.config.window_seconds
            )
        ]
