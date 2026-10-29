from pydantic import PositiveInt

from logsentry.models import Alert, Event, EventType, Severity
from logsentry.rules.base import Rule, RuleConfig, SlidingWindow


class SuccessAfterFailures(Rule):
    id = "success_after_failures"
    name = "SSH login after repeated failures"
    technique_id = "T1078"
    tactic = "Initial Access"
    severity = Severity.HIGH
    sources = frozenset({"sshd"})
    explanation = (
        "Successful SSH login as {user} from {src_ip} after {failures} failed attempts"
        " within {window_seconds}s"
    )

    class Config(RuleConfig):
        threshold: PositiveInt  # failures before the success
        window_seconds: PositiveInt

    config: Config

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self.failures = SlidingWindow(config.window_seconds)

    def process(self, event: Event) -> list[Alert]:
        if event.event_type == EventType.AUTH_FAILURE:
            self.failures.add(event.src_ip, event)
            return []
        if event.event_type != EventType.AUTH_SUCCESS:
            return []
        failures = self.failures.prune(event.src_ip, event.ts)
        if len(failures) < self.config.threshold:
            return []
        return [
            self.make_alert(
                [*failures, event],
                user=event.user_name,
                failures=len(failures),
                window_seconds=self.config.window_seconds,
            )
        ]
