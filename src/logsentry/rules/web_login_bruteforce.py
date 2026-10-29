import re

from pydantic import Field, PositiveInt

from logsentry.models import Alert, Event, Severity
from logsentry.rules.base import Rule, RuleConfig, SlidingWindow


class WebLoginBruteforce(Rule):
    id = "web_login_bruteforce"
    name = "Login brute force"
    technique_id = "T1110"
    tactic = "Credential Access"
    # not raised on 2xx: login forms answer 200 to a wrong password too
    severity = Severity.MEDIUM
    sources = frozenset({"nginx", "iis"})
    explanation = "{count} POSTs to login pages from {src_ip} within {window}s"

    class Config(RuleConfig):
        threshold: PositiveInt  # login POSTs from one IP...
        window_seconds: PositiveInt
        login_paths: list[str] = Field(min_length=1)  # case-insensitive regexes on the URL path

    config: Config

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self.window = SlidingWindow(config.window_seconds)
        self.paths = [re.compile(p, re.IGNORECASE) for p in config.login_paths]

    def process(self, event: Event) -> list[Alert]:
        if event.http_method != "POST" or not any(
            p.search(event.url_path or "") for p in self.paths
        ):
            return []
        events = self.window.add(event.src_ip, event)
        if len(events) < self.config.threshold:
            return []
        return [self.make_alert(list(events), window=self.config.window_seconds)]
