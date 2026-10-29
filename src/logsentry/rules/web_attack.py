import re
from datetime import timedelta
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import unquote_plus

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PositiveInt,
    StringConstraints,
    ValidationInfo,
    field_validator,
    model_validator,
)

from logsentry.models import (
    _CONTROL_CHARS,
    Alert,
    CategoryResult,
    Confidence,
    Event,
    Match,
    Result,
    Severity,
    Technique,
)
from logsentry.outcome import INCLUSION_CATEGORIES, Outcome
from logsentry.rules.base import Rule, RuleConfig

MAX_MATCHED = 100  # characters of attacker text kept per match
MAX_SHOWN = 300  # characters of the request and User-Agent kept per match
MAX_MATCHES = 50  # Alert.matches' cap


def _compile(v: Any) -> re.Pattern[str]:
    """A config regex, always case-insensitive; a bad one stops LogSentry at startup."""
    try:
        return re.compile(v, re.IGNORECASE)
    except (re.error, TypeError) as e:
        raise ValueError(f"bad regex {v!r}: {e}") from None


class Pattern(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    field: Literal["request", "user_agent"]
    regex: re.Pattern[str]

    @field_validator("regex", mode="before")
    @classmethod
    def _compile(cls, v: Any) -> re.Pattern[str]:
        return _compile(v)


class FollowOn(BaseModel):
    """A technique a category's success leads to, e.g. T1059 after a command injection."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    technique_id: str
    name: str
    tactic: str
    # only when a request that worked matches it (on the decoded path and query)
    when: re.Pattern[str] | None = None

    @field_validator("when", mode="before")
    @classmethod
    def _compile(cls, v: Any) -> re.Pattern[str] | None:
        return None if v is None else _compile(v)


class Category(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    technique_id: str
    technique_name: str
    tactic: str
    severity: Severity
    cwe: Annotated[str, StringConstraints(pattern=r"^CWE-\d+$")] | None = None
    patterns: list[Pattern] = Field(min_length=1)
    follow_on: list[FollowOn] = []  # added to the alert only when this category succeeded


def request_text(event: Event) -> str:
    """The URL path and query, decoded twice so double encoding (%252e) can't hide a pattern."""
    if event.url_path is None:  # not an HTTP request line (TLS on port 80, junk)
        return ""
    return unquote_plus(unquote_plus(event.url_path + "?" + (event.url_query or "")))


def _clean(text: str) -> str:
    return _CONTROL_CHARS.sub("", text)


# a request's own verdict from the Apache error_log, keyed by (ts, raw line); see cli.ingest
Confirmations = dict[tuple, Outcome]
STEP = {"succeeded": 1, "mixed": 0, "blocked": -1}


def request_worked(
    event: Event, cat_id: str, usual_sizes: dict, confirmed: Confirmations
) -> tuple[bool, Confidence | None]:
    """Whether this request's `cat_id` attack worked, and how sure that is.

    The error_log's verdict on a file inclusion is proof either way ("confirmed"). Otherwise
    only a 2xx can mean success, and only "likely": a 2xx the same size as that page's usual
    response looks like an ordinary page view, so it doesn't count.
    """
    if cat_id in INCLUSION_CATEGORIES and (o := confirmed.get((event.ts, event.raw))) in (
        "succeeded",
        "failed",
    ):
        return o == "succeeded", "confirmed"
    if event.http_status is None or not 200 <= event.http_status < 300:
        return False, None
    usual = usual_sizes.get(event.url_path)
    if usual is not None and event.http_bytes == usual:
        return False, None
    return True, "likely"


def category_result(
    worked: list[tuple[bool, Confidence | None]],
) -> tuple[Result, Confidence | None]:
    """succeeded: a confirmed success, or every request likely worked. mixed: some likely did.

    "mixed" is not a success: most of those attempts failed and none is proven.
    """
    wins = [c for ok, c in worked if ok]
    if "confirmed" in wins:
        return "succeeded", "confirmed"
    if wins and len(wins) == len(worked):
        return "succeeded", "likely"
    return ("mixed", "likely") if wins else ("blocked", None)


class WebAttack(Rule):
    """One alert per attacking IP, grown while its requests keep coming.

    A request joins its IP's open alert when it comes at most `group_gap_seconds` after the
    alert's last request; otherwise it opens a new one. Every request returns the whole
    alert again, with the same `first_seen`, so the store can update it in place.
    """

    id = "web_attack"
    name = "Web attack"
    technique_id = "T1190"  # replaced by the categories' techniques
    tactic = "Initial Access"
    severity = Severity.MEDIUM  # replaced by the categories' adjusted severities
    sources = frozenset({"nginx", "iis"})
    explanation = "{categories} in {requests} from {src_ip} (HTTP {status})"
    cooldown = False  # the open group is the deduplication

    class Config(RuleConfig):
        patterns_file: Path  # relative to rules.yaml
        group_gap_seconds: PositiveInt  # max quiet time between two requests of one alert
        categories: dict[Annotated[str, StringConstraints(pattern=r"^[a-z0-9_]+$")], Category] = (
            Field(min_length=1)
        )

        @model_validator(mode="before")
        @classmethod
        def _read_patterns_file(cls, data: Any, info: ValidationInfo) -> Any:
            if not isinstance(data, dict) or "patterns_file" not in data or "categories" in data:
                return data
            path = Path((info.context or {}).get("base_dir", ".")) / data["patterns_file"]
            try:
                loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
            except OSError as e:
                raise ValueError(f"can't read {path}: {e}") from None
            categories = loaded.get("categories") if isinstance(loaded, dict) else None
            return {**data, "patterns_file": path, "categories": categories}

    config: Config

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self.gap = timedelta(seconds=config.group_gap_seconds)
        # shortcut: an IP's open group stays in memory until its next request starts a new
        # one; fine for a lab, prune idle groups if this ever faces internet traffic
        self._groups: dict[IPv4Address | IPv6Address, list[tuple[Event, dict[str, Match]]]] = {}

    def classify(self, event: Event) -> dict[str, Match]:
        """The categories the request falls in, each with the first pattern that matched."""
        fields = {"request": request_text(event), "user_agent": event.user_agent or ""}
        found = {}
        for cat_id, category in self.config.categories.items():
            for pattern in category.patterns:
                if m := pattern.regex.search(fields[pattern.field]):
                    found[cat_id] = Match(
                        ts=event.ts,
                        http_status=event.http_status,
                        category=cat_id,
                        pattern=pattern.id,
                        matched=_clean(m.group())[:MAX_MATCHED],
                        name=category.name,
                        request=_clean(fields["request"])[:MAX_SHOWN],
                        user_agent=_clean(fields["user_agent"])[:MAX_SHOWN],
                    )
                    break
        return found

    def process(self, event: Event) -> list[Alert]:
        if not (found := self.classify(event)):
            return []
        hits = self._groups.get(event.src_ip)
        if hits is None or event.ts - hits[-1][0].ts > self.gap:
            hits = self._groups[event.src_ip] = []
        hits.append((event, found))
        return [self.alert_for(hits)]

    def alert_for(
        self,
        hits: list[tuple[Event, dict[str, Match]]],
        usual_sizes: dict | None = None,
        confirmed: Confirmations | None = None,
    ) -> Alert:
        """The alert for one IP's attack requests (oldest first), each with what it matched.

        `usual_sizes` (page → usual response size) and `confirmed` (error_log verdicts) are
        only known to `ingest`, after the whole file is read; `tail` judges by status alone.
        """
        usual_sizes, confirmed = usual_sizes or {}, confirmed or {}
        events = [e for e, _ in hits]
        matches = [m for _, found in hits for m in found.values()]
        by_cat: dict[str, list[tuple[Event, bool, Confidence | None]]] = {}
        for e, found in hits:
            for cat_id in found:
                worked = request_worked(e, cat_id, usual_sizes, confirmed)
                by_cat.setdefault(cat_id, []).append((e, *worked))
        results, techniques = [], {}
        for cat_id, requests in by_cat.items():
            category = self.config.categories[cat_id]
            result, confidence = category_result([(ok, c) for _, ok, c in requests])
            initial = Technique(
                id=category.technique_id, name=category.technique_name, tactic=category.tactic
            )
            techniques.setdefault(initial.id, initial)
            follow_on = []
            if result == "succeeded":
                wins = [request_text(e) for e, ok, _ in requests if ok]
                for f in category.follow_on:
                    if f.when is None or any(f.when.search(text) for text in wins):
                        follow_on.append(f.technique_id)
                        technique = Technique(
                            id=f.technique_id, name=f.name, tactic=f.tactic, follow_on=True
                        )
                        techniques.setdefault(f.technique_id, technique)
            results.append(
                CategoryResult(
                    name=category.name,
                    result=result,
                    confidence=confidence,
                    severity=category.severity.shifted(STEP[result]),
                    cwe=category.cwe,
                    follow_on=follow_on,
                )
            )
        # the initial-access techniques first, then what the successes led to
        chain = sorted(techniques.values(), key=lambda t: t.follow_on)
        statuses = dict.fromkeys(str(e.http_status) for e in events)
        alert = self.make_alert(
            events,
            categories=", ".join(r.name for r in results),
            requests="a request" if len(events) == 1 else f"{len(events)} requests",
            status=", ".join(statuses),
        )
        severity = max((r.severity for r in results), key=list(Severity).index)
        overall = {r.result for r in results}
        result: Result = (
            "succeeded"
            if "succeeded" in overall
            else "blocked"
            if overall == {"blocked"}
            else "mixed"
        )
        confidences = {r.confidence for r in results if r.result == result}
        return alert.model_copy(
            update={
                "technique_id": ", ".join(t.id for t in chain),
                "tactic": ", ".join(dict.fromkeys(t.tactic for t in chain)),
                "techniques": chain,
                "severity": severity.shifted(1) if alert.internal else severity,
                "categories": [r.name for r in results],
                "results": results,
                "result": result,
                "confidence": "confirmed"
                if "confirmed" in confidences
                else ("likely" if result != "blocked" else None),
                "matches": matches[:MAX_MATCHES],
            }
        )
