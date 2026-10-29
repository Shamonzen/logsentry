"""Normalized event and alert schemas shared by parsers, rules and the store."""

import re
from datetime import UTC, datetime
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator

MAX_LINE = 4096
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def shifted(self, steps: int) -> "Severity":
        """This severity `steps` levels up (or down when negative), kept within low..critical."""
        levels = list(Severity)
        return levels[min(max(levels.index(self) + steps, 0), len(levels) - 1)]


Result = Literal["succeeded", "mixed", "blocked"]
Confidence = Literal["confirmed", "likely"]
# RFC 1918 and IPv6 unique local addresses. Not ipaddress's is_private, which also covers the
# documentation ranges (203.0.113.0/24, ...) the tests and examples use as outside attackers.
_INTERNAL = [ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")]


def is_internal(ip: IPv4Address | IPv6Address | str) -> bool:
    ip = ip_address(str(ip))
    return any(ip.version == net.version and ip in net for net in _INTERNAL)


class EventType(StrEnum):
    AUTH_FAILURE = "auth_failure"
    AUTH_SUCCESS = "auth_success"
    INVALID_USER = "invalid_user"
    HTTP_REQUEST = "http_request"


class Event(BaseModel):
    """One parsed log line. Field names loosely follow Elastic Common Schema (ECS)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    ts: AwareDatetime
    source: Literal["sshd", "nginx", "iis"]
    event_type: EventType
    src_ip: IPvAnyAddress
    host: str
    user_name: str | None = None
    http_method: str | None = None
    url_path: str | None = None
    url_query: str | None = None
    http_status: int | None = None
    http_bytes: int | None = None
    user_agent: str | None = None
    raw: str

    @field_validator("ts")
    @classmethod
    def _to_utc(cls, v: datetime) -> datetime:
        return v.astimezone(UTC)

    @field_validator("user_name")
    @classmethod
    def _clean_user_name(cls, v: str | None) -> str | None:
        # attacker-chosen: drop newlines and ANSI escapes so it can't forge log lines or terminals
        return None if v is None else _CONTROL_CHARS.sub("", v)[:64]

    @field_validator("raw")
    @classmethod
    def _cap_raw(cls, v: str) -> str:
        return v[:MAX_LINE]


class Match(BaseModel):
    """Why one request was put in a web attack category: the pattern and the text it matched."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    ts: AwareDatetime
    http_status: int | None
    category: str
    pattern: str
    matched: str  # attacker-controlled: control characters stripped, length capped
    # for display; empty in alerts stored before they were recorded
    name: str = ""  # the category's name
    request: str = ""  # decoded path and query, cleaned like `matched`
    user_agent: str = ""


class Technique(BaseModel):
    """An ATT&CK technique on an alert: how the attacker got in, or what a success led to."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str  # T1190, T1059.004, ...
    name: str
    tactic: str
    follow_on: bool = False  # True: only there because the attack succeeded


class CategoryResult(BaseModel):
    """Whether one attack category in a web alert worked, and what that makes it worth."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    result: Result
    confidence: Confidence | None  # None when blocked
    severity: Severity
    cwe: str | None = None  # the weakness the category exploits, e.g. CWE-22
    follow_on: list[str] = []  # technique ids its success added


class Alert(BaseModel):
    """A detection produced by a rule. `id` and `created_at` are assigned by the store."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    rule_id: str
    rule_name: str
    technique_id: str
    tactic: str
    severity: Severity
    src_ip: IPvAnyAddress
    first_seen: AwareDatetime
    last_seen: AwareDatetime
    event_count: int = Field(ge=1)
    summary: str
    evidence: list[str] = Field(max_length=20)
    # set only by `ingest --error-log` style post-processing; None when nobody judged it
    outcome: Literal["succeeded", "failed", "unknown"] | None = None
    outcome_evidence: list[str] = Field(default=[], max_length=25)
    # web attack alerts only: one entry per request the alert covers, oldest first
    matches: list[Match] = Field(default=[], max_length=50)
    categories: list[str] = []  # web attack category names, in first-seen order
    campaign_id: int | None = None  # set by the store when its /24 campaign is computed
    internal: bool = False  # the source is an RFC 1918 / ULA address
    # web alerts: whether the attacks worked, overall and per category
    result: Result | None = None
    confidence: Confidence | None = None
    results: list[CategoryResult] = []
    techniques: list[Technique] = []  # web alerts: initial access first, then follow-ons
