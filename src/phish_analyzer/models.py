"""Data types shared across the analyzer."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    def __str__(self) -> str:  # "HIGH" rather than "Severity.HIGH"
        return self.name


@dataclass(frozen=True)
class Finding:
    """One observation about an email, with a stable check id."""

    check: str
    severity: Severity
    title: str
    detail: str
    attack: str | None = None  # MITRE ATT&CK technique ID, when one fits

    def to_dict(self) -> dict:
        return {
            "check": self.check,
            "severity": str(self.severity),
            "title": self.title,
            "detail": self.detail,
            "attack": self.attack,
        }


@dataclass(frozen=True)
class Indicator:
    """An IOC worth blocking or hunting for (raw value, never defanged)."""

    kind: str  # url | domain | ip | sha256 | email
    value: str
    context: str

    def to_dict(self) -> dict:
        return {"kind": self.kind, "value": self.value, "context": self.context}


@dataclass(frozen=True)
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str


@dataclass
class ParsedEmail:
    subject: str = ""
    from_display: str = ""
    from_addr: str = ""
    reply_to: list[str] = field(default_factory=list)
    return_path: str = ""
    to: list[str] = field(default_factory=list)
    date: str = ""
    message_id: str = ""
    auth_results: list[str] = field(default_factory=list)
    received: list[str] = field(default_factory=list)
    text_body: str = ""
    html_body: str = ""
    attachments: list[Attachment] = field(default_factory=list)

    @property
    def from_domain(self) -> str:
        return domain_of(self.from_addr)


@dataclass
class Report:
    source: str
    email: ParsedEmail
    findings: list[Finding]
    indicators: list[Indicator]
    score: int
    verdict: str


def domain_of(address: str) -> str:
    """Return the lower-cased domain part of an email address ('' if none)."""
    address = address.strip().strip("<>")
    if "@" not in address:
        return ""
    return address.rpartition("@")[2].strip().lower().rstrip(".")
