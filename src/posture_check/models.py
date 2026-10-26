"""Core domain types.

Everything downstream of a check speaks in `Finding` objects, so adding a new
check never requires changing the reporter or the triage step.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    """Ordered so findings sort naturally: highest severity first."""

    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0

    @property
    def label(self) -> str:
        return self.name.capitalize()


@dataclass(frozen=True, slots=True)
class Target:
    """Something to check. `host` is required; `url` enables the HTTP checks."""

    host: str
    url: str | None = None
    ports: tuple[int, ...] = ()
    facts_file: str | None = None
    tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.host.strip():
            raise ValueError("Target.host must not be empty")


@dataclass(frozen=True, slots=True)
class Finding:
    """One thing that is wrong, and what to do about it.

    `check` and `rule` together identify the finding type, which is what lets
    the triage step group findings without string-matching on titles.
    """

    target: str
    check: str
    rule: str
    title: str
    severity: Severity
    detail: str
    remediation: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.check}:{self.rule}"


@dataclass(slots=True)
class Report:
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def add(self, findings: list[Finding]) -> None:
        self.findings.extend(findings)

    def sorted_findings(self) -> list[Finding]:
        """Highest severity first, then grouped by check and target."""
        return sorted(
            self.findings,
            key=lambda f: (-int(f.severity), f.check, f.rule, f.target),
        )

    def counts(self) -> dict[str, int]:
        out = {s.label: 0 for s in sorted(Severity, reverse=True)}
        for f in self.findings:
            out[f.severity.label] += 1
        return out

    @property
    def worst(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.INFO)
