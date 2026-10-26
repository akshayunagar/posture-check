"""Triage: group findings and write the remediation text.

Two stages, deliberately separable:

1. `group()` — deterministic. Collapses findings that share a rule across many
   targets into one item of work, because "fix HSTS on 14 hosts" is one ticket,
   not fourteen.
2. `summarise()` — optional LLM pass that writes the covering summary and
   sharpens the remediation wording for the audience.

The LLM step degrades gracefully: with no API key, or on any failure, the
deterministic text is used. A security report that silently depends on a
third-party API being up is not a security report.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from .models import Finding, Severity

API_URL = "https://api.anthropic.com/v1/messages"
MODEL = "claude-sonnet-4-5"


@dataclass(slots=True)
class WorkItem:
    """One unit of remediation work, possibly spanning several targets."""

    key: str
    title: str
    severity: Severity
    remediation: str
    targets: list[str] = field(default_factory=list)
    detail: str = ""

    @property
    def effort_hint(self) -> str:
        if len(self.targets) > 5:
            return "fleet-wide — worth a configuration change rather than per-host edits"
        if len(self.targets) > 1:
            return f"{len(self.targets)} hosts"
        return "single host"


def group(findings: list[Finding]) -> list[WorkItem]:
    """Collapse findings sharing a rule into one work item. Deterministic."""
    items: dict[str, WorkItem] = {}
    for f in findings:
        item = items.get(f.key)
        if item is None:
            items[f.key] = WorkItem(
                key=f.key,
                title=f.title,
                severity=f.severity,
                remediation=f.remediation,
                targets=[f.target],
                detail=f.detail,
            )
        else:
            if f.target not in item.targets:
                item.targets.append(f.target)
            # Keep the highest severity seen for this rule.
            if f.severity > item.severity:
                item.severity = f.severity
    return sorted(items.values(), key=lambda i: (-int(i.severity), i.key))


def _fallback_summary(items: list[WorkItem]) -> str:
    if not items:
        return "No findings. Every check that ran came back clean."
    worst = items[0]
    urgent = [i for i in items if i.severity >= Severity.HIGH]
    affected = len({t for i in items for t in i.targets})
    lines = [f"{len(items)} distinct issue(s) across {affected} target(s)."]
    if urgent:
        lines.append(
            f"{len(urgent)} need attention before the next review; start with "
            f"“{worst.title}” ({worst.effort_hint})."
        )
    else:
        lines.append("Nothing is urgent. Clear these during normal maintenance.")
    return " ".join(lines)


def _call_model(prompt: str, api_key: str, timeout: float = 45.0) -> str:
    payload = json.dumps(
        {
            "model": MODEL,
            "max_tokens": 700,
            "messages": [{"role": "user", "content": prompt}],
        }
    ).encode()
    request = urllib.request.Request(
        API_URL,
        data=payload,
        headers={
            "content-type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = json.loads(response.read())
    return "".join(block.get("text", "") for block in body.get("content", []))


def summarise(items: list[WorkItem], api_key: str | None = None) -> str:
    """Write the covering summary. Falls back to deterministic text."""
    key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not key or not items:
        return _fallback_summary(items)

    inventory = "\n".join(
        f"- [{i.severity.label}] {i.title} ({len(i.targets)} target(s)): {i.detail}"
        for i in items[:30]
    )
    prompt = (
        "You are writing the opening summary of a security posture report for the "
        "engineers who have to fix these things. Findings:\n\n"
        f"{inventory}\n\n"
        "Write at most four sentences. Say what matters most and why, in that order. "
        "No preamble, no restating the list, no praise, no exclamation marks. "
        "Plain prose, British English."
    )
    try:
        text = _call_model(prompt, key).strip()
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError,
            json.JSONDecodeError, KeyError):
        return _fallback_summary(items)
    return text or _fallback_summary(items)
