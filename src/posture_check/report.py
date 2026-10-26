"""Renderers.

Markdown for the engineer who has to act; JSON for whatever consumes this next.
Both are pure functions of the report, so they are trivial to test.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from .models import Report, Severity
from .triage import WorkItem

BADGE = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
    Severity.INFO: "INFO",
}


def to_markdown(report: Report, items: list[WorkItem], summary: str) -> str:
    counts = report.counts()
    generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")

    out: list[str] = [
        "# Security posture report",
        "",
        f"_Generated {generated}_",
        "",
        "## Summary",
        "",
        summary,
        "",
        "| Severity | Findings |",
        "| --- | --- |",
    ]
    out += [f"| {label} | {n} |" for label, n in counts.items() if n]
    if not any(counts.values()):
        out.append("| — | 0 |")

    out += ["", "## What to do, in order", ""]
    if not items:
        out.append("Nothing outstanding.")
    for n, item in enumerate(items, start=1):
        targets = ", ".join(f"`{t}`" for t in item.targets[:10])
        if len(item.targets) > 10:
            targets += f" and {len(item.targets) - 10} more"
        out += [
            f"### {n}. {item.title}",
            "",
            f"**{BADGE[item.severity]}** · {item.effort_hint}",
            "",
            f"**Affected:** {targets}",
            "",
            item.detail,
            "",
            f"**Fix:** {item.remediation}" if item.remediation else "",
            "",
        ]

    if report.errors:
        out += ["## Checks that could not run", ""]
        out += [f"- {e}" for e in report.errors]
        out += [""]

    return "\n".join(line for line in out if line is not None).rstrip() + "\n"


def to_json(report: Report, items: list[WorkItem], summary: str) -> str:
    return json.dumps(
        {
            "generated": datetime.now(UTC).isoformat(),
            "summary": summary,
            "counts": report.counts(),
            "worst_severity": report.worst.label,
            "work_items": [
                {
                    "key": i.key,
                    "title": i.title,
                    "severity": i.severity.label,
                    "targets": i.targets,
                    "detail": i.detail,
                    "remediation": i.remediation,
                }
                for i in items
            ],
            "findings": [
                {
                    "target": f.target,
                    "check": f.check,
                    "rule": f.rule,
                    "title": f.title,
                    "severity": f.severity.label,
                    "detail": f.detail,
                    "remediation": f.remediation,
                    "evidence": f.evidence,
                }
                for f in report.sorted_findings()
            ],
            "errors": report.errors,
        },
        indent=2,
    )
