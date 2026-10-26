"""HTTP security header checks.

The policy table is data, not code, so the rules can be reviewed by someone
who does not read Python — which is usually the person who has to sign off on
the exceptions.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from dataclasses import dataclass
from email.message import Message

from ..models import Finding, Severity, Target
from .base import CheckError


@dataclass(frozen=True, slots=True)
class HeaderRule:
    header: str
    rule: str
    severity: Severity
    why: str
    fix: str
    required_substring: str | None = None


POLICY: tuple[HeaderRule, ...] = (
    HeaderRule(
        header="strict-transport-security",
        rule="missing-hsts",
        severity=Severity.HIGH,
        why="Without HSTS a browser can be downgraded to plain HTTP on the first request.",
        fix="Add `Strict-Transport-Security: max-age=31536000; includeSubDomains`.",
        required_substring="max-age",
    ),
    HeaderRule(
        header="content-security-policy",
        rule="missing-csp",
        severity=Severity.HIGH,
        why="CSP is the main defence-in-depth control against cross-site scripting.",
        fix=(
            "Add a Content-Security-Policy, starting with `default-src 'self'` "
            "and loosening only where needed."
        ),
    ),
    HeaderRule(
        header="x-content-type-options",
        rule="missing-nosniff",
        severity=Severity.MEDIUM,
        why=(
            "Browsers may guess content types and execute a response that was never "
            "meant to be script."
        ),
        fix="Add `X-Content-Type-Options: nosniff`.",
        required_substring="nosniff",
    ),
    HeaderRule(
        header="x-frame-options",
        rule="missing-frame-protection",
        severity=Severity.MEDIUM,
        why="Without frame protection the page can be embedded and used for clickjacking.",
        fix="Add `X-Frame-Options: DENY`, or a CSP `frame-ancestors` directive.",
    ),
    HeaderRule(
        header="referrer-policy",
        rule="missing-referrer-policy",
        severity=Severity.LOW,
        why="Full URLs may leak to third parties in the Referer header.",
        fix="Add `Referrer-Policy: strict-origin-when-cross-origin`.",
    ),
)

LEAKY_HEADERS: tuple[tuple[str, str], ...] = (
    ("server", "server-version-disclosed"),
    ("x-powered-by", "framework-disclosed"),
    ("x-aspnet-version", "framework-disclosed"),
)


def evaluate(url: str, headers: Message | dict[str, str]) -> list[Finding]:
    """Pure function: given headers, return findings. No network, so testable."""
    lower = {k.lower(): v for k, v in dict(headers).items()}
    findings: list[Finding] = []

    for rule in POLICY:
        value = lower.get(rule.header)
        missing = value is None
        wrong = (
            not missing
            and rule.required_substring is not None
            and rule.required_substring not in value.lower()
        )
        if missing or wrong:
            state = "is not set" if missing else f"is set to `{value}`"
            findings.append(
                Finding(
                    target=url,
                    check="http-headers",
                    rule=rule.rule,
                    title=f"{rule.header} {'missing' if missing else 'misconfigured'}",
                    severity=rule.severity,
                    detail=f"`{rule.header}` {state}. {rule.why}",
                    remediation=rule.fix,
                    evidence={"header": rule.header, "value": value},
                )
            )

    for header, rule_id in LEAKY_HEADERS:
        value = lower.get(header)
        if value and any(ch.isdigit() for ch in value):
            findings.append(
                Finding(
                    target=url,
                    check="http-headers",
                    rule=rule_id,
                    title=f"{header} discloses version information",
                    severity=Severity.LOW,
                    detail=(
                        f"`{header}: {value}` tells an attacker which software and version to "
                        "look up known vulnerabilities for."
                    ),
                    remediation=f"Suppress or genericise the `{header}` response header.",
                    evidence={"header": header, "value": value},
                )
            )

    return findings


class HttpHeadersCheck:
    name = "http-headers"

    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout

    def applies_to(self, target: Target) -> bool:
        return bool(target.url)

    def run(self, target: Target) -> list[Finding]:
        assert target.url  # guarded by applies_to
        request = urllib.request.Request(
            target.url, method="HEAD", headers={"User-Agent": "posture-check"}
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                headers = response.headers
        except urllib.error.HTTPError as exc:
            headers = exc.headers  # a 403 still carries the headers we care about
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise CheckError(f"could not reach {target.url}: {exc}") from exc
        return evaluate(target.url, headers)
