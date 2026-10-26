"""Host hygiene: accounts, permissions and patch level.

This check deliberately does not log into anything. A small shell collector
(`collect/host_facts.sh`) runs on the host and writes a JSON facts file; this
module analyses it. Splitting collection from analysis means the thing that
needs privileges is twenty auditable lines of shell, and the thing with the
logic in it is Python you can unit-test without a server.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..models import Finding, Severity, Target
from .base import CheckError

SYSTEM_UID_MAX = 999


def evaluate(host: str, facts: dict[str, Any]) -> list[Finding]:
    """Pure function: given collected host facts, return findings."""
    findings: list[Finding] = []

    # ---- Patch level -------------------------------------------------
    upgradable = facts.get("upgradable_packages") or []
    security_upgrades = [p for p in upgradable if p.get("security")]
    if security_upgrades:
        names = ", ".join(sorted(p["name"] for p in security_upgrades)[:8])
        findings.append(
            Finding(
                target=host,
                check="host-hygiene",
                rule="pending-security-updates",
                title=f"{len(security_upgrades)} pending security update(s)",
                severity=Severity.HIGH if len(security_upgrades) > 5 else Severity.MEDIUM,
                detail=f"Packages with security updates available: {names}.",
                remediation=(
                    "Apply security updates, then schedule them so this does not recur."
                ),
                evidence={"count": len(security_upgrades)},
            )
        )
    elif upgradable:
        findings.append(
            Finding(
                target=host,
                check="host-hygiene",
                rule="pending-updates",
                title=f"{len(upgradable)} package update(s) available",
                severity=Severity.LOW,
                detail="Updates are pending but none are flagged as security updates.",
                remediation="Apply during the next maintenance window.",
                evidence={"count": len(upgradable)},
            )
        )

    # ---- Accounts ----------------------------------------------------
    for account in facts.get("accounts") or []:
        name = account.get("name", "?")
        uid = int(account.get("uid", -1))
        shell = account.get("shell", "")
        interactive = shell not in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "")

        if uid == 0 and name != "root":
            findings.append(
                Finding(
                    target=host, check="host-hygiene", rule="extra-uid-0",
                    title=f"Second account with UID 0: {name}",
                    severity=Severity.CRITICAL,
                    detail=(
                        f"`{name}` has UID 0, giving it full root privileges "
                        "alongside root."
                    ),
                    remediation=(
                        "Remove the account, or give it a non-zero UID and sudo "
                        "rights instead."
                    ),
                    evidence={"account": name},
                )
            )
        if interactive and 0 < uid <= SYSTEM_UID_MAX:
            findings.append(
                Finding(
                    target=host, check="host-hygiene", rule="service-account-shell",
                    title=f"Service account {name} has an interactive shell",
                    severity=Severity.MEDIUM,
                    detail=(
                        f"`{name}` (UID {uid}) is a system account but its shell "
                        f"is `{shell}`."
                    ),
                    remediation=(
                        "Set the shell to /usr/sbin/nologin unless "
                        f"`{name}` genuinely needs to log in."
                    ),
                    evidence={"account": name, "shell": shell},
                )
            )
        if account.get("password_never_expires") and interactive:
            findings.append(
                Finding(
                    target=host, check="host-hygiene", rule="password-never-expires",
                    title=f"Password for {name} never expires",
                    severity=Severity.LOW,
                    detail=f"`{name}` can log in and its password has no expiry set.",
                    remediation=(
                        "Set a maximum password age, or move the account to "
                        "key-based authentication."
                    ),
                    evidence={"account": name},
                )
            )

    # ---- Sudo --------------------------------------------------------
    for entry in facts.get("passwordless_sudo") or []:
        findings.append(
            Finding(
                target=host, check="host-hygiene", rule="passwordless-sudo",
                title=f"Passwordless sudo granted to {entry}",
                severity=Severity.HIGH,
                detail=(
                    f"`{entry}` can run commands as root via NOPASSWD, so a stolen "
                    "session is immediately root."
                ),
                remediation=(
                    "Remove NOPASSWD, or narrow it to the specific commands that "
                    "need it."
                ),
                evidence={"grant": entry},
            )
        )

    # ---- Permissions -------------------------------------------------
    world_writable = facts.get("world_writable_files") or []
    if world_writable:
        findings.append(
            Finding(
                target=host, check="host-hygiene", rule="world-writable-files",
                title=f"{len(world_writable)} world-writable file(s) outside /tmp",
                severity=Severity.MEDIUM,
                detail="Examples: " + ", ".join(f"`{p}`" for p in world_writable[:5]),
                remediation=(
                    "Remove the world-writable bit (`chmod o-w`) and set group "
                    "ownership instead."
                ),
                evidence={"count": len(world_writable), "examples": world_writable[:10]},
            )
        )

    for path in facts.get("readable_secrets") or []:
        findings.append(
            Finding(
                target=host, check="host-hygiene", rule="readable-secret-file",
                title=f"Sensitive file is world-readable: {path}",
                severity=Severity.HIGH,
                detail=f"`{path}` can be read by any local user.",
                remediation=f"Restrict to the owning user: `chmod 600 {path}`.",
                evidence={"path": path},
            )
        )

    return findings


class HostHygieneCheck:
    name = "host-hygiene"

    def applies_to(self, target: Target) -> bool:
        return bool(target.facts_file)

    def run(self, target: Target) -> list[Finding]:
        assert target.facts_file  # guarded by applies_to
        path = Path(target.facts_file)
        try:
            facts = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise CheckError(f"facts file not found: {path}") from exc
        except json.JSONDecodeError as exc:
            raise CheckError(f"facts file is not valid JSON: {path} ({exc})") from exc
        if not isinstance(facts, dict):
            raise CheckError(f"facts file must contain a JSON object: {path}")
        return evaluate(target.host, facts)
