"""The check interface.

A check is anything with a name that turns a Target into a list of Findings.
Adding a check means adding a module and registering it — nothing else in the
codebase changes.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..models import Finding, Target


@runtime_checkable
class Check(Protocol):
    name: str

    def applies_to(self, target: Target) -> bool:
        """Whether this check has what it needs to run against this target."""
        ...

    def run(self, target: Target) -> list[Finding]:
        ...


class CheckError(RuntimeError):
    """Raised when a check cannot run — distinct from a check that finds nothing."""
