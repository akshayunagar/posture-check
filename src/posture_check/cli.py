"""Command line entry point.

Exit codes are chosen so this is usable as a CI gate:
  0  nothing at or above the fail threshold
  1  findings at or above the threshold
  2  the run itself failed
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .checks.base import CheckError
from .checks.host_hygiene import HostHygieneCheck
from .checks.http_headers import HttpHeadersCheck
from .checks.open_ports import OpenPortsCheck
from .models import Report, Severity, Target
from .report import to_json, to_markdown
from .triage import group, summarise

CHECKS = (HttpHeadersCheck(), OpenPortsCheck(), HostHygieneCheck())

SEVERITY_BY_NAME = {s.name.lower(): s for s in Severity}


def load_targets(path: Path) -> list[Target]:
    """Read targets from a small YAML-ish file. One target per block.

    Kept dependency-free on purpose: a security tool that needs a parser
    library is a security tool with a supply chain.
    """
    targets: list[Target] = []
    current: dict[str, str] = {}

    def flush() -> None:
        if not current:
            return
        ports = tuple(
            int(p) for p in current.get("ports", "").replace(",", " ").split() if p
        )
        targets.append(
            Target(
                host=current["host"],
                url=current.get("url") or None,
                ports=ports,
                facts_file=current.get("facts_file") or None,
                tags=tuple(current.get("tags", "").replace(",", " ").split()),
            )
        )
        current.clear()

    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if line.lstrip().startswith("- "):
            flush()
            line = line.lstrip()[2:]
        if ":" not in line:
            raise SystemExit(f"cannot parse line: {raw!r}")
        key, _, value = line.partition(":")
        current[key.strip()] = value.strip().strip("'\"")
    flush()

    if not targets:
        raise SystemExit(f"no targets found in {path}")
    return targets


def run(targets: list[Target]) -> Report:
    report = Report()
    for target in targets:
        for check in CHECKS:
            if not check.applies_to(target):
                continue
            try:
                report.add(check.run(target))
            except CheckError as exc:
                report.errors.append(f"{check.name} on {target.host}: {exc}")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="posture-check",
        description="Run security posture checks and write an engineer-readable report.",
    )
    parser.add_argument("--targets", required=True, type=Path, help="targets file")
    parser.add_argument("--out", type=Path, default=Path("report"), help="output directory")
    parser.add_argument(
        "--fail-on",
        default="high",
        choices=sorted(SEVERITY_BY_NAME),
        help="exit 1 if any finding is at or above this severity (default: high)",
    )
    parser.add_argument(
        "--no-ai", action="store_true", help="skip the LLM summary and use deterministic text"
    )
    args = parser.parse_args(argv)

    try:
        targets = load_targets(args.targets)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report = run(targets)
    items = group(report.findings)
    summary = summarise(items, api_key="" if args.no_ai else None)

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "report.md").write_text(to_markdown(report, items, summary), encoding="utf-8")
    (args.out / "report.json").write_text(to_json(report, items, summary), encoding="utf-8")

    threshold = SEVERITY_BY_NAME[args.fail_on]
    print(summary)
    print(f"\n{len(report.findings)} finding(s) in {len(items)} work item(s) -> {args.out}/")
    for err in report.errors:
        print(f"warning: {err}", file=sys.stderr)

    return 1 if report.worst >= threshold else 0


if __name__ == "__main__":
    raise SystemExit(main())
