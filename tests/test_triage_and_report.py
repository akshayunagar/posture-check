"""Tests for grouping, reporting and the graceful-degradation behaviour."""

from __future__ import annotations

import json

from posture_check.models import Finding, Report, Severity
from posture_check.report import to_json, to_markdown
from posture_check.triage import group, summarise


def finding(target: str, rule: str, severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        target=target,
        check="http-headers",
        rule=rule,
        title=f"{rule} on {target}",
        severity=severity,
        detail="detail",
        remediation="do the thing",
    )


class TestGrouping:
    def test_same_rule_across_hosts_becomes_one_work_item(self):
        items = group([finding(f"host{n}", "missing-hsts") for n in range(14)])
        assert len(items) == 1
        assert len(items[0].targets) == 14

    def test_different_rules_stay_separate(self):
        items = group([finding("h", "missing-hsts"), finding("h", "missing-csp")])
        assert len(items) == 2

    def test_duplicate_target_is_not_counted_twice(self):
        items = group([finding("h", "missing-hsts"), finding("h", "missing-hsts")])
        assert items[0].targets == ["h"]

    def test_group_takes_the_highest_severity_seen_for_a_rule(self):
        items = group([
            finding("a", "missing-hsts", Severity.LOW),
            finding("b", "missing-hsts", Severity.CRITICAL),
        ])
        assert items[0].severity is Severity.CRITICAL

    def test_items_are_ordered_most_severe_first(self):
        items = group([
            finding("a", "low-thing", Severity.LOW),
            finding("b", "bad-thing", Severity.CRITICAL),
        ])
        assert [i.severity for i in items] == [Severity.CRITICAL, Severity.LOW]

    def test_effort_hint_reflects_fleet_wide_work(self):
        single = group([finding("a", "r")])[0]
        fleet = group([finding(f"h{n}", "r") for n in range(9)])[0]
        assert single.effort_hint == "single host"
        assert "fleet-wide" in fleet.effort_hint


class TestSummaryFallback:
    def test_no_api_key_produces_deterministic_text_not_an_error(self):
        items = group([finding("a", "missing-hsts")])
        text = summarise(items, api_key="")
        assert text and "issue(s)" in text

    def test_empty_report_says_so_plainly(self):
        assert "No findings" in summarise([], api_key="")

    def test_fallback_mentions_the_worst_item_first(self):
        items = group([
            finding("a", "minor", Severity.LOW),
            finding("b", "severe", Severity.CRITICAL),
        ])
        assert "severe" in summarise(items, api_key="")


class TestRendering:
    def _report(self) -> Report:
        report = Report()
        report.add([finding("a", "missing-hsts"), finding("b", "missing-hsts")])
        report.add([finding("a", "missing-csp", Severity.MEDIUM)])
        return report

    def test_markdown_lists_work_items_in_order(self):
        report = self._report()
        items = group(report.findings)
        md = to_markdown(report, items, "summary text")
        assert md.startswith("# Security posture report")
        assert "summary text" in md
        assert md.index("missing-hsts") < md.index("missing-csp")

    def test_markdown_handles_an_empty_report(self):
        md = to_markdown(Report(), [], "nothing to do")
        assert "Nothing outstanding." in md

    def test_markdown_surfaces_checks_that_failed_to_run(self):
        report = Report()
        report.errors.append("http-headers on web01: timeout")
        md = to_markdown(report, [], "s")
        assert "could not run" in md
        assert "timeout" in md

    def test_json_is_valid_and_carries_both_views(self):
        report = self._report()
        items = group(report.findings)
        payload = json.loads(to_json(report, items, "s"))
        assert payload["worst_severity"] == "High"
        assert len(payload["work_items"]) == 2
        assert len(payload["findings"]) == 3
        assert payload["counts"]["High"] == 2

    def test_counts_only_include_severities_present(self):
        report = self._report()
        md = to_markdown(report, group(report.findings), "s")
        assert "| High | 2 |" in md
        assert "| Critical |" not in md
