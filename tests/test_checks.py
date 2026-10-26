"""Tests for the pure analysis functions.

None of these touch the network or the filesystem. That is the point of
separating `evaluate()` from the code that collects the data: the judgement is
testable even though the collection is not.
"""

from __future__ import annotations

import pytest

from posture_check.checks.host_hygiene import evaluate as evaluate_host
from posture_check.checks.http_headers import evaluate as evaluate_headers
from posture_check.checks.open_ports import evaluate as evaluate_ports
from posture_check.models import Severity, Target

URL = "https://example.test"

SECURE_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
}


class TestHttpHeaders:
    def test_fully_configured_site_has_no_findings(self):
        assert evaluate_headers(URL, SECURE_HEADERS) == []

    def test_missing_every_header_reports_each_once(self):
        findings = evaluate_headers(URL, {})
        rules = {f.rule for f in findings}
        assert rules == {
            "missing-hsts",
            "missing-csp",
            "missing-nosniff",
            "missing-frame-protection",
            "missing-referrer-policy",
        }

    def test_hsts_present_but_without_max_age_is_misconfigured_not_missing(self):
        headers = dict(SECURE_HEADERS, **{"Strict-Transport-Security": "includeSubDomains"})
        findings = evaluate_headers(URL, headers)
        assert len(findings) == 1
        assert findings[0].rule == "missing-hsts"
        assert "misconfigured" in findings[0].title

    def test_header_names_are_matched_case_insensitively(self):
        lowered = {k.lower(): v for k, v in SECURE_HEADERS.items()}
        assert evaluate_headers(URL, lowered) == []

    def test_version_disclosure_is_reported_only_when_a_version_is_present(self):
        with_version = evaluate_headers(URL, dict(SECURE_HEADERS, Server="nginx/1.18.0"))
        without = evaluate_headers(URL, dict(SECURE_HEADERS, Server="nginx"))
        assert [f.rule for f in with_version] == ["server-version-disclosed"]
        assert without == []

    def test_severities_are_ordered_sensibly(self):
        by_rule = {f.rule: f.severity for f in evaluate_headers(URL, {})}
        assert by_rule["missing-hsts"] > by_rule["missing-referrer-policy"]


class TestOpenPorts:
    def test_no_open_ports_means_no_findings(self):
        assert evaluate_ports("host", []) == []

    def test_known_dangerous_port_is_escalated(self):
        findings = evaluate_ports("host", [445])
        assert len(findings) == 1
        assert findings[0].severity is Severity.CRITICAL
        assert findings[0].rule == "exposed-smb"

    def test_unknown_port_is_informational_not_guessed(self):
        findings = evaluate_ports("host", [12345])
        assert findings[0].severity is Severity.INFO
        assert findings[0].rule == "port-open"

    def test_https_is_not_a_finding(self):
        assert [f.rule for f in evaluate_ports("host", [443])] == ["port-open"]

    def test_results_are_ordered_by_port(self):
        findings = evaluate_ports("host", [3306, 23])
        assert [f.evidence["port"] for f in findings] == [23, 3306]


class TestHostHygiene:
    def test_clean_host_has_no_findings(self):
        facts = {
            "accounts": [{"name": "root", "uid": 0, "shell": "/bin/bash"}],
            "upgradable_packages": [],
            "passwordless_sudo": [],
            "world_writable_files": [],
            "readable_secrets": [],
        }
        assert evaluate_host("web01", facts) == []

    def test_second_uid_zero_account_is_critical(self):
        facts = {"accounts": [
            {"name": "root", "uid": 0, "shell": "/bin/bash"},
            {"name": "backdoor", "uid": 0, "shell": "/bin/bash"},
        ]}
        findings = evaluate_host("web01", facts)
        assert [f.rule for f in findings] == ["extra-uid-0"]
        assert findings[0].severity is Severity.CRITICAL

    def test_service_account_with_nologin_shell_is_fine(self):
        facts = {"accounts": [{"name": "www-data", "uid": 33, "shell": "/usr/sbin/nologin"}]}
        assert evaluate_host("web01", facts) == []

    def test_service_account_with_interactive_shell_is_flagged(self):
        facts = {"accounts": [{"name": "www-data", "uid": 33, "shell": "/bin/bash"}]}
        findings = evaluate_host("web01", facts)
        assert [f.rule for f in findings] == ["service-account-shell"]

    def test_security_updates_escalate_above_ordinary_updates(self):
        many = {"upgradable_packages": [
            {"name": f"pkg{n}", "security": True} for n in range(6)
        ]}
        few = {"upgradable_packages": [{"name": "pkg", "security": False}]}
        assert evaluate_host("h", many)[0].severity is Severity.HIGH
        assert evaluate_host("h", few)[0].severity is Severity.LOW

    def test_passwordless_sudo_is_high(self):
        findings = evaluate_host("h", {"passwordless_sudo": ["deploy ALL=(ALL) NOPASSWD: ALL"]})
        assert findings[0].severity is Severity.HIGH

    def test_world_writable_files_collapse_into_one_finding(self):
        facts = {"world_writable_files": [f"/opt/app/f{n}" for n in range(12)]}
        findings = evaluate_host("h", facts)
        assert len(findings) == 1
        assert findings[0].evidence["count"] == 12
        assert len(findings[0].evidence["examples"]) == 10

    def test_missing_keys_are_tolerated(self):
        assert evaluate_host("h", {}) == []


class TestTarget:
    def test_empty_host_is_rejected(self):
        with pytest.raises(ValueError):
            Target(host="  ")

    def test_target_is_hashable_so_it_can_be_deduplicated(self):
        assert len({Target(host="a"), Target(host="a")}) == 1
