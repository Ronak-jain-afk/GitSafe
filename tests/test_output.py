"""Tests for output reporters and the redactor."""

import json

from gitsafe.findings.models import Finding, ScanResult
from gitsafe.findings.redactor import redact, redact_ci, redact_local
from gitsafe.output import json_report, sarif


def _make_result(findings=None) -> ScanResult:
    """Build a ScanResult with sample data."""
    if findings is None:
        findings = [
            Finding(
                id="FINDING-001",
                rule_id="AWS_ACCESS_KEY",
                rule_name="AWS Access Key ID",
                severity="critical",
                category="key",
                file="config/deploy.py",
                line_no=42,
                matched_value="AKIAIOSFODNN7REAL123",
                description="Detects AWS access key IDs.",
                detection_methods=["regex"],
            ),
        ]
    return ScanResult(
        findings=findings,
        suppressed=[],
        skipped_files=[],
        scanned_files=5,
        blocked=True,
        scan_duration_ms=15.3,
    )


class TestRedactor:
    def test_local_partial_reveal(self):
        assert redact_local("AKIAIOSFODNN7REAL123") == "AKIA...23"

    def test_local_short_string(self):
        assert redact_local("short") == "[REDACTED]"

    def test_ci_always_redacted(self):
        assert redact_ci("anything") == "[REDACTED]"

    def test_redact_dispatch(self):
        assert redact("AKIAIOSFODNN7REAL123", ci_mode=False) == "AKIA...23"
        assert redact("AKIAIOSFODNN7REAL123", ci_mode=True) == "[REDACTED]"


class TestJsonReport:
    def test_valid_json(self):
        result = _make_result()
        output = json_report.render(result, ci_mode=True)
        data = json.loads(output)
        assert data["version"] == "1.0"
        assert data["total_findings"] == 1
        assert data["blocked"] is True

    def test_ci_mode_redaction(self):
        result = _make_result()
        output = json_report.render(result, ci_mode=True)
        data = json.loads(output)
        assert data["findings"][0]["value"] == "[REDACTED]"

    def test_local_mode_partial(self):
        result = _make_result()
        output = json_report.render(result, ci_mode=False)
        data = json.loads(output)
        assert data["findings"][0]["value"] != "[REDACTED]"
        assert "..." in data["findings"][0]["value"]

    def test_empty_result(self):
        result = ScanResult()
        output = json_report.render(result)
        data = json.loads(output)
        assert data["total_findings"] == 0
        assert data["blocked"] is False


class TestSarifReport:
    def test_valid_sarif_structure(self):
        result = _make_result()
        output = sarif.render(result)
        data = json.loads(output)
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1
        assert len(data["runs"][0]["results"]) == 1

    def test_sarif_always_redacted(self):
        result = _make_result()
        output = sarif.render(result)
        data = json.loads(output)
        r = data["runs"][0]["results"][0]
        assert "[REDACTED]" in r["message"]["text"]
        snippet = r["locations"][0]["physicalLocation"]["region"]["snippet"]["text"]
        assert snippet == "[REDACTED]"

    def test_sarif_severity_mapping(self):
        result = _make_result()
        output = sarif.render(result)
        data = json.loads(output)
        assert data["runs"][0]["results"][0]["level"] == "error"  # critical → error

    def test_sarif_empty_result(self):
        result = ScanResult()
        output = sarif.render(result)
        data = json.loads(output)
        assert len(data["runs"][0]["results"]) == 0
