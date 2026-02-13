"""Tests for the scan engine — integration tests through the full pipeline."""

from pathlib import Path

import pytest

from gitsafe.config.schema import GitSafeConfig
from gitsafe.rules.registry import build_registry
from gitsafe.scanner.engine import ScanError, scan


def _scan(diff: str, config: GitSafeConfig | None = None, repo_root: Path | None = None):
    """Helper to run a scan with defaults."""
    cfg = config or GitSafeConfig()
    root = repo_root or Path(".")
    registry = build_registry(cfg, root)
    return scan(diff, cfg, registry, root)


class TestCleanDiffs:
    def test_no_findings(self, sample_diff_clean):
        result = _scan(sample_diff_clean)
        assert result.total_findings == 0
        assert result.blocked is False

    def test_empty_diff(self):
        result = _scan("")
        assert result.total_findings == 0
        assert result.blocked is False


class TestSecretDetection:
    def test_aws_key_detected(self, sample_diff_with_aws_key):
        result = _scan(sample_diff_with_aws_key)
        assert result.total_findings >= 1
        assert any(f.rule_id == "AWS_ACCESS_KEY" for f in result.findings)
        assert result.blocked is True  # critical severity >= high threshold

    def test_private_key_detected(self, sample_diff_with_private_key):
        result = _scan(sample_diff_with_private_key)
        assert result.total_findings >= 1
        assert any(f.rule_id == "PRIVATE_KEY" for f in result.findings)

    def test_password_detected(self, sample_diff_with_password):
        result = _scan(sample_diff_with_password)
        assert any(f.rule_id == "HARDCODED_PASSWORD" for f in result.findings)

    def test_jwt_detected(self, sample_diff_jwt):
        result = _scan(sample_diff_jwt)
        assert any(f.rule_id == "GENERIC_JWT" for f in result.findings)

    def test_env_file_detected(self, sample_diff_env_file):
        result = _scan(sample_diff_env_file)
        # Should detect .env file by filename pattern
        assert any(f.rule_id == "ENV_FILE" for f in result.findings)


class TestSuppression:
    def test_inline_suppression(self, sample_diff_with_suppression):
        result = _scan(sample_diff_with_suppression)
        # The AWS key line has #gitsafe-ignore, so it should be suppressed
        aws_findings = [f for f in result.findings if f.rule_id == "AWS_ACCESS_KEY"]
        assert len(aws_findings) == 0
        assert len(result.suppressed) >= 1


class TestSeverityGating:
    def test_fail_on_critical_only(self, sample_diff_with_password):
        cfg = GitSafeConfig()
        cfg.scan.fail_on = "critical"  # type: ignore
        result = _scan(sample_diff_with_password, config=cfg)
        # Password is "high" severity, not "critical"
        if result.findings:
            assert result.blocked is False

    def test_fail_on_low(self, sample_diff_with_password):
        cfg = GitSafeConfig()
        cfg.scan.fail_on = "low"  # type: ignore
        result = _scan(sample_diff_with_password, config=cfg)
        if result.findings:
            assert result.blocked is True


class TestBinaryAndSkipped:
    def test_binary_skipped(self, sample_diff_binary):
        result = _scan(sample_diff_binary)
        assert result.total_findings == 0
        assert any("binary" in s for s in result.skipped_files)

    def test_mode_only_skipped(self, sample_diff_mode_only):
        result = _scan(sample_diff_mode_only)
        assert result.total_findings == 0


class TestRuleDisabling:
    def test_disabled_rule_not_scanned(self, sample_diff_with_aws_key):
        cfg = GitSafeConfig()
        cfg.rules.disable = ["AWS_ACCESS_KEY"]
        result = _scan(sample_diff_with_aws_key, config=cfg)
        assert not any(f.rule_id == "AWS_ACCESS_KEY" for f in result.findings)


class TestPerformance:
    def test_scan_completes_quickly(self, sample_diff_with_aws_key):
        """Scan should complete in well under 1 second."""
        result = _scan(sample_diff_with_aws_key)
        assert result.scan_duration_ms < 1000
