"""Tests for config loading, validation, and env var overrides."""

from pathlib import Path

import pytest

from gitsafe.config.loader import ConfigError, load_config
from gitsafe.config.schema import GitSafeConfig, severity_at_or_above


class TestSeverityComparison:
    def test_at_or_above(self):
        assert severity_at_or_above("critical", "high") is True
        assert severity_at_or_above("high", "high") is True
        assert severity_at_or_above("medium", "high") is False
        assert severity_at_or_above("low", "high") is False

    def test_all_levels(self):
        assert severity_at_or_above("low", "low") is True
        assert severity_at_or_above("medium", "low") is True
        assert severity_at_or_above("high", "low") is True
        assert severity_at_or_above("critical", "low") is True


class TestConfigLoading:
    def test_default_config(self, tmp_path: Path):
        cfg = load_config(tmp_path)
        assert cfg.scan.fail_on == "high"
        assert cfg.entropy.min_entropy == 4.0
        assert cfg.output.format == "terminal"

    def test_custom_toml(self, tmp_path: Path):
        toml_path = tmp_path / ".gitsafe.toml"
        toml_path.write_text(
            'version = "1.0"\n'
            '[scan]\n'
            'fail_on = "critical"\n'
            '[entropy]\n'
            'min_entropy = 3.5\n'
        )
        cfg = load_config(tmp_path)
        assert cfg.scan.fail_on == "critical"
        assert cfg.entropy.min_entropy == 3.5

    def test_config_override_path(self, tmp_path: Path):
        custom = tmp_path / "custom.toml"
        custom.write_text('[scan]\nfail_on = "low"\n')
        cfg = load_config(tmp_path, config_override=str(custom))
        assert cfg.scan.fail_on == "low"

    def test_missing_override_raises(self, tmp_path: Path):
        with pytest.raises(ConfigError):
            load_config(tmp_path, config_override="/nonexistent/config.toml")

    def test_invalid_toml_raises(self, tmp_path: Path):
        bad_toml = tmp_path / ".gitsafe.toml"
        bad_toml.write_text("this is not valid [toml")
        with pytest.raises(ConfigError):
            load_config(tmp_path)


class TestEnvVarOverrides:
    def test_fail_on_override(self, tmp_path: Path, monkeypatch):
        monkeypatch.setenv("CI_GITSAFE_FAIL_ON", "critical")
        cfg = load_config(tmp_path)
        assert cfg.scan.fail_on == "critical"

    def test_format_override(self, tmp_path: Path, monkeypatch):
        monkeypatch.setenv("CI_GITSAFE_FORMAT", "json")
        cfg = load_config(tmp_path)
        assert cfg.output.format == "json"

    def test_disable_rules_override(self, tmp_path: Path, monkeypatch):
        monkeypatch.setenv("CI_GITSAFE_DISABLE_RULES", "AWS_ACCESS_KEY,PRIVATE_KEY")
        cfg = load_config(tmp_path)
        assert "AWS_ACCESS_KEY" in cfg.rules.disable
        assert "PRIVATE_KEY" in cfg.rules.disable

    def test_max_findings_override(self, tmp_path: Path, monkeypatch):
        monkeypatch.setenv("CI_GITSAFE_MAX_FINDINGS", "50")
        cfg = load_config(tmp_path)
        assert cfg.ci.max_findings == 50

    def test_invalid_env_ignored(self, tmp_path: Path, monkeypatch):
        monkeypatch.setenv("CI_GITSAFE_FAIL_ON", "not_a_severity")
        cfg = load_config(tmp_path)
        assert cfg.scan.fail_on == "high"  # default unchanged
