"""Tests for rule models, registry, and built-in rules."""

import re
from pathlib import Path

import pytest
import yaml

from gitsafe.config.schema import GitSafeConfig, RulesConfig
from gitsafe.rules.builtin import ALL_BUILTIN_RULES
from gitsafe.rules.models import Rule
from gitsafe.rules.registry import RuleRegistry, build_registry


class TestRuleModel:
    def test_compiled_pattern_cached(self):
        rule = Rule(
            id="TEST", name="Test", description="", category="secret",
            severity="high", pattern=r"secret_[a-z]+"
        )
        p1 = rule.compiled_pattern
        p2 = rule.compiled_pattern
        assert p1 is p2
        assert p1 is not None
        assert p1.search("my_secret_key")

    def test_no_pattern_returns_none(self):
        rule = Rule(
            id="FILE_ONLY", name="File", description="", category="key",
            severity="high", file_patterns=[".env"]
        )
        assert rule.compiled_pattern is None
        assert rule.is_file_rule is True

    def test_allowlist_compiled(self):
        rule = Rule(
            id="TEST", name="Test", description="", category="secret",
            severity="high", pattern=r"key_\w+",
            allowlist_patterns=["example", "test"],
        )
        assert len(rule.compiled_allowlist) == 2
        assert rule.compiled_allowlist[0].search("example_key")

    def test_is_entropy_rule(self):
        rule = Rule(
            id="ENT", name="Entropy", description="", category="sensitive",
            severity="medium", min_entropy=4.0, min_length=16,
        )
        assert rule.is_entropy_rule is True
        assert rule.is_file_rule is False


class TestRuleRegistry:
    def test_register_and_query(self):
        reg = RuleRegistry()
        rule = Rule(id="R1", name="R1", description="", category="secret", severity="high")
        reg.register(rule)
        assert reg.get("R1") is rule
        assert len(reg.all_rules) == 1

    def test_enable_disable(self):
        reg = RuleRegistry()
        r1 = Rule(id="R1", name="R1", description="", category="secret", severity="high")
        r2 = Rule(id="R2", name="R2", description="", category="secret", severity="low")
        reg.register_many([r1, r2])

        cfg = GitSafeConfig()
        cfg.rules = RulesConfig(enable=[], disable=["R2"])
        reg.apply_config(cfg)

        enabled = reg.enabled_rules()
        assert len(enabled) == 1
        assert enabled[0].id == "R1"

    def test_enable_list_restricts(self):
        reg = RuleRegistry()
        r1 = Rule(id="R1", name="R1", description="", category="secret", severity="high")
        r2 = Rule(id="R2", name="R2", description="", category="secret", severity="low")
        reg.register_many([r1, r2])

        cfg = GitSafeConfig()
        cfg.rules = RulesConfig(enable=["R1"], disable=[])
        reg.apply_config(cfg)

        enabled = reg.enabled_rules()
        assert len(enabled) == 1
        assert enabled[0].id == "R1"

    def test_file_pattern_matching(self):
        reg = RuleRegistry()
        rule = Rule(
            id="ENV", name="Env File", description="", category="config",
            severity="high", file_patterns=[".env", "*.pem"],
        )
        reg.register(rule)
        assert len(reg.match_file_patterns(".env")) == 1
        assert len(reg.match_file_patterns("cert.pem")) == 1
        assert len(reg.match_file_patterns("main.py")) == 0

    def test_load_custom_yaml_rules(self, tmp_path):
        rules_dir = tmp_path / ".gitsafe-rules"
        rules_dir.mkdir()
        rule_file = rules_dir / "custom.yaml"
        rule_file.write_text(yaml.dump([{
            "id": "CUSTOM_1",
            "name": "Custom Rule",
            "pattern": r"custom_secret_\w+",
            "severity": "high",
            "category": "secret",
        }]))

        reg = RuleRegistry()
        count = reg.load_custom_rules(rules_dir)
        assert count == 1
        assert reg.get("CUSTOM_1") is not None


class TestBuiltinRules:
    """Verify each built-in rule compiles and has valid metadata."""

    @pytest.mark.parametrize("rule", ALL_BUILTIN_RULES, ids=lambda r: r.id)
    def test_rule_has_required_fields(self, rule):
        assert rule.id
        assert rule.name
        assert rule.severity in ("low", "medium", "high", "critical")
        assert rule.category in ("secret", "credential", "key", "config", "sensitive")

    @pytest.mark.parametrize("rule", ALL_BUILTIN_RULES, ids=lambda r: r.id)
    def test_pattern_compiles(self, rule):
        if rule.pattern:
            # Should not raise
            compiled = rule.compiled_pattern
            assert compiled is not None

    def test_aws_key_matches(self):
        from gitsafe.rules.builtin.aws import AWS_ACCESS_KEY
        p = AWS_ACCESS_KEY.compiled_pattern
        assert p is not None
        assert p.search('key = "AKIAIOSFODNN7REAL123"')
        assert not p.search('key = "not_an_aws_key"')

    def test_aws_key_allowlist(self):
        from gitsafe.rules.builtin.aws import AWS_ACCESS_KEY
        # Example key should be allowlisted
        assert any(
            al.search("AKIAIOSFODNN7EXAMPLE")
            for al in AWS_ACCESS_KEY.compiled_allowlist
        )

    def test_private_key_matches(self):
        from gitsafe.rules.builtin.keys import PRIVATE_KEY
        p = PRIVATE_KEY.compiled_pattern
        assert p is not None
        assert p.search("-----BEGIN RSA PRIVATE KEY-----")
        assert p.search("-----BEGIN PRIVATE KEY-----")
        assert p.search("-----BEGIN EC PRIVATE KEY-----")
        assert not p.search("-----BEGIN PUBLIC KEY-----")

    def test_jwt_matches(self):
        from gitsafe.rules.builtin.tokens import GENERIC_JWT
        p = GENERIC_JWT.compiled_pattern
        assert p is not None
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def"
        assert p.search(jwt)

    def test_password_matches(self):
        from gitsafe.rules.builtin.passwords import HARDCODED_PASSWORD
        p = HARDCODED_PASSWORD.compiled_pattern
        assert p is not None
        assert p.search('password = "MyStr0ngP@ss!"')
        assert p.search("PASSWORD: 'supersecret123'")
        # Too short (< 8 chars)
        assert not p.search("password = 'short'")

    def test_github_token_matches(self):
        from gitsafe.rules.builtin.tokens import GITHUB_TOKEN
        p = GITHUB_TOKEN.compiled_pattern
        assert p is not None
        assert p.search("ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789")
        assert not p.search("ghx_invalid_prefix_token")
