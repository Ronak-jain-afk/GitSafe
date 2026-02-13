"""Rule registry — loads built-in and custom rules, applies config filters."""

from __future__ import annotations

from fnmatch import fnmatch
from pathlib import Path
from typing import Dict, List, Optional

import yaml

from gitsafe.config.schema import GitSafeConfig
from gitsafe.rules.models import Rule


class RuleRegistry:
    """Central store for all detection rules."""

    def __init__(self) -> None:
        self._rules: Dict[str, Rule] = {}

    # ---- registration ----

    def register(self, rule: Rule) -> None:
        self._rules[rule.id] = rule

    def register_many(self, rules: list[Rule]) -> None:
        for r in rules:
            self.register(r)

    # ---- queries ----

    @property
    def all_rules(self) -> List[Rule]:
        return list(self._rules.values())

    def get(self, rule_id: str) -> Optional[Rule]:
        return self._rules.get(rule_id)

    def enabled_rules(self) -> List[Rule]:
        return [r for r in self._rules.values() if r.enabled]

    def content_rules(self) -> List[Rule]:
        """Rules that scan line content (regex and/or entropy)."""
        return [r for r in self.enabled_rules() if not r.is_file_rule]

    def file_rules(self) -> List[Rule]:
        """Rules that scan by filename pattern."""
        return [r for r in self.enabled_rules() if r.is_file_rule]

    # ---- config filtering ----

    def apply_config(self, config: GitSafeConfig) -> None:
        """Enable / disable rules based on config.rules + config.ignore.rules."""
        enable_list = config.rules.enable
        disable_list = config.rules.disable
        ignore_rules = config.ignore.rules

        for rule in self._rules.values():
            # If an explicit enable-list exists, only those are enabled
            if enable_list:
                rule.enabled = rule.id in enable_list
            # Disable list always takes precedence
            if rule.id in disable_list or rule.id in ignore_rules:
                rule.enabled = False

    # ---- file-pattern matching ----

    def match_file_patterns(self, filepath: str) -> List[Rule]:
        """Return file-level rules whose file_patterns match *filepath*."""
        hits: List[Rule] = []
        basename = Path(filepath).name
        for rule in self.file_rules():
            assert rule.file_patterns is not None
            for pat in rule.file_patterns:
                if fnmatch(basename, pat) or fnmatch(filepath, pat):
                    hits.append(rule)
                    break
        return hits

    # ---- custom rule loading ----

    def load_custom_rules(self, directory: Path) -> int:
        """Load YAML / TOML rule files from *directory*. Returns count loaded."""
        count = 0
        if not directory.is_dir():
            return 0
        for path in sorted(directory.iterdir()):
            if path.suffix in (".yaml", ".yml"):
                count += self._load_yaml_rules(path)
        return count

    def _load_yaml_rules(self, path: Path) -> int:
        with open(path) as f:
            data = yaml.safe_load(f)
        if not isinstance(data, list):
            data = [data]
        count = 0
        for entry in data:
            rule = Rule(
                id=entry["id"],
                name=entry.get("name", entry["id"]),
                description=entry.get("description", ""),
                category=entry.get("category", "secret"),
                severity=entry.get("severity", "medium"),
                pattern=entry.get("pattern"),
                file_patterns=entry.get("file_patterns"),
                min_entropy=entry.get("min_entropy"),
                min_length=entry.get("min_length"),
                allowlist_patterns=entry.get("allowlist_patterns"),
            )
            self.register(rule)
            count += 1
        return count


def build_registry(config: GitSafeConfig, repo_root: Path) -> RuleRegistry:
    """Create a fully populated, config-filtered rule registry."""
    from gitsafe.rules.builtin import ALL_BUILTIN_RULES

    registry = RuleRegistry()
    registry.register_many(ALL_BUILTIN_RULES)

    # Custom rules from .gitsafe-rules/
    custom_dir = repo_root / ".gitsafe-rules"
    registry.load_custom_rules(custom_dir)

    # Apply enable/disable from config
    registry.apply_config(config)

    # Force-compile patterns now (not inside the hot loop)
    for rule in registry.enabled_rules():
        _ = rule.compiled_pattern
        _ = rule.compiled_allowlist

    return registry
