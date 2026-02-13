"""Load and merge configuration from .gitsafe.toml, CLI flags, and env vars."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomllib  # type: ignore[import-not-found]
    except ModuleNotFoundError:
        import tomli as tomllib  # type: ignore[no-redef]

from gitsafe.config.schema import (
    AllowlistConfig,
    CIConfig,
    EntropyConfig,
    GitSafeConfig,
    IgnoreConfig,
    OutputConfig,
    RulesConfig,
    ScanConfig,
)


class ConfigError(Exception):
    """Raised when config is malformed or unreadable."""


def find_config_file(repo_root: Path, override: Optional[str] = None) -> Optional[Path]:
    """Locate the config file. *override* takes precedence."""
    if override:
        p = Path(override)
        if not p.is_file():
            raise ConfigError(f"Config file not found: {override}")
        return p
    candidate = repo_root / ".gitsafe.toml"
    return candidate if candidate.is_file() else None


def _parse_toml(path: Path) -> Dict[str, Any]:
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except Exception as exc:
        raise ConfigError(f"Failed to parse {path}: {exc}") from exc


def _merge_env_overrides(cfg: GitSafeConfig) -> None:
    """Apply CI_GITSAFE_* environment variable overrides."""
    if val := os.environ.get("CI_GITSAFE_FAIL_ON"):
        if val in ("low", "medium", "high", "critical"):
            cfg.scan.fail_on = val  # type: ignore[assignment]
    if val := os.environ.get("CI_GITSAFE_FORMAT"):
        if val in ("terminal", "json", "sarif"):
            cfg.output.format = val  # type: ignore[assignment]
    if val := os.environ.get("CI_GITSAFE_DISABLE_RULES"):
        cfg.rules.disable.extend(r.strip() for r in val.split(",") if r.strip())
    if val := os.environ.get("CI_GITSAFE_IGNORE_PATHS"):
        sep = ":" if os.name != "nt" else ";"
        cfg.ignore.paths.extend(p.strip() for p in val.split(sep) if p.strip())
    if os.environ.get("CI_GITSAFE_EXIT_ZERO") == "1":
        # Handled at CLI level — we store a flag
        cfg.scan.fail_on = "critical"  # type: ignore[assignment]
    if val := os.environ.get("CI_GITSAFE_MAX_FINDINGS"):
        try:
            cfg.ci.max_findings = int(val)
        except ValueError:
            pass


def _build_section(data: Dict[str, Any], cls: type, section: str):
    """Build a dataclass from a TOML section dict, ignoring unknown keys."""
    import dataclasses

    valid_fields = {f.name for f in dataclasses.fields(cls)}
    filtered = {k: v for k, v in data.get(section, {}).items() if k in valid_fields}
    return cls(**filtered)


def load_config(
    repo_root: Path,
    config_override: Optional[str] = None,
) -> GitSafeConfig:
    """Load, validate, and return a GitSafeConfig."""
    config_path = find_config_file(repo_root, config_override)

    if config_path is None:
        cfg = GitSafeConfig()
    else:
        raw = _parse_toml(config_path)
        cfg = GitSafeConfig(
            version=raw.get("version", "1.0"),
            scan=_build_section(raw, ScanConfig, "scan"),
            output=_build_section(raw, OutputConfig, "output"),
            rules=_build_section(raw, RulesConfig, "rules"),
            entropy=_build_section(raw, EntropyConfig, "entropy"),
            ignore=_build_section(raw, IgnoreConfig, "ignore"),
            allowlist=_build_section(raw, AllowlistConfig, "allowlist"),
            ci=_build_section(raw, CIConfig, "ci"),
        )

    _merge_env_overrides(cfg)
    return cfg
