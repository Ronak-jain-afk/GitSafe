"""Configuration loading, schema, and defaults."""

from gitsafe.config.loader import ConfigError, load_config
from gitsafe.config.schema import GitSafeConfig, Severity, severity_at_or_above

__all__ = [
    "ConfigError",
    "GitSafeConfig",
    "Severity",
    "load_config",
    "severity_at_or_above",
]
