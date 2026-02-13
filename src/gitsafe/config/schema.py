"""Configuration schema — dataclasses for every config section."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import List, Optional

if sys.version_info >= (3, 11):
    from typing import Literal
else:
    from typing import Literal

Severity = Literal["low", "medium", "high", "critical"]

SEVERITY_ORDER: dict[str, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}


def severity_at_or_above(finding_sev: str, threshold: str) -> bool:
    """Return True if *finding_sev* is at or above *threshold*."""
    return SEVERITY_ORDER.get(finding_sev, 0) >= SEVERITY_ORDER.get(threshold, 0)


@dataclass
class ScanConfig:
    fail_on: Severity = "high"  # fail on findings at or above this level
    scan_unstaged: bool = False
    max_file_size_kb: int = 512
    early_exit: bool = False  # if True, stop rule loop on first critical per line


@dataclass
class OutputConfig:
    format: Literal["terminal", "json", "sarif"] = "terminal"
    show_summary: bool = True
    show_severity: bool = True


@dataclass
class RulesConfig:
    enable: List[str] = field(default_factory=list)  # empty = all enabled
    disable: List[str] = field(default_factory=list)


@dataclass
class EntropyConfig:
    enabled: bool = True
    min_entropy: float = 4.0
    min_length: int = 16


@dataclass
class IgnoreConfig:
    files: List[str] = field(default_factory=list)
    rules: List[str] = field(default_factory=list)
    paths: List[str] = field(default_factory=list)


@dataclass
class AllowlistConfig:
    patterns: List[str] = field(default_factory=list)


@dataclass
class CIConfig:
    annotation_format: Literal["github", "gitlab", "bitbucket", "none"] = "none"
    full_redaction: bool = True
    max_findings: Optional[int] = None  # circuit-breaker: fail immediately at N findings


@dataclass
class GitSafeConfig:
    version: str = "1.0"
    scan: ScanConfig = field(default_factory=ScanConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    rules: RulesConfig = field(default_factory=RulesConfig)
    entropy: EntropyConfig = field(default_factory=EntropyConfig)
    ignore: IgnoreConfig = field(default_factory=IgnoreConfig)
    allowlist: AllowlistConfig = field(default_factory=AllowlistConfig)
    ci: CIConfig = field(default_factory=CIConfig)
