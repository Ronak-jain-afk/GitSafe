"""Finding data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class RawFinding:
    """A single match produced by the scan engine (before dedup)."""

    rule_id: str
    rule_name: str
    severity: str
    category: str
    file: str
    line_no: int
    matched_value: str
    description: str
    detection_method: str = "regex"  # 'regex' | 'entropy' | 'file_pattern'
    entropy_value: Optional[float] = None
    commit: Optional[str] = None


@dataclass
class Finding:
    """Deduplicated, severity-gated finding for output."""

    id: str  # e.g. FINDING-001
    rule_id: str
    rule_name: str
    severity: str
    category: str
    file: str
    line_no: int
    matched_value: str
    description: str
    detection_methods: List[str] = field(default_factory=list)
    entropy_value: Optional[float] = None
    commit: Optional[str] = None
    is_blocking: bool = True  # does this finding cause exit code 1?


@dataclass
class ScanResult:
    """Complete result of a scan run."""

    findings: List[Finding] = field(default_factory=list)
    suppressed: List["Suppression"] = field(default_factory=list)  # type: ignore[name-defined]
    skipped_files: List[str] = field(default_factory=list)
    scanned_files: int = 0
    blocked: bool = False
    scan_duration_ms: float = 0.0

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def blocking_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.is_blocking]

    @property
    def informational_findings(self) -> List[Finding]:
        return [f for f in self.findings if not f.is_blocking]
