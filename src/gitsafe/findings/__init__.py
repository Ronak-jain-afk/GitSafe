"""Finding models, aggregation, and redaction."""

from gitsafe.findings.aggregator import deduplicate
from gitsafe.findings.models import Finding, RawFinding, ScanResult
from gitsafe.findings.redactor import redact

__all__ = ["Finding", "RawFinding", "ScanResult", "deduplicate", "redact"]
