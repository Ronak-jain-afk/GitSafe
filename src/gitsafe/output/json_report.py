"""JSON reporter for CI pipelines."""

from __future__ import annotations

import json
from typing import Any, Dict, List

from gitsafe.findings.models import ScanResult
from gitsafe.findings.redactor import redact


def to_dict(result: ScanResult, *, ci_mode: bool = True) -> Dict[str, Any]:
    """Convert ScanResult to a JSON-serialisable dict."""
    findings_list: List[Dict[str, Any]] = []
    for f in result.findings:
        findings_list.append({
            "id": f.id,
            "rule": f.rule_id,
            "rule_name": f.rule_name,
            "severity": f.severity,
            "category": f.category,
            "file": f.file,
            "line": f.line_no,
            "value": redact(f.matched_value, ci_mode=ci_mode),
            "description": f.description,
            "detection_methods": f.detection_methods,
            "is_blocking": f.is_blocking,
            **({"commit": f.commit} if f.commit else {}),
            **({"entropy": round(f.entropy_value, 2)} if f.entropy_value else {}),
        })

    suppressed_list: List[Dict[str, Any]] = []
    for s in result.suppressed:
        suppressed_list.append({
            "rule": s.rule_id,
            "file": s.file,
            "line": s.line_no,
            "reason": s.reason,
            "source": s.source,
        })

    return {
        "version": "1.0",
        "scanned_files": result.scanned_files,
        "total_findings": result.total_findings,
        "blocked": result.blocked,
        "findings": findings_list,
        "suppressed": len(result.suppressed),
        "suppressed_details": suppressed_list,
        "skipped_files": result.skipped_files,
        "scan_duration_ms": result.scan_duration_ms,
    }


def render(result: ScanResult, *, ci_mode: bool = True) -> str:
    """Return formatted JSON string."""
    return json.dumps(to_dict(result, ci_mode=ci_mode), indent=2)
