"""SARIF v2.1.0 reporter — GitHub Advanced Security / Code Scanning.

All matched values are ALWAYS redacted in SARIF output — this is a
security invariant and cannot be disabled.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from gitsafe import __version__
from gitsafe.findings.models import ScanResult

_SEVERITY_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def to_dict(result: ScanResult) -> Dict[str, Any]:
    """Convert ScanResult to a SARIF v2.1.0 dict."""
    rules: List[Dict[str, Any]] = []
    seen_rules: set[str] = set()
    results: List[Dict[str, Any]] = []

    for f in result.findings:
        # Rule definition (only once per rule_id)
        if f.rule_id not in seen_rules:
            seen_rules.add(f.rule_id)
            rules.append({
                "id": f.rule_id,
                "name": f.rule_name,
                "shortDescription": {"text": f.rule_name},
                "fullDescription": {"text": f.description},
                "defaultConfiguration": {
                    "level": _SEVERITY_MAP.get(f.severity, "warning"),
                },
                "properties": {
                    "security-severity": _security_severity(f.severity),
                },
            })

        # Result entry — ALWAYS redacted
        results.append({
            "ruleId": f.rule_id,
            "level": _SEVERITY_MAP.get(f.severity, "warning"),
            "message": {
                "text": f"{f.rule_name} detected [REDACTED]",
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file},
                        "region": {
                            "startLine": max(f.line_no, 1),
                            "snippet": {"text": "[REDACTED]"},
                        },
                    }
                }
            ],
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",  # gitsafe-ignore[HIGH_ENTROPY_STRING]
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "gitsafe",
                        "version": __version__,
                        "informationUri": "https://github.com/gitsafe/gitsafe",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return sarif


def render(result: ScanResult) -> str:
    """Return SARIF JSON string."""
    return json.dumps(to_dict(result), indent=2)


def _security_severity(severity: str) -> str:
    """Map severity to SARIF security-severity score (0.0 – 10.0)."""
    mapping = {
        "critical": "9.5",
        "high": "7.5",
        "medium": "5.0",
        "low": "2.0",
    }
    return mapping.get(severity, "5.0")
