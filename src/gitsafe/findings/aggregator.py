"""Finding deduplication, severity gating, and aggregation."""

from __future__ import annotations

from typing import Dict, List, Tuple

from gitsafe.config.schema import SEVERITY_ORDER, severity_at_or_above
from gitsafe.findings.models import Finding, RawFinding


def deduplicate(raw_findings: List[RawFinding], fail_on: str) -> List[Finding]:
    """Deduplicate raw findings and apply severity gate.

    Dedup key: (rule_id, file, line_no).
    When regex + entropy both fire on the same key, merge into one Finding
    with multiple detection_methods and keep the highest severity.
    """
    merged: Dict[Tuple[str, str, int], Finding] = {}
    counter = 0

    for raw in raw_findings:
        key = (raw.rule_id, raw.file, raw.line_no)

        if key in merged:
            existing = merged[key]
            # Add detection method
            if raw.detection_method not in existing.detection_methods:
                existing.detection_methods.append(raw.detection_method)
            # Keep highest severity
            if SEVERITY_ORDER.get(raw.severity, 0) > SEVERITY_ORDER.get(
                existing.severity, 0
            ):
                existing.severity = raw.severity
            # Keep entropy value if available
            if raw.entropy_value is not None:
                existing.entropy_value = raw.entropy_value
        else:
            counter += 1
            finding = Finding(
                id=f"FINDING-{counter:03d}",
                rule_id=raw.rule_id,
                rule_name=raw.rule_name,
                severity=raw.severity,
                category=raw.category,
                file=raw.file,
                line_no=raw.line_no,
                matched_value=raw.matched_value,
                description=raw.description,
                detection_methods=[raw.detection_method],
                entropy_value=raw.entropy_value,
                commit=raw.commit,
                is_blocking=severity_at_or_above(raw.severity, fail_on),
            )
            merged[key] = finding

    return list(merged.values())
