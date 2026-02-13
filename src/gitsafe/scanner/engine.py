"""Core scan engine — orchestrates the full pipeline.

Exception safety: the scan loop wraps all operations so that matched
secret values never leak into tracebacks or error messages.
"""

from __future__ import annotations

import re
import time
from fnmatch import fnmatch
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from gitsafe.config.schema import GitSafeConfig, severity_at_or_above
from gitsafe.findings.aggregator import deduplicate
from gitsafe.findings.models import Finding, RawFinding, ScanResult
from gitsafe.git.diff_parser import DiffParser
from gitsafe.git.models import DiffFile, DiffLine, FileSkipped, LineType
from gitsafe.rules.models import Rule
from gitsafe.rules.registry import RuleRegistry
from gitsafe.scanner.entropy import find_high_entropy
from gitsafe.scanner.suppression import (
    GitSafeIgnore,
    Suppression,
    SuppressionChecker,
)


class ScanError(Exception):
    """Raised on internal scanner error (never contains secret values)."""


def _match_global_allowlist(text: str, patterns: List[re.Pattern[str]]) -> bool:
    """Return True if text matches any global allowlist pattern."""
    return any(p.search(text) for p in patterns)


def _match_rule_allowlist(text: str, rule: Rule) -> bool:
    """Return True if text matches the rule's own allowlist."""
    return any(p.search(text) for p in rule.compiled_allowlist)


def scan(
    diff_text: str,
    config: GitSafeConfig,
    registry: RuleRegistry,
    repo_root: Path,
    *,
    ci_mode: bool = False,
) -> ScanResult:
    """Execute the full scan pipeline on *diff_text*. Returns a ScanResult."""
    start = time.perf_counter()

    # --- Pre-compile global allowlist patterns ---
    global_allowlist = [
        re.compile(p, re.IGNORECASE) for p in config.allowlist.patterns
    ]

    # --- Load .gitsafeignore ---
    ignorefile = GitSafeIgnore.from_file(repo_root / ".gitsafeignore")

    # --- Load ignore paths from config ---
    ignore_globs = config.ignore.files + config.ignore.paths

    # --- Parse diff ---
    parser = DiffParser(diff_text)

    raw_findings: List[RawFinding] = []
    suppressions: List[Suppression] = []
    skipped_files: List[str] = []
    scanned_files_set: set[str] = set()
    ignored_files_set: set[str] = set()  # Track files skipped by ignores

    # Collect lines per file for suppression pre-scan
    file_lines: Dict[str, List[Tuple[int, str]]] = {}
    diff_items = list(parser.parse())

    # Build per-file line lists
    for item in diff_items:
        if isinstance(item, DiffLine) and item.line_type == LineType.ADDED:
            file_lines.setdefault(item.file, []).append((item.line_no, item.content))

    # Pre-scan for inline suppressions
    suppression_checker = SuppressionChecker()
    for file, lines in file_lines.items():
        suppression_checker.register_lines(file, lines)

    # --- Content + file rules ---
    content_rules = registry.content_rules()
    file_rules = registry.file_rules()
    entropy_cfg = config.entropy

    try:
        for item in diff_items:
            # --- FileSkipped ---
            if isinstance(item, FileSkipped):
                skipped_files.append(f"{item.path} ({item.reason})")
                continue

            # --- DiffFile → check file-level rules and ignores ---
            if isinstance(item, DiffFile):
                filepath = item.path

                # Check ignore globs
                if any(fnmatch(filepath, g) for g in ignore_globs):
                    skipped_files.append(f"{filepath} (ignored)")
                    ignored_files_set.add(filepath)
                    continue

                # Check .gitsafeignore (global)
                if ignorefile.is_ignored(filepath):
                    skipped_files.append(f"{filepath} (gitsafeignore)")
                    ignored_files_set.add(filepath)
                    continue

                scanned_files_set.add(filepath)

                # File-pattern rules
                for rule in file_rules:
                    assert rule.file_patterns is not None
                    basename = Path(filepath).name
                    for pat in rule.file_patterns:
                        if fnmatch(basename, pat) or fnmatch(filepath, pat):
                            # Check rule-level allowlist against filename
                            if _match_rule_allowlist(basename, rule):
                                break
                            raw_findings.append(
                                RawFinding(
                                    rule_id=rule.id,
                                    rule_name=rule.name,
                                    severity=rule.severity,
                                    category=rule.category,
                                    file=filepath,
                                    line_no=0,
                                    matched_value=basename,
                                    description=rule.description,
                                    detection_method="file_pattern",
                                )
                            )
                            break
                continue

            # --- DiffLine (added lines only) ---
            if not isinstance(item, DiffLine):
                continue
            if item.line_type != LineType.ADDED:
                continue

            line_content = item.content
            filepath = item.file
            line_no = item.line_no

            # Skip lines in ignored files
            if filepath in ignored_files_set:
                continue

            scanned_files_set.add(filepath)

            # --- Regex rules ---
            for rule in content_rules:
                if rule.is_entropy_rule:
                    continue  # handled separately below
                cp = rule.compiled_pattern
                if cp is None:
                    continue

                m = cp.search(line_content)
                if m is None:
                    continue

                # Extract matched value (prefer named group 'secret')
                matched = m.group("secret") if "secret" in m.groupdict() else m.group(0)

                # Rule-level allowlist
                if _match_rule_allowlist(matched, rule):
                    continue

                # Global allowlist
                if _match_global_allowlist(matched, global_allowlist):
                    continue

                # .gitsafeignore rule-scoped check
                if ignorefile.is_ignored(filepath, rule.id):
                    continue

                # Inline suppression
                sup = suppression_checker.is_suppressed(filepath, line_no, rule.id)
                if sup is not None:
                    suppressions.append(sup)
                    continue

                raw_findings.append(
                    RawFinding(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        category=rule.category,
                        file=filepath,
                        line_no=line_no,
                        matched_value=matched,
                        description=rule.description,
                        detection_method="regex",
                    )
                )

                # Early exit (if enabled and critical)
                if (
                    config.scan.early_exit
                    and rule.severity == "critical"
                ):
                    break

            # --- Entropy scanning ---
            if entropy_cfg.enabled:
                min_ent = entropy_cfg.min_entropy
                min_len = entropy_cfg.min_length
                hits = find_high_entropy(line_content, min_ent, min_len)

                for candidate, entropy_val in hits:
                    # Global allowlist
                    if _match_global_allowlist(candidate, global_allowlist):
                        continue
                    # .gitsafeignore
                    if ignorefile.is_ignored(filepath, "HIGH_ENTROPY_STRING"):
                        continue
                    # Inline suppression
                    sup = suppression_checker.is_suppressed(
                        filepath, line_no, "HIGH_ENTROPY_STRING"
                    )
                    if sup is not None:
                        suppressions.append(sup)
                        continue

                    raw_findings.append(
                        RawFinding(
                            rule_id="HIGH_ENTROPY_STRING",
                            rule_name="High-Entropy String",
                            severity="medium",
                            category="sensitive",
                            file=filepath,
                            line_no=line_no,
                            matched_value=candidate,
                            description=f"Shannon entropy {entropy_val:.2f} bits",
                            detection_method="entropy",
                            entropy_value=entropy_val,
                        )
                    )

            # --- Circuit-breaker (CI) ---
            if config.ci.max_findings is not None:
                if len(raw_findings) >= config.ci.max_findings:
                    break

    except ScanError:
        raise
    except Exception:
        # Exception safety: do NOT let raw findings leak into traceback
        # Clear raw_findings to prevent secret values from being printed
        raw_findings_count = len(raw_findings)
        raw_findings.clear()
        raise ScanError(
            f"Internal scanner error after {raw_findings_count} findings. "
            "Secrets have been scrubbed from this error."
        )

    # --- Dedup and severity gate ---
    findings = deduplicate(raw_findings, config.scan.fail_on)
    blocked = any(f.is_blocking for f in findings)

    elapsed = (time.perf_counter() - start) * 1000

    return ScanResult(
        findings=findings,
        suppressed=suppressions,
        skipped_files=skipped_files,
        scanned_files=len(scanned_files_set),
        blocked=blocked,
        scan_duration_ms=round(elapsed, 2),
    )
