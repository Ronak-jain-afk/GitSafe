"""Inline suppression and .gitsafeignore support.

Suppression conventions (standard — matches ESLint/pylint/semgrep):
  - ``#gitsafe-ignore`` on line N suppresses ALL rules on line N.
  - ``#gitsafe-ignore`` as a standalone comment on line N suppresses line N+1.
  - ``#gitsafe-ignore[RULE_A,RULE_B]`` suppresses only those rules.
  - ``#nosec`` is supported as a shorthand for ``#gitsafe-ignore``.

.gitsafeignore file format:
  - One path glob per line (gitignore-style).
  - Lines starting with ``#`` are comments.
  - ``rule:RULE_ID path/glob`` scopes an ignore to a specific rule.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

# Match inline suppression comments
_SUPPRESS_RE = re.compile(
    r"#\s*(?:gitsafe-ignore|nosec)"
    r"(?:\[([A-Za-z0-9_,\s]+)\])?"  # optional [RULE_A, RULE_B]
    r"\s*$"
)


@dataclass(frozen=True)
class Suppression:
    """Audit record of a suppressed finding."""

    rule_id: str
    file: str
    line_no: int
    reason: str  # 'inline', 'next-line', 'gitsafeignore'
    source: str  # e.g. '#gitsafe-ignore[AWS_ACCESS_KEY]' or '.gitsafeignore:3'


def parse_inline_suppression(line_content: str) -> Tuple[bool, Optional[FrozenSet[str]]]:
    """Parse a line for ``#gitsafe-ignore`` / ``#nosec`` comments.

    Returns:
        (is_suppressed, rule_ids) — *rule_ids* is None to suppress ALL rules,
        or a frozenset of specific IDs.
    """
    m = _SUPPRESS_RE.search(line_content)
    if m is None:
        return False, None
    scope = m.group(1)
    if scope:
        ids = frozenset(r.strip() for r in scope.split(",") if r.strip())
        return True, ids
    return True, None  # suppress all


def is_pure_comment(line_content: str) -> bool:
    """Return True if the line is a standalone comment (Python/shell/JS style)."""
    stripped = line_content.strip()
    return (
        stripped.startswith("#")
        or stripped.startswith("//")
        or stripped.startswith("/*")
    )


class SuppressionChecker:
    """Check whether a finding should be suppressed based on inline comments.

    Requires the list of added lines for a file (in order) so it can look
    at the *previous* line for next-line suppression.
    """

    def __init__(self) -> None:
        # file -> line_no -> (suppress_all, specific_rules)
        self._line_suppressions: Dict[str, Dict[int, Tuple[bool, Optional[FrozenSet[str]]]]] = {}

    def register_lines(self, file: str, lines: List[Tuple[int, str]]) -> None:
        """Pre-scan lines for suppression markers.

        *lines* is a list of (line_no, content) tuples **in order**.
        """
        mapping: Dict[int, Tuple[bool, Optional[FrozenSet[str]]]] = {}
        prev_suppress: Optional[Tuple[bool, Optional[FrozenSet[str]]]] = None
        prev_was_comment = False

        for line_no, content in lines:
            is_suppressed, rule_ids = parse_inline_suppression(content)

            if is_suppressed:
                # Same-line suppression: always applies to THIS line
                mapping[line_no] = (True, rule_ids)

                # If this is a standalone comment, also suppress the NEXT line
                if is_pure_comment(content):
                    prev_suppress = (True, rule_ids)
                    prev_was_comment = True
                else:
                    prev_suppress = None
                    prev_was_comment = False
            else:
                # Check if previous line was a standalone suppression comment
                if prev_suppress is not None and prev_was_comment:
                    mapping[line_no] = prev_suppress
                prev_suppress = None
                prev_was_comment = False

        self._line_suppressions[file] = mapping

    def is_suppressed(self, file: str, line_no: int, rule_id: str) -> Optional[Suppression]:
        """Return a Suppression record if the finding should be suppressed, else None."""
        file_map = self._line_suppressions.get(file)
        if file_map is None:
            return None
        entry = file_map.get(line_no)
        if entry is None:
            return None
        suppress_all, specific_ids = entry
        if suppress_all and specific_ids is None:
            return Suppression(
                rule_id=rule_id,
                file=file,
                line_no=line_no,
                reason="inline",
                source="#gitsafe-ignore",
            )
        if specific_ids is not None and rule_id in specific_ids:
            return Suppression(
                rule_id=rule_id,
                file=file,
                line_no=line_no,
                reason="inline",
                source=f"#gitsafe-ignore[{rule_id}]",
            )
        return None


class GitSafeIgnore:
    """Parse and evaluate .gitsafeignore file."""

    def __init__(self) -> None:
        self._global_patterns: List[str] = []
        self._rule_patterns: Dict[str, List[str]] = {}  # rule_id -> [glob, ...]

    @classmethod
    def from_file(cls, path: Path) -> "GitSafeIgnore":
        """Load a .gitsafeignore file."""
        instance = cls()
        if not path.is_file():
            return instance
        with open(path) as f:
            for line_no, raw in enumerate(f, 1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                # rule-scoped: "rule:RULE_ID path/glob"
                if line.startswith("rule:"):
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        rule_id = parts[0].removeprefix("rule:")
                        pattern = parts[1]
                        instance._rule_patterns.setdefault(rule_id, []).append(pattern)
                    continue
                instance._global_patterns.append(line)
        return instance

    def is_ignored(self, filepath: str, rule_id: Optional[str] = None) -> bool:
        """Return True if *filepath* should be ignored."""
        for pat in self._global_patterns:
            if fnmatch(filepath, pat):
                return True
        if rule_id:
            for pat in self._rule_patterns.get(rule_id, []):
                if fnmatch(filepath, pat):
                    return True
        return False
