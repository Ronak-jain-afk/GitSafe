"""Rule data model — pattern stored as string, compiled at load time."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional

from gitsafe.config.schema import Severity


@dataclass
class Rule:
    """A single detection rule.

    ``pattern`` is stored as a raw string so the rule remains serialisable.
    The compiled regex is built lazily on first access via ``compiled_pattern``.
    """

    id: str
    name: str
    description: str
    category: str  # secret | credential | key | config | sensitive
    severity: Severity
    pattern: Optional[str] = None
    file_patterns: Optional[List[str]] = None
    min_entropy: Optional[float] = None
    min_length: Optional[int] = None
    allowlist_patterns: Optional[List[str]] = None
    enabled: bool = True

    # --- cached compiled objects (not serialised) ---
    _compiled_pattern: Optional[re.Pattern[str]] = field(
        default=None, init=False, repr=False, compare=False
    )
    _compiled_allowlist: Optional[List[re.Pattern[str]]] = field(
        default=None, init=False, repr=False, compare=False
    )

    @property
    def compiled_pattern(self) -> Optional[re.Pattern[str]]:
        if self.pattern is None:
            return None
        if self._compiled_pattern is None:
            self._compiled_pattern = re.compile(self.pattern)
        return self._compiled_pattern

    @property
    def compiled_allowlist(self) -> List[re.Pattern[str]]:
        if self._compiled_allowlist is None:
            if self.allowlist_patterns:
                self._compiled_allowlist = [
                    re.compile(p, re.IGNORECASE) for p in self.allowlist_patterns
                ]
            else:
                self._compiled_allowlist = []
        return self._compiled_allowlist

    @property
    def is_file_rule(self) -> bool:
        """True if this rule detects by filename rather than content."""
        return self.file_patterns is not None and self.pattern is None

    @property
    def is_entropy_rule(self) -> bool:
        return self.min_entropy is not None
