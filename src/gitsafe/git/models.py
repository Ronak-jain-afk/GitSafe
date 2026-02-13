"""Data models for diff parsing."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class LineType(str, Enum):
    ADDED = "added"
    REMOVED = "removed"
    CONTEXT = "context"


class FileStatus(str, Enum):
    ADDED = "added"
    MODIFIED = "modified"
    DELETED = "deleted"
    RENAMED = "renamed"
    MODE_CHANGED = "mode_changed"


@dataclass(frozen=True, slots=True)
class DiffLine:
    """A single parsed line from a unified diff."""

    file: str
    line_no: int
    content: str
    line_type: LineType


@dataclass(frozen=True)
class DiffFile:
    """Metadata about a file appearing in a diff."""

    path: str
    old_path: Optional[str] = None  # set on renames
    status: FileStatus = FileStatus.MODIFIED


@dataclass(frozen=True)
class FileSkipped:
    """Record of a file that was skipped during scanning."""

    path: str
    reason: str  # 'binary', 'mode_only', 'oversized', 'ignored'
