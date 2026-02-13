"""Unified diff parser — handles all edge cases from the spec.

Yields DiffLine objects for added lines. Buffers per-hunk for multi-line
pattern support. Handles BOM, CRLF, binary markers, renames, mode-only
changes, submodule pointers, and all hunk header variations.
"""

from __future__ import annotations

import re
from typing import Generator, List, Optional

from gitsafe.git.models import DiffFile, DiffLine, FileSkipped, FileStatus, LineType

# --- Regex patterns for diff parsing ---

_DIFF_HEADER_RE = re.compile(r"^diff --git a/(.*) b/(.*)$")
_HUNK_HEADER_RE = re.compile(
    r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@"
)
_BINARY_RE = re.compile(r"^Binary files .* and .* differ$")
_RENAME_FROM_RE = re.compile(r"^rename from (.+)$")
_RENAME_TO_RE = re.compile(r"^rename to (.+)$")
_SUBPROJECT_RE = re.compile(r"^[+-]?Subproject commit [0-9a-f]+$")
_NO_NEWLINE_RE = re.compile(r"^\\ No newline at end of file$")
_FILE_HEADER_OLD = re.compile(r"^--- (?:a/|/dev/null)")
_FILE_HEADER_NEW = re.compile(r"^\+\+\+ (?:b/|/dev/null)")
_SIMILARITY_RE = re.compile(r"^similarity index \d+%$")
_OLD_MODE_RE = re.compile(r"^old mode \d+$")
_NEW_MODE_RE = re.compile(r"^new mode \d+$")
_DELETED_FILE_RE = re.compile(r"^deleted file mode \d+$")
_NEW_FILE_RE = re.compile(r"^new file mode \d+$")
_INDEX_RE = re.compile(r"^index [0-9a-f]+\.\.[0-9a-f]+")


def _strip_bom(line: str) -> str:
    """Remove UTF-8 BOM if present."""
    return line.lstrip("\ufeff")


def _normalise(line: str) -> str:
    """Strip trailing CR (CRLF → LF) and trailing whitespace for matching."""
    return line.rstrip("\r").rstrip()


class DiffParser:
    """Parse unified diff text and yield DiffLine / FileSkipped objects.

    Usage::

        parser = DiffParser(diff_text)
        for item in parser.parse():
            if isinstance(item, FileSkipped):
                ...
            elif isinstance(item, DiffLine):
                ...
    """

    def __init__(self, diff_text: str) -> None:
        self._lines = diff_text.splitlines()

    def parse(self) -> Generator[DiffLine | FileSkipped | DiffFile, None, None]:
        """Yield DiffLine, DiffFile, and FileSkipped items."""
        idx = 0
        total = len(self._lines)
        current_file: Optional[str] = None
        old_file: Optional[str] = None
        line_no: int = 0
        is_rename = False
        is_mode_only = False
        is_deleted = False
        is_binary = False
        hunk_remaining: int = 0  # added lines remaining in current hunk
        hunk_buffer: List[DiffLine] = []

        while idx < total:
            raw_line = self._lines[idx]

            # --- diff --git header → new file context ---
            m = _DIFF_HEADER_RE.match(raw_line)
            if m:
                # Flush any buffered hunk lines from previous file
                yield from hunk_buffer
                hunk_buffer.clear()

                old_file = m.group(1)
                current_file = m.group(2)
                is_rename = False
                is_mode_only = False
                is_deleted = False
                is_binary = False
                hunk_remaining = 0
                idx += 1

                # Parse sub-headers (index, mode changes, renames, new/deleted file)
                while idx < total:
                    sub = self._lines[idx]
                    if _INDEX_RE.match(sub):
                        idx += 1
                        continue
                    if _SIMILARITY_RE.match(sub):
                        idx += 1
                        continue
                    if _OLD_MODE_RE.match(sub):
                        is_mode_only = True
                        idx += 1
                        continue
                    if _NEW_MODE_RE.match(sub):
                        idx += 1
                        # Check if ONLY mode changed (no content follows)
                        continue
                    if _DELETED_FILE_RE.match(sub):
                        is_deleted = True
                        idx += 1
                        continue
                    if _NEW_FILE_RE.match(sub):
                        idx += 1
                        continue
                    if (rm := _RENAME_FROM_RE.match(sub)):
                        old_file = rm.group(1)
                        is_rename = True
                        idx += 1
                        continue
                    if (rt := _RENAME_TO_RE.match(sub)):
                        current_file = rt.group(1)
                        idx += 1
                        continue
                    if _BINARY_RE.match(sub):
                        is_binary = True
                        idx += 1
                        continue
                    break  # not a sub-header → stop

                # Emit metadata
                if is_binary:
                    yield FileSkipped(path=current_file, reason="binary")
                    continue
                if is_mode_only and not self._has_hunks_ahead(idx, total):
                    yield FileSkipped(path=current_file, reason="mode_only")
                    continue
                if is_deleted:
                    # Deleted files have only '-' lines → no findings
                    status = FileStatus.DELETED
                elif is_rename:
                    status = FileStatus.RENAMED
                else:
                    status = FileStatus.MODIFIED

                yield DiffFile(
                    path=current_file,
                    old_path=old_file if is_rename else None,
                    status=status,
                )
                continue

            # --- File headers (--- a/ and +++ b/) → skip ---
            if _FILE_HEADER_OLD.match(raw_line) or _FILE_HEADER_NEW.match(raw_line):
                idx += 1
                continue

            # --- Hunk header ---
            hm = _HUNK_HEADER_RE.match(raw_line)
            if hm:
                # Flush previous hunk buffer
                yield from hunk_buffer
                hunk_buffer.clear()

                # Parse new line start and count
                # old_start = int(hm.group(1))
                # old_count = int(hm.group(2)) if hm.group(2) is not None else 1
                new_start = int(hm.group(3))
                # new_count = int(hm.group(4)) if hm.group(4) is not None else 1
                line_no = new_start
                idx += 1
                continue

            # --- Subproject commit lines → skip ---
            if _SUBPROJECT_RE.match(raw_line):  # gitsafe-ignore[HIGH_ENTROPY_STRING]
                idx += 1
                continue

            # --- "\ No newline at end of file" → skip ---
            if _NO_NEWLINE_RE.match(raw_line):
                idx += 1
                continue

            # --- Content lines ---
            if current_file is not None:
                if raw_line.startswith("+"):
                    content = raw_line[1:]  # strip leading '+'
                    content = _strip_bom(content)
                    # Store raw content; normalised version used for pattern matching
                    diff_line = DiffLine(
                        file=current_file,
                        line_no=line_no,
                        content=content,
                        line_type=LineType.ADDED,
                    )
                    hunk_buffer.append(diff_line)
                    line_no += 1
                elif raw_line.startswith("-"):
                    # Removed lines — skip for scanning, but track
                    idx += 1
                    continue
                elif raw_line.startswith(" "):
                    # Context lines
                    line_no += 1
                else:
                    # Unknown line — could be outside diff context, skip
                    pass

            idx += 1

        # Flush remaining buffer
        yield from hunk_buffer

    def _has_hunks_ahead(self, idx: int, total: int) -> bool:
        """Check if there are hunk headers ahead for the current file."""
        while idx < total:
            line = self._lines[idx]
            if _DIFF_HEADER_RE.match(line):
                return False  # next file started
            if _HUNK_HEADER_RE.match(line):
                return True
            idx += 1
        return False
