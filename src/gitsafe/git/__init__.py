"""Git interface layer — adapter, diff parsing, models."""

from gitsafe.git.adapter import (
    GitError,
    get_binary_files,
    get_ci_diff,
    get_repo_root,
    get_staged_diff,
    get_staged_files,
)
from gitsafe.git.diff_parser import DiffParser
from gitsafe.git.models import DiffFile, DiffLine, FileSkipped, FileStatus, LineType

__all__ = [
    "DiffFile",
    "DiffLine",
    "DiffParser",
    "FileSkipped",
    "FileStatus",
    "GitError",
    "LineType",
    "get_binary_files",
    "get_ci_diff",
    "get_repo_root",
    "get_staged_diff",
    "get_staged_files",
]
