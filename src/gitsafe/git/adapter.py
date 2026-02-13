"""Git subprocess wrapper — staged diff, CI diff, binary detection."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Optional


class GitError(Exception):
    """Raised when git is unavailable or returns an unexpected error."""


def _run_git(args: list[str], cwd: Path, timeout: int = 30) -> str:
    """Run a git command and return stdout. Raises GitError on failure."""
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError:
        raise GitError("git is not installed or not on PATH")
    except subprocess.TimeoutExpired:
        raise GitError(f"git command timed out after {timeout}s: git {' '.join(args)}")

    if result.returncode != 0:
        stderr = result.stderr.strip()
        # Empty diff is not an error
        if not stderr or "fatal" not in stderr.lower():
            return result.stdout
        raise GitError(f"git error: {stderr}")
    return result.stdout


def get_repo_root(cwd: Optional[Path] = None) -> Path:
    """Return the root of the current git repository."""
    cwd = cwd or Path.cwd()
    out = _run_git(["rev-parse", "--show-toplevel"], cwd=cwd)
    return Path(out.strip())


def get_staged_diff(repo_root: Path) -> str:
    """Return the unified diff of staged changes (--cached)."""
    return _run_git(
        ["diff", "--cached", "--unified=0", "--no-color"],
        cwd=repo_root,
    )


def get_ci_diff(repo_root: Path, base: str, head: str) -> str:
    """Return the unified diff between two commits (CI mode)."""
    return _run_git(
        ["diff", f"{base}..{head}", "--unified=0", "--no-color"],
        cwd=repo_root,
    )


def get_binary_files(repo_root: Path, staged: bool = True) -> set[str]:
    """Return set of binary file paths from the diff."""
    args = ["diff", "--numstat", "--no-color"]
    if staged:
        args.insert(1, "--cached")
    output = _run_git(args, cwd=repo_root)
    binaries: set[str] = set()
    for line in output.splitlines():
        # Binary files show as: -\t-\tfilename
        if line.startswith("-\t-\t"):
            binaries.add(line.split("\t", 2)[2])
    return binaries


def get_staged_files(repo_root: Path) -> list[str]:
    """Return list of staged file paths."""
    output = _run_git(
        ["diff", "--cached", "--name-only", "--no-color"],
        cwd=repo_root,
    )
    return [line for line in output.splitlines() if line.strip()]
