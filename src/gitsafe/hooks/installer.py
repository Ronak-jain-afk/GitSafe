"""Pre-commit hook installer — gitsafe install / uninstall."""

from __future__ import annotations

from pathlib import Path
from typing import Tuple

_HOOK_MARKER = "# gitsafe-hook"
_HOOK_SCRIPT = f"""\
#!/bin/sh
{_HOOK_MARKER}
# Installed by gitsafe — https://github.com/gitsafe/gitsafe
# To uninstall: gitsafe uninstall

exec gitsafe scan
"""


def _hooks_dir(repo_root: Path) -> Path:
    """Return the hooks directory (respects core.hooksPath if set)."""
    # For simplicity, always use .git/hooks
    return repo_root / ".git" / "hooks"


def install_hook(repo_root: Path, *, force: bool = False) -> Tuple[bool, str]:
    """Install gitsafe as a pre-commit hook.

    Returns (success, message).
    """
    hooks_dir = _hooks_dir(repo_root)
    if not hooks_dir.parent.is_dir():
        return False, f"Not a git repository: {repo_root}"

    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_path = hooks_dir / "pre-commit"

    if hook_path.exists():
        content = hook_path.read_text(encoding="utf-8", errors="replace")
        if _HOOK_MARKER in content:
            return True, "gitsafe hook is already installed."
        if not force:
            return (
                False,
                f"A pre-commit hook already exists at {hook_path}. "
                "Use --force to overwrite, or manually add 'gitsafe scan' to it.",
            )

    hook_path.write_text(_HOOK_SCRIPT, encoding="utf-8")
    # Make executable on Unix
    try:
        hook_path.chmod(0o755)
    except OSError:
        pass  # Windows doesn't need chmod

    return True, f"Installed gitsafe pre-commit hook at {hook_path}"


def uninstall_hook(repo_root: Path) -> Tuple[bool, str]:
    """Remove gitsafe pre-commit hook.

    Returns (success, message).
    """
    hooks_dir = _hooks_dir(repo_root)
    hook_path = hooks_dir / "pre-commit"

    if not hook_path.exists():
        return True, "No pre-commit hook found — nothing to remove."

    content = hook_path.read_text(encoding="utf-8", errors="replace")
    if _HOOK_MARKER not in content:
        return False, "Pre-commit hook exists but was not installed by gitsafe."

    hook_path.unlink()
    return True, f"Removed gitsafe pre-commit hook from {hook_path}"
