"""GitSafe CLI — Typer application with scan, install, init, and audit commands."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from gitsafe import __version__

app = typer.Typer(
    name="gitsafe",
    help="Block secrets before they reach your repository.",
    add_completion=False,
    no_args_is_help=True,
)

console = Console(stderr=True)


def _detect_ci() -> bool:
    """Auto-detect CI environment."""
    return os.environ.get("CI", "").lower() in ("true", "1", "yes")


def _resolve_repo_root() -> Path:
    """Find the git repo root, exit 2 on failure."""
    from gitsafe.git.adapter import GitError, get_repo_root

    try:
        return get_repo_root()
    except GitError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc


# ── scan ──────────────────────────────────────────────────────────────────────


@app.command()
def scan(
    config: Optional[str] = typer.Option(None, "--config", "-c", help="Path to .gitsafe.toml"),
    format: Optional[str] = typer.Option(None, "--format", "-f", help="Output format: terminal | json | sarif"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Write report to file"),
    fail_on: Optional[str] = typer.Option(None, "--fail-on", help="Severity threshold: low | medium | high | critical"),
    ci: bool = typer.Option(False, "--ci", help="Enable CI mode"),
    from_ref: Optional[str] = typer.Option(None, "--from", help="Base commit (CI mode)"),
    to_ref: Optional[str] = typer.Option(None, "--to", help="Head commit (CI mode)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    debug: bool = typer.Option(False, "--debug", help="Debug output with timing"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be scanned without scanning"),
) -> None:
    """Scan staged changes (or commit range in CI) for secrets."""
    from gitsafe.config.loader import ConfigError, load_config
    from gitsafe.git.adapter import GitError, get_ci_diff, get_staged_diff
    from gitsafe.output import json_report, sarif, terminal
    from gitsafe.rules.registry import build_registry
    from gitsafe.scanner.engine import ScanError, scan as run_scan

    repo_root = _resolve_repo_root()

    # --- Load config ---
    try:
        cfg = load_config(repo_root, config)
    except ConfigError as exc:
        console.print(f"[bold red]Config error:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc

    # --- CI auto-detection ---
    ci_mode = ci or _detect_ci()
    if ci_mode:
        if cfg.output.format == "terminal" and format is None:
            cfg.output.format = "json"  # type: ignore[assignment]
        if cfg.ci.full_redaction is None:
            cfg.ci.full_redaction = True

    # --- CLI overrides ---
    if format:
        if format not in ("terminal", "json", "sarif"):
            console.print(f"[bold red]Invalid format:[/bold red] {format}")
            raise typer.Exit(code=2)
        cfg.output.format = format  # type: ignore[assignment]
    if fail_on:
        if fail_on not in ("low", "medium", "high", "critical"):
            console.print(f"[bold red]Invalid fail-on level:[/bold red] {fail_on}")
            raise typer.Exit(code=2)
        cfg.scan.fail_on = fail_on  # type: ignore[assignment]

    # --- Build rules ---
    registry = build_registry(cfg, repo_root)

    if verbose or debug:
        console.print(f"[dim]Rules loaded: {len(registry.enabled_rules())}[/dim]")
        console.print(f"[dim]Repo root: {repo_root}[/dim]")
        console.print(f"[dim]CI mode: {ci_mode}[/dim]")

    # --- Get diff ---
    try:
        if ci_mode and from_ref and to_ref:
            diff_text = get_ci_diff(repo_root, from_ref, to_ref)
        elif ci_mode and from_ref:
            diff_text = get_ci_diff(repo_root, from_ref, "HEAD")
        else:
            diff_text = get_staged_diff(repo_root)
    except GitError as exc:
        console.print(f"[bold red]Git error:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc

    if not diff_text or not diff_text.strip():
        if cfg.output.format == "terminal":
            console.print("[dim]No staged changes to scan.[/dim]")
        elif cfg.output.format == "json":
            from gitsafe.findings.models import ScanResult
            empty = ScanResult()
            print(json_report.render(empty, ci_mode=ci_mode))
        raise typer.Exit(code=0)

    if dry_run:
        from gitsafe.git.diff_parser import DiffParser
        from gitsafe.git.models import DiffFile

        parser = DiffParser(diff_text)
        files = [item.path for item in parser.parse() if isinstance(item, DiffFile)]
        console.print(f"[bold]Dry run — {len(files)} files would be scanned:[/bold]")
        for f in files:
            console.print(f"  {f}")
        raise typer.Exit(code=0)

    # --- Run scan ---
    try:
        result = run_scan(diff_text, cfg, registry, repo_root, ci_mode=ci_mode)
    except ScanError as exc:
        console.print(f"[bold red]Scanner error:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc

    if debug:
        console.print(f"[dim]Scan duration: {result.scan_duration_ms:.0f}ms[/dim]")

    # --- Output ---
    report_text: Optional[str] = None

    if cfg.output.format == "terminal":
        terminal.render(result, ci_mode=ci_mode, show_summary=cfg.output.show_summary)
    elif cfg.output.format == "json":
        report_text = json_report.render(result, ci_mode=ci_mode)
        print(report_text)
    elif cfg.output.format == "sarif":
        report_text = sarif.render(result)
        print(report_text)

    # --- Write to file ---
    if output and report_text:
        Path(output).write_text(report_text, encoding="utf-8")
        if verbose:
            console.print(f"[dim]Report written to {output}[/dim]")
    elif output and cfg.output.format == "terminal":
        # If output file requested but format is terminal, write JSON
        report_text = json_report.render(result, ci_mode=ci_mode)
        Path(output).write_text(report_text, encoding="utf-8")

    # --- CI annotations ---
    if ci_mode and result.findings:
        _emit_ci_annotations(result, cfg)

    # --- Exit code ---
    if result.blocked:
        raise typer.Exit(code=1)

    # Check CI_GITSAFE_EXIT_ZERO
    if os.environ.get("CI_GITSAFE_EXIT_ZERO") == "1":
        raise typer.Exit(code=0)

    raise typer.Exit(code=0)


def _emit_ci_annotations(result, cfg) -> None:
    """Emit CI-specific annotations (GitHub Actions, GitLab, Bitbucket)."""
    fmt = cfg.ci.annotation_format

    if fmt == "github":
        for f in result.findings:
            level = "error" if f.is_blocking else "warning"
            print(
                f"::{level} file={f.file},line={f.line_no}"
                f"::{f.rule_name} detected [REDACTED]"
            )
    elif fmt == "gitlab":
        # GitLab uses code quality format; JSON output is sufficient
        pass
    # bitbucket — not implemented in v1


# ── install ───────────────────────────────────────────────────────────────────


@app.command()
def install(
    force: bool = typer.Option(False, "--force", help="Overwrite existing pre-commit hook"),
) -> None:
    """Install gitsafe as a git pre-commit hook."""
    from gitsafe.hooks.installer import install_hook

    repo_root = _resolve_repo_root()
    success, msg = install_hook(repo_root, force=force)
    if success:
        console.print(f"[green]✓[/green] {msg}")
    else:
        console.print(f"[red]✗[/red] {msg}")
        raise typer.Exit(code=1)


# ── uninstall ─────────────────────────────────────────────────────────────────


@app.command()
def uninstall() -> None:
    """Remove gitsafe pre-commit hook."""
    from gitsafe.hooks.installer import uninstall_hook

    repo_root = _resolve_repo_root()
    success, msg = uninstall_hook(repo_root)
    if success:
        console.print(f"[green]✓[/green] {msg}")
    else:
        console.print(f"[red]✗[/red] {msg}")
        raise typer.Exit(code=1)


# ── init ──────────────────────────────────────────────────────────────────────


@app.command()
def init(
    full: bool = typer.Option(False, "--full", help="Include all config options with comments"),
) -> None:
    """Generate a starter .gitsafe.toml in the repo root."""
    from gitsafe.config.defaults import DEFAULT_TOML, FULL_TOML

    repo_root = _resolve_repo_root()
    config_path = repo_root / ".gitsafe.toml"

    if config_path.exists():
        console.print(f"[yellow]⚠[/yellow]  .gitsafe.toml already exists at {config_path}")
        raise typer.Exit(code=1)

    template = FULL_TOML if full else DEFAULT_TOML
    config_path.write_text(template, encoding="utf-8")
    console.print(f"[green]✓[/green] Created {config_path}")


# ── audit ─────────────────────────────────────────────────────────────────────


@app.command()
def audit() -> None:
    """Scan the codebase for all #gitsafe-ignore comments (audit trail)."""
    import subprocess

    repo_root = _resolve_repo_root()

    try:
        result = subprocess.run(
            ["git", "grep", "-n", "-E", r"#\s*(gitsafe-ignore|nosec)"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except FileNotFoundError:
        console.print("[bold red]Error:[/bold red] git is not available")
        raise typer.Exit(code=2)

    lines = result.stdout.strip().splitlines()
    if not lines:
        console.print("[green]No gitsafe-ignore comments found in the codebase.[/green]")
        raise typer.Exit(code=0)

    console.print(f"[bold]Found {len(lines)} suppression comment(s):[/bold]")
    console.print()
    for line in lines:
        # Parse: file:line_no:content
        parts = line.split(":", 2)
        if len(parts) == 3:
            file, line_no, content = parts
            # Parse rule scope
            scope_match = re.search(r"gitsafe-ignore\[([^\]]+)\]", content)
            scope = scope_match.group(1) if scope_match else "ALL"
            console.print(
                f"  [cyan]{file}[/cyan]:[green]{line_no}[/green]  "
                f"scope=[yellow]{scope}[/yellow]"
            )
        else:
            console.print(f"  {line}")


# ── version ───────────────────────────────────────────────────────────────────


def _version_callback(value: bool) -> None:
    if value:
        print(f"gitsafe {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", "-V", callback=_version_callback,
        is_eager=True, help="Show version and exit",
    ),
) -> None:
    """GitSafe — Block secrets before they reach your repository."""
