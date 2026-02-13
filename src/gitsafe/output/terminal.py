"""Rich terminal reporter — colour, icons, severity pills."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.text import Text

from gitsafe.findings.models import Finding, ScanResult
from gitsafe.findings.redactor import redact

_SEVERITY_STYLE = {
    "critical": "bold white on red",
    "high": "bold white on dark_orange",
    "medium": "bold black on yellow",
    "low": "bold black on bright_cyan",
}

_SEVERITY_ICON = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
}


def _severity_pill(severity: str) -> Text:
    style = _SEVERITY_STYLE.get(severity, "")
    icon = _SEVERITY_ICON.get(severity, "")
    return Text(f" {icon} {severity.upper()} ", style=style)


def render(result: ScanResult, *, ci_mode: bool = False, show_summary: bool = True) -> None:
    """Print scan results to the terminal using Rich."""
    console = Console(stderr=True)

    if not result.findings:
        console.print()
        console.print("[bold green]✅ No secrets detected — commit is clean.[/bold green]")
        if show_summary:
            _print_summary(console, result)
        return

    # Findings table
    console.print()
    table = Table(
        title="GitSafe Findings",
        show_lines=True,
        title_style="bold",
        border_style="dim",
    )
    table.add_column("Severity", justify="center", width=12)
    table.add_column("Rule", style="cyan", min_width=20)
    table.add_column("File", style="magenta")
    table.add_column("Line", justify="right", style="green")
    table.add_column("Match", min_width=15)

    for finding in result.findings:
        sev = _severity_pill(finding.severity)
        matched = redact(finding.matched_value, ci_mode=ci_mode)
        table.add_row(
            sev,
            finding.rule_name,
            finding.file,
            str(finding.line_no) if finding.line_no > 0 else "-",
            matched,
        )

    console.print(table)

    if show_summary:
        _print_summary(console, result)

    # Final verdict
    console.print()
    if result.blocked:
        console.print(
            "[bold red]❌ BLOCKED — secrets detected at or above threshold. "
            "Commit will be rejected.[/bold red]"
        )
    else:
        console.print(
            "[bold yellow]⚠️  Findings detected but below fail threshold. "
            "Commit allowed.[/bold yellow]"
        )


def _print_summary(console: Console, result: ScanResult) -> None:
    console.print()
    console.print(f"[dim]Files scanned:[/dim]  {result.scanned_files}")
    console.print(f"[dim]Findings:[/dim]       {result.total_findings}")
    console.print(
        f"[dim]Blocking:[/dim]      {len(result.blocking_findings)}"
    )
    console.print(f"[dim]Suppressed:[/dim]    {len(result.suppressed)}")
    console.print(f"[dim]Skipped:[/dim]       {len(result.skipped_files)}")
    console.print(f"[dim]Duration:[/dim]      {result.scan_duration_ms:.0f}ms")
