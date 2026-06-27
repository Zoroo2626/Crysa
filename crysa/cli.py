"""CLI entrypoint for Crysa — AI-native security reasoning engine.

Built with Typer for a clean, modern CLI experience.
All terminal output uses Rich for beautiful formatting.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from crysa.utils.config import get_config, reload_config, Config
from crysa.utils.logger import console, output_console, info, warn, error, success, fatal, set_verbose, set_quiet

app = typer.Typer(
    name="crysa",
    help="[bold bright_red]Crysa[/] — AI-native security reasoning engine for coding agents",
    add_completion=False,
    rich_markup_mode="rich",
)

# Severity color mapping
_SEVERITY_COLORS = {
    "CRITICAL": "bold bright_red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "INFO": "dim white",
}


@app.callback()
def _main(
    verbose: bool = typer.Option(False, "--verbose", "-V", help="Enable debug/verbose output", is_eager=True),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress all non-finding output", is_eager=True),
    exit_code: bool = typer.Option(False, "--exit-code", help="Exit with code 1 if any findings are reported", is_eager=True),
) -> None:
    """Crysa — AI-native security reasoning engine for coding agents."""
    if verbose:
        set_verbose(True)
    if quiet:
        set_quiet(True)
    if exit_code:
        # Store in a module-level flag so commands can check it
        _set_exit_code(True)


# Module-level exit-code flag (set via --exit-code global flag)
_exit_on_findings: bool = False


def _set_exit_code(enabled: bool) -> None:
    global _exit_on_findings
    _exit_on_findings = enabled


def _maybe_exit_on_findings(result: "ScanResult") -> None:  # type: ignore[name-defined]
    """Exit 1 if --exit-code was set and findings were found."""
    if _exit_on_findings and result.findings:
        sys.exit(1)


def _display_findings_rich(findings: list, show_fix: bool = True, show_reproduction: bool = True) -> None:
    """Display findings in beautiful Rich format.

    Args:
        findings: List of Finding objects to display.
        show_fix: Whether to show fix suggestions.
        show_reproduction: Whether to show reproduction steps.
    """
    if not findings:
        console.print("[success]✓ No security issues found.[/]")
        return

    for finding in findings:
        sev_color = _SEVERITY_COLORS.get(finding.severity.value, "white")
        conf_text = f"{finding.confidence.value} CONFIDENCE"

        # Build the finding display
        title_text = Text()
        title_text.append(f"  {finding.severity.value}  ", style=f"bold {sev_color} on default")
        title_text.append(f"  •  {finding.vuln_class.value}  •  {conf_text}", style="dim")

        location_text = Text()
        location_text.append(f"  {finding.file}", style="cyan underline")
        location_text.append(f"  lines {finding.line_start}-{finding.line_end}", style="dim")

        body_lines = []
        body_lines.append(f"  [bold]{finding.title}[/]")
        body_lines.append("")
        body_lines.append(f"  {finding.description}")
        body_lines.append("")

        if finding.impact:
            body_lines.append(f"  [bold]IMPACT:[/] {finding.impact}")
            body_lines.append("")

        if show_reproduction and finding.reproduction:
            body_lines.append(f"  [bold]REPRODUCTION:[/]")
            for step in finding.reproduction.split("\n"):
                body_lines.append(f"  {step.strip()}")
            body_lines.append("")

        if show_fix and finding.fix:
            body_lines.append(f"  [bold]FIX:[/] {finding.fix}")

        body = "\n".join(body_lines)

        # Render as a panel
        panel = Panel(
            body,
            title=f"[bold]┌─ {finding.id} ─[/]",
            title_align="left",
            border_style=sev_color,
            width=80,
            padding=(0, 1),
        )

        console.print(title_text)
        console.print(location_text)
        console.print(panel)
        console.print()


def _display_summary(result: "ScanResult") -> None:  # type: ignore[name-defined]
    """Display scan summary panel."""
    from crysa.engine.findings import ScanResult
    sc = result.critical_count
    sh = result.high_count
    sm = result.medium_count
    sl = result.low_count

    summary = Text()
    summary.append(f"  Scanned {result.files_scanned} file{'s' if result.files_scanned != 1 else ''}", style="bold")
    summary.append("  •  ", style="dim")
    summary.append(f"{sc} CRITICAL", style="bold bright_red" if sc else "dim")
    summary.append("  •  ", style="dim")
    summary.append(f"{sh} HIGH", style="red" if sh else "dim")
    summary.append("  •  ", style="dim")
    summary.append(f"{sm} MEDIUM", style="yellow" if sm else "dim")
    summary.append("  •  ", style="dim")
    summary.append(f"{sl} LOW", style="blue" if sl else "dim")

    if sc > 0 or sh > 0:
        border = "red"
    elif sm > 0:
        border = "yellow"
    else:
        border = "green"

    console.print(Panel(summary, border_style=border, width=80))


@app.command()
def scan(
    path: str = typer.Argument(..., help="File or directory to scan"),
    severity: str = typer.Option("LOW", "--severity", "-s", help="Minimum severity: CRITICAL|HIGH|MEDIUM|LOW|INFO"),
    format: str = typer.Option("rich", "--format", "-f", help="Output format: rich|json|sarif"),
    fix: bool = typer.Option(False, "--fix", help="Show fix suggestions inline"),
    watch: bool = typer.Option(False, "--watch", help="Keep running and re-scan on file changes"),
    vuln_classes: Optional[str] = typer.Option(None, "--vuln-class", "-v", help="Comma-separated vuln classes to focus on"),
    workers: int = typer.Option(4, "--workers", "-w", help="Concurrent LLM threads for directory scans (default 4)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Write results to this file (json or sarif format)"),
    baseline: Optional[str] = typer.Option(None, "--baseline", "-b", help="Baseline JSON file — suppress known findings, only report new ones"),
) -> None:
    """Scan a file or directory for security vulnerabilities."""
    target = Path(path).resolve()

    if not target.exists():
        fatal(f"Path does not exist: {target}")

    config = get_config()

    # --- Resolve display options without mutating the global config singleton ---
    show_fix = fix or config.show_fix
    show_reproduction = config.show_reproduction

    classes = vuln_classes.split(",") if vuln_classes else None

    # --- Load baseline for suppression if provided ---
    baseline_keys: set[str] = set()
    if baseline:
        baseline_path = Path(baseline)
        if not baseline_path.exists():
            fatal(f"Baseline file not found: {baseline_path}")
        try:
            baseline_data = json.loads(baseline_path.read_text(encoding="utf-8"))
            for f in baseline_data.get("findings", []):
                key = f"{f.get('vuln_class','')}:{f.get('file','')}:{f.get('title','')}"
                baseline_keys.add(key)
            info(f"Baseline loaded: {len(baseline_keys)} known finding(s) will be suppressed")
        except (json.JSONDecodeError, OSError) as e:
            warn(f"Could not load baseline: {e}")

    def _apply_baseline(result: "ScanResult") -> "ScanResult":  # type: ignore[name-defined]
        if not baseline_keys:
            return result
        from crysa.engine.findings import ScanResult as SR
        new_findings = [
            f for f in result.findings
            if f"{f.vuln_class.value}:{f.file}:{f.title}" not in baseline_keys
        ]
        suppressed = len(result.findings) - len(new_findings)
        if suppressed:
            info(f"Baseline suppressed {suppressed} known finding(s)")
        return SR(findings=new_findings, files_scanned=result.files_scanned, errors=result.errors)

    if watch:
        from crysa.watcher import watch_and_scan
        watch_and_scan(target, config, severity, format, fix, classes)
        return

    console.print(f"\n  [bold]Crysa[/] — Scanning [cyan]{target}[/]\n")

    from crysa.engine.reviewer import review_file, scan_project
    from crysa.engine.findings import ScanResult, Severity as Sev, Confidence

    if target.is_file():
        # --- Single file scan ---
        findings = review_file(target, target.parent, config, vuln_classes=classes)
        result = ScanResult(findings=findings, files_scanned=1)

        # Filter by severity
        try:
            result = result.filter_by_severity(Sev(severity))
        except ValueError:
            warn(f"Invalid severity: {severity}, using LOW")

        result = _apply_baseline(result)

        if output:
            _write_output(result, output)
        elif format == "json":
            output_console.print_json(result.to_json())
        elif format == "sarif":
            output_console.print_json(result.to_sarif_json())
        else:
            _display_findings_rich(result.findings, show_fix=show_fix, show_reproduction=show_reproduction)
            _display_summary(result)

        _maybe_exit_on_findings(result)

    else:
        # --- Directory scan with progress bar and streaming findings ---
        if format == "rich":
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold cyan]{task.description}"),
                BarColumn(bar_width=30),
                TaskProgressColumn(),
                TimeElapsedColumn(),
                console=console,
                transient=True,   # clears the progress bar on completion
            ) as progress:
                task = progress.add_task("Scanning…", total=None)

                def _on_file_start(rel_path: str, idx: int, total: int) -> None:
                    if idx == 1:
                        # Now we know the total — set it so the bar has a denominator
                        progress.update(task, total=total, completed=0)
                    # Update description to show which file is next in queue
                    progress.update(task, description=f"[cyan]{rel_path}[/]")

                def _on_file_done(rel_path: str, findings: list) -> None:
                    """Advance the bar and stream any findings immediately."""
                    # Advance only on actual completion — this is what makes the
                    # bar accurately track progress instead of jumping to 100%.
                    progress.update(task, advance=1)

                    # Filter to the requested severity before display
                    try:
                        sev_filter = Sev(severity)
                        visible = [
                            f for f in findings
                            if f.severity.level >= sev_filter.level
                        ]
                    except ValueError:
                        visible = findings

                    if visible:
                        # Step outside the progress bar temporarily so panels render cleanly
                        progress.stop()
                        _display_findings_rich(visible, show_fix=show_fix, show_reproduction=show_reproduction)
                        progress.start()

                # scan_project is the single source of truth for findings and metadata
                result = scan_project(
                    target, config, severity, classes,
                    on_file_start=_on_file_start,
                    on_file_done=_on_file_done,
                    max_workers=workers,
                )

            result = _apply_baseline(result)

            if output:
                _write_output(result, output)
            else:
                _display_summary(result)

            _maybe_exit_on_findings(result)

        else:
            # Non-rich formats: no streaming, just output the full result
            result = scan_project(target, config, severity, classes, max_workers=workers)
            result = _apply_baseline(result)

            if output:
                _write_output(result, output)
            elif format == "json":
                output_console.print_json(result.to_json())
            elif format == "sarif":
                output_console.print_json(result.to_sarif_json())

            _maybe_exit_on_findings(result)

    if result.errors:
        for err in result.errors:
            warn(err)


def _write_output(result: "ScanResult", output_path: str) -> None:  # type: ignore[name-defined]
    """Write scan results to a file, inferring format from the extension."""
    path = Path(output_path)
    if path.suffix.lower() == ".sarif":
        content = result.to_sarif_json()
    else:
        content = result.to_json()
    try:
        path.write_text(content, encoding="utf-8")
        success(f"Results written to {path} ({len(result.findings)} finding(s))")
    except OSError as e:
        error(f"Could not write output file: {e}")


@app.command()
def watch(
    path: str = typer.Argument(..., help="Directory to watch"),
    severity: str = typer.Option("LOW", "--severity", "-s", help="Minimum severity threshold"),
    format: str = typer.Option("rich", "--format", "-f", help="Output format"),
) -> None:
    """Watch a directory and scan changed files in real time."""
    target = Path(path).resolve()

    if not target.exists():
        fatal(f"Path does not exist: {target}")

    if not target.is_dir():
        fatal(f"Watch mode requires a directory: {target}")

    config = get_config()
    from crysa.watcher import watch_and_scan
    watch_and_scan(target, config, severity, format, config.show_fix)


@app.command(name="diff")
def diff_cmd(
    staged: bool = typer.Option(False, "--staged", help="Scan git staged changes"),
    format: str = typer.Option("rich", "--format", "-f", help="Output format: rich|json|sarif"),
) -> None:
    """Scan a git diff for security vulnerabilities.

    Usage: git diff HEAD | crysa diff
    Or: crysa diff --staged
    """
    config = get_config()
    from crysa.utils.git import get_staged_diff, get_head_diff, get_diff_from_stdin
    from crysa.engine.reviewer import review_diff

    console.print("\n  [bold]Crysa[/] — Scanning git diff\n")

    # Try reading from stdin first
    stdin_diff = get_diff_from_stdin()

    if stdin_diff.strip():
        # Extract the file path from the diff header ('+++ b/path/to/file')
        import re as _re
        _fp_match = _re.search(r'^\+\+\+ b/(.+)$', stdin_diff, _re.MULTILINE)
        stdin_file_path = _fp_match.group(1).strip() if _fp_match else "stdin.diff"
        findings = review_diff(stdin_diff, stdin_file_path, config=config)
    elif staged:
        diffs = get_staged_diff()
        if not diffs:
            info("No staged changes found.")
            return
        findings = []
        for d in diffs:
            if d.diff_text.strip():
                findings.extend(review_diff(d.diff_text, d.file_path, config=config))
    else:
        diffs = get_head_diff()
        if not diffs:
            info("No changes found.")
            return
        findings = []
        for d in diffs:
            if d.diff_text.strip():
                findings.extend(review_diff(d.diff_text, d.file_path, config=config))

    from crysa.engine.findings import ScanResult

    num_files = len(set(f.file for f in findings)) if findings else 0
    result = ScanResult(findings=findings, files_scanned=num_files)

    if format == "json":
        output_console.print_json(result.to_json())
    elif format == "sarif":
        output_console.print_json(result.to_sarif_json())
    else:
        _display_findings_rich(findings, show_fix=config.show_fix, show_reproduction=config.show_reproduction)
        if findings:
            _display_summary(result)

    _maybe_exit_on_findings(result)


@app.command(name="explain")
def explain_cmd(
    report: str = typer.Argument(..., help="JSON report file from a previous scan (or '-' for stdin)"),
    finding_id: str = typer.Argument(..., help="Finding ID to explain (e.g. CRYSA-A3F2B1)"),
) -> None:
    """Generate a comprehensive writeup for a single finding.

    Reads a JSON report produced by `crysa scan --format json` and re-queries
    the LLM with a deep-analysis prompt for the specified finding ID.

    Usage:
        crysa scan myproject --format json --output report.json
        crysa explain report.json CRYSA-A3F2B1
    """
    # Load the report
    if report == "-":
        try:
            raw = sys.stdin.read()
        except KeyboardInterrupt:
            return
    else:
        report_path = Path(report)
        if not report_path.exists():
            fatal(f"Report file not found: {report_path}")
        raw = report_path.read_text(encoding="utf-8")

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        fatal(f"Invalid JSON report: {e}")

    # Find the matching finding
    from crysa.engine.findings import Finding
    target_finding: Finding | None = None
    for item in data.get("findings", []):
        if item.get("id", "") == finding_id:
            try:
                target_finding = Finding.from_dict(item)
                # Preserve the original ID for the writeup (override the new UUID)
                target_finding.id = finding_id
            except ValueError:
                pass
            break

    if target_finding is None:
        fatal(f"Finding '{finding_id}' not found in report. Available IDs: " +
              ", ".join(f.get("id", "?") for f in data.get("findings", [])))

    config = get_config()
    from crysa.engine.reviewer import explain_finding

    console.print(f"\n  [bold]Crysa[/] — Explaining [cyan]{finding_id}[/]: [bold]{target_finding.title}[/]\n")
    info("Querying LLM for deep analysis…")

    report_md = explain_finding(target_finding, config)

    if not report_md:
        fatal("LLM returned an empty response.")

    from rich.markdown import Markdown
    console.print(Markdown(report_md))


@app.command(name="install-hook")
def install_hook_cmd(
    severity: str = typer.Option("HIGH", "--severity", "-s", help="Minimum severity that blocks commits"),
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite existing hook"),
) -> None:
    """Install a git pre-commit hook that scans staged changes.

    The hook blocks commits if any findings at or above the severity
    threshold are found. Use `git commit --no-verify` to bypass.
    """
    hook_path = Path(".git") / "hooks" / "pre-commit"

    if not Path(".git").exists():
        fatal("Not in a git repository root. Run from the project root.")

    if hook_path.exists() and not force:
        fatal(f"Hook already exists at {hook_path}. Use --force to overwrite.")

    hook_content = f"""#!/bin/sh
# Crysa security pre-commit hook
# Generated by: crysa install-hook --severity {severity}
# Bypass: git commit --no-verify

echo "[Crysa] Scanning staged changes for {severity}+ vulnerabilities..."

# Capture JSON output to check for findings
OUTPUT=$(crysa diff --staged --format json 2>/dev/null)
if [ $? -ne 0 ] || [ -z "$OUTPUT" ]; then
    echo "[Crysa] Warning: scan failed or returned no output. Allowing commit."
    exit 0
fi

# Count HIGH+CRITICAL findings
FINDINGS=$(printf '%s' "$OUTPUT" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    s = d.get('summary', {{}})
    sevs = {{'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'INFO': 1}}
    threshold = sevs.get('{severity}', 4)
    count = sum(1 for f in d.get('findings', []) if sevs.get(f.get('severity',''), 0) >= threshold)
    print(count)
except Exception:
    print(0)
" 2>/dev/null)

if [ "${{FINDINGS:-0}}" -gt 0 ]; then
    # Re-run in rich mode so the developer sees the actual findings
    crysa diff --staged --severity {severity} --format rich
    echo ""
    echo "\u26d4 [Crysa] Commit blocked: $FINDINGS {severity}+ finding(s) found."
    echo "   Fix the issues above or run: git commit --no-verify"
    exit 1
fi

echo "[Crysa] ✓ No {severity}+ findings. Proceeding with commit."
exit 0
"""

    hook_path.parent.mkdir(parents=True, exist_ok=True)
    hook_path.write_text(hook_content, encoding="utf-8")

    # Make executable on Unix; on Windows git bash will still run it
    try:
        import stat
        hook_path.chmod(hook_path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    except OSError:
        pass  # Windows — git bash handles execution

    success(f"Pre-commit hook installed at {hook_path}")
    info(f"Blocks commits with {severity}+ findings. Bypass: git commit --no-verify")


@app.command(name="mcp")
def mcp_cmd(
    port: int = typer.Option(3333, "--port", "-p", help="Port for MCP server"),
    host: str = typer.Option("127.0.0.1", "--host", help="Host for MCP server"),
) -> None:
    """Start the Crysa MCP server for AI agent integration."""
    import copy
    config = get_config()
    # Use a shallow copy so we don't mutate the global config singleton
    mcp_config = copy.copy(config)
    mcp_config.mcp_port = port
    mcp_config.mcp_host = host

    info(f"Starting Crysa MCP server on {host}:{port}")
    from crysa.mcp_server import run_server
    run_server(mcp_config)


@app.command()
def context(
    path: str = typer.Argument(".", help="Project root path"),
) -> None:
    """Print the security context snapshot Crysa has built for a project."""
    target = Path(path).resolve()

    if not target.exists():
        fatal(f"Path does not exist: {target}")

    from crysa.engine.context import build_context

    console.print(f"\n  [bold]Crysa[/] — Security context for [cyan]{target}[/]\n")

    ctx = build_context(target, force_rebuild=True)

    table = Table(title="Security Context", show_header=False, box=None, padding=(0, 2))
    table.add_column("Key", style="bold")
    table.add_column("Value")

    table.add_row("Framework", ctx.framework)
    table.add_row("Language", ctx.language)
    table.add_row("Auth Patterns", ctx.auth_summary[:200] if ctx.auth_summary else "None detected")
    table.add_row("Routes Found", str(len(ctx.routes)))
    table.add_row("Models Found", str(len(ctx.models)))
    table.add_row("Roles/Perms Found", str(len(ctx.roles)))

    console.print(table)

    if ctx.routes:
        console.print("\n  [bold]Routes:[/]")
        for r in ctx.routes[:20]:
            console.print(f"    {r}")
        if len(ctx.routes) > 20:
            console.print(f"    [dim]... and {len(ctx.routes) - 20} more[/]")

    if ctx.models:
        console.print("\n  [bold]Models:[/]")
        for m in ctx.models[:15]:
            console.print(f"    {m}")


@app.command(name="init")
def init_cmd() -> None:
    """Interactive setup for Crysa configuration."""
    console.print("\n  [bold bright_red]Crysa[/] — Configuration Setup\n")

    api_key = typer.prompt("  API Key", hide_input=True)
    base_url = typer.prompt("  Base URL", default="https://api.openai.com/v1")
    model = typer.prompt("  Model", default="gpt-4o")

    # Write .env
    env_path = Path(".env")
    env_path.write_text(
        f"CRYSA_BASE_URL={base_url}\n"
        f"CRYSA_MODEL={model}\n"
        f"CRYSA_API_KEY={api_key}\n",
        encoding="utf-8",
    )
    success(f"Written to {env_path}")

    # Write config.yaml if it doesn't exist
    config_path = Path("config.yaml")
    if not config_path.exists():
        import yaml
        config_data = {
            "crysa": {
                "base_url": "${CRYSA_BASE_URL}",
                "model": "${CRYSA_MODEL}",
                "api_key": "${CRYSA_API_KEY}",
                "max_tokens": 4096,
                "temperature": 0.1,
                "severity_threshold": "LOW",
                "confidence_threshold": "MEDIUM",
                "chunk_size": 8000,
                "chunk_overlap": 200,
                "mcp_host": "127.0.0.1",
                "mcp_port": 3333,
                "debounce_ms": 800,
                "max_file_lines": 2000,
                "default_format": "rich",
                "show_fix": True,
                "show_reproduction": True,
            }
        }
        config_path.write_text(yaml.dump(config_data, default_flow_style=False), encoding="utf-8")
        success(f"Written to {config_path}")

    # Print MCP config snippets
    console.print("\n  [bold]MCP Integration Configurations:[/]\n")

    console.print("  [bold cyan]Claude Code[/] (~/.claude/claude_desktop_config.json):")
    console.print(f'  {{\n    "mcpServers": {{\n      "crysa": {{\n        "command": "crysa",\n        "args": ["mcp"]\n      }}\n    }}\n  }}\n')

    console.print("  [bold cyan]Cursor[/] (.cursor/mcp.json):")
    console.print(f'  {{\n    "mcpServers": {{\n      "crysa": {{\n        "command": "crysa",\n        "args": ["mcp"]\n      }}\n    }}\n  }}\n')

    console.print("  [bold cyan]Hermes Agent[/] (~/.hermes/config.yaml):")
    console.print(f'  mcp:\n    servers:\n      crysa:\n        command: crysa\n        args:\n          - mcp\n')

    success("Setup complete! Run `crysa scan <path>` to start scanning.")


def main() -> None:
    """Main entrypoint."""
    app()


if __name__ == "__main__":
    main()
