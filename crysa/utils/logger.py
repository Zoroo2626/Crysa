"""Structured logging for Crysa.

Uses Rich for formatted console output with consistent styling.

Log level behaviour:
  - info / warn / success / fatal always print (unless quiet mode).
  - error always prints regardless of quiet mode.
  - debug() only prints when verbose mode is active.

Verbose mode is activated by:
  - Setting CRYSA_VERBOSE=1 environment variable.
  - Calling set_verbose(True) at startup (from the --verbose CLI flag).

Quiet mode is activated by:
  - Setting CRYSA_QUIET=1 environment variable.
  - Calling set_quiet(True) at startup (from the --quiet CLI flag).
"""

from __future__ import annotations

import os
import sys

from rich.console import Console
from rich.theme import Theme

CRYSA_THEME = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "success": "bold green",
    "critical": "bold bright_red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "muted": "dim white",
    "finding": "bold white",
    "file": "cyan underline",
    "title": "bold",
})

# stderr for status/log messages — keeps stdout clean for JSON/SARIF output
console = Console(theme=CRYSA_THEME, stderr=True)
# stdout for structured output (JSON, SARIF) — must be pipeable
output_console = Console(theme=CRYSA_THEME, highlight=False)

# Runtime flags — can be overridden by CLI flags or env vars
_verbose: bool = os.environ.get("CRYSA_VERBOSE", "").strip() in ("1", "true", "yes")
_quiet: bool = os.environ.get("CRYSA_QUIET", "").strip() in ("1", "true", "yes")


def set_verbose(enabled: bool) -> None:
    """Enable or disable verbose (debug) output at runtime."""
    global _verbose
    _verbose = enabled


def set_quiet(enabled: bool) -> None:
    """Enable or disable quiet mode at runtime."""
    global _quiet
    _quiet = enabled


def is_verbose() -> bool:
    """Return True if verbose mode is currently active."""
    return _verbose


def info(msg: str) -> None:
    """Log an informational message (suppressed in quiet mode)."""
    if not _quiet:
        console.print(f"[info]ℹ[/] {msg}")


def warn(msg: str) -> None:
    """Log a warning message (suppressed in quiet mode)."""
    if not _quiet:
        console.print(f"[warning]⚠[/] {msg}")


def error(msg: str) -> None:
    """Log an error message — never suppressed."""
    console.print(f"[error]✗[/] {msg}")


def success(msg: str) -> None:
    """Log a success message (suppressed in quiet mode)."""
    if not _quiet:
        console.print(f"[success]✓[/] {msg}")


def debug(msg: str) -> None:
    """Log a debug message — only shown when verbose mode is active."""
    if _verbose:
        console.print(f"[muted]·[/] {msg}")


def fatal(msg: str) -> None:
    """Log a fatal error and exit."""
    console.print(f"[error]FATAL:[/] {msg}")
    sys.exit(1)

