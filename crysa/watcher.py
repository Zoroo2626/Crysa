"""File system watcher for Crysa.

Uses watchdog to monitor file changes and trigger security scans
in real time. Perfect for running alongside a coding agent.
"""

from __future__ import annotations

import time
import threading
from pathlib import Path
from typing import Optional, Callable

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent, FileCreatedEvent

from crysa.engine.constants import CODE_EXTENSIONS, SKIP_DIRS, MIN_FILE_BYTES
from crysa.utils.config import Config
from crysa.utils.logger import info, warn, debug, console


class _DebouncedHandler(FileSystemEventHandler):
    """File change handler with debouncing to avoid scanning mid-save."""

    def __init__(
        self,
        callback: Callable[[Path], None],
        debounce_ms: int = 800,
        extensions: Optional[set[str]] = None,
        skip_dirs: Optional[set[str]] = None,
    ):
        """Initialize the handler.

        Args:
            callback: Function to call with the changed file path.
            debounce_ms: Milliseconds to wait after last change before scanning.
            extensions: File extensions to watch.
            skip_dirs: Directory names to skip.
        """
        super().__init__()
        self._callback = callback
        self._debounce_sec = debounce_ms / 1000.0
        self._extensions = extensions or CODE_EXTENSIONS
        self._skip_dirs = skip_dirs or SKIP_DIRS
        self._timers: dict[str, threading.Timer] = {}
        self._lock = threading.Lock()

    def _should_process(self, path: str) -> bool:
        """Check if a file should be processed.

        Args:
            path: File path to check.

        Returns:
            True if the file should be scanned.
        """
        p = Path(path)

        # Check extension
        if p.suffix not in self._extensions:
            return False

        # Check if in skipped directory
        parts = p.parts
        for part in parts:
            if part in self._skip_dirs:
                return False

        # Check file size (skip very small files)
        try:
            if p.stat().st_size < MIN_FILE_BYTES:
                return False
        except OSError:
            return False

        return True

    def _on_change(self, path: str) -> None:
        """Handle a debounced file change.

        Args:
            path: Path of the changed file.
        """
        with self._lock:
            # Cancel existing timer for this path
            if path in self._timers:
                self._timers[path].cancel()

            # Set new timer
            timer = threading.Timer(self._debounce_sec, self._fire_callback, args=[path])
            timer.daemon = True
            self._timers[path] = timer
            timer.start()

    def _fire_callback(self, path: str) -> None:
        """Fire the callback for a changed file.

        Args:
            path: Path of the changed file.
        """
        with self._lock:
            self._timers.pop(path, None)

        try:
            self._callback(Path(path))
        except Exception as e:
            warn(f"Error scanning {path}: {e}")

    def on_modified(self, event: FileModifiedEvent) -> None:
        """Handle file modification events."""
        if not event.is_directory and self._should_process(event.src_path):
            self._on_change(event.src_path)

    def on_created(self, event: FileCreatedEvent) -> None:
        """Handle file creation events."""
        if not event.is_directory and self._should_process(event.src_path):
            self._on_change(event.src_path)


class WatchSession:
    """Manages a file watching session with live finding display."""

    def __init__(self, config: Config, severity: str, format: str, show_fix: bool,
                 vuln_classes: Optional[list[str]] = None):
        """Initialize the watch session.

        Args:
            config: Crysa configuration.
            severity: Minimum severity threshold.
            format: Output format.
            show_fix: Whether to show fix suggestions.
            vuln_classes: Specific vulnerability classes to focus on.
        """
        self.config = config
        self.severity = severity
        self.format = format
        self.show_fix = show_fix
        self.vuln_classes = vuln_classes
        self.total_findings = 0
        self.files_scanned = 0
        self._lock = threading.Lock()

    def scan_file(self, file_path: Path) -> None:
        """Scan a single file and display findings.

        Args:
            file_path: Path to the file to scan.
        """
        from crysa.engine.reviewer import review_file
        from crysa.engine.findings import Severity as Sev

        with self._lock:
            self.files_scanned += 1

        try:
            # Determine project root (parent of the file or cwd)
            project_root = file_path.parent
            while project_root != project_root.parent:
                if (project_root / ".git").exists():
                    break
                if (project_root / "pyproject.toml").exists():
                    break
                if (project_root / "package.json").exists():
                    break
                project_root = project_root.parent

            findings = review_file(file_path, project_root, self.config,
                                   vuln_classes=self.vuln_classes)

            # Filter by severity
            try:
                threshold = Sev(self.severity)
                threshold_level = threshold.level
                findings = [f for f in findings if f.severity.level >= threshold_level]
            except ValueError:
                pass

            if findings:
                timestamp = time.strftime("%H:%M:%S")
                console.print(f"\n  [dim]{timestamp}[/]  [cyan]{file_path.name}[/] — [bold]{len(findings)} finding(s)[/]")

                from crysa.cli import _display_findings_rich
                _display_findings_rich(findings, show_fix=self.show_fix)

                with self._lock:
                    self.total_findings += len(findings)
            else:
                timestamp = time.strftime("%H:%M:%S")
                console.print(f"  [dim]{timestamp}[/]  [cyan]{file_path.name}[/] — [green]✓ clean[/]")

        except Exception as e:
            warn(f"Error scanning {file_path}: {e}")


def watch_and_scan(
    target: Path,
    config: Config,
    severity: str = "LOW",
    format: str = "rich",
    show_fix: bool = True,
    vuln_classes: Optional[list[str]] = None,
) -> None:
    """Watch a directory and scan changed files in real time.

    Args:
        target: Directory to watch.
        config: Crysa configuration.
        severity: Minimum severity threshold.
        format: Output format.
        show_fix: Whether to show fix suggestions.
        vuln_classes: Specific vulnerability classes to focus on.
    """
    session = WatchSession(config, severity, format, show_fix, vuln_classes=vuln_classes)

    handler = _DebouncedHandler(
        callback=session.scan_file,
        debounce_ms=config.debounce_ms,
    )

    observer = Observer()
    observer.schedule(handler, str(target), recursive=True)
    observer.start()

    console.print(f"\n  [bold bright_red]Crysa[/] — Watching [cyan]{target}[/]")
    console.print(f"  [dim]Press Ctrl+C to stop[/]\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        console.print(f"\n  [bold]Session complete:[/] {session.files_scanned} files scanned, "
                      f"{session.total_findings} findings total\n")

    observer.join()
