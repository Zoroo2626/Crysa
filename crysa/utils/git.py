"""Git diff utilities for Crysa.

Extracts diffs from git repositories using GitPython.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import git


@dataclass
class DiffEntry:
    """A single file diff with metadata."""

    file_path: str
    diff_text: str
    is_new_file: bool = False
    is_deleted: bool = False
    lines_added: int = 0
    lines_removed: int = 0


def get_staged_diff(repo_path: Optional[Path] = None) -> list[DiffEntry]:
    """Get diffs of staged (git add'd) files.

    Args:
        repo_path: Path to the git repository root. Defaults to cwd.

    Returns:
        List of DiffEntry objects for each changed file.
    """
    repo = git.Repo(repo_path or Path.cwd(), search_parent_directories=True)
    diffs = repo.index.diff("HEAD", create_patch=True, cached=True) if repo.head.is_valid() else repo.index.diff(None, create_patch=True, cached=True)

    entries = []
    for d in diffs:
        diff_text = d.diff.decode("utf-8", errors="replace") if d.diff else ""
        entry = DiffEntry(
            file_path=d.b_path or d.a_path or "unknown",
            diff_text=diff_text,
            is_new_file=d.new_file,
            is_deleted=d.deleted_file,
            lines_added=diff_text.count("\n+") - diff_text.count("\n+++"),
            lines_removed=diff_text.count("\n-") - diff_text.count("\n---"),
        )
        entries.append(entry)

    return entries


def get_head_diff(repo_path: Optional[Path] = None) -> list[DiffEntry]:
    """Get diff between HEAD and working directory (git diff HEAD).

    Args:
        repo_path: Path to the git repository root. Defaults to cwd.

    Returns:
        List of DiffEntry objects for each changed file.
    """
    repo = git.Repo(repo_path or Path.cwd(), search_parent_directories=True)
    head_commit = repo.head.commit if repo.head.is_valid() else None

    if head_commit is None:
        return get_unstaged_diff(repo_path)

    diffs = head_commit.diff(None, create_patch=True)

    entries = []
    for d in diffs:
        diff_text = d.diff.decode("utf-8", errors="replace") if d.diff else ""
        entry = DiffEntry(
            file_path=d.b_path or d.a_path or "unknown",
            diff_text=diff_text,
            is_new_file=d.new_file,
            is_deleted=d.deleted_file,
            lines_added=diff_text.count("\n+") - diff_text.count("\n+++"),
            lines_removed=diff_text.count("\n-") - diff_text.count("\n---"),
        )
        entries.append(entry)

    return entries


def get_diff_from_stdin() -> str:
    """Read a diff from stdin pipe.

    Returns:
        The diff text as a string.
    """
    import sys
    if sys.stdin.isatty():
        return ""
    return sys.stdin.read()


def detect_repo_root(path: Optional[Path] = None) -> Optional[Path]:
    """Detect the git repository root from a given path.

    Args:
        path: Starting path. Defaults to cwd.

    Returns:
        Path to repo root, or None if not in a git repo.
    """
    try:
        repo = git.Repo(path or Path.cwd(), search_parent_directories=True)
        return Path(repo.working_dir)
    except (git.InvalidGitRepositoryError, git.NoSuchPathError):
        return None
