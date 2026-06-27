"""Tests for crysa.engine.constants.

The constants module is the single source of truth for shared sets.
These tests verify that the constants are correct and that they are
actually imported (not re-defined) by dependent modules.
"""

from __future__ import annotations

import pytest

from crysa.engine.constants import CODE_EXTENSIONS, SKIP_DIRS, MAX_FILE_BYTES, MIN_FILE_BYTES


class TestCodeExtensions:
    def test_contains_core_languages(self):
        assert ".py" in CODE_EXTENSIONS
        assert ".js" in CODE_EXTENSIONS
        assert ".ts" in CODE_EXTENSIONS
        assert ".go" in CODE_EXTENSIONS
        assert ".rb" in CODE_EXTENSIONS
        assert ".java" in CODE_EXTENSIONS
        assert ".rs" in CODE_EXTENSIONS

    def test_contains_frontend_frameworks(self):
        assert ".vue" in CODE_EXTENSIONS
        assert ".svelte" in CODE_EXTENSIONS
        assert ".jsx" in CODE_EXTENSIONS
        assert ".tsx" in CODE_EXTENSIONS

    def test_does_not_contain_non_code(self):
        """Non-code files should never be scanned."""
        for ext in (".txt", ".md", ".json", ".yaml", ".yml", ".csv", ".png", ".jpg"):
            assert ext not in CODE_EXTENSIONS, f"Expected {ext!r} not in CODE_EXTENSIONS"

    def test_is_frozenset(self):
        assert isinstance(CODE_EXTENSIONS, frozenset)

    def test_all_start_with_dot(self):
        for ext in CODE_EXTENSIONS:
            assert ext.startswith("."), f"Extension {ext!r} must start with a dot"

    def test_all_lowercase(self):
        for ext in CODE_EXTENSIONS:
            assert ext == ext.lower(), f"Extension {ext!r} must be lowercase"


class TestSkipDirs:
    def test_contains_package_dirs(self):
        assert "node_modules" in SKIP_DIRS
        assert "vendor" in SKIP_DIRS
        assert "__pycache__" in SKIP_DIRS

    def test_contains_venv_dirs(self):
        assert "venv" in SKIP_DIRS
        assert ".venv" in SKIP_DIRS
        assert "env" in SKIP_DIRS

    def test_contains_build_dirs(self):
        assert "dist" in SKIP_DIRS
        assert "build" in SKIP_DIRS
        assert "target" in SKIP_DIRS

    def test_contains_vcs_dir(self):
        assert ".git" in SKIP_DIRS

    def test_contains_framework_dirs(self):
        assert ".next" in SKIP_DIRS
        assert ".nuxt" in SKIP_DIRS

    def test_is_frozenset(self):
        assert isinstance(SKIP_DIRS, frozenset)


class TestFileSizeConstants:
    def test_max_file_bytes_is_reasonable(self):
        """500 KB is the documented limit. Must be between 100 KB and 10 MB."""
        assert 100_000 <= MAX_FILE_BYTES <= 10_000_000

    def test_min_file_bytes_is_smaller_than_max(self):
        assert MIN_FILE_BYTES < MAX_FILE_BYTES

    def test_min_file_bytes_is_positive(self):
        assert MIN_FILE_BYTES > 0


class TestConsistencyAcrossModules:
    """The constants must be imported (not redefined) in dependent modules.
    
    These tests verify that watcher.py and context.py use the canonical
    constants from crysa.engine.constants directly (the redundant module-level
    aliases were removed as dead code).
    """

    def test_watcher_uses_shared_code_extensions(self):
        import crysa.watcher as watcher
        assert watcher.CODE_EXTENSIONS is CODE_EXTENSIONS

    def test_watcher_uses_shared_skip_dirs(self):
        import crysa.watcher as watcher
        assert watcher.SKIP_DIRS is SKIP_DIRS

    def test_context_uses_shared_code_extensions(self):
        import crysa.engine.context as context
        assert context.CODE_EXTENSIONS is CODE_EXTENSIONS

    def test_context_uses_shared_skip_dirs(self):
        import crysa.engine.context as context
        assert context.SKIP_DIRS is SKIP_DIRS
