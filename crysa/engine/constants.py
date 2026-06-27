"""Shared constants for the Crysa engine.

These are defined once here and imported by context.py, parser.py,
and watcher.py. Adding a new language or extending skip rules only
requires a change in this file.
"""

from __future__ import annotations

# File extensions Crysa considers source code.
# When adding a new language, add its extension here.
CODE_EXTENSIONS: frozenset[str] = frozenset({
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".go", ".rb", ".php", ".java", ".cs",
    ".rs", ".vue", ".svelte",
})

# Directory names Crysa always skips during traversal.
# These are names, not paths — matched against any path segment.
SKIP_DIRS: frozenset[str] = frozenset({
    "node_modules", ".git", "__pycache__", "venv", ".venv",
    "env", ".env", "dist", "build", ".next", ".nuxt",
    "vendor", "target", "bin", "obj", ".tox", ".mypy_cache",
    ".pytest_cache", "egg-info", ".eggs",
})

# Maximum file size in bytes to consider for scanning.
# Files larger than this are skipped to avoid memory and token issues.
MAX_FILE_BYTES: int = 500_000

# Minimum file size in bytes — files smaller than this are almost
# certainly empty, generated, or binary fragments.
MIN_FILE_BYTES: int = 50
