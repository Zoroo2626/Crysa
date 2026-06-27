"""Codebase context builder for Crysa.

Before reviewing code, Crysa builds a security context snapshot of the
surrounding codebase. This is critical — you can't reason about
authorization without understanding how auth works in the project.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from crysa.engine.constants import CODE_EXTENSIONS, SKIP_DIRS, MAX_FILE_BYTES
from crysa.utils.logger import warn, debug


# Framework detection patterns
_FRAMEWORK_PATTERNS: dict[str, list[str]] = {
    "django": [
        r"from django\.", r"import django", r"DJANGO_SETTINGS_MODULE",
        r"django\.conf", r"manage\.py",
    ],
    "flask": [
        r"from flask", r"import flask", r"Flask\(__name__",
    ],
    "fastapi": [
        r"from fastapi", r"import fastapi", r"FastAPI\(",
    ],
    "express": [
        r"require\(['\"]express['\"]", r"from ['\"]express",
        r"express\(\)", r"app\.listen\(",
    ],
    "rails": [
        r"Rails\.application", r"class.*ApplicationController",
        r"ActiveRecord::Base",
    ],
    "spring": [
        r"@RestController", r"@Controller", r"@SpringBootApplication",
        r"org\.springframework",
    ],
    "laravel": [
        r"Illuminate\\", r"use App\\", r"Route::", r"Artisan",
    ],
    "nestjs": [
        r"@nestjs/", r"@Controller\(\)", r"@Injectable\(\)",
    ],
    "gin": [
        r"github.com/gin-gonic/gin", r"gin\.Default\(\)",
        r"gin\.New\(\)",
    ],
    "echo": [
        r"github.com/labstack/echo", r"echo\.New\(\)",
    ],
    "ruby": [
        r"require ['\"]sinatra", r"Sinatra::Application",
    ],
    "php": [
        r"<\?php", r"use Symfony\\", r"use Laravel\\",
        r"\$app->", r"\$router->",
    ],
}

# Pre-compiled framework patterns (compiled once at module load)
_FRAMEWORK_PATTERNS_COMPILED: dict[str, list[re.Pattern]] = {
    fw: [re.compile(p) for p in patterns]
    for fw, patterns in _FRAMEWORK_PATTERNS.items()
}

# Auth pattern detection
_AUTH_PATTERNS: dict[str, list[str]] = {
    "decorator": [
        r"@login_required", r"@auth_required", r"@requires_auth",
        r"@authenticated", r"@jwt_required", r"@permission_required",
    ],
    "middleware": [
        r"auth.*middleware", r"authentication.*middleware",
        r"AuthMiddleware", r"JWTMiddleware", r"SessionMiddleware",
        r"app\.use\(.*auth", r"router\.use\(.*auth",
    ],
    "guard": [
        r"AuthGuard", r"CanActivate", r"@UseGuards",
    ],
    "interceptor": [
        r"AuthInterceptor", r"@UseInterceptors",
    ],
    "dependency": [
        r"Depends\(get_current_user", r"Depends\(get_user",
        r"requireAuth", r"protect\(", r"verifyToken",
    ],
}

# Pre-compiled auth patterns
_AUTH_PATTERNS_COMPILED: dict[str, list[re.Pattern]] = {
    cat: [re.compile(p) for p in patterns]
    for cat, patterns in _AUTH_PATTERNS.items()
}

# Route patterns
_ROUTE_PATTERNS: dict[str, list[str]] = {
    "python": [
        r'@\w+\.(get|post|put|patch|delete|route)\s*\(\s*["\']([^"\']+)["\']',
        r'@app\.(get|post|put|patch|delete|route)\s*\(\s*["\']([^"\']+)["\']',
        r'@router\.(get|post|put|patch|delete)\s*\(\s*["\']([^"\']+)["\']',
        r'path\s*\(\s*["\']([^"\']+)["\']',
        r'urlpatterns\s*=',
    ],
    "javascript": [
        r'app\.(get|post|put|patch|delete)\s*\(\s*["\']([^"\']+)["\']',
        r'router\.(get|post|put|patch|delete)\s*\(\s*["\']([^"\']+)["\']',
        r'Route::(get|post|put|patch|delete)\s*\(\s*["\']([^"\']+)["\']',
    ],
    "go": [
        r'\.(GET|POST|PUT|PATCH|DELETE)\s*\(\s*["\']([^"\']+)["\']',
        r'Handle\w*\s*\(\s*["\']([^"\']+)["\']',
    ],
    "ruby": [
        r'(get|post|put|patch|delete)\s+["\']([^"\']+)["\']',
    ],
    "java": [
        r'@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)\s*\(\s*["\']?([^"\')\s]+)',
    ],
}

# Pre-compiled route patterns
_ROUTE_PATTERNS_COMPILED: dict[str, list[re.Pattern]] = {
    lang: [re.compile(p) for p in patterns]
    for lang, patterns in _ROUTE_PATTERNS.items()
}

# Model patterns
_MODEL_PATTERNS: dict[str, list[str]] = {
    "python": [
        r'class\s+\w+.*Model\b', r'class\s+\w+.*Base\b',
        r'class\s+\w+\(db\.Model\)', r'class\s+\w+\(Base\)',
        r'class\s+\w+\(models\.Model\)', r'class\s+\w+Schema',
        r'class\s+\w+\(BaseModel\)',
    ],
    "javascript": [
        r'mongoose\.model\(', r'Schema\({', r'Sequelize\.define\(',
        r'typeorm.*@Entity', r'prisma.*model',
    ],
    "go": [
        r'type\s+\w+\s+struct\s*{',
    ],
    "ruby": [
        r'class\s+\w+\s*<\s*ApplicationRecord',
        r'class\s+\w+\s*<\s*ActiveRecord::Base',
    ],
    "java": [
        r'@Entity', r'@Table\(',
    ],
}

# Pre-compiled model patterns
_MODEL_PATTERNS_COMPILED: dict[str, list[re.Pattern]] = {
    lang: [re.compile(p) for p in patterns]
    for lang, patterns in _MODEL_PATTERNS.items()
}

# Role/permission patterns
_ROLE_PATTERNS: list[str] = [
    r'(?:is_)?admin', r'(?:is_)?superuser', r'role\s*=\s*',
    r'permission', r'staff', r'moderator', r'Role\.',
    r'ADMIN', r'STAFF', r'SUPERUSER', r'PERMISSION',
    r'has_role', r'check_permission', r'is_authorized',
]

# Single compiled pattern for all role patterns — faster than N separate searches
_ROLE_PATTERN_COMPILED: re.Pattern = re.compile(
    "|".join(f"(?:{p})" for p in _ROLE_PATTERNS)
)

@dataclass
class SecurityContext:
    """A compact summary of the codebase's security-relevant structure."""

    framework: str = "unknown"
    language: str = "unknown"
    auth_summary: str = "No authentication patterns detected."
    routes: list[str] = field(default_factory=list)
    models: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    middleware: list[str] = field(default_factory=list)

    def to_prompt_context(self, max_tokens: int = 2000) -> str:
        """Format the context as a compact string for LLM prompts.

        Args:
            max_tokens: Maximum approximate tokens to generate.

        Returns:
            Formatted context string.
        """
        lines = [
            "=== CODEBASE SECURITY CONTEXT ===",
            f"Framework: {self.framework}",
            f"Language: {self.language}",
            "",
            "AUTHENTICATION:",
            self.auth_summary,
            "",
        ]

        if self.routes:
            lines.append("ROUTES (first 30):")
            for r in self.routes[:30]:
                lines.append(f"  {r}")
            if len(self.routes) > 30:
                lines.append(f"  ... and {len(self.routes) - 30} more")
            lines.append("")

        if self.models:
            lines.append("DATA MODELS (first 20):")
            for m in self.models[:20]:
                lines.append(f"  {m}")
            if len(self.models) > 20:
                lines.append(f"  ... and {len(self.models) - 20} more")
            lines.append("")

        if self.roles:
            lines.append("ROLES/PERMISSIONS:")
            for r in self.roles[:15]:
                lines.append(f"  {r}")
            lines.append("")

        if self.middleware:
            lines.append("AUTH MIDDLEWARE:")
            for m in self.middleware[:10]:
                lines.append(f"  {m}")
            lines.append("")

        result = "\n".join(lines)
        # Rough token estimate: ~4 chars per token
        if len(result) > max_tokens * 4:
            result = result[:max_tokens * 4] + "\n... (truncated)"
        return result


def _detect_framework(
    sample_files: list[tuple[Path, str]],
    pkg_language: str,
) -> tuple[str, str]:
    """Detect the web framework and primary language of the project.

    Args:
        sample_files: Pre-loaded list of (path, content) pairs.
        pkg_language: Language hint derived from package files (may be 'unknown').

    Returns:
        Tuple of (framework, language).
    """
    for fpath, content in sample_files:
        for fw_name, patterns in _FRAMEWORK_PATTERNS_COMPILED.items():
            if any(p.search(content) for p in patterns):
                return fw_name, _framework_to_language(fw_name)

    return "unknown", pkg_language


def _framework_to_language(framework: str) -> str:
    """Map a framework name to its primary language."""
    mapping = {
        "django": "python", "flask": "python", "fastapi": "python",
        "express": "javascript", "nestjs": "javascript",
        "rails": "ruby", "ruby": "ruby",
        "spring": "java",
        "laravel": "php", "php": "php",
        "gin": "go", "echo": "go",
    }
    return mapping.get(framework, "unknown")


def _get_sample_files(project_root: Path, limit: int = 50) -> list[Path]:
    """Get a sample of code files from the project.

    Args:
        project_root: Path to the project root.
        limit: Maximum number of files to return.

    Returns:
        List of code file paths.
    """
    files = []
    try:
        for p in project_root.rglob("*"):
            if len(files) >= limit:
                break
            # Skip directories in _SKIP_DIRS (prune traversal) and all other dirs
            if p.is_dir():
                continue
            # Skip files inside excluded directories
            if any(part in SKIP_DIRS for part in p.relative_to(project_root).parts):
                continue
            if p.suffix in CODE_EXTENSIONS:
                # Skip very large files
                try:
                    if p.stat().st_size > MAX_FILE_BYTES:
                        continue
                except OSError:
                    continue
                files.append(p)
    except (OSError, PermissionError):
        pass
    return files


def _extract_auth_info(
    sample_files: list[tuple[Path, str]],
    project_root: Path,
) -> tuple[str, list[str]]:
    """Extract authentication-related information from the codebase.

    Args:
        sample_files: Pre-loaded list of (path, content) pairs.
        project_root: Project root for computing relative paths.

    Returns:
        Tuple of (auth_summary_text, list_of_auth_files).
    """
    auth_files: list[str] = []
    auth_patterns_found: dict[str, int] = {
        "decorator": 0, "middleware": 0, "guard": 0,
        "interceptor": 0, "dependency": 0,
    }

    for fpath, content in sample_files:
        for category, patterns in _AUTH_PATTERNS_COMPILED.items():
            if any(p.search(content) for p in patterns):
                rel_path = str(fpath.relative_to(project_root))
                if rel_path not in auth_files:
                    auth_files.append(rel_path)
                auth_patterns_found[category] += 1

    # Build summary
    parts = [
        f"{cat}: found in {count} file(s)"
        for cat, count in auth_patterns_found.items()
        if count > 0
    ]

    if not parts:
        return "No authentication patterns detected.", auth_files

    summary = "Auth mechanisms detected:\n" + "\n".join(f"  - {p}" for p in parts)
    return summary, auth_files


def _extract_routes(
    sample_files: list[tuple[Path, str]],
    language: str,
) -> list[str]:
    """Extract route definitions from the codebase.

    Args:
        sample_files: Pre-loaded list of (path, content) pairs.
        language: Primary programming language.

    Returns:
        List of route strings.
    """
    routes: list[str] = []
    patterns = (
        _ROUTE_PATTERNS_COMPILED.get(language)
        or _ROUTE_PATTERNS_COMPILED.get("python")
        or []
    )

    seen: set[str] = set()
    for _fpath, content in sample_files:
        for pattern in patterns:
            for match in pattern.finditer(content):
                route = match.group(0)
                if route not in seen:
                    seen.add(route)
                    routes.append(route)

    return routes


def _extract_models(
    sample_files: list[tuple[Path, str]],
    language: str,
) -> list[str]:
    """Extract data model definitions from the codebase.

    Args:
        sample_files: Pre-loaded list of (path, content) pairs.
        language: Primary programming language.

    Returns:
        List of model definition strings.
    """
    models: list[str] = []
    patterns = (
        _MODEL_PATTERNS_COMPILED.get(language)
        or _MODEL_PATTERNS_COMPILED.get("python")
        or []
    )

    seen: set[str] = set()
    for _fpath, content in sample_files:
        for pattern in patterns:
            for match in pattern.finditer(content):
                model = match.group(0).strip()
                if model not in seen:
                    seen.add(model)
                    models.append(model)

    return models


def _extract_roles(sample_files: list[tuple[Path, str]]) -> list[str]:
    """Extract role and permission definitions from the codebase.

    Args:
        sample_files: Pre-loaded list of (path, content) pairs.

    Returns:
        List of role/permission context strings.
    """
    roles: list[str] = []
    seen: set[str] = set()

    for _fpath, content in sample_files:
        for match in _ROLE_PATTERN_COMPILED.finditer(content):
            # Get the surrounding line for context
            start = max(0, match.start() - 50)
            end = min(len(content), match.end() + 50)
            ctx_line = content[start:end].strip().split("\n")[0]
            if ctx_line not in seen:
                seen.add(ctx_line)
                roles.append(ctx_line)

    return roles


# Cache for the current session
_context_cache: dict[str, SecurityContext] = {}


# Map package manifest filenames to their primary language.
# Checked as a fast stat-only pass before any file reading.
_PKG_LANGUAGE_MAP: dict[str, str] = {
    "package.json": "javascript",
    "requirements.txt": "python",
    "pyproject.toml": "python",
    "go.mod": "go",
    "Gemfile": "ruby",
    "composer.json": "php",
    "pom.xml": "java",
    "build.gradle": "java",
    "Cargo.toml": "rust",
}


def build_context(project_root: Path, force_rebuild: bool = False) -> SecurityContext:
    """Build a security context snapshot of the codebase.

    This is the main entry point. It scans the project and returns
    a SecurityContext that gets prepended to every review prompt.

    The implementation does a **single filesystem traversal** — files are
    collected once and read once, then the (path, content) list is passed to
    all extractors. This avoids the original 5x repeated traversal cost.

    Args:
        project_root: Path to the project root.
        force_rebuild: If True, ignore the cache and rebuild.

    Returns:
        A SecurityContext with all extracted information.
    """
    cache_key = str(project_root.resolve())

    if not force_rebuild and cache_key in _context_cache:
        debug(f"Using cached context for {project_root}")
        return _context_cache[cache_key]

    if not project_root.exists() or not project_root.is_dir():
        warn(f"Project root does not exist: {project_root}")
        return SecurityContext()

    debug(f"Building security context for {project_root}")

    # --- Step 1: Detect language from package manifests (cheap stat-only check) ---
    pkg_language = "unknown"
    for fname, lang in _PKG_LANGUAGE_MAP.items():
        if (project_root / fname).exists():
            pkg_language = lang
            break

    # --- Step 2: Single traversal — collect + read files once ---
    raw_files = _get_sample_files(project_root, limit=100)
    loaded: list[tuple[Path, str]] = []
    for fpath in raw_files:
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
            loaded.append((fpath, content))
        except (OSError, PermissionError):
            continue

    debug(f"Context builder: loaded {len(loaded)} files for analysis")

    # --- Step 3: Fan out to all extractors using the same loaded list ---
    framework, language = _detect_framework(loaded, pkg_language)
    auth_summary, auth_files = _extract_auth_info(loaded, project_root)
    routes = _extract_routes(loaded, language)
    models = _extract_models(loaded, language)
    roles = _extract_roles(loaded)

    # Build middleware list from auth files
    middleware = [
        f for f in auth_files
        if "middleware" in f.lower() or "guard" in f.lower()
    ]

    ctx = SecurityContext(
        framework=framework,
        language=language,
        auth_summary=auth_summary,
        routes=routes,
        models=models,
        roles=roles,
        middleware=middleware,
    )

    _context_cache[cache_key] = ctx
    return ctx



def invalidate_context(project_root: Path) -> None:
    """Invalidate the cached context for a project.

    Args:
        project_root: Path to the project root.
    """
    cache_key = str(project_root.resolve())
    _context_cache.pop(cache_key, None)


def get_cached_context(project_root: Path) -> Optional[SecurityContext]:
    """Get the cached context if available.

    Args:
        project_root: Path to the project root.

    Returns:
        Cached SecurityContext or None.
    """
    cache_key = str(project_root.resolve())
    return _context_cache.get(cache_key)
