"""MCP server for Crysa — exposes security review tools to AI agents.

Built with FastMCP for seamless integration with Claude Code,
Cursor, Hermes Agent, and any MCP-compatible client.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from crysa.utils.config import Config, get_config
from crysa.utils.logger import info, warn, error


def _create_mcp_server(config: Optional[Config] = None):
    """Create and configure the FastMCP server.

    Args:
        config: Crysa configuration. Uses default if None.

    Returns:
        Configured FastMCP server instance.
    """
    from fastmcp import FastMCP

    if config is None:
        config = get_config()

    mcp = FastMCP(
        name="Crysa",
        version="0.1.0",
        description="AI-native security reasoning engine — catches logic-level vulnerabilities",
    )

    @mcp.tool()
    def review_diff(diff: str, file_path: str, context: str = "") -> str:
        """Review a code diff for security vulnerabilities.

        Returns structured findings for any logic-level security issues found.
        Analyzes the diff like an experienced bug bounty hunter, catching
        IDOR, auth bypass, privilege escalation, mass assignment, JWT flaws,
        business logic vulnerabilities, and data exposure.

        Args:
            diff: The unified diff to review.
            file_path: Path of the file being changed.
            context: Optional extra context about the change.

        Returns:
            JSON array of security findings.
        """
        from crysa.engine.reviewer import review_diff as engine_review_diff
        from pathlib import Path as P

        project_root = P.cwd()
        findings = engine_review_diff(
            diff_text=diff,
            file_path=file_path,
            project_root=project_root,
            config=config,
            extra_context=context,
        )

        return json.dumps([f.to_dict() for f in findings], indent=2)

    @mcp.tool()
    def review_file(file_path: str, content: str) -> str:
        """Review an entire file for security vulnerabilities.

        Analyzes the full file content for logic-level security issues including
        IDOR, auth bypass, privilege escalation, mass assignment, JWT flaws,
        business logic vulnerabilities, and sensitive data exposure.

        Args:
            file_path: Path to the file.
            content: Full file content.

        Returns:
            JSON array of security findings.
        """
        from crysa.engine.reviewer import review_chunk, _deduplicate_findings, _create_client
        from crysa.engine.context import build_context
        from crysa.engine.parser import chunk_text, detect_language
        from pathlib import Path as P

        project_root = P.cwd()
        context = build_context(project_root)

        chunks = chunk_text(
            content, file_path,
            max_tokens=config.chunk_size,
            overlap_tokens=config.chunk_overlap,
        )

        # Create one client for all chunks
        client = _create_client(config)

        all_findings = []
        for chunk in chunks:
            findings = review_chunk(chunk, context, config, client=client)
            all_findings.extend(findings)

        deduped = _deduplicate_findings(all_findings)

        return json.dumps([f.to_dict() for f in deduped], indent=2)

    @mcp.tool()
    def get_context(project_root: str) -> str:
        """Get Crysa's current security context snapshot of the codebase.

        Use this to understand how auth and permissions are structured
        before making changes. Shows detected framework, auth patterns,
        routes, models, and role definitions.

        Args:
            project_root: Path to project root.

        Returns:
            JSON object with framework, auth_summary, routes, models.
        """
        from crysa.engine.context import build_context
        from pathlib import Path as P

        root = P(project_root)
        ctx = build_context(root, force_rebuild=True)

        return json.dumps({
            "framework": ctx.framework,
            "language": ctx.language,
            "auth_summary": ctx.auth_summary,
            "routes": ctx.routes,
            "models": ctx.models,
            "roles": ctx.roles,
            "middleware": ctx.middleware,
        }, indent=2)

    @mcp.tool()
    def scan_project(project_root: str, severity_threshold: str = "LOW") -> str:
        """Run a full security scan of an entire project directory.

        Scans all code files and returns all findings across the project.
        Use this for a comprehensive security audit.

        Args:
            project_root: Path to project root.
            severity_threshold: Minimum severity to report (CRITICAL|HIGH|MEDIUM|LOW|INFO).

        Returns:
            JSON with summary stats and full findings array.
        """
        from crysa.engine.reviewer import scan_project as engine_scan_project
        from pathlib import Path as P

        root = P(project_root)
        result = engine_scan_project(root, config, severity_threshold)

        return result.to_json()

    return mcp


def run_server(config: Optional[Config] = None) -> None:
    """Start the Crysa MCP server.

    Args:
        config: Crysa configuration. Uses default if None.
    """
    if config is None:
        config = get_config()

    mcp = _create_mcp_server(config)

    info(f"Crysa MCP server starting on {config.mcp_host}:{config.mcp_port}")
    info("Tools available: review_diff, review_file, get_context, scan_project")

    mcp.run(transport="sse", host=config.mcp_host, port=config.mcp_port)


def main() -> None:
    """Standalone MCP server entrypoint."""
    run_server()


if __name__ == "__main__":
    main()
