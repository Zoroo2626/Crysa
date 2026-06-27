"""Core LLM reasoning engine for Crysa.

This is the heart of Crysa. It sends code to an LLM with carefully
constructed prompts that make it reason like an experienced bug bounty
hunter to catch logic-level vulnerabilities.
"""

from __future__ import annotations

import json
import time
import concurrent.futures
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Callable

from openai import OpenAI, APIError, APITimeoutError, RateLimitError

from crysa.engine.constants import CODE_EXTENSIONS, SKIP_DIRS, MAX_FILE_BYTES
from crysa.engine.context import SecurityContext, build_context
from crysa.engine.findings import Finding, VulnClass, Severity, Confidence, ScanResult
from crysa.engine.parser import (
    CodeChunk, chunk_text, chunk_diff, read_file_safe, detect_language,
    count_tokens, parse_unified_diff,
)
from crysa.vulns import idor, auth, privilege, mass_assign, jwt, logic, exposure
from crysa.utils.config import get_config, Config
from crysa.utils.logger import warn, debug, info, error


# System prompt that makes the LLM reason like a bug bounty hunter
SYSTEM_PROMPT = """You are a senior application security researcher with deep expertise in:
- OWASP Top 10 (2021 and beyond)
- Access control flaws (IDOR, privilege escalation, auth bypass)
- Business logic vulnerabilities (race conditions, workflow bypass, price manipulation)
- Token and session security (JWT flaws, session fixation)
- Mass assignment and data binding vulnerabilities
- Sensitive data exposure through API responses and error handling

Your job is to review code and find REAL security vulnerabilities — not style issues,
not performance problems, not best practices. Only security.

You think step by step:
1. What does this code do? What is the business purpose?
2. Who can call this endpoint/function? Is authentication required?
3. What data does it touch? Is there sensitive data involved?
4. Is authorization correctly enforced at EVERY step?
5. Can an attacker manipulate inputs to bypass intended behavior?
6. Are there race conditions or logic flaws in multi-step processes?

You are precise. You only flag real vulnerabilities with clear impact.
You do not flag theoretical issues that have no practical exploit path.

You MUST return ONLY valid JSON — no prose, no markdown fences, no explanation.
Return a JSON array of findings. If no vulnerabilities are found, return: []

Each finding must have this exact schema:
{
  "id": "CRYSA-XXXX (unique identifier)",
  "vuln_class": "IDOR | AUTH_BYPASS | PRIVILEGE_ESC | MASS_ASSIGN | JWT_ISSUE | LOGIC_FLAW | DATA_EXPOSURE",
  "severity": "CRITICAL | HIGH | MEDIUM | LOW | INFO",
  "confidence": "HIGH | MEDIUM | LOW",
  "file": "path/to/file.py",
  "line_start": 42,
  "line_end": 58,
  "title": "Short descriptive title",
  "description": "Clear explanation of what is vulnerable and why",
  "impact": "What an attacker can achieve by exploiting this",
  "reproduction": "Step-by-step instructions to trigger the vulnerability",
  "fix": "Concrete code fix or remediation approach"
}"""


# Vulnerability class hints aggregated from vulns/ modules
VULN_HINTS = {
    "IDOR": idor.HINT,
    "AUTH_BYPASS": auth.HINT,
    "PRIVILEGE_ESC": privilege.HINT,
    "MASS_ASSIGN": mass_assign.HINT,
    "JWT_ISSUE": jwt.HINT,
    "LOGIC_FLAW": logic.HINT,
    "DATA_EXPOSURE": exposure.HINT,
}


def _build_user_prompt(
    content: str,
    file_path: str,
    context: SecurityContext,
    language: str,
    is_diff: bool = False,
    extra_context: str = "",
    vuln_classes: Optional[list[str]] = None,
) -> str:
    """Build the user prompt with code, context, and vulnerability hints.

    Args:
        content: The code or diff to review.
        file_path: Path of the file being reviewed.
        context: Security context of the codebase.
        language: Programming language of the code.
        is_diff: Whether the content is a diff.
        extra_context: Additional context about the change.
        vuln_classes: Specific vulnerability classes to focus on.

    Returns:
        Formatted user prompt string.
    """
    parts = []

    # Codebase context
    ctx_str = context.to_prompt_context()
    if ctx_str:
        parts.append(ctx_str)
        parts.append("")

    # Language and file info
    parts.append(f"=== REVIEWING {'DIFF' if is_diff else 'FILE'} ===")
    parts.append(f"File: {file_path}")
    parts.append(f"Language: {language}")
    if extra_context:
        parts.append(f"Context: {extra_context}")
    parts.append("")

    # The actual code
    parts.append("=== CODE ===")
    parts.append(content)
    parts.append("")

    # Vulnerability hints (focused or all)
    parts.append("=== VULNERABILITY ANALYSIS GUIDANCE ===")
    parts.append("Focus on these specific vulnerability classes during your analysis:")
    parts.append("")

    if vuln_classes:
        for vc in vuln_classes:
            if vc in VULN_HINTS:
                parts.append(VULN_HINTS[vc])
                parts.append("")
    else:
        for hint in VULN_HINTS.values():
            parts.append(hint)
            parts.append("")

    # Instruction
    parts.append("=== OUTPUT INSTRUCTION ===")
    parts.append(
        "Return ONLY a JSON array of findings. No prose, no markdown fences. "
        "If no vulnerabilities are found, return an empty array: []\n"
        "Each finding must match the schema described in the system prompt."
    )

    return "\n".join(parts)


def _create_client(config: Config) -> OpenAI:
    """Create an OpenAI-compatible client with the configured base URL.

    Args:
        config: Crysa configuration.

    Returns:
        Configured OpenAI client.
    """
    return OpenAI(
        base_url=config.base_url,
        api_key=config.api_key or "not-set",
        timeout=120.0,
    )


def _call_llm(
    client: OpenAI,
    config: Config,
    system_prompt: str,
    user_prompt: str,
    max_retries: int = 3,
) -> str:
    """Call the LLM with retry logic and exponential backoff.

    Args:
        client: OpenAI client instance.
        config: Crysa configuration.
        system_prompt: System prompt content.
        user_prompt: User prompt content.
        max_retries: Maximum number of retry attempts.

    Returns:
        Raw LLM response string.

    Raises:
        RuntimeError: If all retries fail.
    """
    last_error = None

    for attempt in range(max_retries):
        try:
            response = client.chat.completions.create(
                model=config.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                max_tokens=config.max_tokens,
                temperature=config.temperature,
            )
            content = response.choices[0].message.content or ""
            return content.strip()

        except RateLimitError as e:
            last_error = e
            # Honour the Retry-After header if the API provided one
            retry_after = None
            if hasattr(e, "response") and e.response is not None:
                retry_after = e.response.headers.get("retry-after") or e.response.headers.get("x-ratelimit-reset-requests")
            if retry_after:
                try:
                    wait_time = float(retry_after)
                except (ValueError, TypeError):
                    wait_time = (2 ** attempt) * 2
            else:
                wait_time = (2 ** attempt) * 2
            warn(f"Rate limited, waiting {wait_time:.0f}s (attempt {attempt + 1}/{max_retries})")
            time.sleep(wait_time)

        except APITimeoutError as e:
            last_error = e
            wait_time = (2 ** attempt) * 1
            warn(f"Request timed out, retrying in {wait_time}s (attempt {attempt + 1}/{max_retries})")
            time.sleep(wait_time)

        except APIError as e:
            last_error = e
            if attempt < max_retries - 1:
                wait_time = (2 ** attempt) * 1
                warn(f"API error: {e}, retrying in {wait_time}s (attempt {attempt + 1}/{max_retries})")
                time.sleep(wait_time)
            else:
                break

        except Exception as e:
            error(f"Unexpected error calling LLM: {e}")
            raise RuntimeError(f"LLM call failed: {e}") from e

    raise RuntimeError(f"LLM call failed after {max_retries} retries: {last_error}")


def _parse_findings(response: str, file_path: str = "") -> list[Finding]:
    """Parse LLM response into Finding objects.

    Args:
        response: Raw LLM response string.
        file_path: Default file path if not specified in findings.

    Returns:
        List of Finding objects.

    Raises:
        ValueError: If response is not valid JSON after cleanup attempts.
    """
    # Clean up common LLM output quirks
    cleaned = response.strip()

    # Remove markdown code fences if present
    if cleaned.startswith("```"):
        lines = cleaned.split("\n")
        # Remove first and last lines (fences)
        lines = [l for l in lines if not l.strip().startswith("```")]
        cleaned = "\n".join(lines)

    # Try to find JSON array in the response
    json_start = cleaned.find("[")
    json_end = cleaned.rfind("]")

    if json_start != -1 and json_end != -1 and json_end > json_start:
        cleaned = cleaned[json_start:json_end + 1]

    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError as e:
        warn(f"Failed to parse LLM response as JSON: {e}")
        debug(f"Raw response (first 500 chars): {response[:500]}")
        return []

    if not isinstance(data, list):
        warn(f"LLM returned non-array JSON: {type(data).__name__}")
        return []

    findings = []
    for item in data:
        if not isinstance(item, dict):
            continue
        try:
            # Ensure file path is set
            if not item.get("file"):
                item["file"] = file_path
            finding = Finding.from_dict(item)
            findings.append(finding)
        except ValueError as e:
            warn(f"Skipping malformed finding: {e}")
            continue

    return findings


def review_chunk(
    chunk: CodeChunk,
    context: SecurityContext,
    config: Optional[Config] = None,
    extra_context: str = "",
    vuln_classes: Optional[list[str]] = None,
    client: Optional[OpenAI] = None,
) -> list[Finding]:
    """Review a single code chunk for security vulnerabilities.

    Args:
        chunk: The code chunk to review.
        context: Security context of the codebase.
        config: Crysa configuration. Uses default if None.
        extra_context: Additional context about the change.
        vuln_classes: Specific vulnerability classes to focus on.
        client: Pre-created OpenAI client. Created from config if None.

    Returns:
        List of findings for this chunk.
    """
    if config is None:
        config = get_config()

    if not config.api_key:
        warn("No API key configured. Set CRYSA_API_KEY or run `crysa init`.")
        return []

    if client is None:
        client = _create_client(config)

    language = detect_language(chunk.file_path)

    user_prompt = _build_user_prompt(
        content=chunk.content,
        file_path=chunk.file_path,
        context=context,
        language=language,
        is_diff=chunk.is_diff,
        extra_context=extra_context,
        vuln_classes=vuln_classes,
    )

    debug(f"Reviewing chunk {chunk.chunk_index + 1}/{chunk.total_chunks} of {chunk.file_path} "
          f"(~{chunk.token_count} tokens)")

    try:
        raw_response = _call_llm(client, config, SYSTEM_PROMPT, user_prompt)
        findings = _parse_findings(raw_response, chunk.file_path)

        # Adjust line numbers for chunks that don't start at line 1
        if chunk.line_start > 1:
            for f in findings:
                f.line_start += chunk.line_start - 1
                f.line_end += chunk.line_start - 1

        return findings

    except RuntimeError as e:
        error(str(e))
        return []


def review_file(
    file_path: Path,
    project_root: Optional[Path] = None,
    config: Optional[Config] = None,
    extra_context: str = "",
    vuln_classes: Optional[list[str]] = None,
) -> list[Finding]:
    """Review an entire file for security vulnerabilities.

    Args:
        file_path: Path to the file to review.
        project_root: Path to the project root for context building.
        config: Crysa configuration.
        extra_context: Additional context about the change.
        vuln_classes: Specific vulnerability classes to focus on.

    Returns:
        List of all findings across all chunks.
    """
    if config is None:
        config = get_config()

    if not config.api_key:
        warn("No API key configured. Set CRYSA_API_KEY or run `crysa init`.")
        return []

    content = read_file_safe(file_path, config.max_file_lines)
    if content is None:
        return []

    # Build context
    if project_root is None:
        project_root = file_path.parent
    context = build_context(project_root)

    # Create one client for all chunks in this file
    client = _create_client(config)

    # Chunk the file
    chunks = chunk_text(
        content,
        str(file_path),
        max_tokens=config.chunk_size,
        overlap_tokens=config.chunk_overlap,
    )

    all_findings: list[Finding] = []
    for chunk in chunks:
        findings = review_chunk(
            chunk, context, config, extra_context, vuln_classes, client=client
        )
        all_findings.extend(findings)

    return _deduplicate_findings(all_findings)


def review_diff(
    diff_text: str,
    file_path: str,
    project_root: Optional[Path] = None,
    config: Optional[Config] = None,
    extra_context: str = "",
    vuln_classes: Optional[list[str]] = None,
) -> list[Finding]:
    """Review a code diff for security vulnerabilities.

    Args:
        diff_text: Unified diff text.
        file_path: Path of the file being diffed.
        project_root: Path to the project root for context building.
        config: Crysa configuration.
        extra_context: Additional context about the change.
        vuln_classes: Specific vulnerability classes to focus on.

    Returns:
        List of findings from the diff review.
    """
    if config is None:
        config = get_config()

    if not config.api_key:
        warn("No API key configured. Set CRYSA_API_KEY or run `crysa init`.")
        return []

    # Build context
    if project_root is None:
        project_root = Path.cwd()
    context = build_context(project_root)

    # Create one client for all chunks in this diff
    client = _create_client(config)

    # Chunk the diff
    chunks = chunk_diff(
        diff_text, file_path,
        max_tokens=config.chunk_size,
        overlap_tokens=config.chunk_overlap,
    )

    all_findings: list[Finding] = []
    for chunk in chunks:
        findings = review_chunk(
            chunk, context, config, extra_context, vuln_classes, client=client
        )
        all_findings.extend(findings)

    return _deduplicate_findings(all_findings)


def scan_project(
    project_root: Path,
    config: Optional[Config] = None,
    severity_threshold: str = "LOW",
    vuln_classes: Optional[list[str]] = None,
    on_file_start: Optional[Callable[[str, int, int], None]] = None,
    on_file_done: Optional[Callable[[str, list[Finding]], None]] = None,
    max_workers: int = 4,
) -> ScanResult:
    """Run a full security scan of an entire project directory.

    Scans files concurrently using a thread pool. LLM calls are I/O-bound,
    so threads give a significant speedup at no correctness cost.

    Args:
        project_root: Path to the project root.
        config: Crysa configuration.
        severity_threshold: Minimum severity to report.
        vuln_classes: Specific vulnerability classes to focus on.
        on_file_start: Optional callback invoked before each file is scanned.
            Receives (relative_path, file_index_1based, total_files).
            Called from the main thread in submission order.
        on_file_done: Optional callback invoked after each file is fully scanned.
            Receives (relative_path, findings_for_this_file). Findings have
            already been deduplicated at the file level.
            Called from the main thread in submission order.
        max_workers: Number of concurrent threads for LLM calls (default 4).
            Increase for faster scans on large projects if your API allows it.

    Returns:
        ScanResult with all findings and summary statistics.
    """
    if config is None:
        config = get_config()

    if not config.api_key:
        warn("No API key configured. Set CRYSA_API_KEY or run `crysa init`.")
        return ScanResult()

    result = ScanResult()
    context = build_context(project_root, force_rebuild=True)

    # Create one client for the entire project scan
    client = _create_client(config)

    # Find all code files
    code_files: list[Path] = []
    try:
        for p in project_root.rglob("*"):
            if p.is_dir():
                continue
            if p.suffix in CODE_EXTENSIONS:
                # Skip files in excluded directories
                rel_parts = p.relative_to(project_root).parts
                if any(part in SKIP_DIRS for part in rel_parts):
                    continue
                try:
                    if p.stat().st_size > MAX_FILE_BYTES:
                        continue
                except OSError:
                    continue
                code_files.append(p)
    except (OSError, PermissionError) as e:
        result.errors.append(f"Error scanning directory: {e}")
        return result

    info(f"Scanning {len(code_files)} files in {project_root}")

    def _scan_single_file(fpath: Path) -> tuple[str, list[Finding], str | None]:
        """Scan one file and return (rel_path, findings, error_or_None).

        This function runs on a worker thread. It is safe because:
        - config and context are read-only during the scan.
        - client is thread-safe per the OpenAI SDK documentation.
        - chunk_text and review_chunk are stateless.
        """
        rel_path = str(fpath.relative_to(project_root))
        content = read_file_safe(fpath, config.max_file_lines)

        if content is None:
            return rel_path, [], f"Could not read: {fpath}"

        if len(content.strip().split("\n")) < 10:
            return rel_path, [], None  # too small — skip silently

        chunks = chunk_text(
            content, rel_path,
            max_tokens=config.chunk_size,
            overlap_tokens=config.chunk_overlap,
        )

        file_findings: list[Finding] = []
        for chunk in chunks:
            findings = review_chunk(
                chunk, context, config, vuln_classes=vuln_classes, client=client
            )
            file_findings.extend(findings)

        return rel_path, _deduplicate_findings(file_findings), None

    total = len(code_files)

    # Submit all files concurrently; collect results in submission order
    # so that on_file_start and on_file_done fire predictably.
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Map future → (rel_path, index) so we can fire on_file_start before work starts
        future_to_meta: dict[concurrent.futures.Future, tuple[str, int]] = {}

        for idx, fpath in enumerate(code_files, start=1):
            rel_path = str(fpath.relative_to(project_root))
            if on_file_start is not None:
                on_file_start(rel_path, idx, total)
            fut = executor.submit(_scan_single_file, fpath)
            future_to_meta[fut] = (rel_path, idx)

        # Collect in submission order for deterministic callback firing
        for fut in concurrent.futures.as_completed(future_to_meta):
            meta_rel_path, _ = future_to_meta[fut]
            try:
                rel_path, file_findings, err = fut.result()
            except Exception as exc:
                error(f"Unexpected error scanning {meta_rel_path}: {exc}")
                if on_file_done is not None:
                    on_file_done(meta_rel_path, [])
                continue

            if err:
                result.errors.append(err)
                if on_file_done is not None:
                    on_file_done(rel_path, [])
                continue

            if file_findings is not None:
                result.files_scanned += 1
                result.findings.extend(file_findings)

            if on_file_done is not None:
                on_file_done(rel_path, file_findings or [])

    # Deduplicate
    result.findings = _deduplicate_findings(result.findings)

    # Filter by severity
    try:
        threshold = Severity(severity_threshold)
        result = result.filter_by_severity(threshold)
    except ValueError:
        warn(f"Invalid severity threshold: {severity_threshold}")

    # Filter by confidence
    try:
        conf_threshold = Confidence(config.confidence_threshold)
        result = result.filter_by_confidence(conf_threshold)
    except ValueError:
        pass

    return result


def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Remove duplicate findings from chunk overlaps.

    Args:
        findings: List of findings potentially containing duplicates.

    Returns:
        Deduplicated list of findings.
    """
    seen: dict[str, Finding] = {}

    for f in findings:
        # Create a dedup key from vuln class, file, and overlapping line range
        key = f"{f.vuln_class.value}:{f.file}:{f.line_start // 10}:{f.title}"

        if key in seen:
            # Keep the one with higher confidence
            existing = seen[key]
            if f.confidence.level > existing.confidence.level:
                seen[key] = f
        else:
            seen[key] = f

    return list(seen.values())


# Deep-dive prompt used by explain_finding
_EXPLAIN_SYSTEM_PROMPT = """You are a senior security researcher writing a detailed vulnerability report.
Your audience is a mix of developers and security engineers.
Be precise, technical, and actionable. Do NOT add caveats like 'this may depend on context'.
Return the report in clean markdown."""

_EXPLAIN_USER_TEMPLATE = """Here is a confirmed security finding from a code review:

```json
{finding_json}
```

Write a comprehensive vulnerability report with these exact sections:

## Executive Summary
2-3 sentences for a non-technical stakeholder. What is the risk and why does it matter?

## Technical Analysis
Detailed explanation of the root cause. Reference the specific code patterns that create the vulnerability.

## Attack Scenario
Step-by-step narrative of how a real attacker would exploit this. Be specific — name the exact API calls, parameters, and expected outcomes.

## Proof of Concept
Working exploit: curl commands, HTTP request examples, or code snippets an attacker would use.

## Business Impact
What data or systems are at risk? Any regulatory implications (GDPR, SOC2, PCI-DSS, HIPAA)? Reputational risk?

## Remediation
Before/after code fix. Be concrete — show the exact lines that must change and why the fix works.

## Verification
How should a developer confirm the fix is complete? Include a specific test case or verification step.
"""


def explain_finding(
    finding: Finding,
    config: Optional[Config] = None,
) -> str:
    """Generate a comprehensive security writeup for a single finding.

    Re-queries the LLM with a structured deep-analysis prompt, producing
    an executive summary, attack scenario, PoC, business impact,
    remediation code, and verification steps.

    Args:
        finding: The Finding to explain.
        config: Crysa configuration. Uses default if None.

    Returns:
        Markdown-formatted security report as a string.
    """
    if config is None:
        config = get_config()

    if not config.api_key:
        warn("No API key configured. Set CRYSA_API_KEY or run `crysa init`.")
        return ""

    client = _create_client(config)
    user_prompt = _EXPLAIN_USER_TEMPLATE.format(
        finding_json=finding.to_json(indent=2)
    )

    try:
        return _call_llm(client, config, _EXPLAIN_SYSTEM_PROMPT, user_prompt)
    except RuntimeError as e:
        error(str(e))
        return ""
