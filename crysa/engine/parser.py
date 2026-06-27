"""Diff and file parser for Crysa.

Handles parsing diffs, chunking large files, and extracting
relevant code sections for security review.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import tiktoken

from crysa.utils.logger import debug, warn


@dataclass
class CodeChunk:
    """A chunk of code ready for LLM review."""

    content: str
    file_path: str
    line_start: int
    line_end: int
    chunk_index: int = 0
    total_chunks: int = 1
    is_diff: bool = False

    @property
    def token_count(self) -> int:
        """Estimate token count for this chunk."""
        return count_tokens(self.content)


@dataclass
class ParsedDiff:
    """A parsed unified diff with structured information."""

    file_path: str
    hunks: list[DiffHunk] = field(default_factory=list)
    raw_diff: str = ""
    is_new_file: bool = False
    is_deleted: bool = False


@dataclass
class DiffHunk:
    """A single hunk within a diff."""

    header: str = ""
    added_lines: list[tuple[int, str]] = field(default_factory=list)
    removed_lines: list[tuple[int, str]] = field(default_factory=list)
    context_lines: list[tuple[int, str]] = field(default_factory=list)
    line_start: int = 0
    line_end: int = 0


# Cache encoder at module level — tiktoken init is expensive (~100ms first call)
_TOKENIZER: tiktoken.Encoding | None = None


def _get_tokenizer() -> tiktoken.Encoding:
    """Get (or lazily create) the shared tiktoken encoder."""
    global _TOKENIZER
    if _TOKENIZER is None:
        try:
            _TOKENIZER = tiktoken.encoding_for_model("gpt-4")
        except KeyError:
            _TOKENIZER = tiktoken.get_encoding("cl100k_base")
    return _TOKENIZER


def count_tokens(text: str) -> int:
    """Count tokens in text using tiktoken.

    Args:
        text: Text to count tokens for.

    Returns:
        Approximate token count.
    """
    return len(_get_tokenizer().encode(text))


def parse_unified_diff(diff_text: str, file_path: str = "") -> ParsedDiff:
    """Parse a unified diff string into structured hunks.

    Args:
        diff_text: Raw unified diff text.
        file_path: Path of the file being diffed.

    Returns:
        A ParsedDiff with structured hunk information.
    """
    parsed = ParsedDiff(file_path=file_path, raw_diff=diff_text)

    # Detect new/deleted files
    if diff_text.startswith("new file"):
        parsed.is_new_file = True
    elif diff_text.startswith("deleted file"):
        parsed.is_deleted = True

    # Extract file path from diff header if not provided
    if not file_path:
        path_match = re.search(r"^\+\+\+ [b/](.+)$", diff_text, re.MULTILINE)
        if path_match:
            parsed.file_path = path_match.group(1).strip()

    # Parse hunks
    hunk_pattern = re.compile(
        r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$",
        re.MULTILINE,
    )

    hunk_starts = []
    for match in hunk_pattern.finditer(diff_text):
        hunk_starts.append(match)

    for i, match in enumerate(hunk_starts):
        hunk = DiffHunk()
        hunk.header = match.group(0)

        old_start = int(match.group(1))
        new_start = int(match.group(3))
        hunk.line_start = new_start

        # Get hunk content
        content_start = match.end()
        content_end = hunk_starts[i + 1].start() if i + 1 < len(hunk_starts) else len(diff_text)
        hunk_content = diff_text[content_start:content_end]

        old_line = old_start
        new_line = new_start

        for line in hunk_content.split("\n"):
            if not line:
                continue
            if line.startswith("+"):
                hunk.added_lines.append((new_line, line[1:]))
                new_line += 1
            elif line.startswith("-"):
                hunk.removed_lines.append((old_line, line[1:]))
                old_line += 1
            elif line.startswith(" "):
                hunk.context_lines.append((new_line, line[1:]))
                old_line += 1
                new_line += 1
            elif line.startswith("\\"):
                # "\ No newline at end of file"
                continue

        hunk.line_end = new_line - 1
        parsed.hunks.append(hunk)

    return parsed


def chunk_text(
    text: str,
    file_path: str,
    max_tokens: int = 8000,
    overlap_tokens: int = 200,
    is_diff: bool = False,
) -> list[CodeChunk]:
    """Split text into token-bounded chunks with overlap.

    Args:
        text: Text to chunk.
        file_path: Path of the source file.
        max_tokens: Maximum tokens per chunk.
        overlap_tokens: Number of tokens to overlap between chunks.
        is_diff: Whether the text is a diff.

    Returns:
        List of CodeChunk objects.
    """
    total_tokens = count_tokens(text)

    if total_tokens <= max_tokens:
        return [CodeChunk(
            content=text,
            file_path=file_path,
            line_start=1,
            line_end=text.count("\n") + 1,
            chunk_index=0,
            total_chunks=1,
            is_diff=is_diff,
        )]

    chunks = []
    lines = text.split("\n")
    current_chunk_lines: list[str] = []
    current_token_count = 0
    chunk_start_line = 1
    chunk_index = 0

    # Estimate tokens per line for fast approximation
    avg_tokens_per_line = total_tokens / max(len(lines), 1)

    for i, line in enumerate(lines):
        line_tokens = max(1, int(avg_tokens_per_line)) if avg_tokens_per_line > 0 else 1

        if current_token_count + line_tokens > max_tokens and current_chunk_lines:
            # Finalize current chunk
            chunk_text_content = "\n".join(current_chunk_lines)
            chunks.append(CodeChunk(
                content=chunk_text_content,
                file_path=file_path,
                line_start=chunk_start_line,
                line_end=chunk_start_line + len(current_chunk_lines) - 1,
                chunk_index=chunk_index,
                is_diff=is_diff,
            ))
            chunk_index += 1

            # Overlap: keep last N lines
            overlap_lines = max(1, int(overlap_tokens / avg_tokens_per_line)) if avg_tokens_per_line > 0 else 1
            current_chunk_lines = current_chunk_lines[-overlap_lines:]
            current_token_count = sum(max(1, int(avg_tokens_per_line)) for _ in current_chunk_lines)
            chunk_start_line = chunk_start_line + len(current_chunk_lines) - overlap_lines

        current_chunk_lines.append(line)
        current_token_count += line_tokens

    # Final chunk
    if current_chunk_lines:
        chunk_text_content = "\n".join(current_chunk_lines)
        chunks.append(CodeChunk(
            content=chunk_text_content,
            file_path=file_path,
            line_start=chunk_start_line,
            line_end=chunk_start_line + len(current_chunk_lines) - 1,
            chunk_index=chunk_index,
            is_diff=is_diff,
        ))

    # Update total_chunks
    for chunk in chunks:
        chunk.total_chunks = len(chunks)

    return chunks


def chunk_diff(diff_text: str, file_path: str, max_tokens: int = 8000, overlap_tokens: int = 200) -> list[CodeChunk]:
    """Chunk a diff, keeping hunks together when possible.

    Args:
        diff_text: Raw unified diff text.
        file_path: Path of the file being diffed.
        max_tokens: Maximum tokens per chunk.
        overlap_tokens: Overlap between chunks.

    Returns:
        List of CodeChunk objects.
    """
    parsed = parse_unified_diff(diff_text, file_path)

    if not parsed.hunks:
        return chunk_text(diff_text, file_path, max_tokens, overlap_tokens, is_diff=True)

    # Group hunks into chunks
    chunks: list[CodeChunk] = []
    current_hunks: list[str] = []
    current_tokens = 0
    chunk_start_line = 1
    chunk_index = 0

    for hunk in parsed.hunks:
        hunk_text = hunk.header + "\n"
        for line_no, line in hunk.added_lines:
            hunk_text += f"+{line}\n"
        for line_no, line in hunk.removed_lines:
            hunk_text += f"-{line}\n"
        for line_no, line in hunk.context_lines:
            hunk_text += f" {line}\n"

        hunk_tokens = count_tokens(hunk_text)

        if current_tokens + hunk_tokens > max_tokens and current_hunks:
            # Finalize chunk
            chunk_content = "\n".join(current_hunks)
            chunks.append(CodeChunk(
                content=chunk_content,
                file_path=file_path,
                line_start=chunk_start_line,
                line_end=hunk.line_start - 1,
                chunk_index=chunk_index,
                is_diff=True,
            ))
            chunk_index += 1
            current_hunks = []
            current_tokens = 0
            chunk_start_line = hunk.line_start

        current_hunks.append(hunk_text)
        current_tokens += hunk_tokens

    # Final chunk — line_end is the end of the last hunk we processed
    if current_hunks:
        last_hunk = parsed.hunks[-1]
        chunk_content = "\n".join(current_hunks)
        chunks.append(CodeChunk(
            content=chunk_content,
            file_path=file_path,
            line_start=chunk_start_line,
            line_end=last_hunk.line_end,
            chunk_index=chunk_index,
            is_diff=True,
        ))

    for chunk in chunks:
        chunk.total_chunks = len(chunks)

    return chunks


def read_file_safe(file_path: Path, max_lines: int = 2000) -> Optional[str]:
    """Safely read a file, respecting line limits.

    Args:
        file_path: Path to the file.
        max_lines: Maximum lines to read.

    Returns:
        File content as string, or None if file can't be read.
    """
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
        lines = content.split("\n")
        if len(lines) > max_lines:
            debug(f"Truncating {file_path} from {len(lines)} to {max_lines} lines")
            content = "\n".join(lines[:max_lines])
        return content
    except (OSError, PermissionError) as e:
        warn(f"Cannot read {file_path}: {e}")
        return None


def detect_language(file_path: str) -> str:
    """Detect the programming language from a file path.

    Args:
        file_path: Path to the file.

    Returns:
        Language name string.
    """
    ext_map = {
        ".py": "python", ".js": "javascript", ".ts": "typescript",
        ".jsx": "javascript", ".tsx": "typescript", ".go": "go",
        ".rb": "ruby", ".php": "php", ".java": "java",
        ".cs": "csharp", ".rs": "rust", ".vue": "vue",
        ".svelte": "svelte",
    }
    suffix = Path(file_path).suffix.lower()
    return ext_map.get(suffix, "unknown")
