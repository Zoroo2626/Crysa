"""Tests for crysa.engine.parser.

Covers diff parsing, text chunking, language detection, and file reading.
No I/O calls to LLM — pure unit tests.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from crysa.engine.parser import (
    CodeChunk,
    DiffHunk,
    ParsedDiff,
    chunk_diff,
    chunk_text,
    count_tokens,
    detect_language,
    parse_unified_diff,
    read_file_safe,
)


# ---------------------------------------------------------------------------
# detect_language
# ---------------------------------------------------------------------------

class TestDetectLanguage:
    def test_python(self):
        assert detect_language("app/views.py") == "python"

    def test_javascript(self):
        assert detect_language("src/index.js") == "javascript"

    def test_typescript(self):
        assert detect_language("src/App.tsx") == "typescript"

    def test_go(self):
        assert detect_language("main.go") == "go"

    def test_ruby(self):
        assert detect_language("app/controllers/users_controller.rb") == "ruby"

    def test_java(self):
        assert detect_language("src/main/java/Service.java") == "java"

    def test_rust(self):
        assert detect_language("src/lib.rs") == "rust"

    def test_php(self):
        assert detect_language("routes/web.php") == "php"

    def test_unknown_returns_unknown(self):
        assert detect_language("something.xyz") == "unknown"

    def test_uppercase_extension(self):
        # Extensions from the filesystem can be uppercase on some OSes
        lang = detect_language("App.PY")
        # We just assert it doesn't crash; the result may be unknown or python
        assert isinstance(lang, str)


# ---------------------------------------------------------------------------
# count_tokens
# ---------------------------------------------------------------------------

class TestCountTokens:
    def test_empty_string(self):
        assert count_tokens("") == 0

    def test_short_string(self):
        result = count_tokens("hello world")
        assert result > 0

    def test_longer_is_more_tokens(self):
        short = count_tokens("hello")
        long = count_tokens("hello world this is a much longer string")
        assert long > short

    def test_returns_int(self):
        assert isinstance(count_tokens("test"), int)


# ---------------------------------------------------------------------------
# chunk_text
# ---------------------------------------------------------------------------

class TestChunkText:
    SMALL_CODE = """\
def get_user(user_id):
    return db.query(User).filter(User.id == user_id).first()

def update_user(user_id, data):
    user = db.query(User).filter(User.id == user_id).first()
    user.update(data)
    db.commit()
"""

    def test_small_file_is_single_chunk(self):
        chunks = chunk_text(self.SMALL_CODE, "views.py", max_tokens=8000)
        assert len(chunks) == 1

    def test_chunk_has_correct_file_path(self):
        chunks = chunk_text(self.SMALL_CODE, "api/views.py")
        assert chunks[0].file_path == "api/views.py"

    def test_chunk_is_not_diff(self):
        chunks = chunk_text(self.SMALL_CODE, "views.py")
        assert not chunks[0].is_diff

    def test_chunk_contains_content(self):
        chunks = chunk_text(self.SMALL_CODE, "views.py")
        assert "get_user" in chunks[0].content

    def test_line_start_is_1_for_single_chunk(self):
        chunks = chunk_text(self.SMALL_CODE, "views.py")
        assert chunks[0].line_start == 1

    def test_chunk_index_and_total(self):
        chunks = chunk_text(self.SMALL_CODE, "views.py", max_tokens=8000)
        assert chunks[0].chunk_index == 0
        assert chunks[0].total_chunks == len(chunks)

    def test_large_file_splits_into_multiple_chunks(self):
        # 400 lines of code — forces splitting with max_tokens=100
        large_code = "\n".join([f"x_{i} = {i}  # variable number {i}" for i in range(400)])
        chunks = chunk_text(large_code, "vars.py", max_tokens=100, overlap_tokens=10)
        assert len(chunks) > 1

    def test_chunks_are_ordered_by_line_start(self):
        large_code = "\n".join([f"line_{i} = True" for i in range(300)])
        chunks = chunk_text(large_code, "code.py", max_tokens=100, overlap_tokens=10)
        starts = [c.line_start for c in chunks]
        assert starts == sorted(starts)

    def test_all_chunks_have_content(self):
        large_code = "\n".join([f"var_{i} = {i}" for i in range(200)])
        chunks = chunk_text(large_code, "code.py", max_tokens=100, overlap_tokens=10)
        for c in chunks:
            assert c.content.strip()

    def test_empty_input_returns_one_empty_chunk(self):
        chunks = chunk_text("", "empty.py")
        assert len(chunks) == 1
        assert chunks[0].content == ""


# ---------------------------------------------------------------------------
# parse_unified_diff
# ---------------------------------------------------------------------------

SIMPLE_DIFF = """\
diff --git a/api/views.py b/api/views.py
index abc123..def456 100644
--- a/api/views.py
+++ b/api/views.py
@@ -10,6 +10,12 @@ class OrderView:
     def get(self, request, order_id):
-        return Order.objects.get(pk=order_id)
+        order = Order.objects.get(pk=order_id, user=request.user)
+        return order
"""

class TestParseUnifiedDiff:
    def test_returns_parsed_diff(self):
        result = parse_unified_diff(SIMPLE_DIFF, "api/views.py")
        assert isinstance(result, ParsedDiff)

    def test_file_path_set(self):
        result = parse_unified_diff(SIMPLE_DIFF, "api/views.py")
        assert result.file_path == "api/views.py"

    def test_raw_diff_preserved(self):
        result = parse_unified_diff(SIMPLE_DIFF, "api/views.py")
        assert result.raw_diff == SIMPLE_DIFF

    def test_hunks_detected(self):
        result = parse_unified_diff(SIMPLE_DIFF, "api/views.py")
        assert len(result.hunks) >= 1

    def test_added_lines_detected(self):
        result = parse_unified_diff(SIMPLE_DIFF, "api/views.py")
        all_added = []
        for hunk in result.hunks:
            all_added.extend(hunk.added_lines)
        assert any("request.user" in line for _, line in all_added)

    def test_removed_lines_detected(self):
        result = parse_unified_diff(SIMPLE_DIFF, "api/views.py")
        all_removed = []
        for hunk in result.hunks:
            all_removed.extend(hunk.removed_lines)
        assert any("Order.objects.get" in line for _, line in all_removed)

    def test_empty_diff(self):
        result = parse_unified_diff("", "empty.py")
        assert isinstance(result, ParsedDiff)
        assert result.hunks == []


# ---------------------------------------------------------------------------
# chunk_diff
# ---------------------------------------------------------------------------

class TestChunkDiff:
    def test_returns_list_of_chunks(self):
        chunks = chunk_diff(SIMPLE_DIFF, "api/views.py")
        assert isinstance(chunks, list)
        assert len(chunks) >= 1

    def test_chunks_are_marked_as_diff(self):
        chunks = chunk_diff(SIMPLE_DIFF, "api/views.py")
        assert all(c.is_diff for c in chunks)

    def test_file_path_on_chunks(self):
        chunks = chunk_diff(SIMPLE_DIFF, "api/views.py")
        for c in chunks:
            assert c.file_path == "api/views.py"

    def test_empty_diff_returns_one_chunk(self):
        chunks = chunk_diff("", "empty.py")
        assert len(chunks) == 1


# ---------------------------------------------------------------------------
# read_file_safe
# ---------------------------------------------------------------------------

class TestReadFileSafe:
    def test_reads_existing_file(self, tmp_path):
        f = tmp_path / "code.py"
        f.write_text("x = 1\ny = 2\n")
        content = read_file_safe(f)
        assert "x = 1" in content
        assert "y = 2" in content

    def test_returns_none_for_missing_file(self, tmp_path):
        result = read_file_safe(tmp_path / "nonexistent.py")
        assert result is None

    def test_truncates_at_max_lines(self, tmp_path):
        f = tmp_path / "large.py"
        lines = [f"line_{i} = True" for i in range(500)]
        f.write_text("\n".join(lines))
        content = read_file_safe(f, max_lines=100)
        assert content is not None
        # Should have at most 100 lines
        assert content.count("\n") <= 100

    def test_reads_unicode_content(self, tmp_path):
        f = tmp_path / "unicode.py"
        f.write_text("# © Crysa Project\nname = '日本語'\n", encoding="utf-8")
        content = read_file_safe(f)
        assert content is not None
        assert "Crysa" in content


# ---------------------------------------------------------------------------
# CodeChunk.token_count property
# ---------------------------------------------------------------------------

class TestCodeChunkTokenCount:
    def test_token_count_is_positive_for_nonempty_content(self):
        chunk = CodeChunk(
            content="def hello(): pass",
            file_path="test.py",
            line_start=1,
            line_end=1,
            chunk_index=0,
            total_chunks=1,
            is_diff=False,
        )
        assert chunk.token_count > 0

    def test_token_count_is_zero_for_empty_content(self):
        chunk = CodeChunk(
            content="",
            file_path="test.py",
            line_start=1,
            line_end=1,
            chunk_index=0,
            total_chunks=1,
            is_diff=False,
        )
        assert chunk.token_count == 0
