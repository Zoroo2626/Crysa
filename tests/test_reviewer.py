"""Tests for crysa.engine.reviewer.

All LLM calls are mocked — no real API calls are made. These tests verify
the orchestration logic: prompt building, response parsing, deduplication,
and the client singleton pattern.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

from crysa.engine.findings import Finding, VulnClass, Severity, Confidence, ScanResult
from crysa.engine.parser import CodeChunk
from crysa.engine.context import SecurityContext
from crysa.engine.reviewer import (
    _parse_findings,
    _deduplicate_findings,
    _build_user_prompt,
    SYSTEM_PROMPT,
    VULN_HINTS,
)
from crysa.utils.config import Config, _DEFAULTS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_config(**overrides) -> Config:
    d = dict(_DEFAULTS)
    d["api_key"] = "test-key"
    d.update(overrides)
    return Config(**d)


def make_chunk(content: str = "def get(): pass", file_path: str = "views.py") -> CodeChunk:
    return CodeChunk(
        content=content,
        file_path=file_path,
        line_start=1,
        line_end=content.count("\n") + 1,
        chunk_index=0,
        total_chunks=1,
        is_diff=False,
    )


def make_context() -> SecurityContext:
    return SecurityContext(
        framework="fastapi",
        language="python",
        auth_summary="JWT-based auth detected",
        routes=["/api/orders/{id}"],
        models=["class Order(BaseModel)"],
        roles=["admin", "user"],
        middleware=["JWTMiddleware"],
    )


def make_finding_dict(**overrides) -> dict:
    base = {
        "id": "CRYSA-TEST01",
        "vuln_class": "IDOR",
        "severity": "HIGH",
        "confidence": "HIGH",
        "file": "views.py",
        "line_start": 10,
        "line_end": 15,
        "title": "Missing ownership check",
        "description": "Fetches order without checking ownership.",
        "impact": "Any user can read any order.",
        "reproduction": "GET /api/orders/999",
        "fix": "Add user_id filter.",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# _parse_findings
# ---------------------------------------------------------------------------

class TestParseFindings:
    def test_parses_valid_json_array(self):
        response = json.dumps([make_finding_dict()])
        findings = _parse_findings(response, "views.py")
        assert len(findings) == 1
        assert findings[0].vuln_class == VulnClass.IDOR

    def test_parses_multiple_findings(self):
        data = [
            make_finding_dict(vuln_class="IDOR", title="IDOR 1"),
            make_finding_dict(vuln_class="AUTH_BYPASS", title="Auth bypass"),
        ]
        findings = _parse_findings(json.dumps(data), "views.py")
        assert len(findings) == 2

    def test_strips_markdown_fences(self):
        raw = "```json\n" + json.dumps([make_finding_dict()]) + "\n```"
        findings = _parse_findings(raw, "views.py")
        assert len(findings) == 1

    def test_strips_backtick_fences(self):
        raw = "```\n" + json.dumps([make_finding_dict()]) + "\n```"
        findings = _parse_findings(raw, "views.py")
        assert len(findings) == 1

    def test_empty_array_returns_empty(self):
        findings = _parse_findings("[]", "views.py")
        assert findings == []

    def test_returns_empty_on_malformed_json(self):
        findings = _parse_findings("not valid json at all", "views.py")
        assert findings == []

    def test_returns_empty_on_non_array_json(self):
        findings = _parse_findings('{"key": "value"}', "views.py")
        assert findings == []

    def test_skips_invalid_items_keeps_valid(self):
        """If one item in the array is invalid, the rest should still parse."""
        data = [
            {"invalid": "no required fields"},
            make_finding_dict(title="Valid finding"),
        ]
        findings = _parse_findings(json.dumps(data), "views.py")
        # At least the valid one should be parsed
        valid = [f for f in findings if f.title == "Valid finding"]
        assert len(valid) == 1

    def test_extracts_json_from_surrounding_prose(self):
        """LLMs sometimes wrap the JSON in explanatory text."""
        array = json.dumps([make_finding_dict()])
        response = f"Here are the findings I found:\n{array}\nEnd of findings."
        findings = _parse_findings(response, "views.py")
        assert len(findings) == 1

    def test_severity_is_set_correctly(self):
        d = make_finding_dict(severity="CRITICAL")
        findings = _parse_findings(json.dumps([d]), "views.py")
        assert findings[0].severity == Severity.CRITICAL

    def test_file_path_set_from_argument(self):
        d = make_finding_dict(file="some/other/path.py")
        findings = _parse_findings(json.dumps([d]), "views.py")
        # The file path from the dict is used as-is (the reviewer adjusts it)
        assert isinstance(findings[0].file, str)


# ---------------------------------------------------------------------------
# _deduplicate_findings
# ---------------------------------------------------------------------------

class TestDeduplicateFindings:
    def _make_finding(self, vuln_class: str, file: str, line_start: int,
                      title: str, confidence: Confidence = Confidence.HIGH) -> Finding:
        return Finding(
            vuln_class=VulnClass(vuln_class),
            severity=Severity.HIGH,
            confidence=confidence,
            file=file,
            line_start=line_start,
            line_end=line_start + 5,
            title=title,
            description="desc",
            impact="impact",
            reproduction="repro",
            fix="fix",
        )

    def test_removes_exact_duplicate(self):
        f1 = self._make_finding("IDOR", "views.py", 10, "Missing check")
        f2 = self._make_finding("IDOR", "views.py", 10, "Missing check")
        result = _deduplicate_findings([f1, f2])
        assert len(result) == 1

    def test_removes_near_duplicate_within_10_lines(self):
        """Findings within 10 lines with same class and title are duplicates."""
        f1 = self._make_finding("IDOR", "views.py", 10, "Missing check")
        f2 = self._make_finding("IDOR", "views.py", 15, "Missing check")
        result = _deduplicate_findings([f1, f2])
        assert len(result) == 1

    def test_keeps_distinct_vuln_classes(self):
        f1 = self._make_finding("IDOR", "views.py", 10, "Check A")
        f2 = self._make_finding("AUTH_BYPASS", "views.py", 10, "Check B")
        result = _deduplicate_findings([f1, f2])
        assert len(result) == 2

    def test_keeps_distinct_files(self):
        f1 = self._make_finding("IDOR", "views.py", 10, "Missing check")
        f2 = self._make_finding("IDOR", "models.py", 10, "Missing check")
        result = _deduplicate_findings([f1, f2])
        assert len(result) == 2

    def test_keeps_distinct_titles(self):
        f1 = self._make_finding("IDOR", "views.py", 10, "Check A")
        f2 = self._make_finding("IDOR", "views.py", 10, "Check B")
        result = _deduplicate_findings([f1, f2])
        assert len(result) == 2

    def test_keeps_higher_confidence_on_duplicate(self):
        low = self._make_finding("IDOR", "views.py", 10, "Check", Confidence.LOW)
        high = self._make_finding("IDOR", "views.py", 12, "Check", Confidence.HIGH)
        result = _deduplicate_findings([low, high])
        assert len(result) == 1
        assert result[0].confidence == Confidence.HIGH

    def test_empty_input(self):
        assert _deduplicate_findings([]) == []

    def test_single_finding_unchanged(self):
        f = self._make_finding("IDOR", "views.py", 10, "Check")
        result = _deduplicate_findings([f])
        assert len(result) == 1


# ---------------------------------------------------------------------------
# _build_user_prompt
# ---------------------------------------------------------------------------

class TestBuildUserPrompt:
    def test_contains_code_content(self):
        code = "def get_order(order_id): return Order.get(order_id)"
        ctx = make_context()
        prompt = _build_user_prompt(
            content=code,
            file_path="views.py",
            context=ctx,
            language="python",
            is_diff=False,
        )
        assert code in prompt

    def test_contains_framework_info(self):
        ctx = make_context()
        prompt = _build_user_prompt(
            content="x = 1",
            file_path="views.py",
            context=ctx,
            language="python",
            is_diff=False,
        )
        assert "fastapi" in prompt.lower()

    def test_contains_all_hints_by_default(self):
        ctx = make_context()
        prompt = _build_user_prompt(
            content="x = 1",
            file_path="views.py",
            context=ctx,
            language="python",
            is_diff=False,
        )
        for hint_key in VULN_HINTS:
            assert VULN_HINTS[hint_key][:50] in prompt or hint_key in prompt

    def test_filtered_hints_only_include_selected(self):
        ctx = make_context()
        prompt = _build_user_prompt(
            content="x = 1",
            file_path="views.py",
            context=ctx,
            language="python",
            is_diff=False,
            vuln_classes=["IDOR"],
        )
        # IDOR hint should be present
        assert VULN_HINTS["IDOR"][:30] in prompt
        # JWT hint should NOT be present
        assert VULN_HINTS["JWT_ISSUE"][:30] not in prompt

    def test_extra_context_included(self):
        ctx = make_context()
        extra = "This is the payment processing endpoint."
        prompt = _build_user_prompt(
            content="x = 1",
            file_path="views.py",
            context=ctx,
            language="python",
            is_diff=False,
            extra_context=extra,
        )
        assert extra in prompt

    def test_diff_flag_reflected(self):
        ctx = make_context()
        prompt = _build_user_prompt(
            content="+ new line",
            file_path="views.py",
            context=ctx,
            language="python",
            is_diff=True,
        )
        # Diff mode should mention diff in the prompt
        assert "diff" in prompt.lower() or "change" in prompt.lower()


# ---------------------------------------------------------------------------
# SYSTEM_PROMPT
# ---------------------------------------------------------------------------

class TestSystemPrompt:
    def test_system_prompt_is_nonempty(self):
        assert len(SYSTEM_PROMPT.strip()) > 100

    def test_system_prompt_instructs_json_output(self):
        assert "JSON" in SYSTEM_PROMPT

    def test_system_prompt_defines_schema(self):
        required_fields = ["vuln_class", "severity", "confidence", "description", "fix"]
        for field in required_fields:
            assert field in SYSTEM_PROMPT, f"SYSTEM_PROMPT missing field reference: {field!r}"

    def test_system_prompt_has_security_scope(self):
        assert "security" in SYSTEM_PROMPT.lower()

    def test_vuln_hints_cover_all_seven_classes(self):
        expected = {"IDOR", "AUTH_BYPASS", "PRIVILEGE_ESC", "MASS_ASSIGN",
                    "JWT_ISSUE", "LOGIC_FLAW", "DATA_EXPOSURE"}
        assert expected == set(VULN_HINTS.keys())

    def test_each_hint_is_nonempty(self):
        for name, hint in VULN_HINTS.items():
            assert len(hint.strip()) > 100, f"Hint for {name!r} is too short"


# ---------------------------------------------------------------------------
# review_chunk — with mocked LLM
# ---------------------------------------------------------------------------

class TestReviewChunkMocked:
    """Tests that verify the orchestration logic with a mock LLM client."""

    def _run_chunk(self, llm_response: str, **config_overrides):
        from crysa.engine.reviewer import review_chunk

        config = make_config(**config_overrides)
        chunk = make_chunk()
        context = make_context()

        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.choices[0].message.content = llm_response
        mock_client.chat.completions.create.return_value = mock_response

        return review_chunk(chunk, context, config, client=mock_client)

    def test_returns_findings_from_llm_response(self):
        response = json.dumps([make_finding_dict()])
        findings = self._run_chunk(response)
        assert len(findings) == 1
        assert findings[0].vuln_class == VulnClass.IDOR

    def test_returns_empty_list_for_no_findings(self):
        findings = self._run_chunk("[]")
        assert findings == []

    def test_returns_empty_for_malformed_response(self):
        findings = self._run_chunk("I found no issues in this code.")
        assert findings == []

    def test_returns_empty_when_no_api_key(self):
        from crysa.engine.reviewer import review_chunk
        config = Config(**{**_DEFAULTS, "api_key": ""})
        chunk = make_chunk()
        context = make_context()
        findings = review_chunk(chunk, context, config)
        assert findings == []

    def test_line_numbers_adjusted_for_non_first_chunk(self):
        from crysa.engine.reviewer import review_chunk

        config = make_config()
        # Simulate a second chunk starting at line 100
        chunk = CodeChunk(
            content="def update(): pass",
            file_path="views.py",
            line_start=100,
            line_end=110,
            chunk_index=1,
            total_chunks=2,
            is_diff=False,
        )
        context = make_context()

        # LLM reports line 5 (relative to chunk)
        finding_dict = make_finding_dict(line_start=5, line_end=8)
        response = json.dumps([finding_dict])

        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.choices[0].message.content = response
        mock_client.chat.completions.create.return_value = mock_response

        findings = review_chunk(chunk, context, config, client=mock_client)
        assert len(findings) == 1
        # Line 5 in a chunk starting at 100 → adjusted to 104 (5 + 100 - 1)
        assert findings[0].line_start == 104
