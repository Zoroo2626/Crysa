"""Tests for crysa.engine.findings.

Covers the Finding and ScanResult data models, serialization (JSON, SARIF),
and filtering methods. These tests are pure unit tests with no I/O or LLM calls.
"""

from __future__ import annotations

import json
import pytest
from dataclasses import asdict

from crysa.engine.findings import (
    Finding,
    ScanResult,
    VulnClass,
    Severity,
    Confidence,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_finding(**overrides) -> Finding:
    """Build a valid Finding with sensible defaults, overridable per-test."""
    defaults = dict(
        vuln_class=VulnClass.IDOR,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        file="api/views.py",
        line_start=42,
        line_end=58,
        title="Missing ownership check",
        description="The endpoint fetches resources by ID without verifying ownership.",
        impact="Any authenticated user can read any other user's data.",
        reproduction="1. Authenticate as User A.\n2. GET /api/orders/999 (belonging to User B).",
        fix="Add user_id filter: Order.get(id=order_id, user_id=current_user.id)",
    )
    defaults.update(overrides)
    return Finding(**defaults)


# ---------------------------------------------------------------------------
# Finding identity
# ---------------------------------------------------------------------------

class TestFindingId:
    def test_id_is_generated(self):
        f = make_finding()
        assert f.id.startswith("CRYSA-")

    def test_id_is_unique(self):
        ids = {make_finding().id for _ in range(50)}
        assert len(ids) == 50, "Finding IDs are not unique"

    def test_id_length(self):
        f = make_finding()
        # "CRYSA-" + 6 hex chars
        assert len(f.id) == len("CRYSA-") + 6


# ---------------------------------------------------------------------------
# Finding serialization
# ---------------------------------------------------------------------------

class TestFindingToDict:
    def test_required_keys_present(self):
        f = make_finding()
        d = f.to_dict()
        required = {
            "id", "vuln_class", "severity", "confidence",
            "file", "line_start", "line_end",
            "title", "description", "impact", "reproduction", "fix",
        }
        assert required.issubset(d.keys())

    def test_enum_values_are_strings(self):
        f = make_finding()
        d = f.to_dict()
        assert isinstance(d["vuln_class"], str)
        assert isinstance(d["severity"], str)
        assert isinstance(d["confidence"], str)

    def test_vuln_class_value(self):
        f = make_finding(vuln_class=VulnClass.AUTH_BYPASS)
        assert f.to_dict()["vuln_class"] == "AUTH_BYPASS"

    def test_severity_value(self):
        f = make_finding(severity=Severity.CRITICAL)
        assert f.to_dict()["severity"] == "CRITICAL"


class TestFindingToJson:
    def test_is_valid_json(self):
        f = make_finding()
        data = json.loads(f.to_json())
        assert isinstance(data, dict)

    def test_json_matches_dict(self):
        f = make_finding()
        assert json.loads(f.to_json()) == f.to_dict()


class TestFindingFromDict:
    def test_round_trip(self):
        original = make_finding()
        restored = Finding.from_dict(original.to_dict())
        assert restored.vuln_class == original.vuln_class
        assert restored.severity == original.severity
        assert restored.confidence == original.confidence
        assert restored.file == original.file
        assert restored.line_start == original.line_start
        assert restored.title == original.title

    def test_raises_on_missing_required_fields(self):
        d = make_finding().to_dict()
        del d["title"]
        with pytest.raises(ValueError):
            Finding.from_dict(d)

    def test_accepts_safe_vuln_class(self):
        d = make_finding().to_dict()
        d["vuln_class"] = "SAFE"
        f = Finding.from_dict(d)
        assert f.vuln_class == VulnClass.SAFE


# ---------------------------------------------------------------------------
# Severity ordering
# ---------------------------------------------------------------------------

class TestSeverityLevel:
    def test_critical_is_highest(self):
        assert Severity.CRITICAL.level > Severity.HIGH.level

    def test_high_above_medium(self):
        assert Severity.HIGH.level > Severity.MEDIUM.level

    def test_medium_above_low(self):
        assert Severity.MEDIUM.level > Severity.LOW.level

    def test_low_above_info(self):
        assert Severity.LOW.level > Severity.INFO.level

    def test_complete_ordering(self):
        ordered = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        levels = [s.level for s in ordered]
        assert levels == sorted(levels, reverse=True)


# ---------------------------------------------------------------------------
# Confidence ordering
# ---------------------------------------------------------------------------

class TestConfidenceLevel:
    def test_high_is_highest(self):
        assert Confidence.HIGH.level > Confidence.MEDIUM.level
        assert Confidence.MEDIUM.level > Confidence.LOW.level


# ---------------------------------------------------------------------------
# ScanResult
# ---------------------------------------------------------------------------

class TestScanResult:
    def _make_result(self) -> ScanResult:
        return ScanResult(
            findings=[
                make_finding(severity=Severity.CRITICAL, confidence=Confidence.HIGH),
                make_finding(severity=Severity.HIGH, confidence=Confidence.HIGH),
                make_finding(severity=Severity.MEDIUM, confidence=Confidence.MEDIUM),
                make_finding(severity=Severity.LOW, confidence=Confidence.LOW),
                make_finding(severity=Severity.INFO, confidence=Confidence.LOW),
            ],
            files_scanned=3,
        )

    def test_count_properties(self):
        r = self._make_result()
        assert r.critical_count == 1
        assert r.high_count == 1
        assert r.medium_count == 1
        assert r.low_count == 1
        assert r.info_count == 1

    def test_filter_by_severity_high(self):
        r = self._make_result()
        filtered = r.filter_by_severity(Severity.HIGH)
        severities = {f.severity for f in filtered.findings}
        assert Severity.MEDIUM not in severities
        assert Severity.LOW not in severities
        assert Severity.INFO not in severities
        assert Severity.HIGH in severities
        assert Severity.CRITICAL in severities

    def test_filter_by_severity_critical_only(self):
        r = self._make_result()
        filtered = r.filter_by_severity(Severity.CRITICAL)
        assert len(filtered.findings) == 1
        assert filtered.findings[0].severity == Severity.CRITICAL

    def test_filter_by_severity_info_returns_all(self):
        r = self._make_result()
        filtered = r.filter_by_severity(Severity.INFO)
        assert len(filtered.findings) == 5

    def test_filter_by_confidence_high(self):
        r = self._make_result()
        filtered = r.filter_by_confidence(Confidence.HIGH)
        for f in filtered.findings:
            assert f.confidence == Confidence.HIGH

    def test_filter_preserves_files_scanned(self):
        r = self._make_result()
        filtered = r.filter_by_severity(Severity.CRITICAL)
        assert filtered.files_scanned == r.files_scanned

    def test_empty_result(self):
        r = ScanResult()
        assert r.critical_count == 0
        assert r.high_count == 0
        assert len(r.findings) == 0


# ---------------------------------------------------------------------------
# SARIF output
# ---------------------------------------------------------------------------

class TestSarif:
    def test_sarif_structure(self):
        r = ScanResult(findings=[make_finding()], files_scanned=1)
        sarif = r.to_sarif()
        assert sarif["version"] == "2.1.0"
        assert "runs" in sarif
        assert len(sarif["runs"]) == 1

    def test_sarif_run_has_tool(self):
        r = ScanResult(findings=[make_finding()], files_scanned=1)
        run = r.to_sarif()["runs"][0]
        assert "tool" in run
        assert run["tool"]["driver"]["name"] == "Crysa"

    def test_sarif_results_count(self):
        findings = [make_finding() for _ in range(3)]
        r = ScanResult(findings=findings, files_scanned=1)
        run = r.to_sarif()["runs"][0]
        assert len(run["results"]) == 3

    def test_sarif_level_mapping(self):
        cases = [
            (Severity.CRITICAL, "error"),
            (Severity.HIGH, "error"),
            (Severity.MEDIUM, "warning"),
            (Severity.LOW, "note"),
            (Severity.INFO, "note"),
        ]
        for severity, expected_level in cases:
            r = ScanResult(findings=[make_finding(severity=severity)], files_scanned=1)
            result = r.to_sarif()["runs"][0]["results"][0]
            assert result["level"] == expected_level, (
                f"Severity {severity} should map to SARIF level {expected_level!r}"
            )

    def test_sarif_is_valid_json(self):
        r = ScanResult(findings=[make_finding()], files_scanned=1)
        sarif_json = r.to_sarif_json()
        parsed = json.loads(sarif_json)
        assert parsed["version"] == "2.1.0"

    def test_sarif_empty_scan(self):
        r = ScanResult(findings=[], files_scanned=0)
        sarif = r.to_sarif()
        assert sarif["runs"][0]["results"] == []


# ---------------------------------------------------------------------------
# ScanResult JSON
# ---------------------------------------------------------------------------

class TestScanResultJson:
    def test_json_has_summary_and_findings(self):
        r = ScanResult(findings=[make_finding()], files_scanned=2)
        data = json.loads(r.to_json())
        assert "summary" in data
        assert "findings" in data
        assert data["summary"]["files_scanned"] == 2
        assert len(data["findings"]) == 1

    def test_json_summary_counts(self):
        r = ScanResult(
            findings=[
                make_finding(severity=Severity.CRITICAL),
                make_finding(severity=Severity.HIGH),
            ],
            files_scanned=1,
        )
        data = json.loads(r.to_json())
        assert data["summary"]["critical"] == 1
        assert data["summary"]["high"] == 1
        assert data["summary"]["medium"] == 0
