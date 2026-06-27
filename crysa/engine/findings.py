"""Finding data models and formatter for Crysa.

Defines the structured output schema for security findings
and provides serialization, filtering, and display formatting.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional
from uuid import uuid4


class VulnClass(str, Enum):
    """Vulnerability classification taxonomy."""
    IDOR = "IDOR"
    AUTH_BYPASS = "AUTH_BYPASS"
    PRIVILEGE_ESC = "PRIVILEGE_ESC"
    MASS_ASSIGN = "MASS_ASSIGN"
    JWT_ISSUE = "JWT_ISSUE"
    LOGIC_FLAW = "LOGIC_FLAW"
    DATA_EXPOSURE = "DATA_EXPOSURE"
    SAFE = "SAFE"


class Severity(str, Enum):
    """Finding severity levels, ordered from most to least critical."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def level(self) -> int:
        """Numeric severity for comparison (higher = more critical)."""
        _levels = {
            "CRITICAL": 5, "HIGH": 4, "MEDIUM": 3,
            "LOW": 2, "INFO": 1,
        }
        return _levels.get(self.value, 0)


class Confidence(str, Enum):
    """How confident the engine is in a finding."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def level(self) -> int:
        """Numeric confidence for comparison."""
        return {"HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(self.value, 0)


@dataclass
class Finding:
    """A single security finding produced by the reasoning engine."""

    vuln_class: VulnClass
    severity: Severity
    confidence: Confidence
    file: str
    line_start: int
    line_end: int
    title: str
    description: str
    impact: str
    reproduction: str
    fix: str
    id: str = field(default_factory=lambda: f"CRYSA-{uuid4().hex[:6].upper()}")

    def to_dict(self) -> dict:
        """Serialize finding to a JSON-compatible dictionary."""
        return {
            "id": self.id,
            "vuln_class": self.vuln_class.value,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "file": self.file,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "title": self.title,
            "description": self.description,
            "impact": self.impact,
            "reproduction": self.reproduction,
            "fix": self.fix,
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize finding to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict) -> Finding:
        """Deserialize a Finding from a dictionary.

        Args:
            data: Dictionary with finding fields.

        Returns:
            A Finding instance.

        Raises:
            ValueError: If required fields are missing or invalid.
        """
        try:
            return cls(
                # Always generate a fresh UUID-based ID — the LLM emits
                # sequential numbers that reset per file (CRYSA-0001, CRYSA-0002…)
                # which are non-unique across a project scan.
                id=f"CRYSA-{uuid4().hex[:6].upper()}",
                vuln_class=VulnClass(data["vuln_class"]),
                severity=Severity(data["severity"]),
                confidence=Confidence(data["confidence"]),
                file=data["file"],
                line_start=int(data["line_start"]),
                line_end=int(data["line_end"]),
                title=data["title"],
                description=data["description"],
                impact=data["impact"],
                reproduction=data["reproduction"],
                fix=data["fix"],
            )
        except (KeyError, ValueError) as e:
            raise ValueError(f"Invalid finding data: {e}") from e


@dataclass
class ScanResult:
    """Aggregated results from a scan operation."""

    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        """Count of CRITICAL severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        """Count of HIGH severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        """Count of MEDIUM severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        """Count of LOW severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        """Count of INFO severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    def filter_by_severity(self, threshold: Severity) -> ScanResult:
        """Return a new ScanResult with only findings at or above the threshold.

        Args:
            threshold: Minimum severity to include.

        Returns:
            New ScanResult with filtered findings.
        """
        threshold_level = threshold.level
        filtered = [f for f in self.findings if f.severity.level >= threshold_level]
        return ScanResult(
            findings=filtered,
            files_scanned=self.files_scanned,
            errors=self.errors,
        )

    def filter_by_confidence(self, threshold: Confidence) -> ScanResult:
        """Return a new ScanResult with only findings at or above confidence threshold.

        Args:
            threshold: Minimum confidence to include.

        Returns:
            New ScanResult with filtered findings.
        """
        threshold_level = threshold.level
        filtered = [f for f in self.findings if f.confidence.level >= threshold_level]
        return ScanResult(
            findings=filtered,
            files_scanned=self.files_scanned,
            errors=self.errors,
        )

    def to_dict(self) -> dict:
        """Serialize scan result to a JSON-compatible dictionary."""
        return {
            "summary": {
                "files_scanned": self.files_scanned,
                "total_findings": len(self.findings),
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
            },
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize scan result to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def to_sarif(self) -> dict:
        """Serialize findings to SARIF 2.1.0 format.

        Returns:
            A SARIF-compatible dictionary for GitHub Code Scanning integration.
        """
        sarif_results = []
        for f in self.findings:
            level_map = {
                "CRITICAL": "error", "HIGH": "error",
                "MEDIUM": "warning", "LOW": "note", "INFO": "note",
            }
            sarif_results.append({
                "ruleId": f.vuln_class.value,
                "level": level_map.get(f.severity.value, "note"),
                "message": {
                    "text": f"{f.title}\n\n{f.description}\n\nImpact: {f.impact}\n\nFix: {f.fix}",
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.file,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": f.line_start,
                            "endLine": f.line_end,
                        },
                    },
                }],
                "fingerprints": {
                    "crysa/id": f.id,
                },
                "properties": {
                    "crysa/vuln_class": f.vuln_class.value,
                    "crysa/confidence": f.confidence.value,
                    "crysa/reproduction": f.reproduction,
                },
            })

        rule_descriptions = {}
        for f in self.findings:
            if f.vuln_class.value not in rule_descriptions:
                rule_descriptions[f.vuln_class.value] = {
                    "id": f.vuln_class.value,
                    "shortDescription": {"text": f.vuln_class.value.replace("_", " ").title()},
                    "defaultConfiguration": {"level": "warning"},
                }

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Crysa",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/crysa/crysa",
                        "rules": list(rule_descriptions.values()),
                    },
                },
                "results": sarif_results,
            }],
        }

    def to_sarif_json(self, indent: int = 2) -> str:
        """Serialize to SARIF 2.1.0 JSON string."""
        return json.dumps(self.to_sarif(), indent=indent)
