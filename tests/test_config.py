"""Tests for crysa.utils.config.

Covers loading, env var resolution, defaults, and type casting.
Uses temp files to avoid touching the real config.yaml or .env.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from crysa.utils.config import Config, load_config, _DEFAULTS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_yaml(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "config.yaml"
    p.write_text(content)
    return p


def make_env(tmp_path: Path, content: str) -> Path:
    p = tmp_path / ".env"
    p.write_text(content)
    return p


# ---------------------------------------------------------------------------
# _DEFAULTS
# ---------------------------------------------------------------------------

class TestDefaults:
    def test_all_default_keys_match_config_fields(self):
        """Every key in _DEFAULTS must correspond to a field in Config."""
        config_fields = {f.name for f in Config.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        for key in _DEFAULTS:
            assert key in config_fields, f"_DEFAULTS has orphan key: {key!r}"

    def test_default_temperature_is_low(self):
        assert _DEFAULTS["temperature"] <= 0.2

    def test_default_severity_threshold(self):
        assert _DEFAULTS["severity_threshold"] == "LOW"

    def test_default_confidence_threshold(self):
        assert _DEFAULTS["confidence_threshold"] == "MEDIUM"

    def test_default_chunk_size_is_reasonable(self):
        assert 1000 <= _DEFAULTS["chunk_size"] <= 32_000


# ---------------------------------------------------------------------------
# load_config — basic loading
# ---------------------------------------------------------------------------

class TestLoadConfig:
    def test_loads_with_no_files(self, tmp_path):
        """When no config files exist, defaults are used."""
        config = load_config(
            config_path=str(tmp_path / "nonexistent.yaml"),
            env_path=str(tmp_path / ".env"),
        )
        assert isinstance(config, Config)
        assert config.temperature == _DEFAULTS["temperature"]

    def test_loads_model_from_yaml(self, tmp_path):
        yaml = make_yaml(tmp_path, "crysa:\n  model: gpt-4o\n")
        config = load_config(config_path=str(yaml), env_path=str(tmp_path / ".env"))
        assert config.model == "gpt-4o"

    def test_yaml_overrides_default(self, tmp_path):
        yaml = make_yaml(tmp_path, "crysa:\n  chunk_size: 4000\n")
        config = load_config(config_path=str(yaml), env_path=str(tmp_path / ".env"))
        assert config.chunk_size == 4000

    def test_missing_yaml_key_uses_default(self, tmp_path):
        yaml = make_yaml(tmp_path, "crysa:\n  model: gpt-4o\n")
        config = load_config(config_path=str(yaml), env_path=str(tmp_path / ".env"))
        # temperature not in yaml → should be default
        assert config.temperature == _DEFAULTS["temperature"]


# ---------------------------------------------------------------------------
# load_config — env var resolution
# ---------------------------------------------------------------------------

class TestEnvVarResolution:
    def test_api_key_from_env_file(self, tmp_path, monkeypatch):
        # Ensure no real key from the project .env bleeds into this test
        monkeypatch.delenv("CRYSA_API_KEY", raising=False)
        env = make_env(tmp_path, "CRYSA_API_KEY=test-secret-key\n")
        yaml = make_yaml(
            tmp_path,
            "crysa:\n  api_key: ${CRYSA_API_KEY}\n",
        )
        config = load_config(config_path=str(yaml), env_path=str(env))
        assert config.api_key == "test-secret-key"

    def test_base_url_from_env(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CRYSA_BASE_URL", "https://api.example.com/v1")
        yaml = make_yaml(
            tmp_path,
            "crysa:\n  base_url: ${CRYSA_BASE_URL}\n",
        )
        config = load_config(config_path=str(yaml), env_path=str(tmp_path / ".env"))
        assert config.base_url == "https://api.example.com/v1"

    def test_unresolved_placeholder_stays_as_empty_or_literal(self, tmp_path):
        """A ${VAR} that doesn't exist should not crash — it resolves to empty."""
        yaml = make_yaml(
            tmp_path,
            "crysa:\n  api_key: ${CRYSA_UNDEFINED_VAR_XYZ}\n",
        )
        # Should not raise
        config = load_config(config_path=str(yaml), env_path=str(tmp_path / ".env"))
        assert isinstance(config.api_key, str)


# ---------------------------------------------------------------------------
# load_config — type casting
# ---------------------------------------------------------------------------

class TestTypeCasting:
    def test_chunk_size_is_int(self, tmp_path):
        yaml = make_yaml(tmp_path, "crysa:\n  chunk_size: '4000'\n")
        config = load_config(config_path=str(yaml), env_path=str(tmp_path / ".env"))
        assert isinstance(config.chunk_size, int)
        assert config.chunk_size == 4000

    def test_temperature_is_float(self, tmp_path):
        yaml = make_yaml(tmp_path, "crysa:\n  temperature: '0.2'\n")
        config = load_config(config_path=str(yaml), env_path=str(tmp_path / ".env"))
        assert isinstance(config.temperature, float)

    def test_show_fix_is_bool(self, tmp_path):
        yaml = make_yaml(tmp_path, "crysa:\n  show_fix: false\n")
        config = load_config(config_path=str(yaml), env_path=str(tmp_path / ".env"))
        assert config.show_fix is False


# ---------------------------------------------------------------------------
# Config dataclass
# ---------------------------------------------------------------------------

class TestConfigDataclass:
    def test_config_is_mutable(self):
        """Config fields can be set (used by tests and advanced users)."""
        config = Config(**_DEFAULTS)
        config.model = "claude-3-opus"
        assert config.model == "claude-3-opus"

    def test_config_has_all_expected_fields(self):
        required = {
            "base_url", "model", "api_key", "max_tokens",
            "temperature", "severity_threshold", "confidence_threshold",
            "chunk_size", "chunk_overlap", "mcp_host", "mcp_port",
            "debounce_ms", "max_file_lines", "default_format",
            "show_fix", "show_reproduction",
        }
        config = Config(**_DEFAULTS)
        for field in required:
            assert hasattr(config, field), f"Config is missing field: {field!r}"
