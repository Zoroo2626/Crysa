"""Configuration loader for Crysa.

Loads config.yaml and .env, merges them, and provides
a typed Config object with sane defaults.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union

import yaml
from dotenv import load_dotenv


_DEFAULTS = {
    "base_url": "https://api.openai.com/v1",
    "model": "gpt-4o",
    "api_key": "",
    "max_tokens": 4096,
    "temperature": 0.1,
    "severity_threshold": "LOW",
    "confidence_threshold": "MEDIUM",
    "chunk_size": 8000,
    "chunk_overlap": 200,
    "mcp_host": "127.0.0.1",
    "mcp_port": 3333,
    "debounce_ms": 800,
    "max_file_lines": 2000,
    "default_format": "rich",
    "show_fix": True,
    "show_reproduction": True,
}


@dataclass
class Config:
    """Typed Crysa configuration with all settings."""

    base_url: str = _DEFAULTS["base_url"]
    model: str = _DEFAULTS["model"]
    api_key: str = _DEFAULTS["api_key"]
    max_tokens: int = _DEFAULTS["max_tokens"]
    temperature: float = _DEFAULTS["temperature"]
    severity_threshold: str = _DEFAULTS["severity_threshold"]
    confidence_threshold: str = _DEFAULTS["confidence_threshold"]
    chunk_size: int = _DEFAULTS["chunk_size"]
    chunk_overlap: int = _DEFAULTS["chunk_overlap"]
    mcp_host: str = _DEFAULTS["mcp_host"]
    mcp_port: int = _DEFAULTS["mcp_port"]
    debounce_ms: int = _DEFAULTS["debounce_ms"]
    max_file_lines: int = _DEFAULTS["max_file_lines"]
    default_format: str = _DEFAULTS["default_format"]
    show_fix: bool = _DEFAULTS["show_fix"]
    show_reproduction: bool = _DEFAULTS["show_reproduction"]


def _resolve_env(value: str) -> str:
    """Resolve ${VAR} placeholders in a string with environment values."""
    if not isinstance(value, str):
        return value
    if value.startswith("${") and value.endswith("}"):
        env_key = value[2:-1]
        return os.environ.get(env_key, "")
    return value


def _resolve_env_recursive(obj: object) -> object:
    """Recursively resolve env placeholders in a config dict."""
    if isinstance(obj, str):
        return _resolve_env(obj)
    if isinstance(obj, dict):
        return {k: _resolve_env_recursive(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_resolve_env_recursive(v) for v in obj]
    return obj


def load_config(
    config_path: Optional[Union[str, Path]] = None,
    env_path: Optional[Union[str, Path]] = None,
) -> Config:
    """Load configuration from config.yaml and .env.

    Args:
        config_path: Path to config.yaml. Defaults to ./config.yaml.
            Accepts both str and Path.
        env_path: Path to .env. Defaults to ./.env.
            Accepts both str and Path.

    Returns:
        A fully resolved Config object.
    """
    # Normalize to Path so callers can pass strings freely
    if config_path is not None:
        config_path = Path(config_path)
    if env_path is not None:
        env_path = Path(env_path)

    # Load .env first so env vars are available for config.yaml resolution
    if env_path and env_path.exists():
        load_dotenv(env_path)
    else:
        load_dotenv()

    # Load config.yaml
    cfg_dict: dict = {}
    if config_path is None:
        config_path = Path("config.yaml")

    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        cfg_dict = raw.get("crysa", raw)

    # Resolve env placeholders
    cfg_dict = _resolve_env_recursive(cfg_dict)

    # Merge with defaults
    merged = {**_DEFAULTS, **cfg_dict}

    # Cast types
    merged["max_tokens"] = int(merged["max_tokens"])
    merged["temperature"] = float(merged["temperature"])
    merged["chunk_size"] = int(merged["chunk_size"])
    merged["chunk_overlap"] = int(merged["chunk_overlap"])
    merged["mcp_port"] = int(merged["mcp_port"])
    merged["debounce_ms"] = int(merged["debounce_ms"])
    merged["max_file_lines"] = int(merged["max_file_lines"])
    merged["show_fix"] = bool(merged["show_fix"])
    merged["show_reproduction"] = bool(merged["show_reproduction"])

    return Config(**merged)


# Singleton config loaded once at import
_config: Optional[Config] = None


def get_config() -> Config:
    """Get the global config singleton, loading it if needed."""
    global _config
    if _config is None:
        _config = load_config()
    return _config


def reload_config(config_path: Optional[Path] = None, env_path: Optional[Path] = None) -> Config:
    """Force reload configuration from disk."""
    global _config
    _config = load_config(config_path, env_path)
    return _config
