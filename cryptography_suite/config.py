"""Backward-compatible config facade."""

from __future__ import annotations

from .core.settings import RuntimeEnvironment, SuiteSettings, load_settings

load_settings.cache_clear()
SETTINGS: SuiteSettings = load_settings()
STRICT_KEYS: str = SETTINGS.strict_keys_mode
RUNTIME_ENV: RuntimeEnvironment = SETTINGS.environment
LOG_LEVEL: str = SETTINGS.log_level

__all__ = ["SETTINGS", "STRICT_KEYS", "RUNTIME_ENV", "LOG_LEVEL", "load_settings"]
