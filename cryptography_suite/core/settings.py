"""Typed runtime settings and environment-aware config loading."""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache

from .errors import ErrorCode, SuiteError


class RuntimeEnvironment(str, Enum):
    DEV = "dev"
    TEST = "test"
    PROD = "prod"


@dataclass(frozen=True, slots=True)
class SuiteSettings:
    environment: RuntimeEnvironment = RuntimeEnvironment.DEV
    strict_keys_mode: str = "warn"
    log_level: str = "INFO"


def _normalize_strict_keys_mode(raw_value: str) -> str:
    value = raw_value.lower().strip()
    if value in {"1", "true"}:
        return "error"
    if value in {"0", "false"}:
        return "false"
    if value in {"warn", "error"}:
        return value
    raise SuiteError(
        message=(
            "Invalid CRYPTOSUITE_STRICT_KEYS value. Allowed values: "
            "warn/error/true/false/1/0"
        ),
        code=ErrorCode.CONFIGURATION_ERROR,
        details={"CRYPTOSUITE_STRICT_KEYS": raw_value},
    )


def _parse_environment(raw_value: str) -> RuntimeEnvironment:
    try:
        return RuntimeEnvironment(raw_value.lower().strip())
    except ValueError as exc:
        raise SuiteError(
            message="Invalid CRYPTOSUITE_ENV value. Allowed values: dev/test/prod",
            code=ErrorCode.CONFIGURATION_ERROR,
            details={"CRYPTOSUITE_ENV": raw_value},
        ) from exc


@lru_cache(maxsize=1)
def load_settings() -> SuiteSettings:
    """Load validated settings from environment once per process."""

    return SuiteSettings(
        environment=_parse_environment(os.getenv("CRYPTOSUITE_ENV", "dev")),
        strict_keys_mode=_normalize_strict_keys_mode(
            os.getenv("CRYPTOSUITE_STRICT_KEYS", "warn")
        ),
        log_level=os.getenv("CRYPTOSUITE_LOG_LEVEL", "INFO").upper(),
    )
