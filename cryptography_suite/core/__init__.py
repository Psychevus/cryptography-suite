"""Core application primitives with no crypto-adapter dependencies."""

from .errors import ErrorCode, SuiteError
from .logging import (
    configure_structured_logging,
    get_correlation_id,
    get_structured_logger,
    set_correlation_id,
)
from .settings import RuntimeEnvironment, SuiteSettings, load_settings

__all__ = [
    "ErrorCode",
    "RuntimeEnvironment",
    "SuiteError",
    "SuiteSettings",
    "configure_structured_logging",
    "get_correlation_id",
    "get_structured_logger",
    "load_settings",
    "set_correlation_id",
]
