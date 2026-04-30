"""Verbose debugging utilities for cryptography-suite."""

import logging
import os

REDACTED_VALUE = "***REDACTED***"
SENSITIVE_DEBUG_TERMS = (
    "ciphertext",
    "derived key",
    "dh output",
    "dh1:",
    "dh2:",
    "dh3:",
    "dh4:",
    "diffie-hellman output",
    "nonce",
    "passphrase",
    "password",
    "pem",
    "plaintext",
    "private",
    "raw key",
    "seed",
    "secret",
    "shared",
    "signature",
    "token",
)

# Explicit opt-in for verbose logging. This must be combined with a DEBUG
# logging level; otherwise a runtime error is raised.
VERBOSE = os.getenv("CRYPTOSUITE_VERBOSE_MODE") == "1"

_logger = logging.getLogger("cryptography-suite")


def redact_message(message: str) -> str:
    """Return a log-safe version of a debug message."""

    lowered = message.lower()
    if any(term in lowered for term in SENSITIVE_DEBUG_TERMS):
        return f"{REDACTED_VALUE} sensitive debug output redacted"
    return message


def verbose_print(message: str) -> None:
    """Log *message* when :data:`VERBOSE` is enabled."""

    if not VERBOSE:
        return
    if _logger.level > logging.DEBUG:
        raise RuntimeError("Verbose mode requires DEBUG level")
    _logger.debug(redact_message(message))


__all__ = ["REDACTED_VALUE", "VERBOSE", "redact_message", "verbose_print"]
