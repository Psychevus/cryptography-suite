import logging
import os

"""Verbose debugging utilities for cryptography-suite.

WARNING: Never enable in production environments.
"""

# Explicit opt-in for verbose logging. This must be combined with a DEBUG
# logging level; otherwise a runtime error is raised.
VERBOSE = os.getenv("CRYPTOSUITE_VERBOSE_MODE") == "1"

_logger = logging.getLogger("cryptography-suite")


def verbose_print(message: str) -> None:
    """Log *message* when :data:`VERBOSE` is enabled."""

    if not VERBOSE:
        return
    if _logger.level > logging.DEBUG:
        raise RuntimeError("Verbose mode requires DEBUG level")
    _logger.debug(message)


__all__ = ["VERBOSE", "verbose_print"]
