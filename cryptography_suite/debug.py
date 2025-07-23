import os

"""Verbose debugging utilities for cryptography-suite.

WARNING: Never enable in production environments.
"""

VERBOSE_MODE = os.getenv("VERBOSE_MODE", "").lower() not in {"", "0", "false"}


def verbose_print(message: str) -> None:
    """Print *message* when :data:`VERBOSE_MODE` is enabled."""
    if VERBOSE_MODE:
        print(message)


__all__ = ["VERBOSE_MODE", "verbose_print"]
