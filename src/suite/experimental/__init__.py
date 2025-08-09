"""Experimental cryptographic primitives for :mod:`suite`.

Importing this package emits a loud warning to discourage production use.
"""

from suite.utils.warnings import experimental_warning

experimental_warning("suite.experimental")

try:  # re-export existing experimental modules if available
    from crypto_suite.experimental import *  # type: ignore  # noqa: F401,F403
except Exception:  # pragma: no cover - best effort if crypto_suite unavailable
    pass
