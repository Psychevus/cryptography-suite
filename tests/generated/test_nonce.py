import sys
from pathlib import Path

import pytest
from hypothesis import given, strategies as st, settings

# Ensure src directory is importable
ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from crypto_suite.nonce import NonceManager  # noqa: E402


@settings(max_examples=64, deadline=None)
@given(start=st.integers(max_value=-1))
def test_init_start_must_be_non_negative(start: int) -> None:
    with pytest.raises(ValueError):
        NonceManager(start=start)


@settings(max_examples=64, deadline=None)
@given(start=st.integers(min_value=0, max_value=2**16), delta=st.integers(min_value=0))
def test_init_limit_must_exceed_start(start: int, delta: int) -> None:
    limit = start - delta
    with pytest.raises(ValueError):
        NonceManager(start=start, limit=limit)


@settings(max_examples=64, deadline=None)
@given(nonce=st.binary().filter(lambda b: len(b) != 12))
def test_remember_rejects_wrong_length(nonce: bytes) -> None:
    manager = NonceManager()
    with pytest.raises(ValueError):
        manager.remember(nonce)
