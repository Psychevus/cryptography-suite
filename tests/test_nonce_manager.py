import sys
from pathlib import Path

import pytest
from hypothesis import given, strategies as st
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Ensure src directory is importable
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from crypto_suite.nonce import KeyRotationRequired, NonceManager, NonceReuseError
from crypto_suite.aead import AesGcm


@given(st.integers(min_value=1, max_value=100))
def test_nonce_monotonic(count: int) -> None:
    manager = NonceManager()
    nonces = [int.from_bytes(manager.next(), "big") for _ in range(count)]
    assert nonces == sorted(nonces)


@given(st.binary(min_size=12, max_size=12))
def test_nonce_reuse_detection(nonce: bytes) -> None:
    manager = NonceManager()
    manager.remember(nonce)
    with pytest.raises(NonceReuseError):
        manager.remember(nonce)


@given(st.integers(min_value=1, max_value=10))
def test_nonce_limit_triggers_rotation(limit: int) -> None:
    manager = NonceManager(limit=limit)
    for _ in range(limit):
        manager.next()
    with pytest.raises(KeyRotationRequired):
        manager.next()


def test_aead_byte_limit_rotation() -> None:
    key = AESGCM.generate_key(bit_length=128)
    aes = AesGcm(key, byte_limit=16)
    manager = NonceManager()
    aes.encrypt(b"a" * 8, nonce_manager=manager)
    with pytest.raises(KeyRotationRequired):
        aes.encrypt(b"b" * 9, nonce_manager=manager)
