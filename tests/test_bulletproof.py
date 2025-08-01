import pytest

from cryptography_suite.experimental import bulletproof


pytestmark = pytest.mark.skipif(
    not getattr(bulletproof, "BULLETPROOF_AVAILABLE", False),
    reason="pybulletproofs not installed",
)  # vulture: ignore-used

__all__ = ["pytestmark"]


def test_bulletproof_roundtrip():
    bulletproof.setup()
    value = 42
    proof, commit, nonce = bulletproof.prove(value)
    assert bulletproof.verify(proof, commit)
