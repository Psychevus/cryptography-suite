import os
import pytest

from cryptography_suite import bulletproof


pytestmark = pytest.mark.skipif(
    not getattr(bulletproof, "BULLETPROOF_AVAILABLE", False),
    reason="pybulletproofs not installed",
)


def test_bulletproof_roundtrip():
    bulletproof.setup()
    value = 42
    proof, commit, nonce = bulletproof.prove(value)
    assert bulletproof.verify(proof, commit)

