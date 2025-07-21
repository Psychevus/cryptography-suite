import pytest

try:
    from cryptography_suite import zksnark
except Exception:
    zksnark = None

@pytest.mark.skipif(zksnark is None, reason="PySNARK not installed")
def test_zksnark_preimage():
    zksnark.setup()
    preimage = b"hello"
    hash_hex, proof = zksnark.prove(preimage)
    assert zksnark.verify(hash_hex, proof)

