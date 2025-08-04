import unittest
import os
import pytest

if not os.getenv("CRYPTOSUITE_ALLOW_EXPERIMENTAL"):
    pytest.skip("experimental features disabled", allow_module_level=True)

from cryptography_suite.experimental import zksnark


@unittest.skipUnless(
    getattr(zksnark, "ZKSNARK_AVAILABLE", False), "PySNARK not installed"
)
class TestZkSnark(unittest.TestCase):
    def test_preimage_proof(self) -> None:
        zksnark.setup()
        preimage = b"hello"
        hash_hex, proof = zksnark.prove(preimage)
        self.assertTrue(zksnark.verify(hash_hex, proof))
