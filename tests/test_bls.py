import unittest
from cryptography_suite.bls import (
    generate_bls_keypair,
    bls_sign,
    bls_verify,
    bls_aggregate,
    bls_aggregate_verify,
)


class TestBLS(unittest.TestCase):
    def setUp(self):
        self.message1 = b"Hello BLS"
        self.message2 = b"Another message"

    def test_sign_and_verify(self):
        sk, pk = generate_bls_keypair()
        signature = bls_sign(self.message1, sk)
        self.assertTrue(bls_verify(self.message1, signature, pk))

    def test_sign_with_empty_message(self):
        sk, _ = generate_bls_keypair()
        with self.assertRaises(ValueError):
            bls_sign(b"", sk)

    def test_verify_with_invalid_public_key_type(self):
        sk, _ = generate_bls_keypair()
        sig = bls_sign(self.message1, sk)
        with self.assertRaises(TypeError):
            bls_verify(self.message1, sig, "not_bytes")

    def test_aggregate_and_verify(self):
        sk1, pk1 = generate_bls_keypair()
        sk2, pk2 = generate_bls_keypair()
        sig1 = bls_sign(self.message1, sk1)
        sig2 = bls_sign(self.message2, sk2)
        agg_sig = bls_aggregate([sig1, sig2])
        self.assertTrue(
            bls_aggregate_verify([pk1, pk2], [self.message1, self.message2], agg_sig)
        )

    def test_aggregate_verify_mismatched_lengths(self):
        sk, pk = generate_bls_keypair()
        sig = bls_sign(self.message1, sk)
        agg = bls_aggregate([sig])
        with self.assertRaises(ValueError):
            bls_aggregate_verify([pk, pk], [self.message1], agg)

    def test_known_vector(self):
        """Verify implementation against a deterministic test vector."""
        seed = b"\x11" * 32
        expected_sk = 23657700540186605117143072292512185602964840914375503215744843051745997498405
        expected_pk = bytes.fromhex(
            "8e5a712e4cb2c51893c27ae19afb3455f3efcc66030dc25e13eb1afc2edf3973"
            "17a0bb2d28a55513a32d7dcc404be3ba"
        )
        expected_sig = bytes.fromhex(
            "a008c7df216b75c7497dbde10d2188fb6b943f999b654df82a064c10723b9249"
            "93d9d4933c4670e7e2e536ddc87b9a7a0e0f8ecf5faedbeda5ee2ea7bee4065f"
            "4aefed8f4d665569ec636b04f36ff6fd853f66283d413843761acbda652fd43d"
        )

        sk, pk = generate_bls_keypair(seed)
        self.assertEqual(sk, expected_sk)
        self.assertEqual(pk, expected_pk)

        sig = bls_sign(b"hello world", sk)
        self.assertEqual(sig, expected_sig)
        self.assertTrue(bls_verify(b"hello world", sig, pk))


if __name__ == "__main__":
    unittest.main()
