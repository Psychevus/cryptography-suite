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


if __name__ == "__main__":
    unittest.main()
