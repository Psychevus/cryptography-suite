import unittest

from cryptography_suite.post_quantum import (
    generate_kyber_keypair,
    kyber_encapsulate,
    kyber_decapsulate,
    generate_dilithium_keypair,
    dilithium_sign,
    dilithium_verify,
)


class TestPostQuantum(unittest.TestCase):
    def test_kyber_kem(self):
        pk, sk = generate_kyber_keypair()
        ct, ss1 = kyber_encapsulate(pk)
        ss2 = kyber_decapsulate(ct, sk)
        self.assertEqual(ss1, ss2)

    def test_dilithium_signature(self):
        pk, sk = generate_dilithium_keypair()
        message = b"test message"
        sig = dilithium_sign(message, sk)
        self.assertTrue(dilithium_verify(message, sig, pk))


if __name__ == "__main__":
    unittest.main()
