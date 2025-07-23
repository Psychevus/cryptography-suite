import unittest

from cryptography_suite.pqc import (
    PQCRYPTO_AVAILABLE,
    generate_kyber_keypair,
    kyber_encrypt,
    kyber_decrypt,
    generate_dilithium_keypair,
    dilithium_sign,
    dilithium_verify,
)


@unittest.skipUnless(PQCRYPTO_AVAILABLE, "pqcrypto not installed")
class TestPQC(unittest.TestCase):
    def test_kyber_encrypt_decrypt_levels(self):
        msg = b"pqc test"
        for lvl in (512, 768, 1024):
            pk, sk = generate_kyber_keypair(level=lvl)
            ct, ss = kyber_encrypt(pk, msg, level=lvl)
            self.assertIsInstance(ct, str)
            self.assertIsInstance(ss, str)
            self.assertEqual(kyber_decrypt(sk, ct, ss, level=lvl), msg)
            # also validate auto-decapsulation path
            self.assertEqual(kyber_decrypt(sk, ct, level=lvl), msg)

    def test_dilithium_signature(self):
        pk, sk = generate_dilithium_keypair()
        msg = b"sign me"
        sig = dilithium_sign(sk, msg)
        self.assertIsInstance(sig, str)
        self.assertTrue(dilithium_verify(pk, msg, sig))


if __name__ == "__main__":
    unittest.main()
