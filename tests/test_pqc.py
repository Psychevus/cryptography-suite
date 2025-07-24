import unittest

from cryptography_suite.pqc import (
    PQCRYPTO_AVAILABLE,
    SPHINCS_AVAILABLE,
    generate_kyber_keypair,
    kyber_encrypt,
    kyber_decrypt,
    generate_dilithium_keypair,
    dilithium_sign,
    dilithium_verify,
    generate_sphincs_keypair,
    sphincs_sign,
    sphincs_verify,
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

    @unittest.skipUnless(SPHINCS_AVAILABLE, "SPHINCS+ not available")
    def test_sphincs_signature(self):
        pk, sk = generate_sphincs_keypair()
        msg = b"sphincs test"
        sig = sphincs_sign(sk, msg)
        self.assertIsInstance(sig, str)
        self.assertTrue(sphincs_verify(pk, msg, sig))

    @unittest.skipUnless(SPHINCS_AVAILABLE, "SPHINCS+ not available")
    def test_sphincs_negative(self):
        pk, sk = generate_sphincs_keypair()
        msg = b"hello"
        sig = sphincs_sign(sk, msg)
        self.assertFalse(sphincs_verify(pk, b"bye", sig))
        pk2, _ = generate_sphincs_keypair()
        self.assertFalse(sphincs_verify(pk2, msg, sig))


if __name__ == "__main__":
    unittest.main()
