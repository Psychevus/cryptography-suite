import base64
import unittest

from cryptography_suite import hybrid_decrypt, hybrid_encrypt
from cryptography_suite.pqc import (
    PQCRYPTO_AVAILABLE,
    generate_kyber_keypair,
    kyber_encrypt,
    kyber_decrypt,
)
from cryptography_suite.asymmetric import generate_rsa_keypair, generate_x25519_keypair
from cryptography_suite.errors import CryptographySuiteError


class TestHybrid(unittest.TestCase):
    def test_hybrid_rsa_roundtrip(self):
        priv, pub = generate_rsa_keypair()
        msg = b"hybrid"
        data = hybrid_encrypt(msg, pub)
        self.assertIsInstance(data, dict)
        pt = hybrid_decrypt(priv, data)
        self.assertEqual(pt, msg)

    def test_hybrid_ecies_roundtrip(self):
        priv, pub = generate_x25519_keypair()
        msg = b"ecies"
        data = hybrid_encrypt(msg, pub)
        self.assertIn("encrypted_key", data)
        self.assertEqual(hybrid_decrypt(priv, data), msg)

    def test_hybrid_encrypt_empty_message(self):
        _, pub = generate_rsa_keypair()
        with self.assertRaises(CryptographySuiteError):
            hybrid_encrypt(b"", pub)

    def test_hybrid_decrypt_wrong_key(self):
        priv, pub = generate_rsa_keypair()
        wrong_priv, _ = generate_rsa_keypair()
        data = hybrid_encrypt(b"msg", pub)
        with self.assertRaises(CryptographySuiteError):
            hybrid_decrypt(wrong_priv, data)

    def test_hybrid_decrypt_tampered_ciphertext(self):
        priv, pub = generate_x25519_keypair()
        data = hybrid_encrypt(b"msg", pub)
        ct = base64.b64decode(data["ciphertext"])
        data["ciphertext"] = base64.b64encode(ct[:-1] + bytes([ct[-1] ^ 1])).decode()
        with self.assertRaises(CryptographySuiteError):
            hybrid_decrypt(priv, data)

    @unittest.skipUnless(PQCRYPTO_AVAILABLE, "pqcrypto not installed")
    def test_kyber_aes_gcm_roundtrip(self):
        msg = b"kyber hybrid"
        for lvl in (512, 768, 1024):
            pk, sk = generate_kyber_keypair(level=lvl)
            ct, ss = kyber_encrypt(pk, msg, level=lvl)
            self.assertEqual(kyber_decrypt(sk, ct, ss, level=lvl), msg)
            self.assertEqual(kyber_decrypt(sk, ct, level=lvl), msg)


if __name__ == "__main__":
    unittest.main()
