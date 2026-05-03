import unittest

from cryptography_suite import hybrid_decrypt, hybrid_encrypt
from cryptography_suite.asymmetric import generate_rsa_keypair, generate_x25519_keypair
from cryptography_suite.errors import CryptographySuiteError
from cryptography_suite.hybrid import EncryptedHybridMessage
from cryptography_suite.pqc import (
    PQCRYPTO_AVAILABLE,
    generate_ml_kem_keypair,
    ml_kem_decrypt,
    ml_kem_encrypt,
)


class TestHybrid(unittest.TestCase):
    def test_hybrid_rsa_roundtrip(self):
        priv, pub = generate_rsa_keypair()
        msg = b"hybrid"
        data = hybrid_encrypt(msg, pub)
        self.assertIsInstance(data, EncryptedHybridMessage)
        pt = hybrid_decrypt(priv, data)
        self.assertEqual(pt, msg)

    def test_hybrid_ecies_roundtrip(self):
        priv, pub = generate_x25519_keypair()
        msg = b"ecies"
        data = hybrid_encrypt(msg, pub)
        self.assertIsInstance(data, EncryptedHybridMessage)
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
        ct = data.ciphertext
        data = EncryptedHybridMessage(
            encrypted_key=data.encrypted_key,
            nonce=data.nonce,
            ciphertext=ct[:-1] + bytes([ct[-1] ^ 1]),
            tag=data.tag,
        )
        with self.assertRaises(CryptographySuiteError):
            hybrid_decrypt(priv, data)

    @unittest.skipUnless(PQCRYPTO_AVAILABLE, "pqcrypto not installed")
    def test_kyber_aes_gcm_roundtrip(self):
        msg = b"kyber hybrid"
        for lvl in (512, 768, 1024):
            pk, sk = generate_ml_kem_keypair(level=lvl)
            envelope = ml_kem_encrypt(pk, msg, level=lvl)
            self.assertIsInstance(envelope, str)
            self.assertNotIsInstance(envelope, tuple)
            self.assertEqual(ml_kem_decrypt(sk, envelope, level=lvl), msg)


if __name__ == "__main__":
    unittest.main()
