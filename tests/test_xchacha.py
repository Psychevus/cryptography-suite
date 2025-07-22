import os
import unittest

import cryptography.hazmat.primitives.ciphers.aead as aead

from cryptography_suite.symmetric import xchacha_encrypt, xchacha_decrypt
from cryptography_suite.errors import EncryptionError, DecryptionError

if not hasattr(aead, "XChaCha20Poly1305"):
    raise unittest.SkipTest("XChaCha20Poly1305 not available")


class TestXChaCha20(unittest.TestCase):
    def test_encrypt_decrypt(self):
        key = os.urandom(32)
        nonce = os.urandom(24)
        message = b"Top secret"
        enc = xchacha_encrypt(message, key, nonce)
        dec = xchacha_decrypt(enc["ciphertext"], key, enc["nonce"])
        self.assertEqual(dec, message)

    def test_invalid_key_length(self):
        nonce = os.urandom(24)
        with self.assertRaises(EncryptionError):
            xchacha_encrypt(b"msg", b"short", nonce)

    def test_invalid_nonce_length(self):
        key = os.urandom(32)
        with self.assertRaises(EncryptionError):
            xchacha_encrypt(b"msg", key, os.urandom(12))

    def test_decrypt_with_wrong_key(self):
        key = os.urandom(32)
        nonce = os.urandom(24)
        message = b"Secret"
        enc = xchacha_encrypt(message, key, nonce)
        with self.assertRaises(DecryptionError):
            xchacha_decrypt(enc["ciphertext"], os.urandom(32), nonce)


if __name__ == "__main__":
    unittest.main()
