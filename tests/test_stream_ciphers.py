import os
import unittest

from cryptography_suite.symmetric.stream import (
    salsa20_encrypt,
    salsa20_decrypt,
    chacha20_stream_encrypt,
    chacha20_stream_decrypt,
)
from cryptography_suite.errors import EncryptionError, DecryptionError


class TestStreamCiphers(unittest.TestCase):
    def test_salsa20_encrypt_decrypt(self):
        key = os.urandom(32)
        nonce = os.urandom(8)
        msg = b"secret"
        ct = salsa20_encrypt(msg, key, nonce)
        pt = salsa20_decrypt(ct, key, nonce)
        self.assertEqual(pt, msg)

    def test_salsa20_deterministic(self):
        key = os.urandom(32)
        nonce = os.urandom(8)
        msg = b"msg"
        ct1 = salsa20_encrypt(msg, key, nonce)
        ct2 = salsa20_encrypt(msg, key, nonce)
        self.assertEqual(ct1, ct2)

    def test_salsa20_invalid_lengths(self):
        with self.assertRaises(EncryptionError):
            salsa20_encrypt(b"x", b"short", b"12345678")
        with self.assertRaises(EncryptionError):
            salsa20_encrypt(b"x", os.urandom(32), b"short")
        with self.assertRaises(DecryptionError):
            salsa20_decrypt(b"", os.urandom(32), os.urandom(8))

    def test_chacha20_encrypt_decrypt(self):
        key = os.urandom(32)
        nonce = os.urandom(8)
        msg = b"hello"
        ct = chacha20_stream_encrypt(msg, key, nonce)
        pt = chacha20_stream_decrypt(ct, key, nonce)
        self.assertEqual(pt, msg)

    def test_chacha20_invalid_nonce_length(self):
        key = os.urandom(32)
        with self.assertRaises(EncryptionError):
            chacha20_stream_encrypt(b"x", key, b"123")
        with self.assertRaises(DecryptionError):
            chacha20_stream_decrypt(b"x", key, b"123")


if __name__ == "__main__":
    unittest.main()
