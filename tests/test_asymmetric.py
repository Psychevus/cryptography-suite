import unittest
from asymmetric import (
    generate_rsa_keys,
    rsa_encrypt,
    rsa_decrypt,
    serialize_private_key,
    serialize_public_key,
    load_private_key,
    load_public_key
)
from cryptography.hazmat.primitives.asymmetric import rsa


class TestAsymmetric(unittest.TestCase):
    def setUp(self):
        self.private_key, self.public_key = generate_rsa_keys()
        self.password = "strong_password"

    def test_rsa_encrypt_decrypt(self):
        message = "Secure Message"
        encrypted = rsa_encrypt(message, self.public_key)
        decrypted = rsa_decrypt(encrypted, self.private_key)
        self.assertEqual(message, decrypted)

    def test_rsa_encrypt_invalid_key(self):
        # Expect TypeError when invalid key is passed
        with self.assertRaises(TypeError):
            rsa_encrypt("Test message", "not_a_public_key")

    def test_rsa_decrypt_invalid_key(self):
        # Encrypt a message with a valid key first
        encrypted = rsa_encrypt("Test message", self.public_key)
        # Expect TypeError when an invalid private key is used for decryption
        with self.assertRaises(TypeError):
            rsa_decrypt(encrypted, "not_a_private_key")

    def test_serialize_private_key(self):
        pem = serialize_private_key(self.private_key, self.password)
        self.assertTrue(pem.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"))
        loaded_private_key = load_private_key(pem, self.password)
        self.assertIsInstance(loaded_private_key, rsa.RSAPrivateKey)

    def test_serialize_public_key(self):
        pem = serialize_public_key(self.public_key)
        self.assertTrue(pem.startswith(b"-----BEGIN PUBLIC KEY-----"))
        loaded_public_key = load_public_key(pem)
        self.assertIsInstance(loaded_public_key, rsa.RSAPublicKey)

    def test_load_private_key_invalid_password(self):
        pem = serialize_private_key(self.private_key, self.password)
        with self.assertRaises(ValueError):
            load_private_key(pem, "wrong_password")

    def test_load_private_key_invalid_data(self):
        with self.assertRaises(ValueError):
            load_private_key(b"invalid_pem_data", self.password)

    def test_load_public_key_invalid_data(self):
        with self.assertRaises(ValueError):
            load_public_key(b"invalid_pem_data")

    def test_rsa_encrypt_with_empty_message(self):
        # Encrypting an empty message (should raise an error or handle gracefully)
        with self.assertRaises(ValueError):
            rsa_encrypt("", self.public_key)

    def test_rsa_decrypt_invalid_data(self):
        # Attempt to decrypt data that wasn’t encrypted by RSA
        with self.assertRaises(ValueError):
            rsa_decrypt("invalid_encrypted_data", self.private_key)

    def test_rsa_decrypt_with_corrupt_data(self):
        # Test decryption with invalid encrypted data
        with self.assertRaises(ValueError):
            rsa_decrypt("corrupt_data", self.private_key)

    def test_rsa_decrypt_with_invalid_encrypted_data(self):
        # Attempt to decrypt data that was not encrypted correctly
        with self.assertRaises(ValueError):
            rsa_decrypt("invalid_encrypted_data", self.private_key)

    def test_rsa_decrypt_invalid_data(self):
        # Attempt to decrypt with invalid encrypted data
        with self.assertRaises(ValueError):
            rsa_decrypt("invalid_encrypted_data", self.private_key)


if __name__ == "__main__":
    unittest.main()
