import unittest
from encryption import aes_encrypt, aes_decrypt


class TestEncryption(unittest.TestCase):
    def test_aes_encrypt_decrypt(self):
        message = "Top Secret Data"
        password = "strongpassword"
        encrypted = aes_encrypt(message, password)
        decrypted = aes_decrypt(encrypted, password)
        self.assertEqual(message, decrypted)

    def test_aes_encrypt_with_empty_message(self):
        # Attempt to encrypt an empty string, which may raise an error
        password = "strongpassword"
        with self.assertRaises(ValueError):
            aes_encrypt("", password)

    def test_aes_decrypt_invalid_data(self):
        # Attempt to decrypt invalid data with AES
        with self.assertRaises(ValueError):
            aes_decrypt("invalid_encrypted_data", "strongpassword")

    def test_aes_decrypt_with_invalid_base64(self):
        # Decrypt with invalid base64-encoded data
        with self.assertRaises(ValueError):
            aes_decrypt("invalid_base64", "strongpassword")

    def test_aes_decrypt_with_malformed_data(self):
        # Test AES decryption with malformed base64 data
        with self.assertRaises(ValueError):
            aes_decrypt("malformed_base64_data", "password")

    def test_aes_decrypt_with_invalid_base64_data(self):
        # Decrypt with malformed base64 data
        with self.assertRaises(ValueError):
            aes_decrypt("malformed_data", "password")


if __name__ == "__main__":
    unittest.main()
