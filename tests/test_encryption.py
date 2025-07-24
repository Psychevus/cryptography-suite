import base64
import os
import unittest
from unittest.mock import patch

from cryptography_suite.symmetric import (
    aes_encrypt,
    aes_decrypt,
    chacha20_encrypt,
    chacha20_decrypt,
    derive_key_argon2,
    encrypt_file,
    decrypt_file,
)
from cryptography_suite.errors import (
    CryptographySuiteError,
    EncryptionError,
    DecryptionError,
    KeyDerivationError,
)


class TestEncryption(unittest.TestCase):
    def setUp(self):
        self.message = "Confidential Message"
        self.password = "StrongPassword123!"
        self.empty_message = ""

    def test_aes_encrypt_decrypt_scrypt(self):
        """Test AES encryption and decryption with Scrypt KDF."""
        encrypted = aes_encrypt(self.message, self.password, kdf="scrypt")
        decrypted = aes_decrypt(encrypted, self.password, kdf="scrypt")
        self.assertEqual(self.message, decrypted)

    def test_aes_encrypt_decrypt_pbkdf2(self):
        """Test AES encryption and decryption with PBKDF2 KDF."""
        encrypted = aes_encrypt(self.message, self.password, kdf="pbkdf2")
        decrypted = aes_decrypt(encrypted, self.password, kdf="pbkdf2")
        self.assertEqual(self.message, decrypted)

    def test_aes_encrypt_decrypt_argon2(self):
        """Test AES encryption and decryption with Argon2id KDF."""
        encrypted = aes_encrypt(self.message, self.password, kdf="argon2")
        decrypted = aes_decrypt(encrypted, self.password, kdf="argon2")
        self.assertEqual(self.message, decrypted)

    def test_derive_key_argon2(self):
        """Test Argon2id key derivation is deterministic and correct length."""
        salt = os.urandom(16)
        key1 = derive_key_argon2(self.password, salt)
        key2 = derive_key_argon2(self.password, salt)
        self.assertEqual(key1, key2)
        self.assertEqual(len(key1), 32)

    def test_derive_key_argon2_different_salt(self):
        """Different salts should produce different Argon2id keys."""
        salt1 = os.urandom(16)
        salt2 = os.urandom(16)
        key1 = derive_key_argon2(self.password, salt1)
        key2 = derive_key_argon2(self.password, salt2)
        self.assertNotEqual(key1, key2)

    def test_aes_decrypt_with_wrong_password(self):
        """Test AES decryption with incorrect password."""
        encrypted = aes_encrypt(self.message, self.password)
        with self.assertRaises(CryptographySuiteError):
            aes_decrypt(encrypted, "WrongPassword")

    def test_aes_encrypt_with_empty_message(self):
        """Test AES encryption with empty message."""
        with self.assertRaises(CryptographySuiteError):
            aes_encrypt(self.empty_message, self.password)

    def test_chacha20_encrypt_decrypt(self):
        """Test ChaCha20 encryption and decryption."""
        encrypted = chacha20_encrypt(self.message, self.password)
        decrypted = chacha20_decrypt(encrypted, self.password)
        self.assertEqual(self.message, decrypted)

    def test_chacha20_decrypt_with_wrong_password(self):
        """Test ChaCha20 decryption with incorrect password."""
        encrypted = chacha20_encrypt(self.message, self.password)
        with self.assertRaises(CryptographySuiteError):
            chacha20_decrypt(encrypted, "WrongPassword")

    def test_encrypt_file_and_decrypt_file(self):
        """Test file encryption and decryption."""
        test_filename = "test_file.txt"
        encrypted_filename = "test_file.enc"
        decrypted_filename = "test_file_decrypted.txt"

        with open(test_filename, "w") as f:
            f.write(self.message)

        encrypt_file(test_filename, encrypted_filename, self.password)
        decrypt_file(encrypted_filename, decrypted_filename, self.password)

        with open(decrypted_filename, "r") as f:
            decrypted_content = f.read()

        self.assertEqual(self.message, decrypted_content)

        # Clean up
        os.remove(test_filename)
        os.remove(encrypted_filename)
        os.remove(decrypted_filename)

    def test_encrypt_file_with_wrong_password(self):
        """Test file decryption with incorrect password."""
        test_filename = "test_file.txt"
        encrypted_filename = "test_file.enc"

        with open(test_filename, "w") as f:
            f.write(self.message)

        encrypt_file(test_filename, encrypted_filename, self.password)

        with self.assertRaises(CryptographySuiteError) as context:
            decrypt_file(
                encrypted_filename,
                "should_not_exist.txt",
                "WrongPassword",
            )

        self.assertIn(
            "Invalid password or corrupted file",
            str(context.exception),
        )

        # Clean up
        os.remove(test_filename)
        os.remove(encrypted_filename)

    def test_aes_decrypt_invalid_data(self):
        """Test AES decryption with invalid encrypted data."""
        with self.assertRaises(CryptographySuiteError):
            aes_decrypt("invalid_data", self.password)

    def test_chacha20_decrypt_invalid_data(self):
        """Test ChaCha20 decryption with invalid encrypted data."""
        with self.assertRaises(CryptographySuiteError):
            chacha20_decrypt("invalid_data", self.password)

    def test_encrypt_file_nonexistent_input(self):
        """Test encrypting a nonexistent input file."""
        with self.assertRaises(IOError):
            encrypt_file("nonexistent.txt", "output.enc", self.password)

    def test_decrypt_file_nonexistent_input(self):
        """Test decrypting a nonexistent input file."""
        with self.assertRaises(IOError):
            decrypt_file("nonexistent.enc", "output.txt", self.password)

    def test_aes_encrypt_with_empty_data(self):
        """Test AES encryption with empty data."""
        with self.assertRaises(CryptographySuiteError):
            aes_encrypt("", self.password)

    def test_aes_encrypt_with_empty_password(self):
        """Test AES encryption with empty password."""
        with self.assertRaises(CryptographySuiteError):
            aes_encrypt(self.message, "")

    def test_aes_decrypt_with_empty_data(self):
        """Test AES decryption with empty data."""
        with self.assertRaises(CryptographySuiteError):
            aes_decrypt("", self.password)

    def test_chacha20_encrypt_with_empty_data(self):
        """Test ChaCha20 encryption with empty data."""
        with self.assertRaises(CryptographySuiteError):
            chacha20_encrypt("", self.password)

    def test_chacha20_encrypt_with_empty_password(self):
        """Test ChaCha20 encryption with empty password."""
        with self.assertRaises(CryptographySuiteError):
            chacha20_encrypt(self.message, "")

    def test_chacha20_decrypt_with_empty_data(self):
        """Test ChaCha20 decryption with empty data."""
        with self.assertRaises(CryptographySuiteError):
            chacha20_decrypt("", self.password)

    def test_chacha20_decrypt_with_invalid_data(self):
        """Test ChaCha20 decryption with invalid data."""
        with self.assertRaises(CryptographySuiteError):
            chacha20_decrypt("invalid_data", self.password)

    def test_encrypt_file_with_invalid_kdf(self):
        """Test encrypting file with an unsupported KDF."""
        test_filename = "test_file.txt"
        with open(test_filename, "w") as f:
            f.write(self.message)

        with self.assertRaises(CryptographySuiteError):
            encrypt_file(
                test_filename,
                "output.enc",
                self.password,
                kdf="invalid_kdf",
            )

        os.remove(test_filename)

    def test_decrypt_file_with_empty_password(self):
        """Test decrypting file with empty password."""
        test_filename = "test_file.txt"
        encrypted_filename = "test_file.enc"

        with open(test_filename, "w") as f:
            f.write(self.message)

        encrypt_file(test_filename, encrypted_filename, self.password)

        with self.assertRaises(CryptographySuiteError):
            decrypt_file(encrypted_filename, "output.txt", "")

        os.remove(test_filename)
        os.remove(encrypted_filename)

    def test_aes_encrypt_with_invalid_kdf(self):
        """Test AES encryption with an unsupported KDF."""
        with self.assertRaises(CryptographySuiteError):
            aes_encrypt(
                self.message,
                self.password,
                kdf="invalid_kdf",
            )

    def test_aes_encrypt_with_unsupported_kdf(self):
        """Test AES encryption with an unsupported KDF."""
        with self.assertRaises(CryptographySuiteError):
            aes_encrypt(
                self.message,
                self.password,
                kdf="unsupported_kdf",
            )

    def test_aes_decrypt_with_empty_encrypted_data(self):
        """Test AES decryption with empty encrypted data."""
        with self.assertRaises(CryptographySuiteError) as context:
            aes_decrypt("", self.password)
        self.assertEqual(
            str(context.exception),
            "Encrypted data cannot be empty.",
        )

    def test_aes_decrypt_with_empty_password(self):
        """Test AES decryption with empty password."""
        encrypted = aes_encrypt(self.message, self.password)
        with self.assertRaises(CryptographySuiteError) as context:
            aes_decrypt(encrypted, "")
        self.assertEqual(str(context.exception), "Password cannot be empty.")

    def test_aes_decrypt_with_invalid_encrypted_data(self):
        """Test AES decryption with invalid encrypted data length."""
        invalid_data = base64.b64encode(b"short").decode()
        with self.assertRaises(CryptographySuiteError) as context:
            aes_decrypt(invalid_data, self.password)
        self.assertEqual(str(context.exception), "Invalid encrypted data.")

    def test_aes_encrypt_with_empty_plaintext(self):
        """Test AES encryption with empty plaintext."""
        with self.assertRaises(CryptographySuiteError) as context:
            aes_encrypt("", self.password)
        self.assertEqual(str(context.exception), "Plaintext cannot be empty.")

    def test_chacha20_encrypt_with_empty_plaintext(self):
        """Test ChaCha20 encryption with empty plaintext."""
        with self.assertRaises(CryptographySuiteError) as context:
            chacha20_encrypt("", self.password)
        self.assertEqual(str(context.exception), "Plaintext cannot be empty.")

    def test_aes_decrypt_with_invalid_encrypted_data_length(self):
        """Test AES decryption with invalid encrypted data length."""
        invalid_data = base64.b64encode(b"short").decode()
        with self.assertRaises(CryptographySuiteError) as context:
            aes_decrypt(invalid_data, self.password)
        self.assertEqual(str(context.exception), "Invalid encrypted data.")

    def test_encrypt_file_with_empty_password(self):
        """Test encrypting a file with empty password."""
        test_filename = "test_file.txt"
        with open(test_filename, "w") as f:
            f.write(self.message)
        with self.assertRaises(CryptographySuiteError) as context:
            encrypt_file(test_filename, "output.enc", "")
        self.assertEqual(
            str(context.exception),
            "Password cannot be empty.",
        )
        os.remove(test_filename)

    def test_encrypt_file_with_unsupported_kdf(self):
        """Test encrypting a file with unsupported KDF."""
        test_filename = "test_file.txt"
        with open(test_filename, "w") as f:
            f.write(self.message)
        with self.assertRaises(CryptographySuiteError) as context:
            encrypt_file(
                test_filename,
                "output.enc",
                self.password,
                kdf="unsupported_kdf",
            )
        self.assertEqual(
            str(context.exception),
            "Unsupported KDF specified.",
        )
        os.remove(test_filename)

    def test_decrypt_file_with_unsupported_kdf(self):
        """Test decrypting a file with unsupported KDF."""
        test_filename = "test_file.txt"
        encrypted_filename = "output.enc"
        with open(test_filename, "w") as f:
            f.write(self.message)
        encrypt_file(test_filename, encrypted_filename, self.password)
        with self.assertRaises(CryptographySuiteError) as context:
            decrypt_file(
                encrypted_filename,
                "output_decrypted.txt",
                self.password,
                kdf="unsupported_kdf",
            )
        self.assertEqual(
            str(context.exception),
            "Unsupported KDF specified.",
        )
        os.remove(test_filename)
        os.remove(encrypted_filename)

    def test_encrypt_file_io_error(self):
        """Test encrypt_file handling of I/O error."""
        with patch("builtins.open", side_effect=IOError("File not found")):
            with self.assertRaises(IOError) as context:
                encrypt_file(
                    "nonexistent.txt",
                    "output.enc",
                    self.password,
                )
            self.assertIn(
                "File encryption failed",
                str(context.exception),
            )

    def test_decrypt_file_io_error(self):
        """Test decrypt_file handling of I/O error."""
        with patch("builtins.open", side_effect=IOError("File not found")):
            with self.assertRaises(IOError) as context:
                decrypt_file(
                    "nonexistent.enc",
                    "output.txt",
                    self.password,
                )
            self.assertIn(
                "Failed to read encrypted file",
                str(context.exception),
            )

    def test_encrypt_decrypt_empty_file(self):
        """Encrypt and decrypt an empty file."""
        test_filename = "empty.txt"
        encrypted_filename = "empty.enc"
        decrypted_filename = "empty.dec"

        open(test_filename, "wb").close()

        encrypt_file(test_filename, encrypted_filename, self.password)
        decrypt_file(encrypted_filename, decrypted_filename, self.password)

        with open(decrypted_filename, "rb") as f:
            self.assertEqual(b"", f.read())

        os.remove(test_filename)
        os.remove(encrypted_filename)
        os.remove(decrypted_filename)

    def test_encrypt_decrypt_large_file(self):
        """Encrypt and decrypt a large file (~5MB)."""
        test_filename = "large.txt"
        encrypted_filename = "large.enc"
        decrypted_filename = "large.dec"

        data = b"A" * (5 * 1024 * 1024)
        with open(test_filename, "wb") as f:
            f.write(data)

        encrypt_file(test_filename, encrypted_filename, self.password)
        decrypt_file(encrypted_filename, decrypted_filename, self.password)

        with open(decrypted_filename, "rb") as f:
            self.assertEqual(data, f.read())

        os.remove(test_filename)
        os.remove(encrypted_filename)
        os.remove(decrypted_filename)



    def test_aes_decrypt_with_unsupported_kdf(self):
        encrypted = aes_encrypt(self.message, self.password)
        with self.assertRaises(CryptographySuiteError):
            aes_decrypt(encrypted, self.password, kdf="unsupported")
