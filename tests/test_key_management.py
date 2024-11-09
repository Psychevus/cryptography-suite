import unittest
import os
import platform
from key_management import (
    generate_aes_key,
    rotate_aes_key,
    generate_rsa_key_pair,
    serialize_private_key,
    serialize_public_key,
    secure_save_key_to_file,
    load_private_key_from_file,
    load_public_key_from_file,
    key_exists
)
from cryptography.hazmat.primitives.asymmetric import rsa


class TestKeyManagement(unittest.TestCase):
    def setUp(self):
        self.password = "secure_password"
        self.private_key, self.public_key = generate_rsa_key_pair()
        self.private_key_path = "temp_private_key.pem"
        self.public_key_path = "temp_public_key.pem"

    def tearDown(self):
        if os.path.exists(self.private_key_path):
            os.remove(self.private_key_path)
        if os.path.exists(self.public_key_path):
            os.remove(self.public_key_path)

    def test_secure_save_key_to_file_and_load_private_key(self):
        pem = serialize_private_key(self.private_key, self.password)
        secure_save_key_to_file(pem, self.private_key_path)

        self.assertTrue(os.path.exists(self.private_key_path))

        if platform.system() != "Windows":
            # Check Unix-like permissions
            self.assertEqual(oct(os.stat(self.private_key_path).st_mode)[-3:], "600")

        loaded_private_key = load_private_key_from_file(self.private_key_path, self.password)
        self.assertIsInstance(loaded_private_key, rsa.RSAPrivateKey)

    def test_secure_save_key_to_file_and_load_public_key(self):
        pem = serialize_public_key(self.public_key)
        secure_save_key_to_file(pem, self.public_key_path)

        self.assertTrue(os.path.exists(self.public_key_path))

        if platform.system() != "Windows":
            # Check Unix-like permissions
            self.assertEqual(oct(os.stat(self.public_key_path).st_mode)[-3:], "600")

        loaded_public_key = load_public_key_from_file(self.public_key_path)
        self.assertIsInstance(loaded_public_key, rsa.RSAPublicKey)

    def test_generate_aes_key_boundary(self):
        # Test AES key generation with expected length
        key = generate_aes_key()
        self.assertEqual(len(key), 44)  # 32 bytes in base64 is typically 44 chars

    def test_serialize_private_key_invalid_password(self):
        # Serialize the private key with a valid password but attempt to load with an incorrect password
        pem = serialize_private_key(self.private_key, self.password)
        secure_save_key_to_file(pem, self.private_key_path)
        with self.assertRaises(ValueError):
            load_private_key_from_file(self.private_key_path, "incorrect_password")

    def test_key_exists_on_invalid_path(self):
        # Test that key_exists returns False for a nonexistent file path
        self.assertFalse(key_exists("nonexistent_path.pem"))

    def test_load_private_key_with_invalid_path(self):
        # Attempt to load a private key from a nonexistent file
        with self.assertRaises(FileNotFoundError):
            load_private_key_from_file("nonexistent_file.pem", self.password)

    def test_load_public_key_with_invalid_path(self):
        # Attempt to load a public key from a nonexistent file
        with self.assertRaises(FileNotFoundError):
            load_public_key_from_file("nonexistent_file.pem")

    def test_load_public_key_invalid_format(self):
        # Write invalid PEM data to a file and attempt to load it
        with open(self.public_key_path, "wb") as f:
            f.write(b"INVALID PUBLIC KEY DATA")
        with self.assertRaises(ValueError):
            load_public_key_from_file(self.public_key_path)

    def test_secure_save_key_to_invalid_path(self):
        # Try saving to an invalid path and catch expected error
        with self.assertRaises(FileNotFoundError):
            secure_save_key_to_file(b"data", "/invalid_path/key.pem")

    def test_load_private_key_invalid_path(self):
        # Attempt to load private key from nonexistent file
        with self.assertRaises(FileNotFoundError):
            load_private_key_from_file("nonexistent_file.pem", self.password)

    def test_load_private_key_malformed_data(self):
        with open(self.private_key_path, "wb") as f:
            f.write(b"INVALID PRIVATE KEY DATA")
        with self.assertRaises(ValueError):
            load_private_key_from_file(self.private_key_path, self.password)

    def test_secure_save_key_to_invalid_directory(self):
        # Try saving to an invalid directory path
        with self.assertRaises(FileNotFoundError):
            secure_save_key_to_file(b"data", "/nonexistent_dir/key.pem")

    def test_load_public_key_from_nonexistent_file(self):
        # Try to load a public key from a nonexistent file
        with self.assertRaises(FileNotFoundError):
            load_public_key_from_file("nonexistent_public_key.pem")

    def test_load_private_key_invalid_data(self):
        # Write invalid PEM data to a file and attempt to load it
        with open(self.private_key_path, "wb") as f:
            f.write(b"INVALID PRIVATE KEY DATA")
        with self.assertRaises(ValueError):
            load_private_key_from_file(self.private_key_path, self.password)

    def test_save_key_to_invalid_directory(self):
        # Try saving a key to an invalid directory and check for an error
        with self.assertRaises(FileNotFoundError):
            secure_save_key_to_file(b"data", "/invalid_directory/key.pem")

    def test_load_public_key_nonexistent_file(self):
        # Attempt to load a public key from a nonexistent file
        with self.assertRaises(FileNotFoundError):
            load_public_key_from_file("nonexistent_public_key.pem")



    def test_save_key_invalid_directory(self):
        with self.assertRaises(FileNotFoundError):
            secure_save_key_to_file(b"data", "/invalid_dir/key.pem")

    def test_load_private_key_wrong_password(self):
        pem = serialize_private_key(self.private_key, self.password)
        secure_save_key_to_file(pem, self.private_key_path)
        with self.assertRaises(ValueError):
            load_private_key_from_file(self.private_key_path, "wrong_password")


if __name__ == "__main__":
    unittest.main()
