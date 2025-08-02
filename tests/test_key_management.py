import os
import unittest

from cryptography_suite.errors import CryptographySuiteError

from cryptography.hazmat.primitives.asymmetric import rsa, ec

from cryptography_suite.protocols import (
    generate_aes_key,
    rotate_aes_key,
    generate_random_password,
    secure_save_key_to_file,
    load_private_key_from_file,
    load_public_key_from_file,
    key_exists,
    KeyManager,
)


class TestKeyManagement(unittest.TestCase):
    def setUp(self):
        self.km = KeyManager()
        self.password = "KeyManagementPassword"
        self.private_key_path = "private_key.pem"
        self.public_key_path = "public_key.pem"

    def tearDown(self):
        if os.path.exists(self.private_key_path):
            os.remove(self.private_key_path)
        if os.path.exists(self.public_key_path):
            os.remove(self.public_key_path)

    def test_generate_aes_key(self):
        """Test AES key generation."""
        key = generate_aes_key(sensitive=False)
        self.assertIsInstance(key, bytes)
        self.assertEqual(len(key), 32)

    def test_generate_random_password(self):
        pwd = generate_random_password(24)
        self.assertEqual(len(pwd), 24)
        self.assertTrue(any(c.islower() for c in pwd))
        self.assertTrue(any(c.isupper() for c in pwd))
        self.assertTrue(any(c.isdigit() for c in pwd))

    def test_rotate_aes_key(self):
        """Test AES key rotation."""
        old_key = generate_aes_key(sensitive=False)
        new_key = rotate_aes_key(sensitive=False)
        self.assertNotEqual(old_key, new_key)

    def test_secure_save_and_load_rsa_keys(self):
        """Test generating, saving, and loading RSA keys."""
        self.km.generate_rsa_keypair_and_save(
            self.private_key_path, self.public_key_path, self.password
        )
        self.assertTrue(key_exists(self.private_key_path))
        self.assertTrue(key_exists(self.public_key_path))

        private_key = load_private_key_from_file(self.private_key_path, self.password)
        public_key = load_public_key_from_file(self.public_key_path)

        self.assertIsInstance(private_key, rsa.RSAPrivateKey)
        self.assertIsInstance(public_key, rsa.RSAPublicKey)

    def test_secure_save_and_load_ec_keys(self):
        """Test generating, saving, and loading EC keys."""
        self.km.generate_ec_keypair_and_save(
            self.private_key_path, self.public_key_path, self.password
        )
        self.assertTrue(key_exists(self.private_key_path))
        self.assertTrue(key_exists(self.public_key_path))

        private_key = load_private_key_from_file(self.private_key_path, self.password)
        public_key = load_public_key_from_file(self.public_key_path)

        self.assertIsInstance(private_key, ec.EllipticCurvePrivateKey)
        self.assertIsInstance(public_key, ec.EllipticCurvePublicKey)

    def test_secure_save_key_to_invalid_path(self):
        """Test saving key to an invalid path."""
        with self.assertRaises(IOError):
            secure_save_key_to_file(b"key_data", "/invalid_path/key.pem")

    def test_load_private_key_with_wrong_password(self):
        """Test loading private key with incorrect password."""
        self.km.generate_rsa_keypair_and_save(
            self.private_key_path, self.public_key_path, self.password
        )
        with self.assertRaises(CryptographySuiteError):
            load_private_key_from_file(self.private_key_path, "WrongPassword")

    def test_load_private_key_from_nonexistent_file(self):
        """Test loading private key from a nonexistent file."""
        with self.assertRaises(FileNotFoundError):
            load_private_key_from_file("nonexistent.pem", self.password)

    def test_load_public_key_from_nonexistent_file(self):
        """Test loading public key from a nonexistent file."""
        with self.assertRaises(FileNotFoundError):
            load_public_key_from_file("nonexistent.pem")

    def test_key_exists_function(self):
        """Test key_exists function."""
        self.assertFalse(key_exists(self.private_key_path))
        open(self.private_key_path, "a").close()
        self.assertTrue(key_exists(self.private_key_path))

    def test_generate_ec_keypair_and_save_with_invalid_curve(self):
        """Test generating EC key pair with invalid curve."""
        with self.assertRaises(TypeError):
            self.km.generate_ec_keypair_and_save(
                self.private_key_path,
                self.public_key_path,
                self.password,
                curve="invalid_curve",
            )

    def test_generate_ed25519_and_ed448_keypair_and_save(self):
        """Generate and load EdDSA key pairs using KeyManager."""
        ed_priv = "ed_priv.pem"
        ed_pub = "ed_pub.pem"
        ed448_priv = "ed448_priv.pem"
        ed448_pub = "ed448_pub.pem"

        try:
            self.km.generate_ed25519_keypair_and_save(ed_priv, ed_pub, self.password)
            self.km.generate_ed448_keypair_and_save(ed448_priv, ed448_pub, self.password)

            priv = load_private_key_from_file(ed_priv, self.password)
            pub = load_public_key_from_file(ed_pub)
            self.assertIsNotNone(priv)
            self.assertIsNotNone(pub)

            priv2 = load_private_key_from_file(ed448_priv, self.password)
            pub2 = load_public_key_from_file(ed448_pub)
            self.assertIsNotNone(priv2)
            self.assertIsNotNone(pub2)
        finally:
            for f in (ed_priv, ed_pub, ed448_priv, ed448_pub):
                if os.path.exists(f):
                    os.remove(f)


if __name__ == "__main__":
    unittest.main()
