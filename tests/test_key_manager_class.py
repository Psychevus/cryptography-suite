import os
import shutil
import unittest

from cryptography.hazmat.primitives.asymmetric import rsa

from cryptography_suite.asymmetric import generate_rsa_keypair
from cryptography_suite.protocols import KeyManager


class TestKeyManagerClass(unittest.TestCase):
    def setUp(self):
        self.km = KeyManager()
        self.password = "StrongPassword"
        self.filepath = "km_private.pem"
        self.key_dir = "km_keys"
        os.makedirs(self.key_dir, exist_ok=True)

    def tearDown(self):
        if os.path.exists(self.filepath):
            os.remove(self.filepath)
        if os.path.isdir(self.key_dir):
            shutil.rmtree(self.key_dir)

    def test_save_and_load_unencrypted(self):
        priv, _ = generate_rsa_keypair()
        self.km.save_private_key(priv, self.filepath)
        loaded = self.km.load_private_key(self.filepath)
        self.assertIsInstance(loaded, rsa.RSAPrivateKey)

    def test_save_and_load_encrypted(self):
        priv, _ = generate_rsa_keypair()
        self.km.save_private_key(priv, self.filepath, self.password)
        loaded = self.km.load_private_key(self.filepath, self.password)
        self.assertIsInstance(loaded, rsa.RSAPrivateKey)

    def test_rotate_keys(self):
        self.km.rotate_keys(self.key_dir)
        self.assertTrue(os.path.exists(os.path.join(self.key_dir, "private_key.pem")))
        self.assertTrue(os.path.exists(os.path.join(self.key_dir, "public_key.pem")))


if __name__ == "__main__":  # pragma: no cover - manual execution
    unittest.main()
