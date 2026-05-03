import importlib
import os
import shutil
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa

import cryptography_suite.config as config
from cryptography_suite.asymmetric import generate_rsa_keypair
from cryptography_suite.errors import SecurityError
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

    def test_save_unencrypted_requires_explicit_unsafe(self):
        priv, _ = generate_rsa_keypair()
        with self.assertRaises(SecurityError):
            self.km.save_private_key(priv, self.filepath)

    def test_save_and_load_unencrypted_unsafe(self):
        priv, _ = generate_rsa_keypair()
        self.km.save_private_key(
            priv,
            self.filepath,
            allow_unencrypted=True,
        )
        loaded = self.km.load_private_key(self.filepath)
        self.assertIsInstance(loaded, rsa.RSAPrivateKey)

    def test_save_and_load_encrypted(self):
        priv, _ = generate_rsa_keypair()
        self.km.save_private_key(priv, self.filepath, self.password)
        loaded = self.km.load_private_key(self.filepath, self.password)
        self.assertIsInstance(loaded, rsa.RSAPrivateKey)

    def test_save_private_key_does_not_overwrite_existing_file(self):
        priv, _ = generate_rsa_keypair()
        self.km.save_private_key(priv, self.filepath, self.password)
        original = Path(self.filepath).read_bytes()

        with self.assertRaises(OSError):
            self.km.save_private_key(priv, self.filepath, self.password)

        self.assertEqual(Path(self.filepath).read_bytes(), original)

    def test_warning_on_unencrypted_save(self):
        priv, _ = generate_rsa_keypair()
        with self.assertLogs(
            "cryptography_suite.protocols.key_management", level="WARNING"
        ) as cm:
            self.km.save_private_key(
                priv,
                self.filepath,
                allow_unencrypted=True,
            )
        self.assertIn("Saving private key unencrypted", "\n".join(cm.output))

    def test_strict_env_var_blocks_unencrypted_save(self):
        priv, _ = generate_rsa_keypair()
        os.environ["CRYPTOSUITE_STRICT_KEYS"] = "error"
        importlib.reload(config)
        try:
            with self.assertRaises(SecurityError):
                self.km.save_private_key(
                    priv,
                    self.filepath,
                    allow_unencrypted=True,
                )
        finally:
            os.environ.pop("CRYPTOSUITE_STRICT_KEYS", None)
            importlib.reload(config)

    def test_rotate_keys(self):
        self.km.rotate_keys(self.key_dir, self.password)
        self.assertTrue(os.path.exists(os.path.join(self.key_dir, "private_key.pem")))
        self.assertTrue(os.path.exists(os.path.join(self.key_dir, "public_key.pem")))
        loaded = self.km.load_private_key(
            os.path.join(self.key_dir, "private_key.pem"),
            self.password,
        )
        self.assertIsInstance(loaded, rsa.RSAPrivateKey)

    def test_rotate_keys_requires_password(self):
        with self.assertRaises(SecurityError):
            self.km.rotate_keys(self.key_dir)


if __name__ == "__main__":  # pragma: no cover - manual execution
    unittest.main()
