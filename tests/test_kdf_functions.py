import unittest

from cryptography_suite.symmetric.kdf import (
    derive_hkdf,
    kdf_pbkdf2,
    ARGON2_AVAILABLE,
)


class TestKdfFunctions(unittest.TestCase):
    def test_derive_hkdf_deterministic(self):
        key = b"secret"
        salt = b"salt"
        info = b"info"
        out1 = derive_hkdf(key, salt, info, 32)
        out2 = derive_hkdf(key, salt, info, 32)
        self.assertEqual(out1, out2)
        self.assertEqual(len(out1), 32)

    def test_derive_hkdf_diff_salt(self):
        key = b"secret"
        info = b"context"
        out1 = derive_hkdf(key, b"a", info, 16)
        out2 = derive_hkdf(key, b"b", info, 16)
        self.assertNotEqual(out1, out2)

    def test_derive_pbkdf2_custom_iterations(self):
        password = "password"
        salt = b"salt"
        out1 = kdf_pbkdf2(password, salt, 1000, 32)
        out2 = kdf_pbkdf2(password, salt, 1000, 32)
        self.assertEqual(out1, out2)
        self.assertEqual(len(out1), 32)
        out3 = kdf_pbkdf2(password, salt, 2000, 32)
        self.assertNotEqual(out1, out3)

    @unittest.skipUnless(ARGON2_AVAILABLE, "Argon2id KDF not available")
    def test_argon2_env_overrides(self):
        import os, importlib

        os.environ["CRYPTOSUITE_ARGON2_MEMORY_COST"] = "32768"
        os.environ["CRYPTOSUITE_ARGON2_TIME_COST"] = "2"

        import cryptography_suite.symmetric.kdf as kdf
        importlib.reload(kdf)

        self.assertEqual(kdf.ARGON2_MEMORY_COST, 32768)
        self.assertEqual(kdf.ARGON2_TIME_COST, 2)
        key = kdf.derive_key_argon2("pw", b"a" * 16)
        self.assertEqual(len(key), 32)

        os.environ.pop("CRYPTOSUITE_ARGON2_MEMORY_COST")
        os.environ.pop("CRYPTOSUITE_ARGON2_TIME_COST")
        importlib.reload(kdf)


if __name__ == "__main__":
    unittest.main()
