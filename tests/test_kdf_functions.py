import unittest

from cryptography_suite.symmetric.kdf import derive_hkdf, derive_pbkdf2


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
        out1 = derive_pbkdf2(password, salt, 1000, 32)
        out2 = derive_pbkdf2(password, salt, 1000, 32)
        self.assertEqual(out1, out2)
        self.assertEqual(len(out1), 32)
        out3 = derive_pbkdf2(password, salt, 2000, 32)
        self.assertNotEqual(out1, out3)


if __name__ == "__main__":
    unittest.main()
