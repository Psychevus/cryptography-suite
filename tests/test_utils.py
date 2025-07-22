import unittest
from cryptography_suite.utils import (
    base62_encode,
    base62_decode,
    secure_zero,
    generate_secure_random_string,
    KeyVault,
)


class TestUtils(unittest.TestCase):
    def test_base62_encode_decode(self):
        """Test Base62 encoding and decoding."""
        data = b"Test data for Base62"
        encoded = base62_encode(data)
        decoded = base62_decode(encoded)
        self.assertEqual(data, decoded)

    def test_base62_encode_empty(self):
        """Test Base62 encoding with empty data."""
        encoded = base62_encode(b"")
        self.assertEqual(encoded, "0")

    def test_base62_decode_empty(self):
        """Test Base62 decoding with empty data."""
        decoded = base62_decode("")
        self.assertEqual(decoded, b"")

    def test_secure_zero(self):
        """Test secure_zero function."""
        data = bytearray(b"Sensitive data")
        secure_zero(data)
        self.assertTrue(all(b == 0 for b in data))

    def test_generate_secure_random_string(self):
        """Test generating a secure random string."""
        random_string = generate_secure_random_string(16)
        self.assertIsInstance(random_string, str)
        self.assertTrue(len(random_string) > 0)

    def test_key_vault_context_manager(self):
        """Test KeyVault securely erases key on exit."""
        data = b"secret-key"
        with KeyVault(data) as key:
            self.assertIsInstance(key, bytearray)
            self.assertEqual(bytes(key), data)
        self.assertTrue(all(b == 0 for b in key))


if __name__ == "__main__":
    unittest.main()
