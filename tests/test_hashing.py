import unittest

from cryptography_suite.hashing import (
    sha256_hash,
    sha384_hash,
    sha512_hash,
    sha3_256_hash,
    sha3_512_hash,
    blake2b_hash,
    blake3_hash,
    derive_key_scrypt,
    derive_key_pbkdf2,
    verify_derived_key_scrypt,
    verify_derived_key_pbkdf2,
    generate_salt,
)


class TestHashing(unittest.TestCase):
    def setUp(self):
        self.data = "Data to hash"
        self.password = "Password123!"
        self.salt = generate_salt()
        self.empty_data = ""
        self.empty_password = ""

    def test_sha256_hash(self):
        """Test SHA-256 hashing."""
        digest = sha256_hash(self.data)
        self.assertIsInstance(digest, str)
        self.assertEqual(len(digest), 64)  # SHA-256 hash length in hex

    def test_sha384_hash(self):
        """Test SHA-384 hashing."""
        digest = sha384_hash(self.data)
        self.assertIsInstance(digest, str)
        self.assertEqual(len(digest), 96)  # SHA-384 hash length in hex

    def test_sha512_hash(self):
        """Test SHA-512 hashing."""
        digest = sha512_hash(self.data)
        self.assertIsInstance(digest, str)
        self.assertEqual(len(digest), 128)  # SHA-512 hash length in hex

    def test_blake2b_hash(self):
        """Test BLAKE2b hashing."""
        digest = blake2b_hash(self.data)
        self.assertIsInstance(digest, str)
        self.assertEqual(len(digest), 128)  # BLAKE2b default digest size is 64 bytes

    def test_sha3_256_hash_vector(self):
        """Test SHA3-256 against a known vector."""
        digest = sha3_256_hash("The quick brown fox jumps over the lazy dog")
        self.assertEqual(
            digest,
            "69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04",
        )

    def test_sha3_512_hash_vector(self):
        """Test SHA3-512 against a known vector."""
        digest = sha3_512_hash("The quick brown fox jumps over the lazy dog")
        self.assertEqual(
            digest,
            "01dedd5de4ef14642445ba5f5b97c15e47b9ad931326e4b0727cd94cefc44fff"
            "23f07bf543139939b49128caf436dc1bdee54fcb24023a08d9403f9b4bf0d450",
        )

    def test_blake3_hash_vector(self):
        """Test BLAKE3 against a known vector."""
        digest = blake3_hash("The quick brown fox jumps over the lazy dog")
        self.assertEqual(
            digest,
            "2f1514181aadccd913abd94cfa592701a5686ab23f8df1dff1b74710febc6d4a",
        )

    def test_derive_key_scrypt(self):
        """Test key derivation using Scrypt."""
        derived_key = derive_key_scrypt(self.password, self.salt)
        self.assertIsInstance(derived_key, bytes)
        self.assertEqual(len(derived_key), 32)

    def test_derive_key_pbkdf2(self):
        """Test key derivation using PBKDF2."""
        derived_key = derive_key_pbkdf2(self.password, self.salt)
        self.assertIsInstance(derived_key, bytes)
        self.assertEqual(len(derived_key), 32)

    def test_verify_derived_key_scrypt(self):
        """Test verification of derived key using Scrypt."""
        derived_key = derive_key_scrypt(self.password, self.salt)
        self.assertTrue(verify_derived_key_scrypt(self.password, self.salt, derived_key))
        self.assertFalse(verify_derived_key_scrypt("WrongPassword", self.salt, derived_key))

    def test_verify_derived_key_pbkdf2(self):
        """Test verification of derived key using PBKDF2."""
        derived_key = derive_key_pbkdf2(self.password, self.salt)
        self.assertTrue(verify_derived_key_pbkdf2(self.password, self.salt, derived_key))
        self.assertFalse(verify_derived_key_pbkdf2("WrongPassword", self.salt, derived_key))

    def test_derive_key_with_empty_password(self):
        """Test key derivation with empty password."""
        with self.assertRaises(ValueError):
            derive_key_scrypt(self.empty_password, self.salt)

    def test_derive_key_with_invalid_salt(self):
        """Test key derivation with invalid salt."""
        with self.assertRaises(TypeError):
            derive_key_scrypt(self.password, "InvalidSalt")

    def test_verify_derived_key_scrypt_with_invalid_parameters(self):
        """Test verify_derived_key_scrypt with invalid parameters."""
        derived_key = derive_key_scrypt(self.password, self.salt)
        with self.assertRaises(TypeError):
            verify_derived_key_scrypt(None, self.salt, derived_key)
        with self.assertRaises(TypeError):
            verify_derived_key_scrypt(self.password, None, derived_key)
        with self.assertRaises(TypeError):
            verify_derived_key_scrypt(self.password, self.salt, None)

    def test_derive_key_scrypt_with_empty_password(self):
        """Test deriving key with empty password using Scrypt."""
        with self.assertRaises(ValueError) as context:
            derive_key_scrypt('', self.salt)
        self.assertEqual(str(context.exception), "Password cannot be empty.")


if __name__ == "__main__":
    unittest.main()
