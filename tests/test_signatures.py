import unittest
from cryptography_suite.asymmetric.signatures import (
    generate_ed25519_keypair,
    generate_ed448_keypair,
    sign_message,
    sign_message_ed448,
    verify_signature,
    verify_signature_ed448,
    serialize_ed25519_private_key,
    serialize_ed25519_public_key,
    load_ed25519_private_key,
    load_ed25519_public_key,
    generate_ecdsa_keypair,
    sign_message_ecdsa,
    verify_signature_ecdsa,
    serialize_ecdsa_private_key,
    serialize_ecdsa_public_key,
    load_ecdsa_private_key,
    load_ecdsa_public_key,
)
from cryptography.hazmat.primitives.asymmetric import ed25519, ed448, ec


class TestSignatures(unittest.TestCase):
    def setUp(self):
        self.message = b"Message to sign"
        self.password = "SecurePassword!"

    def test_ed25519_sign_and_verify(self):
        """Test Ed25519 signature generation and verification."""
        private_key, public_key = generate_ed25519_keypair()
        signature = sign_message(self.message, private_key)
        is_valid = verify_signature(self.message, signature, public_key)
        self.assertTrue(is_valid)

    def test_ed25519_sign_with_empty_message(self):
        """Test Ed25519 signing with empty message."""
        private_key, _ = generate_ed25519_keypair()
        with self.assertRaises(CryptographySuiteError)):
            sign_message(b"", private_key)

    def test_ed25519_verify_with_invalid_signature(self):
        """Test Ed25519 verification with invalid signature."""
        _, public_key = generate_ed25519_keypair()
        invalid_signature = b"invalid_signature"
        is_valid = verify_signature(self.message, invalid_signature, public_key)
        self.assertFalse(is_valid)

    def test_ed25519_serialize_and_load_keys(self):
        """Test serialization and loading of Ed25519 keys."""
        private_key, public_key = generate_ed25519_keypair()
        private_pem = serialize_ed25519_private_key(private_key, self.password)
        public_pem = serialize_ed25519_public_key(public_key)

        loaded_private_key = load_ed25519_private_key(private_pem, self.password)
        loaded_public_key = load_ed25519_public_key(public_pem)

        self.assertIsInstance(loaded_private_key, ed25519.Ed25519PrivateKey)
        self.assertIsInstance(loaded_public_key, ed25519.Ed25519PublicKey)

    def test_ed448_sign_and_verify(self):
        """Test Ed448 signature generation and verification."""
        private_key, public_key = generate_ed448_keypair()
        signature = sign_message_ed448(self.message, private_key)
        is_valid = verify_signature_ed448(self.message, signature, public_key)
        self.assertTrue(is_valid)

    def test_ed448_sign_with_empty_message(self):
        """Test Ed448 signing with empty message."""
        private_key, _ = generate_ed448_keypair()
        with self.assertRaises(CryptographySuiteError)):
            sign_message_ed448(b"", private_key)

    def test_ed448_verify_with_invalid_signature(self):
        """Test Ed448 verification with invalid signature."""
        _, public_key = generate_ed448_keypair()
        invalid_signature = b"invalid_signature"
        self.assertFalse(
            verify_signature_ed448(self.message, invalid_signature, public_key)
        )

    def test_ecdsa_sign_and_verify(self):
        """Test ECDSA signature generation and verification."""
        private_key, public_key = generate_ecdsa_keypair()
        signature = sign_message_ecdsa(self.message, private_key)
        is_valid = verify_signature_ecdsa(self.message, signature, public_key)
        self.assertTrue(is_valid)

    def test_ecdsa_sign_with_empty_message(self):
        """Test ECDSA signing with empty message."""
        private_key, _ = generate_ecdsa_keypair()
        with self.assertRaises(CryptographySuiteError)):
            sign_message_ecdsa(b"", private_key)

    def test_ecdsa_verify_with_invalid_signature(self):
        """Test ECDSA verification with invalid signature."""
        _, public_key = generate_ecdsa_keypair()
        invalid_signature = b"invalid_signature"
        is_valid = verify_signature_ecdsa(self.message, invalid_signature, public_key)
        self.assertFalse(is_valid)

    def test_ecdsa_serialize_and_load_keys(self):
        """Test serialization and loading of ECDSA keys."""
        private_key, public_key = generate_ecdsa_keypair()
        private_pem = serialize_ecdsa_private_key(private_key, self.password)
        public_pem = serialize_ecdsa_public_key(public_key)

        loaded_private_key = load_ecdsa_private_key(private_pem, self.password)
        loaded_public_key = load_ecdsa_public_key(public_pem)

        self.assertIsInstance(loaded_private_key, ec.EllipticCurvePrivateKey)
        self.assertIsInstance(loaded_public_key, ec.EllipticCurvePublicKey)

    def test_load_private_key_with_invalid_password(self):
        """Test loading private key with incorrect password."""
        private_key, _ = generate_ed25519_keypair()
        private_pem = serialize_ed25519_private_key(private_key, self.password)
        with self.assertRaises(CryptographySuiteError)):
            load_ed25519_private_key(private_pem, "WrongPassword")

    def test_load_private_key_with_invalid_data(self):
        """Test loading private key with invalid data."""
        with self.assertRaises(CryptographySuiteError)):
            load_ed25519_private_key(b"invalid_data", self.password)

    def test_load_public_key_with_invalid_data(self):
        """Test loading public key with invalid data."""
        with self.assertRaises(CryptographySuiteError)):
            load_ed25519_public_key(b"invalid_data")

    def test_serialize_ed25519_private_key_with_empty_password(self):
        """Test serializing Ed25519 private key with empty password."""
        private_key, _ = generate_ed25519_keypair()
        with self.assertRaises(CryptographySuiteError)):
            serialize_ed25519_private_key(private_key, "")

    def test_load_ed25519_private_key_with_empty_password(self):
        """Test loading Ed25519 private key with empty password."""
        private_key, _ = generate_ed25519_keypair()
        private_pem = serialize_ed25519_private_key(private_key, self.password)
        with self.assertRaises(CryptographySuiteError)):
            load_ed25519_private_key(private_pem, "")

    def test_load_ed25519_private_key_with_invalid_data(self):
        """Test loading Ed25519 private key with invalid data."""
        with self.assertRaises(CryptographySuiteError)):
            load_ed25519_private_key(b"invalid_data", self.password)

    def test_load_ed25519_public_key_with_invalid_data(self):
        """Test loading Ed25519 public key with invalid data."""
        with self.assertRaises(CryptographySuiteError)):
            load_ed25519_public_key(b"invalid_data")

    def test_serialize_ecdsa_private_key_with_empty_password(self):
        """Test serializing ECDSA private key with empty password."""
        private_key, _ = generate_ecdsa_keypair()
        with self.assertRaises(CryptographySuiteError)):
            serialize_ecdsa_private_key(private_key, "")

    def test_load_ecdsa_private_key_with_empty_password(self):
        """Test loading ECDSA private key with empty password."""
        private_key, _ = generate_ecdsa_keypair()
        private_pem = serialize_ecdsa_private_key(private_key, self.password)
        with self.assertRaises(CryptographySuiteError)):
            load_ecdsa_private_key(private_pem, "")

    def test_load_ecdsa_private_key_with_invalid_data(self):
        """Test loading ECDSA private key with invalid data."""
        with self.assertRaises(CryptographySuiteError)):
            load_ecdsa_private_key(b"invalid_data", self.password)

    def test_load_ecdsa_public_key_with_invalid_data(self):
        """Test loading ECDSA public key with invalid data."""
        with self.assertRaises(CryptographySuiteError)):
            load_ecdsa_public_key(b"invalid_data")

    def test_sign_message_with_empty_message(self):
        """Test signing message with empty message using Ed25519."""
        private_key, _ = generate_ed25519_keypair()
        with self.assertRaises(CryptographySuiteError)) as context:
            sign_message(b'', private_key)
        self.assertEqual(str(context.exception), "Message cannot be empty.")

    def test_sign_message_with_invalid_private_key(self):
        """Test signing message with invalid private key."""
        invalid_private_key = "not_a_private_key"
        with self.assertRaises(CryptographySuiteError)) as context:
            sign_message(self.message, invalid_private_key)
        self.assertEqual(str(context.exception), "Invalid Ed25519 private key.")

    def test_sign_message_ecdsa_with_empty_message(self):
        """Test signing message with empty message using ECDSA."""
        private_key, _ = generate_ecdsa_keypair()
        with self.assertRaises(CryptographySuiteError)) as context:
            sign_message_ecdsa(b'', private_key)
        self.assertEqual(str(context.exception), "Message cannot be empty.")

    def test_sign_message_ecdsa_with_invalid_private_key(self):
        """Test signing message with invalid ECDSA private key."""
        invalid_private_key = "not_a_private_key"
        with self.assertRaises(CryptographySuiteError)) as context:
            sign_message_ecdsa(self.message, invalid_private_key)
        self.assertEqual(str(context.exception), "Invalid ECDSA private key.")

    def test_verify_signature_with_invalid_public_key(self):
        """Test verifying signature with invalid Ed25519 public key."""
        private_key, _ = generate_ed25519_keypair()
        signature = sign_message(self.message, private_key)
        invalid_public_key = "not_a_public_key"
        with self.assertRaises(CryptographySuiteError)) as context:
            verify_signature(self.message, signature, invalid_public_key)
        self.assertEqual(str(context.exception), "Invalid Ed25519 public key.")

    def test_verify_signature_ecdsa_with_invalid_public_key(self):
        """Test verifying signature with invalid ECDSA public key."""
        private_key, _ = generate_ecdsa_keypair()
        signature = sign_message_ecdsa(self.message, private_key)
        invalid_public_key = "not_a_public_key"
        with self.assertRaises(CryptographySuiteError)) as context:
            verify_signature_ecdsa(self.message, signature, invalid_public_key)
        self.assertEqual(str(context.exception), "Invalid ECDSA public key.")

    def test_verify_signature_ed448_with_invalid_public_key(self):
        """Test verifying signature with invalid Ed448 public key."""
        private_key, _ = generate_ed448_keypair()
        signature = sign_message_ed448(self.message, private_key)
        invalid_public_key = "not_a_public_key"
        with self.assertRaises(CryptographySuiteError)) as context:
            verify_signature_ed448(self.message, signature, invalid_public_key)
        self.assertEqual(str(context.exception), "Invalid Ed448 public key.")


if __name__ == "__main__":
    unittest.main()
