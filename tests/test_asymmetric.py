import unittest
import base64
from cryptography_suite.asymmetric import (
    generate_rsa_keypair,
    generate_rsa_keypair_async,
    serialize_private_key,
    serialize_public_key,
    load_private_key,
    load_public_key,
    generate_x25519_keypair,
    derive_x25519_shared_key,
    generate_x448_keypair,
    derive_x448_shared_key,
    generate_ec_keypair,
    ec_encrypt,
    ec_decrypt,
)
from cryptography_suite.pipeline import RSAEncrypt, RSADecrypt


def rsa_encrypt(data, public_key, *, raw_output=False):
    return RSAEncrypt(public_key=public_key, raw_output=raw_output).run(data)


def rsa_decrypt(data, private_key):
    return RSADecrypt(private_key=private_key).run(data)
from cryptography.hazmat.primitives.asymmetric import rsa, x25519, x448, ec
from cryptography_suite.errors import CryptographySuiteError


class TestAsymmetric(unittest.TestCase):
    def setUp(self):
        self.password = "SecurePassphrase"
        self.message = b"Secret Message"
        self.empty_message = b""

    def test_rsa_encrypt_decrypt(self):
        """Test RSA encryption and decryption."""
        private_key, public_key = generate_rsa_keypair()
        ciphertext = rsa_encrypt(self.message, public_key)
        self.assertIsInstance(ciphertext, str)
        plaintext = rsa_decrypt(ciphertext, private_key)
        self.assertEqual(self.message, plaintext)

    def test_rsa_encrypt_with_empty_message(self):
        """Test RSA encryption with empty message."""
        _, public_key = generate_rsa_keypair()
        with self.assertRaises(CryptographySuiteError):
            rsa_encrypt(b'', public_key)

    def test_load_private_key_with_empty_password(self):
        """Test loading private key with empty password."""
        private_key, _ = generate_rsa_keypair()
        private_pem = serialize_private_key(private_key, self.password)
        with self.assertRaises(CryptographySuiteError):
            load_private_key(private_pem, "")

    def test_derive_x25519_shared_key_with_invalid_private_key(self):
        """Test deriving shared key with invalid private key."""
        _, public_key = generate_x25519_keypair()
        invalid_private_key = "not_a_private_key"
        with self.assertRaises(TypeError):
            derive_x25519_shared_key(invalid_private_key, public_key)

    def test_derive_x25519_shared_key_with_invalid_public_key(self):
        """Test deriving shared key with invalid public key."""
        private_key, _ = generate_x25519_keypair()
        invalid_public_key = "not_a_public_key"
        with self.assertRaises(TypeError):
            derive_x25519_shared_key(private_key, invalid_public_key)

    def test_derive_x448_shared_key_with_invalid_private_key(self):
        """Test deriving X448 shared key with invalid private key."""
        _, public_key = generate_x448_keypair()
        with self.assertRaises(TypeError):
            derive_x448_shared_key("bad", public_key)

    def test_derive_x448_shared_key_with_invalid_public_key(self):
        """Test deriving X448 shared key with invalid public key."""
        private_key, _ = generate_x448_keypair()
        with self.assertRaises(TypeError):
            derive_x448_shared_key(private_key, "bad")

    def test_ec_functions_with_invalid_key_types(self):
        """Test EC functions with invalid key types."""
        invalid_private_key = "not_a_private_key"
        invalid_public_key = "not_a_public_key"

        # Test serialize_private_key with invalid EC private key
        with self.assertRaises(TypeError):
            serialize_private_key(invalid_private_key, self.password)

        # Test serialize_public_key with invalid EC public key
        with self.assertRaises(TypeError):
            serialize_public_key(invalid_public_key)

        # Test sign_message_ecdsa with invalid private key
        from cryptography_suite.asymmetric.signatures import (
            sign_message_ecdsa,
            generate_ecdsa_keypair,
        )

        with self.assertRaises(CryptographySuiteError):
            sign_message_ecdsa(self.message, invalid_private_key)

        # Generate valid private key for signing
        private_key, _ = generate_ecdsa_keypair()
        signature = sign_message_ecdsa(self.message, private_key)

        # Test verify_signature_ecdsa with invalid public key
        from cryptography_suite.asymmetric.signatures import verify_signature_ecdsa

        with self.assertRaises(CryptographySuiteError):
            verify_signature_ecdsa(self.message, signature, invalid_public_key)

    def test_rsa_decrypt_with_invalid_ciphertext(self):
        """Test RSA decryption with invalid ciphertext."""
        private_key, _ = generate_rsa_keypair()
        with self.assertRaises(CryptographySuiteError):
            rsa_decrypt(b"invalid_ciphertext", private_key)

    def test_rsa_serialize_and_load_keys(self):
        """Test serialization and loading of RSA keys."""
        private_key, public_key = generate_rsa_keypair()
        private_pem = serialize_private_key(private_key, self.password)
        public_pem = serialize_public_key(public_key)

        loaded_private_key = load_private_key(private_pem, self.password)
        loaded_public_key = load_public_key(public_pem)

        self.assertIsInstance(loaded_private_key, rsa.RSAPrivateKey)
        self.assertIsInstance(loaded_public_key, rsa.RSAPublicKey)

    def test_x25519_key_exchange(self):
        """Test X25519 key exchange."""
        alice_private, alice_public = generate_x25519_keypair()
        bob_private, bob_public = generate_x25519_keypair()

        alice_shared = derive_x25519_shared_key(alice_private, bob_public)
        bob_shared = derive_x25519_shared_key(bob_private, alice_public)

        self.assertEqual(alice_shared, bob_shared)

    def test_x25519_serialize_and_load_keys(self):
        """Test serialization and loading of X25519 keys."""
        private_key, public_key = generate_x25519_keypair()
        private_pem = serialize_private_key(private_key, self.password)
        public_pem = serialize_public_key(public_key)

        loaded_private_key = load_private_key(private_pem, self.password)
        loaded_public_key = load_public_key(public_pem)

        self.assertIsInstance(loaded_private_key, x25519.X25519PrivateKey)
        self.assertIsInstance(loaded_public_key, x25519.X25519PublicKey)

    def test_x448_key_exchange(self):
        """Test X448 key exchange."""
        alice_private, alice_public = generate_x448_keypair()
        bob_private, bob_public = generate_x448_keypair()

        alice_shared = derive_x448_shared_key(alice_private, bob_public)
        bob_shared = derive_x448_shared_key(bob_private, alice_public)

        self.assertEqual(alice_shared, bob_shared)

    def test_x448_serialize_and_load_keys(self):
        """Test serialization and loading of X448 keys."""
        private_key, public_key = generate_x448_keypair()
        private_pem = serialize_private_key(private_key, self.password)
        public_pem = serialize_public_key(public_key)

        loaded_private_key = load_private_key(private_pem, self.password)
        loaded_public_key = load_public_key(public_pem)

        self.assertIsInstance(loaded_private_key, x448.X448PrivateKey)
        self.assertIsInstance(loaded_public_key, x448.X448PublicKey)

    def test_ec_key_generation(self):
        """Test EC key pair generation."""
        private_key, public_key = generate_ec_keypair()
        self.assertIsInstance(private_key, ec.EllipticCurvePrivateKey)
        self.assertIsInstance(public_key, ec.EllipticCurvePublicKey)

    def test_ec_serialize_and_load_keys(self):
        """Test serialization and loading of EC keys."""
        private_key, public_key = generate_ec_keypair()
        private_pem = serialize_private_key(private_key, self.password)
        public_pem = serialize_public_key(public_key)

        loaded_private_key = load_private_key(private_pem, self.password)
        loaded_public_key = load_public_key(public_pem)

        self.assertIsInstance(loaded_private_key, ec.EllipticCurvePrivateKey)
        self.assertIsInstance(loaded_public_key, ec.EllipticCurvePublicKey)

    def test_rsa_encrypt_with_invalid_public_key(self):
        """Test RSA encryption with invalid public key."""
        with self.assertRaises(TypeError):
            rsa_encrypt(self.message, "invalid_public_key")

    def test_rsa_decrypt_with_invalid_private_key(self):
        """Test RSA decryption with invalid private key."""
        _, public_key = generate_rsa_keypair()
        ciphertext = rsa_encrypt(self.message, public_key)
        with self.assertRaises(TypeError):
            rsa_decrypt(ciphertext, "invalid_private_key")

    def test_load_private_key_with_invalid_password(self):
        """Test loading private key with incorrect password."""
        private_key, _ = generate_rsa_keypair()
        private_pem = serialize_private_key(private_key, self.password)
        with self.assertRaises(CryptographySuiteError):
            load_private_key(private_pem, "WrongPassword")

    def test_load_private_key_with_invalid_data(self):
        """Test loading private key with invalid data."""
        with self.assertRaises(CryptographySuiteError):
            load_private_key(b"invalid_data", self.password)

    def test_load_public_key_with_invalid_data(self):
        """Test loading public key with invalid data."""
        with self.assertRaises(CryptographySuiteError):
            load_public_key(b"invalid_data")

    def test_rsa_encrypt_with_none_message(self):
        """Test RSA encryption with None as message."""
        _, public_key = generate_rsa_keypair()
        with self.assertRaises(CryptographySuiteError):
            rsa_encrypt(None, public_key)

    def test_serialize_private_key_with_empty_password(self):
        """Test serializing private key with empty password."""
        private_key, _ = generate_rsa_keypair()
        with self.assertRaises(CryptographySuiteError) as context:
            serialize_private_key(private_key, '')
        self.assertEqual(str(context.exception), "Password cannot be empty.")

    def test_generate_ec_keypair_with_invalid_curve(self):
        """Test generating EC key pair with invalid curve."""
        with self.assertRaises(TypeError) as context:
            generate_ec_keypair(curve="invalid_curve")
        self.assertEqual(str(context.exception), "Curve must be an instance of EllipticCurve.")

    def test_rsa_encrypt_with_empty_plaintext(self):
        """Test RSA encryption with empty plaintext."""
        _, public_key = generate_rsa_keypair()
        with self.assertRaises(CryptographySuiteError) as context:
            rsa_encrypt(b'', public_key)
        self.assertEqual(str(context.exception), "Plaintext cannot be empty.")

    def test_ecies_encrypt_decrypt(self):
        """ECIES encryption and decryption round-trip."""
        priv, pub = generate_x25519_keypair()
        data = b"Top secret"
        ct = ec_encrypt(data, pub)
        self.assertIsInstance(ct, str)
        pt = ec_decrypt(ct, priv)
        self.assertEqual(data, pt)

    def test_ecies_decrypt_with_wrong_key(self):
        """Decryption should fail with an incorrect private key."""
        priv, pub = generate_x25519_keypair()
        wrong_priv, _ = generate_x25519_keypair()
        ct = ec_encrypt(self.message, pub)
        with self.assertRaises(CryptographySuiteError):
            ec_decrypt(ct, wrong_priv)

    def test_ecies_decrypt_tampered_ciphertext(self):
        """Tampering with ciphertext must raise an error."""
        priv, pub = generate_x25519_keypair()
        ct = ec_encrypt(self.message, pub)
        raw = base64.b64decode(ct)
        tampered = raw[:-1] + bytes([raw[-1] ^ 0x01])
        tampered_b64 = base64.b64encode(tampered).decode()
        with self.assertRaises(CryptographySuiteError):
            ec_decrypt(tampered_b64, priv)

    def test_generate_rsa_keypair_async_future(self):
        """Asynchronous RSA key generation returns a Future."""
        fut = generate_rsa_keypair_async(key_size=2048)
        priv, pub = fut.result(timeout=30)
        self.assertIsInstance(priv, rsa.RSAPrivateKey)
        self.assertIsInstance(pub, rsa.RSAPublicKey)

    def test_generate_rsa_keypair_async_callback(self):
        """Callback is invoked with the generated keys."""
        out: dict[str, rsa.RSAPrivateKey | rsa.RSAPublicKey] = {}

        def cb(priv: rsa.RSAPrivateKey, pub: rsa.RSAPublicKey) -> None:
            out["priv"] = priv
            out["pub"] = pub

        fut = generate_rsa_keypair_async(key_size=2048, callback=cb)
        fut.result(timeout=30)
        self.assertIsInstance(out.get("priv"), rsa.RSAPrivateKey)
        self.assertIsInstance(out.get("pub"), rsa.RSAPublicKey)


if __name__ == "__main__":
    unittest.main()
