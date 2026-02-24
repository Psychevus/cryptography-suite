import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.asymmetric import rsa

from cryptography_suite.asymmetric import generate_rsa_keypair
from cryptography_suite.errors import DecryptionError
from cryptography_suite.hybrid import EncryptedHybridMessage
from cryptography_suite.utils import (
    KeyVault,
    base62_decode,
    base62_encode,
    constant_time_compare,
    decode_encrypted_message,
    encode_encrypted_message,
    from_pem,
    generate_secure_random_string,
    is_encrypted_pem,
    pem_to_json,
    secure_zero,
    to_pem,
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

    def test_base62_decode_invalid_character_raises(self):
        with self.assertRaises(ValueError):
            base62_decode("%")

    def test_secure_zero(self):
        """Test secure_zero function."""
        data = bytearray(b"Sensitive data")
        secure_zero(data)
        self.assertTrue(all(b == 0 for b in data))

    def test_secure_zero_falls_back_when_libc_unavailable(self):
        data = bytearray(b"Sensitive data")
        with mock.patch("ctypes.util.find_library", return_value=None):
            secure_zero(data)
        self.assertTrue(all(b == 0 for b in data))

    def test_generate_secure_random_string(self):
        """Test generating a secure random string."""
        random_string = generate_secure_random_string(16)
        self.assertIsInstance(random_string, str)
        self.assertTrue(len(random_string) > 0)

    def test_constant_time_compare(self):
        self.assertTrue(constant_time_compare(b"a", b"a"))
        self.assertFalse(constant_time_compare(b"a", b"b"))

    def test_key_vault_context_manager(self):
        """Test KeyVault securely erases key on exit."""
        data = b"secret-key"
        with KeyVault(data) as key:
            self.assertIsInstance(key, bytearray)
            self.assertEqual(bytes(key), data)
        self.assertTrue(all(b == 0 for b in key))

    def test_key_vault_del(self):
        """KeyVault should erase memory when deleted."""
        data = b"secret-key"
        vault = KeyVault(data)
        buf = vault._key
        vault.__del__()
        self.assertTrue(all(b == 0 for b in buf))

    def test_to_pem_and_from_pem(self):
        """Round trip conversion to and from PEM."""
        priv, pub = generate_rsa_keypair()
        priv_pem = to_pem(priv)
        pub_pem = to_pem(pub)
        self.assertIsInstance(priv_pem, str)
        self.assertIsInstance(pub_pem, str)
        loaded_priv = from_pem(priv_pem)
        loaded_pub = from_pem(pub_pem)
        self.assertIsInstance(loaded_priv, rsa.RSAPrivateKey)
        self.assertIsInstance(loaded_pub, rsa.RSAPublicKey)

    def test_from_pem_invalid(self):
        """Invalid PEM data should raise DecryptionError."""
        with self.assertRaises(DecryptionError):
            from_pem("NOT A VALID PEM")

    def test_from_pem_rejects_non_string(self):
        with self.assertRaises(TypeError):
            from_pem(b"-----BEGIN PRIVATE KEY-----")  # type: ignore[arg-type]

    def test_is_encrypted_pem_false_for_invalid_pem(self):
        temp_path = Path("tests") / "_tmp_invalid.pem"
        self.addCleanup(lambda: temp_path.unlink(missing_ok=True))
        temp_path.write_text("not a pem", encoding="utf-8")
        self.assertFalse(is_encrypted_pem(temp_path))

    def test_is_encrypted_pem_reraises_unrelated_type_error(self):
        temp_path = Path("tests") / "_tmp_type_error.pem"
        self.addCleanup(lambda: temp_path.unlink(missing_ok=True))
        temp_path.write_text("irrelevant", encoding="utf-8")

        with mock.patch(
            "cryptography.hazmat.primitives.serialization.load_pem_private_key",
            side_effect=TypeError("bad argument type"),
        ):
            with self.assertRaises(TypeError):
                is_encrypted_pem(temp_path)

    def test_pem_to_json_and_decode_message(self):
        _, pub = generate_rsa_keypair()
        json_blob = pem_to_json(pub)
        self.assertIn("pem", json_blob)

        msg = {"ciphertext": b"a", "nonce": b"b"}
        encoded = encode_encrypted_message(msg)
        decoded = decode_encrypted_message(encoded)
        self.assertEqual(decoded["ciphertext"], b"a")

    def test_encode_decode_message_preserves_non_bytes_fields(self):
        msg = {"ciphertext": b"a", "nonce": b"b", "counter": 3}
        encoded = encode_encrypted_message(msg)
        decoded = decode_encrypted_message(encoded)
        self.assertEqual(decoded["counter"], 3)

    def test_encode_decode_hybrid_dataclass(self):
        msg = EncryptedHybridMessage(
            encrypted_key=b"k",
            nonce=b"n",
            ciphertext=b"c",
            tag=b"t",
        )
        encoded = encode_encrypted_message(msg)
        decoded = decode_encrypted_message(encoded)
        self.assertIsInstance(decoded, EncryptedHybridMessage)
        self.assertEqual(decoded.nonce, b"n")


if __name__ == "__main__":
    unittest.main()
