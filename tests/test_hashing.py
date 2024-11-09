import unittest
import base64
from hashing import sha384_hash, generate_salt, derive_key, verify_derived_key


class TestHashing(unittest.TestCase):
    def test_sha384_hash(self):
        data = "Sensitive Data"
        hashed = sha384_hash(data)
        self.assertIsInstance(hashed, str)

    def test_derived_key_verification(self):
        data = "Sensitive Data"
        salt = generate_salt()
        derived_key = derive_key(data, salt)
        self.assertTrue(verify_derived_key(data, salt, derived_key))

    def test_derive_key_empty_data(self):
        # Test edge case for empty string input to derive_key
        salt = generate_salt()
        with self.assertRaises(ValueError):
            derive_key("", salt)  # Expect this to raise an error if empty data is not allowed

    def test_derive_key_invalid_type(self):
        # Test invalid data type for password (e.g., None instead of a string)
        salt = generate_salt()
        with self.assertRaises(TypeError):
            derive_key(None, salt)

    def test_verify_derived_key_with_wrong_password(self):
        # Test verify_derived_key with a wrong password
        salt = generate_salt()
        correct_key = derive_key("correct_password", salt)
        self.assertFalse(verify_derived_key("wrong_password", salt, correct_key))

    def test_verify_derived_key_with_wrong_salt(self):
        # Verify with an incorrect salt
        salt = generate_salt()
        derived_key = derive_key("password", salt)
        wrong_salt = generate_salt()
        self.assertFalse(verify_derived_key("password", wrong_salt, derived_key))

    def test_verify_derived_key_with_altered_key(self):
        salt = generate_salt()
        derived_key = derive_key("password", salt)

        # Convert derived_key to bytes if it’s a string
        if isinstance(derived_key, str):
            derived_key = derived_key.encode()

        # Alter the last byte and re-encode in base64
        altered_key_bytes = derived_key[:-1] + bytes([derived_key[-1] ^ 0x01])
        altered_key = base64.b64encode(altered_key_bytes).decode()

        # Verify that altered_key fails verification
        self.assertFalse(verify_derived_key("password", salt, altered_key))

    def test_verify_derived_key_with_corrupt_key(self):
        salt = generate_salt()
        derived_key = derive_key("password", salt)

        # Ensure derived_key is in bytes
        if isinstance(derived_key, str):
            derived_key = derived_key.encode()

        # Alter the last byte and base64-encode it
        corrupt_key = base64.b64encode(derived_key[:-1] + b'0').decode()

        # Verify that corrupt_key fails verification
        self.assertFalse(verify_derived_key("password", salt, corrupt_key))

if __name__ == "__main__":
    unittest.main()
