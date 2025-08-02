import base64
import unittest
import warnings

from cryptography_suite.errors import CryptographySuiteError

from cryptography_suite.protocols import (
    generate_totp,
    verify_totp,
    generate_hotp,
    verify_hotp,
)


class TestOTP(unittest.TestCase):
    def setUp(self):
        self.secret = base64.b32encode(b'secret_key').decode('utf-8')
        self.digits = 6
        self.interval = 30
        self.counter = 1

    def test_generate_and_verify_totp(self):
        """Test TOTP generation and verification."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            totp_code = generate_totp(self.secret, interval=self.interval, digits=self.digits)
        is_valid = verify_totp(totp_code, self.secret, interval=self.interval, digits=self.digits)
        self.assertTrue(is_valid)

    def test_verify_totp_with_invalid_code(self):
        """Test TOTP verification with invalid code."""
        invalid_code = "123456"
        is_valid = verify_totp(invalid_code, self.secret)
        self.assertFalse(is_valid)

    def test_generate_and_verify_hotp(self):
        """Test HOTP generation and verification."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            hotp_code = generate_hotp(self.secret, self.counter, digits=self.digits)
        is_valid = verify_hotp(hotp_code, self.secret, self.counter, digits=self.digits)
        self.assertTrue(is_valid)

    def test_verify_hotp_with_invalid_code(self):
        """Test HOTP verification with invalid code."""
        invalid_code = "654321"
        is_valid = verify_hotp(invalid_code, self.secret, self.counter)
        self.assertFalse(is_valid)

    def test_totp_with_stronger_hash_algorithms(self):
        """Test TOTP with SHA-256 and SHA-512."""
        for algorithm in ['sha256', 'sha512']:
            totp_code = generate_totp(self.secret, algorithm=algorithm)
            is_valid = verify_totp(totp_code, self.secret, algorithm=algorithm)
            self.assertTrue(is_valid)

    def test_hotp_with_stronger_hash_algorithms(self):
        """Test HOTP with SHA-256 and SHA-512."""
        for algorithm in ['sha256', 'sha512']:
            hotp_code = generate_hotp(self.secret, self.counter, algorithm=algorithm)
            is_valid = verify_hotp(hotp_code, self.secret, self.counter, algorithm=algorithm)
            self.assertTrue(is_valid)

    def test_default_sha1_warning(self):
        """Ensure using the default SHA-1 algorithm emits a warning."""
        with self.assertWarns(UserWarning):
            generate_totp(self.secret)

    def test_generate_totp_with_invalid_secret(self):
        """Test TOTP generation with invalid secret."""
        with self.assertRaises(CryptographySuiteError):
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                generate_totp("invalid_secret")

    def test_generate_hotp_with_invalid_secret(self):
        """Test generating HOTP with invalid secret."""
        invalid_secret = "invalid_base32_secret"
        with self.assertRaises(CryptographySuiteError) as context:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                generate_hotp(invalid_secret, self.counter)
        self.assertIn("Invalid secret", str(context.exception))


    def test_invalid_algorithm(self):
        with self.assertRaises(CryptographySuiteError):
            generate_totp(self.secret, algorithm="md5")
        with self.assertRaises(CryptographySuiteError):
            generate_hotp(self.secret, self.counter, algorithm="md5")

    def test_verify_totp_with_timestamp(self):
        ts = 1000000000
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            code = generate_totp(self.secret, timestamp=ts)
        self.assertTrue(verify_totp(code, self.secret, timestamp=ts))

    def test_totp_with_missing_padding(self):
        secret = base64.b32encode(b'123456789').decode('utf-8').rstrip('=')
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            code = generate_totp(secret)
        self.assertTrue(verify_totp(code, secret))

    def test_totp_with_lowercase_secret(self):
        secret = self.secret.lower()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            code = generate_totp(secret)
        self.assertTrue(verify_totp(code, secret))

    def test_totp_invalid_secret_should_raise(self):
        with self.assertRaises(CryptographySuiteError):
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                generate_totp('%%%%')
