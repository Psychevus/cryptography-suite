import base64
import unittest
import warnings

from cryptography_suite.errors import CryptographySuiteError
from cryptography_suite.protocols import (
    generate_hotp,
    generate_totp,
    verify_hotp,
    verify_totp,
)


class TestOTP(unittest.TestCase):
    def setUp(self):
        self.secret = base64.b32encode(b"secret_key").decode("utf-8")
        self.digits = 6
        self.interval = 30
        self.counter = 1

    def test_generate_and_verify_totp(self):
        """Test TOTP generation and verification."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            totp_code = generate_totp(
                self.secret, interval=self.interval, digits=self.digits
            )
        is_valid = verify_totp(
            totp_code, self.secret, interval=self.interval, digits=self.digits
        )
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
        for algorithm in ["sha256", "sha512"]:
            totp_code = generate_totp(self.secret, algorithm=algorithm)
            is_valid = verify_totp(totp_code, self.secret, algorithm=algorithm)
            self.assertTrue(is_valid)

    def test_hotp_with_stronger_hash_algorithms(self):
        """Test HOTP with SHA-256 and SHA-512."""
        for algorithm in ["sha256", "sha512"]:
            hotp_code = generate_hotp(self.secret, self.counter, algorithm=algorithm)
            is_valid = verify_hotp(
                hotp_code, self.secret, self.counter, algorithm=algorithm
            )
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
        secret = base64.b32encode(b"123456789").decode("utf-8").rstrip("=")
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
                generate_totp("%%%%")

    def test_hotp_rfc4226_vectors(self):
        """Validate HOTP values against RFC 4226 test vectors."""
        secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        expected = [
            "755224",
            "287082",
            "359152",
            "969429",
            "338314",
            "254676",
            "287922",
            "162583",
            "399871",
            "520489",
        ]

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            for counter, otp in enumerate(expected):
                self.assertEqual(
                    generate_hotp(secret, counter, digits=6, algorithm="sha1"), otp
                )

    def test_totp_rfc6238_vectors(self):
        """Validate TOTP values against RFC 6238 Appendix B vectors."""
        timestamps = [59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000]
        vectors = {
            "sha1": {
                "secret": base64.b32encode(b"12345678901234567890").decode("utf-8"),
                "expected": [
                    "94287082",
                    "07081804",
                    "14050471",
                    "89005924",
                    "69279037",
                    "65353130",
                ],
            },
            "sha256": {
                "secret": base64.b32encode(b"12345678901234567890123456789012").decode(
                    "utf-8"
                ),
                "expected": [
                    "46119246",
                    "68084774",
                    "67062674",
                    "91819424",
                    "90698825",
                    "77737706",
                ],
            },
            "sha512": {
                "secret": base64.b32encode(
                    b"1234567890123456789012345678901234567890123456789012345678901234"
                ).decode("utf-8"),
                "expected": [
                    "90693936",
                    "25091201",
                    "99943326",
                    "93441116",
                    "38618901",
                    "47863826",
                ],
            },
        }

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            for algorithm, vector in vectors.items():
                for timestamp, otp in zip(timestamps, vector["expected"], strict=False):
                    self.assertEqual(
                        generate_totp(
                            vector["secret"],
                            interval=30,
                            digits=8,
                            algorithm=algorithm,
                            timestamp=timestamp,
                        ),
                        otp,
                    )

    def test_verify_hotp_with_negative_counter_is_fail_safe(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            self.assertFalse(verify_hotp("123456", self.secret, counter=-5, window=2))

    def test_verify_totp_with_negative_timestamp_is_fail_safe(self):
        self.assertFalse(verify_totp("123456", self.secret, timestamp=-1, window=1))
