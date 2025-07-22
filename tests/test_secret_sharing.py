import unittest
from cryptography_suite.protocols import (
    create_shares,
    reconstruct_secret,
)


class TestSecretSharing(unittest.TestCase):
    def setUp(self):
        self.secret = 12345678901234567890
        self.threshold = 3
        self.num_shares = 5

    def test_create_shares_with_threshold_greater_than_num_shares(self):
        """Test creating shares with threshold greater than num_shares."""
        with self.assertRaises(CryptographySuiteError)):
            create_shares(self.secret, self.num_shares + 1, self.num_shares)

    def test_create_and_reconstruct_secret(self):
        """Test creating shares and reconstructing the secret."""
        shares = create_shares(self.secret, self.threshold, self.num_shares)
        selected_shares = shares[:self.threshold]
        recovered_secret = reconstruct_secret(selected_shares)
        self.assertEqual(self.secret, recovered_secret)

    def test_reconstruct_secret_with_insufficient_shares(self):
        """Test reconstructing secret with insufficient shares."""
        shares = create_shares(self.secret, self.threshold, self.num_shares)
        selected_shares = shares[:self.threshold - 1]
        recovered_secret = reconstruct_secret(selected_shares)
        self.assertNotEqual(
            self.secret, recovered_secret,
            "Secret should not be recoverable with insufficient shares."
        )

    def test_create_shares_with_invalid_threshold(self):
        """Test creating shares with threshold greater than number of shares."""
        with self.assertRaises(CryptographySuiteError)) as context:
            create_shares(self.secret, 6, self.num_shares)
        self.assertEqual(
            str(context.exception),
            "Threshold cannot be greater than the number of shares."
        )

    def test_create_shares_with_large_secret(self):
        """Test creating shares with a secret larger than prime."""
        large_secret = 2 ** 522
        with self.assertRaises(CryptographySuiteError)):
            create_shares(large_secret, self.threshold, self.num_shares)

    def test_reconstruct_secret_with_invalid_shares(self):
        """Test reconstructing secret with invalid shares."""
        shares = [("invalid_x", "invalid_y")]
        with self.assertRaises(TypeError):
            reconstruct_secret(shares)

    def test_create_shares_with_threshold_exceeding_num_shares(self):
        """Test creating shares with threshold exceeding number of shares."""
        with self.assertRaises(CryptographySuiteError)) as context:
            create_shares(self.secret, self.num_shares + 1, self.num_shares)
        self.assertEqual(
            str(context.exception),
            "Threshold cannot be greater than the number of shares."
        )


if __name__ == "__main__":
    unittest.main()
