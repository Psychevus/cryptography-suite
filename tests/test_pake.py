import unittest

from cryptography.exceptions import InvalidKey

from cryptography_suite.pake import SPAKE2Client, SPAKE2Server


class TestPAKE(unittest.TestCase):
    def setUp(self):
        self.password = "shared_password"

    def test_spake2_successful_key_exchange(self):
        """Test successful SPAKE2 key exchange."""
        client = SPAKE2Client(self.password)
        server = SPAKE2Server(self.password)

        client_msg = client.generate_message()
        server_msg = server.generate_message()

        client_shared_key = client.compute_shared_key(server_msg)
        server_shared_key = server.compute_shared_key(client_msg)

        self.assertEqual(client_shared_key, server_shared_key)

    def test_spake2_with_empty_password(self):
        """Test SPAKE2 initialization with empty password."""
        with self.assertRaises(ValueError):
            SPAKE2Client("")
        with self.assertRaises(ValueError):
            SPAKE2Server("")

    def test_spake2_compute_shared_key_before_generate_message(self):
        """Test computing shared key before generating message."""
        client = SPAKE2Client(self.password)
        server = SPAKE2Server(self.password)

        # Attempt to compute shared key without generating messages
        server_public_bytes = server.generate_message()
        with self.assertRaises(ValueError):
            # Client has not generated its own message yet
            client.compute_shared_key(server_public_bytes)

    def test_spake2_with_invalid_peer_public_key(self):
        """Test SPAKE2 with invalid peer public key."""
        client = SPAKE2Client(self.password)
        client.generate_message()
        invalid_public_bytes = b"invalid_public_key"

        with self.assertRaises(InvalidKey):
            client.compute_shared_key(invalid_public_bytes)

    def test_spake2_get_shared_key_before_computation(self):
        """Test getting shared key before computation."""
        client = SPAKE2Client(self.password)
        client.generate_message()
        with self.assertRaises(ValueError) as context:
            client.get_shared_key()
        self.assertEqual(str(context.exception), "Shared key has not been computed yet.")



    def test_spake2_get_shared_key_after_computation(self):
        client = SPAKE2Client(self.password)
        server = SPAKE2Server(self.password)
        cm = client.generate_message()
        sm = server.generate_message()
        client.compute_shared_key(sm)
        server.compute_shared_key(cm)
        self.assertEqual(client.get_shared_key(), server.get_shared_key())

    def test_spake2_mismatched_password(self):
        """Clients with different passwords should derive different keys."""
        client = SPAKE2Client(self.password)
        server = SPAKE2Server("other_password")
        client_msg = client.generate_message()
        server_msg = server.generate_message()
        ck = client.compute_shared_key(server_msg)
        sk = server.compute_shared_key(client_msg)
        self.assertNotEqual(ck, sk)
