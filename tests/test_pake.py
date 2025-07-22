import unittest

from cryptography.exceptions import InvalidKey

from cryptography_suite.protocols import SPAKE2Client, SPAKE2Server


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

    def test_spake2_server_before_generate_message(self):
        """Server.compute_shared_key should fail if generate_message() not called."""
        server = SPAKE2Server(self.password)
        with self.assertRaises(ValueError):
            server.compute_shared_key(b"msg")

    def test_spake2_reflection_error(self):
        """Passing our own message should raise InvalidKey due to SPAKEError."""
        client = SPAKE2Client(self.password)
        msg = client.generate_message()
        with self.assertRaises(InvalidKey):
            client.compute_shared_key(msg)

    def test_base_spake2party_roundtrip(self):
        """The base SPAKE2Party class using X25519 should exchange keys."""
        from cryptography_suite.protocols.pake import SPAKE2Party

        a = SPAKE2Party(self.password)
        b = SPAKE2Party(self.password)
        amsg = a.generate_message()
        bmsg = b.generate_message()
        akey = a.compute_shared_key(bmsg)
        bkey = b.compute_shared_key(amsg)
        self.assertEqual(akey, bkey)

    def test_base_spake2party_errors(self):
        from cryptography_suite.protocols.pake import SPAKE2Party

        party = SPAKE2Party(self.password)
        with self.assertRaises(ValueError):
            party.compute_shared_key(b"x")
        party.generate_message()
        with self.assertRaises(InvalidKey):
            party.compute_shared_key(b"short")
        with self.assertRaises(ValueError):
            SPAKE2Party("")
        with self.assertRaises(ValueError):
            SPAKE2Party("pw").get_shared_key()
