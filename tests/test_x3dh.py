import unittest
from cryptography_suite.protocols import initialize_signal_session
from cryptography_suite.protocols.signal import x3dh_initiator, x3dh_responder
from cryptography_suite.asymmetric import generate_x25519_keypair
from cryptography_suite.errors import SignatureVerificationError


class TestX3DH(unittest.TestCase):
    def test_invalid_signed_prekey(self):
        sender, receiver = initialize_signal_session()
        bundle = list(sender.handshake_bundle)
        bundle[3] = b"bad"  # corrupt signature
        with self.assertRaises(SignatureVerificationError):
            receiver.initialize_session(*bundle)

    def test_one_time_prekey_usage(self):
        ik_a_priv, _ = generate_x25519_keypair()
        ik_b_priv, ik_b_pub = generate_x25519_keypair()
        spk_b_priv, spk_b_pub = generate_x25519_keypair()
        ek_a_priv, ek_a_pub = generate_x25519_keypair()
        opk_a_priv, opk_a_pub = generate_x25519_keypair()

        secret1 = x3dh_initiator(
            ik_a_priv,
            ek_a_priv,
            ik_b_pub,
            spk_b_pub,
            opk_priv=opk_a_priv,
        )
        secret2 = x3dh_responder(
            ik_b_priv,
            spk_b_priv,
            ik_a_priv.public_key(),
            ek_a_pub,
            opk_a_pub,
        )
        self.assertEqual(secret1, secret2)


if __name__ == "__main__":
    unittest.main()
