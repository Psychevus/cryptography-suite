import unittest

from cryptography_suite.experimental.signal import initialize_signal_session


class TestSignalProtocol(unittest.TestCase):
    def test_message_exchange_and_ratchet(self):
        sender, receiver = initialize_signal_session()
        first_root = sender.ratchet.root_key

        msg1 = b"Hello Bob"
        enc1 = sender.encrypt(msg1)
        dec1 = receiver.decrypt(enc1)
        self.assertEqual(dec1, msg1)

        msg2 = b"Hello Alice"
        enc2 = receiver.encrypt(msg2)
        dec2 = sender.decrypt(enc2)
        self.assertEqual(dec2, msg2)

        self.assertNotEqual(sender.ratchet.root_key, first_root)


if __name__ == "__main__":
    unittest.main()
