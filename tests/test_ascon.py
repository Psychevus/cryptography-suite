import unittest

from cryptography_suite.symmetric.ascon import encrypt, decrypt


class TestAscon128a(unittest.TestCase):
    def setUp(self):
        self.key = bytes(range(16))
        self.nonce = bytes(range(16))
        self.msg = b"hello ascon"
        self.ad = b"adata"

    def test_encrypt_decrypt(self):
        ct = encrypt(self.key, self.nonce, self.ad, self.msg)
        pt = decrypt(self.key, self.nonce, self.ad, ct)
        self.assertEqual(pt, self.msg)

    def test_invalid_tag(self):
        ct = encrypt(self.key, self.nonce, self.ad, self.msg)
        tampered = ct[:-1] + bytes([ct[-1] ^ 0x01])
        with self.assertRaises(CryptographySuiteError)):
            decrypt(self.key, self.nonce, self.ad, tampered)

    def test_reference_vectors(self):
        vectors = [
            (b"", b"", "7a834e6f09210957067b10fd831f0078"),
            (b"", b"\x00", "6e652b55bfdc8cad2ec43815b1666b1a3a"),
            (b"\x00", b"", "af3031b07b129ec84153373ddcaba528"),
            (b"\x00", b"\x00", "e9c2813cc8c6dd2f245f3bb976da566e9d"),
            (bytes(range(16)), bytes(range(16)), "52499ac9c84323a4ae24eaeccf45c137316d7ab17724ba67a85ecd3c0457c459"),
        ]
        for ad, pt, expected in vectors:
            ct = encrypt(self.key, self.nonce, ad, pt)
            self.assertEqual(ct.hex(), expected)
            self.assertEqual(decrypt(self.key, self.nonce, ad, ct), pt)


if __name__ == "__main__":
    unittest.main()
