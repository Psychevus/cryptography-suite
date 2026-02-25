import unittest

from cryptography_suite.errors import DecryptionError
from cryptography_suite.pqc import (
    PQCRYPTO_AVAILABLE,
    SPHINCS_AVAILABLE,
    dilithium_sign,
    dilithium_verify,
    generate_dilithium_keypair,
    generate_kyber_keypair,
    generate_sphincs_keypair,
    kyber_decrypt,
    kyber_encrypt,
    sphincs_sign,
    sphincs_verify,
)


@unittest.skipUnless(PQCRYPTO_AVAILABLE, "pqcrypto not installed")
class TestPQC(unittest.TestCase):
    def test_kyber_encrypt_decrypt_levels(self):
        msg = b"pqc test"
        for lvl in (512, 768, 1024):
            pk, sk = generate_kyber_keypair(level=lvl)
            ct, ss = kyber_encrypt(pk, msg, level=lvl)
            self.assertIsInstance(ct, str)
            self.assertIsInstance(ss, str)
            self.assertEqual(kyber_decrypt(sk, ct, ss, level=lvl), msg)
            # also validate auto-decapsulation path
            self.assertEqual(kyber_decrypt(sk, ct, level=lvl), msg)

    def test_dilithium_signature(self):
        pk, sk = generate_dilithium_keypair()
        msg = b"sign me"
        sig = dilithium_sign(sk, msg)
        self.assertIsInstance(sig, str)
        self.assertTrue(dilithium_verify(pk, msg, sig))

    def test_kyber_decrypt_short_ciphertext_raises_decryption_error(self):
        _, sk = generate_kyber_keypair(level=512)
        with self.assertRaises(DecryptionError):
            kyber_decrypt(sk, b"\x00" * 10, level=512)

    def test_kyber_decrypt_corrupt_nonce_or_tag_raises_decryption_error(self):
        msg = b"nonce/tag corruption test"
        pk, sk = generate_kyber_keypair(level=512)
        ct, _ = kyber_encrypt(pk, msg, level=512, raw_output=True)

        # Corrupt nonce byte (first byte after KEM ciphertext + salt).
        nonce_corrupt = bytearray(ct)
        kem_ct_size = len(ct) - (16 + 12 + len(msg) + 16)
        nonce_index = kem_ct_size + 16
        nonce_corrupt[nonce_index] ^= 0x01
        with self.assertRaises(DecryptionError):
            kyber_decrypt(sk, bytes(nonce_corrupt), level=512)

        # Corrupt tag byte (last byte of payload).
        tag_corrupt = bytearray(ct)
        tag_corrupt[-1] ^= 0x01
        with self.assertRaises(DecryptionError):
            kyber_decrypt(sk, bytes(tag_corrupt), level=512)

    @unittest.skipUnless(SPHINCS_AVAILABLE, "SPHINCS+ not available")
    def test_sphincs_signature(self):
        pk, sk = generate_sphincs_keypair()
        msg = b"sphincs test"
        sig = sphincs_sign(sk, msg)
        self.assertIsInstance(sig, str)
        self.assertTrue(sphincs_verify(pk, msg, sig))

    @unittest.skipUnless(SPHINCS_AVAILABLE, "SPHINCS+ not available")
    def test_sphincs_negative(self):
        pk, sk = generate_sphincs_keypair()
        msg = b"hello"
        sig = sphincs_sign(sk, msg)
        self.assertFalse(sphincs_verify(pk, b"bye", sig))
        pk2, _ = generate_sphincs_keypair()
        self.assertFalse(sphincs_verify(pk2, msg, sig))


if __name__ == "__main__":
    unittest.main()
