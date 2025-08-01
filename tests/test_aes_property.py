import unittest
from hypothesis import given, strategies as st
from cryptography_suite.pipeline import AESGCMEncrypt, AESGCMDecrypt


def aes_encrypt(message, password, kdf="scrypt"):
    return AESGCMEncrypt(password=password, kdf=kdf).run(message)


def aes_decrypt(ciphertext, password, kdf="scrypt"):
    return AESGCMDecrypt(password=password, kdf=kdf).run(ciphertext)

class TestAesProperty(unittest.TestCase):
    @given(message=st.text(min_size=1), password=st.text(min_size=1))
    def test_roundtrip(self, message, password):
        encrypted = aes_encrypt(message, password, kdf="scrypt")
        decrypted = aes_decrypt(encrypted, password, kdf="scrypt")
        self.assertEqual(message, decrypted)

if __name__ == "__main__":
    unittest.main()
