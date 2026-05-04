import base64
import re
import unittest
from pathlib import Path
from typing import cast

import pytest

from cryptography_suite import pqc as pqc_module
from cryptography_suite.errors import DecryptionError, EncryptionError
from cryptography_suite.pipeline import (
    KyberDecrypt,
    KyberEncrypt,
    MLKEMDecrypt,
    MLKEMEncrypt,
    Pipeline,
)
from cryptography_suite.pqc import (
    PQCRYPTO_AVAILABLE,
    SPHINCS_AVAILABLE,
    dilithium_sign,
    dilithium_verify,
    generate_dilithium_keypair,
    generate_ml_kem_keypair,
    generate_sphincs_keypair,
    kyber_decrypt,
    kyber_encrypt,
    ml_kem_decrypt,
    ml_kem_encrypt,
    sphincs_sign,
    sphincs_verify,
)


class DummyEnvelopeKEM:
    CIPHERTEXT_SIZE = 6
    SHARED_SECRET = b"DUMMY_KEM_SHARED_SECRET_MARKER"

    @staticmethod
    def generate_keypair():
        return b"dummy-public-key", b"dummy-private-key"

    @staticmethod
    def encrypt(public_key):
        if public_key != b"dummy-public-key":
            raise ValueError("bad public key")
        return b"KEMCT1", DummyEnvelopeKEM.SHARED_SECRET

    @staticmethod
    def decrypt(private_key, ciphertext):
        if private_key != b"dummy-private-key" or ciphertext != b"KEMCT1":
            raise ValueError("bad ciphertext")
        return DummyEnvelopeKEM.SHARED_SECRET


@pytest.fixture()
def dummy_ml_kem(monkeypatch):
    monkeypatch.setattr(pqc_module, "PQCRYPTO_AVAILABLE", True)
    for level in (512, 768, 1024):
        monkeypatch.setitem(pqc_module._KYBER_LEVEL_MAP, level, DummyEnvelopeKEM)
    return DummyEnvelopeKEM


def test_ml_kem_encrypt_decrypt_round_trip(dummy_ml_kem):
    public_key, private_key = pqc_module.generate_ml_kem_keypair(sensitive=False)

    envelope = pqc_module.ml_kem_encrypt(public_key, b"pqc test")

    assert isinstance(envelope, str)
    assert pqc_module.ml_kem_decrypt(private_key, envelope) == b"pqc test"

    raw_envelope = pqc_module.ml_kem_encrypt(
        public_key, b"raw pqc test", raw_output=True
    )
    assert isinstance(raw_envelope, bytes)
    assert raw_envelope.startswith(pqc_module._ML_KEM_ENVELOPE_MAGIC)
    assert pqc_module.ml_kem_decrypt(private_key, raw_envelope) == b"raw pqc test"


def test_kyber_encrypt_no_longer_returns_tuple_or_shared_secret(dummy_ml_kem):
    public_key, private_key = pqc_module.generate_ml_kem_keypair(sensitive=False)

    with pytest.warns(DeprecationWarning):
        envelope = pqc_module.kyber_encrypt(public_key, b"compat pqc")

    assert isinstance(envelope, str)
    assert not isinstance(envelope, tuple)

    with pytest.warns(DeprecationWarning):
        assert pqc_module.kyber_decrypt(private_key, envelope) == b"compat pqc"


def test_kyber_decrypt_ignores_old_shared_secret_argument(dummy_ml_kem):
    public_key, private_key = pqc_module.generate_ml_kem_keypair(sensitive=False)
    envelope = pqc_module.ml_kem_encrypt(public_key, b"compat decrypt")

    with pytest.warns(DeprecationWarning):
        decrypted = pqc_module.kyber_decrypt(
            private_key, envelope, b"caller supplied secret is ignored"
        )

    assert decrypted == b"compat decrypt"


def test_envelope_does_not_contain_shared_secret_directly(dummy_ml_kem):
    public_key, _ = pqc_module.generate_ml_kem_keypair(sensitive=False)
    secret = DummyEnvelopeKEM.SHARED_SECRET

    text_envelope = pqc_module.ml_kem_encrypt(public_key, b"secret check")
    raw_envelope = cast(
        bytes, pqc_module.ml_kem_encrypt(public_key, b"secret check", raw_output=True)
    )

    assert text_envelope != secret.decode()
    assert base64.b64encode(secret).decode() not in text_envelope
    assert secret not in base64.b64decode(text_envelope, validate=True)
    assert raw_envelope != secret
    assert secret not in raw_envelope


def test_malformed_and_truncated_envelopes_raise_decryption_error(dummy_ml_kem):
    public_key, private_key = pqc_module.generate_ml_kem_keypair(sensitive=False)
    raw_envelope = cast(
        bytes, pqc_module.ml_kem_encrypt(public_key, b"truncated", raw_output=True)
    )

    for bad_envelope in (
        b"not an envelope",
        raw_envelope[: len(pqc_module._ML_KEM_ENVELOPE_MAGIC)],
        raw_envelope[:-1],
    ):
        with pytest.raises(DecryptionError):
            pqc_module.ml_kem_decrypt(private_key, bad_envelope)


def test_corrupted_kem_ciphertext_nonce_or_tag_raises_decryption_error(dummy_ml_kem):
    public_key, private_key = pqc_module.generate_ml_kem_keypair(sensitive=False)
    raw_envelope = cast(
        bytes, pqc_module.ml_kem_encrypt(public_key, b"corruption", raw_output=True)
    )

    kem_corrupt = bytearray(raw_envelope)
    kem_corrupt[pqc_module._ML_KEM_HEADER_SIZE] ^= 0x01
    with pytest.raises(DecryptionError):
        pqc_module.ml_kem_decrypt(private_key, bytes(kem_corrupt))

    nonce_corrupt = bytearray(raw_envelope)
    nonce_index = (
        pqc_module._ML_KEM_HEADER_SIZE
        + DummyEnvelopeKEM.CIPHERTEXT_SIZE
        + pqc_module._ML_KEM_SALT_SIZE
    )
    nonce_corrupt[nonce_index] ^= 0x01
    with pytest.raises(DecryptionError):
        pqc_module.ml_kem_decrypt(private_key, bytes(nonce_corrupt))

    tag_corrupt = bytearray(raw_envelope)
    tag_corrupt[-1] ^= 0x01
    with pytest.raises(DecryptionError):
        pqc_module.ml_kem_decrypt(private_key, bytes(tag_corrupt))


def test_invalid_ml_kem_level_fails_deterministically(dummy_ml_kem):
    public_key, private_key = pqc_module.generate_ml_kem_keypair(sensitive=False)
    envelope = pqc_module.ml_kem_encrypt(public_key, b"level check")

    with pytest.raises(EncryptionError):
        pqc_module.ml_kem_encrypt(public_key, b"level check", level=999)
    with pytest.raises(DecryptionError):
        pqc_module.ml_kem_decrypt(private_key, envelope, level=999)
    with pytest.raises(DecryptionError):
        pqc_module.ml_kem_decrypt(private_key, envelope, level=768)


def test_pipeline_ml_kem_and_kyber_wrappers_return_envelope_only(dummy_ml_kem):
    public_key, private_key = pqc_module.generate_ml_kem_keypair(sensitive=False)

    envelope = (Pipeline() >> MLKEMEncrypt(public_key=public_key)).run(b"pipeline")
    assert isinstance(envelope, str)
    assert not isinstance(envelope, tuple)
    assert (
        Pipeline()
        >> MLKEMEncrypt(public_key=public_key)
        >> MLKEMDecrypt(private_key=private_key)
    ).run(b"pipeline") == b"pipeline"

    with pytest.warns(DeprecationWarning):
        compat_envelope = (Pipeline() >> KyberEncrypt(public_key=public_key)).run(
            b"compat pipeline"
        )
    assert isinstance(compat_envelope, str)
    assert not isinstance(compat_envelope, tuple)
    with pytest.warns(DeprecationWarning):
        assert KyberDecrypt(private_key=private_key).run(compat_envelope) == (
            b"compat pipeline"
        )


def test_pqc_docs_do_not_show_shared_secret_kyber_examples():
    repo_root = Path(__file__).resolve().parents[1]
    paths = [repo_root / "README.md"]
    paths.extend((repo_root / "docs").rglob("*.md"))
    paths.extend((repo_root / "docs").rglob("*.rst"))
    docs_text = "\n".join(path.read_text(encoding="utf-8") for path in paths)
    old_unpack_example = "ct, " + "ss = kyber_encrypt"

    assert old_unpack_example not in docs_text
    assert not re.search(r"kyber_decrypt\([^)\n]*\bss\b", docs_text)


@unittest.skipUnless(PQCRYPTO_AVAILABLE, "pqcrypto not installed")
class TestPQC(unittest.TestCase):
    def test_ml_kem_encrypt_decrypt_levels(self):
        msg = b"pqc test"
        for lvl in (512, 768, 1024):
            pk, sk = generate_ml_kem_keypair(level=lvl)
            envelope = ml_kem_encrypt(pk, msg, level=lvl)
            self.assertIsInstance(envelope, str)
            self.assertEqual(ml_kem_decrypt(sk, envelope, level=lvl), msg)

            with self.assertWarns(DeprecationWarning):
                compat_envelope = kyber_encrypt(pk, msg, level=lvl)
            self.assertIsInstance(compat_envelope, str)
            self.assertNotIsInstance(compat_envelope, tuple)
            with self.assertWarns(DeprecationWarning):
                self.assertEqual(kyber_decrypt(sk, compat_envelope, level=lvl), msg)

    def test_dilithium_signature(self):
        pk, sk = generate_dilithium_keypair()
        msg = b"sign me"
        sig = dilithium_sign(sk, msg)
        self.assertIsInstance(sig, str)
        self.assertTrue(dilithium_verify(pk, msg, sig))

    def test_ml_kem_decrypt_short_ciphertext_raises_decryption_error(self):
        _, sk = generate_ml_kem_keypair(level=512)
        with self.assertRaises(DecryptionError):
            ml_kem_decrypt(sk, b"\x00" * 10, level=512)

    def test_ml_kem_decrypt_corrupt_kem_nonce_or_tag_raises_decryption_error(self):
        msg = b"nonce/tag corruption test"
        pk, sk = generate_ml_kem_keypair(level=512)
        raw_envelope = cast(bytes, ml_kem_encrypt(pk, msg, level=512, raw_output=True))
        kem_ct_size = pqc_module._KYBER_LEVEL_MAP[512].CIPHERTEXT_SIZE

        kem_corrupt = bytearray(raw_envelope)
        kem_corrupt[pqc_module._ML_KEM_HEADER_SIZE] ^= 0x01
        with self.assertRaises(DecryptionError):
            ml_kem_decrypt(sk, bytes(kem_corrupt), level=512)

        nonce_corrupt = bytearray(raw_envelope)
        nonce_index = (
            pqc_module._ML_KEM_HEADER_SIZE + kem_ct_size + pqc_module._ML_KEM_SALT_SIZE
        )
        nonce_corrupt[nonce_index] ^= 0x01
        with self.assertRaises(DecryptionError):
            ml_kem_decrypt(sk, bytes(nonce_corrupt), level=512)

        tag_corrupt = bytearray(raw_envelope)
        tag_corrupt[-1] ^= 0x01
        with self.assertRaises(DecryptionError):
            ml_kem_decrypt(sk, bytes(tag_corrupt), level=512)

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
