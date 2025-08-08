import os

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

os.environ.setdefault("CRYPTOSUITE_ALLOW_EXPERIMENTAL", "1")

from cryptography_suite.experimental.aes_gcm_sst import (
    aes_gcm_sst_decrypt,
    aes_gcm_sst_encrypt,
)

pytestmark = pytest.mark.experimental


def test_roundtrip() -> None:
    key = AESGCM.generate_key(bit_length=128)
    nonce = os.urandom(12)
    pt = b"secret data"
    ad = b"header"
    ct = aes_gcm_sst_encrypt(key, nonce, pt, associated_data=ad)
    out = aes_gcm_sst_decrypt(key, nonce, ct, associated_data=ad)
    assert out == pt
