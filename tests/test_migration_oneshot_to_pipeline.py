import string
import pytest
from hypothesis import given, settings, strategies as st

import cryptography_suite.symmetric.aes as aes_mod
import cryptography_suite.asymmetric as asym
from cryptography_suite.pipeline import (
    Pipeline,
    AESGCMEncrypt,
    AESGCMDecrypt,
    RSAEncrypt,
    RSADecrypt,
)

# Mapping of deprecated helpers to their pipeline equivalents.
DEPRECATED_HELPERS = [
    {
        "name": "aes",
        "encrypt": lambda pt, key: aes_mod.aes_encrypt(pt, key),
        "decrypt": lambda ct, key: aes_mod.aes_decrypt(ct, key),
        "pipeline_encrypt": lambda key: Pipeline() >> AESGCMEncrypt(password=key),
        "pipeline_decrypt": lambda key: Pipeline() >> AESGCMDecrypt(password=key),
        "plaintext_strategy": st.text(
            alphabet=string.printable, min_size=1, max_size=32
        ),
        "key_strategy": st.text(alphabet=string.printable, min_size=1, max_size=32),
        "patch_module": aes_mod,
        "patch_kdf": True,
    },
    {
        "name": "rsa",
        "encrypt": lambda pt, kp: asym.rsa_encrypt(pt, kp[1]),
        "decrypt": lambda ct, kp: asym.rsa_decrypt(ct, kp[0]),
        "pipeline_encrypt": lambda kp: Pipeline() >> RSAEncrypt(public_key=kp[1]),
        "pipeline_decrypt": lambda kp: Pipeline() >> RSADecrypt(private_key=kp[0]),
        "plaintext_strategy": st.binary(min_size=1, max_size=32),
        "key_strategy": st.builds(asym.generate_rsa_keypair, key_size=st.just(2048)),
        "expect_equal": False,
    },
]


@pytest.mark.parametrize("case", DEPRECATED_HELPERS, ids=lambda c: c["name"])
@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_migration_oneshot_to_pipeline(case, monkeypatch):
    # Ensure deterministic output for randomized helpers like AES by patching RNG.
    patch_mod = case.get("patch_module")
    if patch_mod is not None:
        monkeypatch.setattr(patch_mod, "urandom", lambda n: b"\x00" * n)
    if case.get("patch_kdf"):
        monkeypatch.setattr(
            aes_mod, "select_kdf", lambda password, salt, kdf: b"\x01" * 32
        )

    @settings(max_examples=1)
    @given(
        plaintext=case["plaintext_strategy"], key=case["key_strategy"]
    )
    def inner(plaintext, key):
        helper_ct = case["encrypt"](plaintext, key)
        pipeline_ct = case["pipeline_encrypt"](key).run(plaintext)
        if case.get("expect_equal", True):
            assert helper_ct == pipeline_ct
        assert case["decrypt"](pipeline_ct, key) == plaintext
        assert case["pipeline_decrypt"](key).run(helper_ct) == plaintext

    inner()
