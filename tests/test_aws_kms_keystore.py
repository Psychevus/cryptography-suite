import sys
import types

import pytest


class StubKMSClient:
    def __init__(self, key_spec: str, signing_algorithms: list[str]):
        self.key_spec = key_spec
        self.signing_algorithms = signing_algorithms
        self.sign_calls = []

    def get_paginator(self, _name):
        return types.SimpleNamespace(paginate=lambda: [{"Keys": []}])

    def list_keys(self, Limit=1):  # noqa: N803
        return {"Keys": []}

    def get_public_key(self, KeyId):  # noqa: N803
        return {"KeySpec": self.key_spec, "SigningAlgorithms": self.signing_algorithms}

    def describe_key(self, KeyId):  # noqa: N803
        return {"KeyMetadata": {"KeySpec": self.key_spec}}

    def sign(self, **kwargs):
        self.sign_calls.append(kwargs)
        return {"Signature": b"sig"}

    def decrypt(self, **kwargs):
        return {"Plaintext": b"plain"}


@pytest.mark.parametrize(
    ("key_spec", "supported", "expected"),
    [
        ("RSA_2048", ["RSASSA_PKCS1_V1_5_SHA_256", "RSASSA_PSS_SHA_256"], "RSASSA_PSS_SHA_256"),
        ("ECC_NIST_P384", ["ECDSA_SHA_384"], "ECDSA_SHA_384"),
        ("ED25519", ["EDDSA"], "EDDSA"),
    ],
)
def test_aws_kms_sign_algorithm_selection(monkeypatch, key_spec, supported, expected):
    fake_client = StubKMSClient(key_spec=key_spec, signing_algorithms=supported)
    boto3_mod = types.SimpleNamespace(client=lambda *a, **k: fake_client)
    monkeypatch.setitem(sys.modules, "boto3", boto3_mod)

    from cryptography_suite.keystores.aws_kms import AWSKMSKeyStore

    ks = AWSKMSKeyStore(region_name="us-west-2")
    assert ks.sign("kid", b"data") == b"sig"
    assert fake_client.sign_calls[-1]["SigningAlgorithm"] == expected


def test_aws_kms_sign_algorithm_falls_back_to_supported(monkeypatch):
    fake_client = StubKMSClient(key_spec="RSA_2048", signing_algorithms=["RSASSA_PKCS1_V1_5_SHA_384"])
    boto3_mod = types.SimpleNamespace(client=lambda *a, **k: fake_client)
    monkeypatch.setitem(sys.modules, "boto3", boto3_mod)

    from cryptography_suite.keystores.aws_kms import AWSKMSKeyStore

    ks = AWSKMSKeyStore()
    ks.sign("kid", b"data")
    assert fake_client.sign_calls[-1]["SigningAlgorithm"] == "RSASSA_PKCS1_V1_5_SHA_384"


def test_aws_kms_import_key_not_implemented(monkeypatch):
    fake_client = StubKMSClient(key_spec="RSA_2048", signing_algorithms=["RSASSA_PSS_SHA_256"])
    boto3_mod = types.SimpleNamespace(client=lambda *a, **k: fake_client)
    monkeypatch.setitem(sys.modules, "boto3", boto3_mod)

    from cryptography_suite.keystores.aws_kms import AWSKMSKeyStore

    ks = AWSKMSKeyStore()
    with pytest.raises(NotImplementedError, match="ImportKeyMaterial"):
        ks.import_key(b"raw", {"id": "k"})
