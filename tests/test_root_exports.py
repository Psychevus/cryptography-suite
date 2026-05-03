import cryptography_suite as cs

# Basic smoke test ensuring key functions are exposed at package level


def test_root_exports_available():
    from cryptography_suite.pipeline import AESGCMEncrypt, RSAEncrypt

    assert callable(AESGCMEncrypt)
    assert callable(RSAEncrypt)
    assert callable(cs.KeyVault)
    assert callable(cs.to_pem)
    assert callable(cs.to_public_pem)
    assert callable(cs.to_encrypted_private_pem)
    assert callable(cs.to_unencrypted_private_pem_unsafe)
    assert callable(cs.from_pem)
    assert callable(cs.load_public_pem)
    assert callable(cs.load_encrypted_private_pem)
    assert callable(cs.pem_to_json)
    assert callable(cs.encode_encrypted_message)
    assert callable(cs.decode_encrypted_message)
    assert callable(cs.generate_csr)
    assert callable(cs.self_sign_certificate)
    assert callable(cs.load_certificate)
