import cryptography_suite as cs

# Basic smoke test ensuring key functions are exposed at package level

def test_root_exports_available():
    assert callable(cs.aes_encrypt)
    assert callable(cs.rsa_encrypt)
