import cryptography_suite as cs

# Baseline of allowed legacy helpers. New crypto features should be exposed
# via the Pipeline DSL instead of introducing additional one-shot functions.
EXPECTED_ONE_SHOTS = {
    "aes_decrypt",
    "aes_encrypt",
    "argon2_decrypt",
    "argon2_encrypt",
    "chacha20_decrypt",
    "chacha20_encrypt",
    "chacha20_stream_decrypt",
    "chacha20_stream_encrypt",
    "ec_decrypt",
    "ec_encrypt",
    "hybrid_decrypt",
    "hybrid_encrypt",
    "kyber_decrypt",
    "kyber_encrypt",
    "pbkdf2_decrypt",
    "pbkdf2_encrypt",
    "rsa_decrypt",
    "rsa_encrypt",
    "scrypt_decrypt",
    "scrypt_encrypt",
    "xchacha_decrypt",
    "xchacha_encrypt",
}

def test_no_new_oneshot_helpers():
    current = {n for n in cs.__all__ if n.endswith("_encrypt") or n.endswith("_decrypt")}
    assert current <= EXPECTED_ONE_SHOTS
