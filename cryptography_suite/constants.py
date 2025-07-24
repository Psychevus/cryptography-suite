"""Module-wide cryptographic defaults."""

from os import getenv

# Key sizes
AES_KEY_SIZE = 32  # 256 bits
CHACHA20_KEY_SIZE = 32

# Nonce and salt lengths
SALT_SIZE = 16
NONCE_SIZE = 12

# Scrypt parameters
SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1

# PBKDF2 iterations
PBKDF2_ITERATIONS = 100_000

# Argon2id defaults, overridable via environment variables
ARGON2_MEMORY_COST = int(getenv("CRYPTOSUITE_ARGON2_MEMORY_COST", "65536"))
ARGON2_TIME_COST = int(getenv("CRYPTOSUITE_ARGON2_TIME_COST", "3"))
ARGON2_PARALLELISM = int(getenv("CRYPTOSUITE_ARGON2_PARALLELISM", "1"))

__all__ = [
    "AES_KEY_SIZE",
    "CHACHA20_KEY_SIZE",
    "SALT_SIZE",
    "NONCE_SIZE",
    "SCRYPT_N",
    "SCRYPT_R",
    "SCRYPT_P",
    "PBKDF2_ITERATIONS",
    "ARGON2_MEMORY_COST",
    "ARGON2_TIME_COST",
    "ARGON2_PARALLELISM",
]
