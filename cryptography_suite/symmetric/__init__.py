"""Symmetric cryptography primitives."""

from .aes import (
    encrypt_file,
    decrypt_file,
    encrypt_file_async,
    decrypt_file_async,
    scrypt_encrypt,
    scrypt_decrypt,
    pbkdf2_encrypt,
    pbkdf2_decrypt,
    argon2_encrypt,
    argon2_decrypt,
)
from .chacha import (
    chacha20_encrypt,
    chacha20_decrypt,
    xchacha_encrypt,
    xchacha_decrypt,
)
from .kdf import (
    derive_key_scrypt,
    verify_derived_key_scrypt,
    derive_key_pbkdf2,
    verify_derived_key_pbkdf2,
    derive_key_argon2,
    derive_hkdf,
    kdf_pbkdf2,
    generate_salt,
)

__all__ = [
    "encrypt_file",
    "decrypt_file",
    "encrypt_file_async",
    "decrypt_file_async",
    "scrypt_encrypt",
    "scrypt_decrypt",
    "pbkdf2_encrypt",
    "pbkdf2_decrypt",
    "argon2_encrypt",
    "argon2_decrypt",
    "chacha20_encrypt",
    "chacha20_decrypt",
    "xchacha_encrypt",
    "xchacha_decrypt",
    "derive_key_scrypt",
    "verify_derived_key_scrypt",
    "derive_key_pbkdf2",
    "verify_derived_key_pbkdf2",
    "derive_key_argon2",
    "derive_hkdf",
    "kdf_pbkdf2",
    "generate_salt",
]
