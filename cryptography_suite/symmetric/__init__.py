"""Symmetric cryptography primitives."""

from .aes import (
    aes_encrypt,
    aes_decrypt,
    encrypt_file,
    decrypt_file,
    scrypt_encrypt,
    scrypt_decrypt,
    pbkdf2_encrypt,
    pbkdf2_decrypt,
    argon2_encrypt,
    argon2_decrypt,
)
from .chacha import chacha20_encrypt, chacha20_decrypt
from .ascon import encrypt as ascon_encrypt, decrypt as ascon_decrypt
from .kdf import (
    derive_key_scrypt,
    verify_derived_key_scrypt,
    derive_key_pbkdf2,
    verify_derived_key_pbkdf2,
    derive_key_argon2,
    generate_salt,
)

__all__ = [
    "aes_encrypt",
    "aes_decrypt",
    "encrypt_file",
    "decrypt_file",
    "scrypt_encrypt",
    "scrypt_decrypt",
    "pbkdf2_encrypt",
    "pbkdf2_decrypt",
    "argon2_encrypt",
    "argon2_decrypt",
    "chacha20_encrypt",
    "chacha20_decrypt",
    "ascon_encrypt",
    "ascon_decrypt",
    "derive_key_scrypt",
    "verify_derived_key_scrypt",
    "derive_key_pbkdf2",
    "verify_derived_key_pbkdf2",
    "derive_key_argon2",
    "generate_salt",
]
