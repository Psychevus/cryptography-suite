"""Cryptography Suite Package Initialization (src wrapper)."""
# flake8: noqa: E402
from __future__ import annotations

from typing import TYPE_CHECKING
import importlib
import importlib.util
import os
from pathlib import Path
import pkgutil
import sys

# Ensure the package can locate implementation modules that live alongside this
# thin src wrapper.
_package_root = Path(__file__).resolve().parents[2] / "cryptography_suite"
if _package_root.is_dir():
    # Avoid duplicating entries if the path is already present.
    for _path in (str(_package_root),):
        if _path not in __path__:
            __path__.append(_path)

# Allow access to the lightweight crypto_suite implementation (used by some
# protocol demos/tests) through the main package namespace.
_crypto_suite_root = Path(__file__).resolve().parents[1] / "crypto_suite"
if _crypto_suite_root.is_dir():
    _crypto_suite_parent = str(_crypto_suite_root.parent)
    if _crypto_suite_parent not in sys.path:
        sys.path.append(_crypto_suite_parent)

_crypto_suite_spec = importlib.util.find_spec("crypto_suite")
if _crypto_suite_spec is not None:
    _crypto_suite = importlib.import_module("crypto_suite")
    _crypto_prefix = _crypto_suite.__name__
    for _module_info in pkgutil.walk_packages(
        _crypto_suite.__path__, prefix=f"{_crypto_prefix}."
    ):
        _module = importlib.import_module(_module_info.name)
        _alias = f"{__name__}{_module_info.name[len(_crypto_prefix):]}"
        sys.modules.setdefault(_alias, _module)
        if _alias.count(".") == 1:
            setattr(sys.modules[__name__], _alias.split(".")[-1], _module)

from .errors import (
    CryptographySuiteError,
    DecryptionError,
    EncryptionError,
    KeyDerivationError,
    MissingDependencyError,
    ProtocolError,
    UnsupportedAlgorithm,
    SignatureVerificationError,
    StrictKeyPolicyError,
)

__version__ = "3.0.0"

from .aead import chacha20_decrypt_aead, chacha20_encrypt_aead

# Asymmetric primitives ------------------------------------------------------
from .asymmetric import (
    derive_x448_shared_key,
    derive_x25519_shared_key,
    ec_decrypt,
    ec_encrypt,
    generate_ec_keypair,
    generate_rsa_keypair,
    generate_rsa_keypair_async,
    generate_x448_keypair,
    generate_x25519_keypair,
    load_private_key,
    load_public_key,
    serialize_private_key,
    serialize_public_key,
)

from .asymmetric.signatures import (
    generate_ecdsa_keypair,
    generate_ed25519_keypair,
    load_ecdsa_private_key,
    load_ecdsa_public_key,
    load_ed25519_private_key,
    load_ed25519_public_key,
    serialize_ecdsa_private_key,
    serialize_ecdsa_public_key,
    serialize_ed25519_private_key,
    serialize_ed25519_public_key,
    sign_message,
    sign_message_ecdsa,
    verify_signature,
    verify_signature_ecdsa,
)

# Backend registry -----------------------------------------------------------
from .crypto_backends import pyca_backend  # noqa: F401 - registers default backend
from .crypto_backends import available_backends, use_backend, select_backend
from .hybrid import HybridEncryptor, hybrid_decrypt, hybrid_encrypt

# Symmetric primitives -------------------------------------------------------
from .symmetric import (
    argon2_decrypt,
    argon2_encrypt,
    chacha20_decrypt,
    chacha20_encrypt,
    decrypt_file,
    decrypt_file_async,
    derive_hkdf,
    derive_key_argon2,
    derive_key_pbkdf2,
    derive_key_scrypt,
    encrypt_file,
    encrypt_file_async,
    generate_salt,
    kdf_pbkdf2,
    pbkdf2_decrypt,
    pbkdf2_encrypt,
    scrypt_decrypt,
    scrypt_encrypt,
    verify_derived_key_pbkdf2,
    verify_derived_key_scrypt,
    xchacha_decrypt,
    xchacha_encrypt,
)

from .audit import audit_log, set_audit_logger

# Hashing --------------------------------------------------------------------
from .hashing import (
    blake2b_hash,
    blake3_hash,
    sha3_256_hash,
    sha3_512_hash,
    sha256_hash,
    sha384_hash,
    sha512_hash,
)

from .protocols import (
    KeyManager,
    SPAKE2Client,
    SPAKE2Server,
    create_shares,
    generate_aes_key,
    generate_hotp,
    generate_totp,
    key_exists,
    load_private_key_from_file,
    load_public_key_from_file,
    reconstruct_secret,
    rotate_aes_key,
    secure_save_key_to_file,
    verify_hotp,
    verify_totp,
)

# Core utilities -------------------------------------------------------------
from .utils import (
    KeyVault,
    base62_decode,
    base62_encode,
    constant_time_compare,
    ct_equal,
    decode_encrypted_message,
    encode_encrypted_message,
    from_pem,
    generate_secure_random_string,
    pem_to_json,
    secure_zero,
    to_pem,
)

from .x509 import generate_csr, load_certificate, self_sign_certificate

__all__ = [
    # Encryption
    "chacha20_encrypt",
    "chacha20_decrypt",
    "chacha20_encrypt_aead",
    "chacha20_decrypt_aead",
    "xchacha_encrypt",
    "xchacha_decrypt",
    "scrypt_encrypt",
    "scrypt_decrypt",
    "argon2_encrypt",
    "argon2_decrypt",
    "pbkdf2_encrypt",
    "pbkdf2_decrypt",
    "encrypt_file",
    "decrypt_file",
    "encrypt_file_async",
    "decrypt_file_async",
    "derive_key_scrypt",
    "derive_key_pbkdf2",
    "derive_key_argon2",
    "derive_hkdf",
    "kdf_pbkdf2",
    "verify_derived_key_scrypt",
    "verify_derived_key_pbkdf2",
    "generate_salt",
    # Asymmetric
    "generate_rsa_keypair",
    "generate_rsa_keypair_async",
    "serialize_private_key",
    "serialize_public_key",
    "load_private_key",
    "load_public_key",
    "generate_x25519_keypair",
    "derive_x25519_shared_key",
    "generate_x448_keypair",
    "derive_x448_shared_key",
    "generate_ec_keypair",
    "ec_encrypt",
    "ec_decrypt",
    "hybrid_encrypt",
    "hybrid_decrypt",
    "HybridEncryptor",
    # Signatures
    "generate_ed25519_keypair",
    "sign_message",
    "verify_signature",
    "serialize_ed25519_private_key",
    "serialize_ed25519_public_key",
    "load_ed25519_private_key",
    "load_ed25519_public_key",
    "generate_ecdsa_keypair",
    "sign_message_ecdsa",
    "verify_signature_ecdsa",
    "serialize_ecdsa_private_key",
    "serialize_ecdsa_public_key",
    "load_ecdsa_private_key",
    "load_ecdsa_public_key",
    # Hashing
    "sha384_hash",
    "sha256_hash",
    "sha512_hash",
    "sha3_256_hash",
    "sha3_512_hash",
    "blake2b_hash",
    "blake3_hash",
    # Key Management
    "generate_aes_key",
    "rotate_aes_key",
    "secure_save_key_to_file",
    "load_private_key_from_file",
    "load_public_key_from_file",
    "key_exists",
    # Secret Sharing
    "create_shares",
    "reconstruct_secret",
    # PAKE
    "SPAKE2Client",
    "SPAKE2Server",
    # OTP
    "generate_totp",
    "verify_totp",
    "generate_hotp",
    "verify_hotp",
    # Utils
    "base62_encode",
    "base62_decode",
    "secure_zero",
    "constant_time_compare",
    "ct_equal",
    "generate_secure_random_string",
    "KeyVault",
    "to_pem",
    "from_pem",
    "pem_to_json",
    "encode_encrypted_message",
    "decode_encrypted_message",
    "KeyManager",
    # x509
    "generate_csr",
    "self_sign_certificate",
    "load_certificate",
    # Audit
    "audit_log",
    "set_audit_logger",
    # Exceptions
    "CryptographySuiteError",
    "EncryptionError",
    "DecryptionError",
    "KeyDerivationError",
    "SignatureVerificationError",
    "MissingDependencyError",
    "ProtocolError",
    "UnsupportedAlgorithm",
    "StrictKeyPolicyError",
    # Backends
    "available_backends",
    "use_backend",
    "select_backend",
]


def __getattr__(name: str):
    if name == "experimental":
        if TYPE_CHECKING or os.getenv("CRYPTOSUITE_ALLOW_EXPERIMENTAL"):
            return importlib.import_module(".experimental", __name__)
        raise ImportError(
            "Experimental features require CRYPTOSUITE_ALLOW_EXPERIMENTAL=1"
        )
    raise AttributeError(name)
