"""Cryptography Suite Package Initialization."""

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
