"""Cryptography Suite Package Initialization."""

__version__ = "2.0.0"

# Symmetric primitives -------------------------------------------------------
from .symmetric import (
    aes_encrypt,
    aes_decrypt,
    chacha20_encrypt,
    chacha20_decrypt,
    scrypt_encrypt,
    scrypt_decrypt,
    argon2_encrypt,
    argon2_decrypt,
    pbkdf2_encrypt,
    pbkdf2_decrypt,
    encrypt_file,
    decrypt_file,
    ascon_encrypt,
    ascon_decrypt,
    derive_key_scrypt,
    derive_key_pbkdf2,
    derive_key_argon2,
    verify_derived_key_scrypt,
    verify_derived_key_pbkdf2,
    generate_salt,
)

# Asymmetric primitives ------------------------------------------------------
from .asymmetric import (
    generate_rsa_keypair,
    rsa_encrypt,
    rsa_decrypt,
    serialize_private_key,
    serialize_public_key,
    load_private_key,
    load_public_key,
    generate_x25519_keypair,
    derive_x25519_shared_key,
    generate_x448_keypair,
    derive_x448_shared_key,
    generate_ec_keypair,
    ec_encrypt,
    ec_decrypt,
)
from .asymmetric.signatures import (
    generate_ed25519_keypair,
    generate_ed448_keypair,
    sign_message,
    sign_message_ed448,
    verify_signature,
    verify_signature_ed448,
    serialize_ed25519_private_key,
    serialize_ed25519_public_key,
    load_ed25519_private_key,
    load_ed25519_public_key,
    generate_ecdsa_keypair,
    sign_message_ecdsa,
    verify_signature_ecdsa,
    serialize_ecdsa_private_key,
    serialize_ecdsa_public_key,
    load_ecdsa_private_key,
    load_ecdsa_public_key,
)
from .asymmetric.bls import (
    generate_bls_keypair,
    bls_sign,
    bls_verify,
    bls_aggregate,
    bls_aggregate_verify,
)

# Post-quantum cryptography --------------------------------------------------
try:  # pragma: no cover - optional dependency
    from .pqc import (
        generate_kyber_keypair,
        kyber_encapsulate,
        kyber_decapsulate,
        generate_dilithium_keypair,
        dilithium_sign,
        dilithium_verify,
        PQCRYPTO_AVAILABLE,
    )  # noqa: F401
except Exception:  # pragma: no cover - fallback when pqcrypto is missing
    PQCRYPTO_AVAILABLE = False

# Hashing and utilities ------------------------------------------------------
from .hashing import (
    sha384_hash,
    sha256_hash,
    sha512_hash,
    blake2b_hash,
)
from .protocols import (
    generate_aes_key,
    rotate_aes_key,
    secure_save_key_to_file,
    load_private_key_from_file,
    load_public_key_from_file,
    key_exists,
    generate_rsa_keypair_and_save,
    generate_ec_keypair_and_save,
    create_shares,
    reconstruct_secret,
    SPAKE2Client,
    SPAKE2Server,
    generate_totp,
    verify_totp,
    generate_hotp,
    verify_hotp,
    SignalSender,
    SignalReceiver,
    initialize_signal_session,
)

# Optional homomorphic encryption -------------------------------------------
try:  # pragma: no cover - optional dependency
    from .homomorphic import (
        keygen as fhe_keygen,
        encrypt as fhe_encrypt,
        decrypt as fhe_decrypt,
        add as fhe_add,
        multiply as fhe_multiply,
    )  # noqa: F401

    FHE_AVAILABLE = True
except Exception:  # pragma: no cover - handle missing Pyfhel
    FHE_AVAILABLE = False

# Zero-knowledge proofs ------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from .zk import bulletproof
    BULLETPROOF_AVAILABLE = True
except Exception:  # pragma: no cover - handle missing dependency
    bulletproof = None
    BULLETPROOF_AVAILABLE = False

try:  # pragma: no cover - optional dependency
    from .zk import zksnark
    ZKSNARK_AVAILABLE = getattr(zksnark, "ZKSNARK_AVAILABLE", False)
except Exception:  # pragma: no cover - handle missing dependency
    zksnark = None
    ZKSNARK_AVAILABLE = False

from .utils import (
    base62_encode,
    base62_decode,
    secure_zero,
    generate_secure_random_string,
)

__all__ = [
    # Encryption
    "aes_encrypt",
    "aes_decrypt",
    "chacha20_encrypt",
    "chacha20_decrypt",
    "scrypt_encrypt",
    "scrypt_decrypt",
    "argon2_encrypt",
    "argon2_decrypt",
    "pbkdf2_encrypt",
    "pbkdf2_decrypt",
    "ascon_encrypt",
    "ascon_decrypt",
    "encrypt_file",
    "decrypt_file",
    "derive_key_scrypt",
    "derive_key_pbkdf2",
    "derive_key_argon2",
    "verify_derived_key_scrypt",
    "verify_derived_key_pbkdf2",
    "generate_salt",
    # Asymmetric
    "generate_rsa_keypair",
    "rsa_encrypt",
    "rsa_decrypt",
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
    # Signatures
    "generate_ed25519_keypair",
    "generate_ed448_keypair",
    "sign_message",
    "sign_message_ed448",
    "verify_signature",
    "verify_signature_ed448",
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
    # BLS Signatures
    "generate_bls_keypair",
    "bls_sign",
    "bls_verify",
    "bls_aggregate",
    "bls_aggregate_verify",
    # Hashing
    "sha384_hash",
    "sha256_hash",
    "sha512_hash",
    "blake2b_hash",
    # Key Management
    "generate_aes_key",
    "rotate_aes_key",
    "secure_save_key_to_file",
    "load_private_key_from_file",
    "load_public_key_from_file",
    "key_exists",
    "generate_rsa_keypair_and_save",
    "generate_ec_keypair_and_save",
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
    "generate_secure_random_string",
    # Signal Protocol
    "SignalSender",
    "SignalReceiver",
    "initialize_signal_session",
]

# Conditional exports -------------------------------------------------------
if PQCRYPTO_AVAILABLE:
    __all__.extend(
        [
            "generate_kyber_keypair",
            "kyber_encapsulate",
            "kyber_decapsulate",
            "generate_dilithium_keypair",
            "dilithium_sign",
            "dilithium_verify",
        ]
    )

if FHE_AVAILABLE:
    __all__.extend(
        [
            "fhe_keygen",
            "fhe_encrypt",
            "fhe_decrypt",
            "fhe_add",
            "fhe_multiply",
        ]
    )

# Zero-knowledge proofs modules
if BULLETPROOF_AVAILABLE:
    __all__.append("bulletproof")
if ZKSNARK_AVAILABLE:
    __all__.append("zksnark")
