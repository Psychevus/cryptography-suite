"""Cryptography Suite Package Initialization."""

from .errors import (
    CryptographySuiteError,
    DecryptionError,
    EncryptionError,
    KeyDerivationError,
    MissingDependencyError,
    ProtocolError,
    SignatureVerificationError,
)
from .debug import VERBOSE_MODE, verbose_print

__version__ = "2.0.0"

# Asymmetric primitives ------------------------------------------------------
from .asymmetric import (
    derive_x448_shared_key,
    derive_x25519_shared_key,
    ec_decrypt,
    ec_encrypt,
    generate_ec_keypair,
    generate_rsa_keypair,
    generate_x448_keypair,
    generate_x25519_keypair,
    load_private_key,
    load_public_key,
    rsa_decrypt,
    rsa_encrypt,
    serialize_private_key,
    serialize_public_key,
)
from .asymmetric.bls import (
    bls_aggregate,
    bls_aggregate_verify,
    bls_sign,
    bls_verify,
    generate_bls_keypair,
)
from .asymmetric.signatures import (
    generate_ecdsa_keypair,
    generate_ed448_keypair,
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
    sign_message_ed448,
    verify_signature,
    verify_signature_ecdsa,
    verify_signature_ed448,
)
from .hybrid import hybrid_decrypt, hybrid_encrypt

# Symmetric primitives -------------------------------------------------------
from .symmetric import (
    aes_decrypt,
    aes_encrypt,
    argon2_decrypt,
    argon2_encrypt,
    ascon_decrypt,
    ascon_encrypt,
    chacha20_decrypt,
    chacha20_encrypt,
    chacha20_stream_encrypt,
    chacha20_stream_decrypt,
    salsa20_encrypt,
    salsa20_decrypt,
    xchacha_encrypt,
    xchacha_decrypt,
    decrypt_file,
    derive_key_argon2,
    derive_key_pbkdf2,
    derive_key_scrypt,
    derive_hkdf,
    kdf_pbkdf2,
    derive_pbkdf2,
    encrypt_file,
    generate_salt,
    pbkdf2_decrypt,
    pbkdf2_encrypt,
    scrypt_decrypt,
    scrypt_encrypt,
    verify_derived_key_pbkdf2,
    verify_derived_key_scrypt,
)

# Post-quantum cryptography --------------------------------------------------
try:  # pragma: no cover - optional dependency
    from .pqc import (  # noqa: F401
        PQCRYPTO_AVAILABLE,
        SPHINCS_AVAILABLE,
        dilithium_sign,
        dilithium_verify,
        generate_dilithium_keypair,
        generate_sphincs_keypair,
        generate_kyber_keypair,
        kyber_decapsulate,
        kyber_decrypt,
        kyber_encapsulate,
        kyber_encrypt,
        sphincs_sign,
        sphincs_verify,
    )
except Exception:  # pragma: no cover - fallback when pqcrypto is missing
    PQCRYPTO_AVAILABLE = False

# Hashing and utilities ------------------------------------------------------
from .hashing import (
    blake2b_hash,
    blake3_hash,
    blake3_hash_v2,
    sha3_256_hash,
    sha3_512_hash,
    sha256_hash,
    sha384_hash,
    sha512_hash,
)
from .protocols import (
    SignalReceiver,
    SignalSender,
    SPAKE2Client,
    SPAKE2Server,
    create_shares,
    generate_aes_key,
    generate_ec_keypair_and_save,
    generate_hotp,
    generate_rsa_keypair_and_save,
    generate_totp,
    initialize_signal_session,
    key_exists,
    load_private_key_from_file,
    load_public_key_from_file,
    reconstruct_secret,
    rotate_aes_key,
    secure_save_key_to_file,
    verify_hotp,
    verify_totp,
    KeyManager,
)

# Optional homomorphic encryption -------------------------------------------
try:  # pragma: no cover - optional dependency
    from .homomorphic import add as fhe_add
    from .homomorphic import decrypt as fhe_decrypt
    from .homomorphic import encrypt as fhe_encrypt
    from .homomorphic import keygen as fhe_keygen  # noqa: F401
    from .homomorphic import multiply as fhe_multiply

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
    KeyVault,
    base62_decode,
    base62_encode,
    generate_secure_random_string,
    secure_zero,
    to_pem,
    from_pem,
    pem_to_json,
    encode_encrypted_message,
    decode_encrypted_message,
)
from .audit import audit_log, set_audit_logger
from .x509 import generate_csr, self_sign_certificate, load_certificate

__all__ = [
    # Encryption
    "aes_encrypt",
    "aes_decrypt",
    "chacha20_encrypt",
    "chacha20_decrypt",
    "chacha20_stream_encrypt",
    "chacha20_stream_decrypt",
    "salsa20_encrypt",
    "salsa20_decrypt",
    "xchacha_encrypt",
    "xchacha_decrypt",
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
    "derive_hkdf",
    "kdf_pbkdf2",
    "derive_pbkdf2",
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
    "hybrid_encrypt",
    "hybrid_decrypt",
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
    "sha3_256_hash",
    "sha3_512_hash",
    "blake2b_hash",
    "blake3_hash",
    "blake3_hash_v2",
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
    "KeyVault",
    "to_pem",
    "from_pem",
    "pem_to_json",
    "encode_encrypted_message",
    "decode_encrypted_message",
    "KeyManager",
    "generate_csr",
    "self_sign_certificate",
    "load_certificate",
    "audit_log",
    "set_audit_logger",
    # Signal Protocol
    "SignalSender",
    "SignalReceiver",
    "initialize_signal_session",
    # Exceptions
    "CryptographySuiteError",
    "EncryptionError",
    "DecryptionError",
    "KeyDerivationError",
    "SignatureVerificationError",
    "MissingDependencyError",
    "ProtocolError",
]

# Conditional exports -------------------------------------------------------
if PQCRYPTO_AVAILABLE:
    __all__.extend(
        [
            "generate_kyber_keypair",
            "kyber_encapsulate",
            "kyber_decapsulate",
            "kyber_encrypt",
            "kyber_decrypt",
            "generate_dilithium_keypair",
            "dilithium_sign",
            "dilithium_verify",
            "generate_sphincs_keypair",
            "sphincs_sign",
            "sphincs_verify",
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
