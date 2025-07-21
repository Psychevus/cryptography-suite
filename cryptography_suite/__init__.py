"""
Cryptography Suite Package Initialization.

Provides a comprehensive suite of cryptographic functions including symmetric encryption,
asymmetric encryption, hashing, key management, digital signatures, secret sharing,
password-authenticated key exchange, and one-time passwords.

Now includes additional algorithms and enhanced features for cutting-edge security applications.
"""

__version__ = "1.1.0"

from .encryption import (
    aes_encrypt,
    aes_decrypt,
    chacha20_encrypt,
    chacha20_decrypt,
    scrypt_encrypt,
    scrypt_decrypt,
    encrypt_file,
    decrypt_file,
    pbkdf2_encrypt,
    pbkdf2_decrypt,
)
from .ascon_cipher import encrypt as ascon_encrypt, decrypt as ascon_decrypt

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
    generate_ec_keypair,
)

from .signatures import (
    generate_ed25519_keypair,
    sign_message,
    verify_signature,
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

try:  # pragma: no cover - optional dependency
    from .post_quantum import (
        generate_kyber_keypair,
        kyber_encapsulate,
        kyber_decapsulate,
        generate_dilithium_keypair,
        dilithium_sign,
        dilithium_verify,
        PQCRYPTO_AVAILABLE,
    )
except Exception:
    PQCRYPTO_AVAILABLE = False

from .hashing import (
    sha384_hash,
    sha256_hash,
    sha512_hash,
    blake2b_hash,
    derive_key_scrypt,
    derive_key_pbkdf2,
    verify_derived_key_scrypt,
    verify_derived_key_pbkdf2,
    generate_salt,
)

from .key_management import (
    generate_aes_key,
    rotate_aes_key,
    secure_save_key_to_file,
    load_private_key_from_file,
    load_public_key_from_file,
    key_exists,
    generate_rsa_keypair_and_save,
    generate_ec_keypair_and_save,
)

from .secret_sharing import (
    create_shares,
    reconstruct_secret,
)

from .pake import (
    SPAKE2Client,
    SPAKE2Server,
)

from .otp import (
    generate_totp,
    verify_totp,
    generate_hotp,
    verify_hotp,
)

try:  # pragma: no cover - optional dependency
    from .homomorphic import (
        keygen as fhe_keygen,
        encrypt as fhe_encrypt,
        decrypt as fhe_decrypt,
        add as fhe_add,
        multiply as fhe_multiply,
    )
    FHE_AVAILABLE = True
except Exception:  # pragma: no cover - handle missing Pyfhel
    FHE_AVAILABLE = False

try:  # pragma: no cover - optional dependency
    from . import bulletproof
    BULLETPROOF_AVAILABLE = True
except Exception:  # pragma: no cover - handle missing pybulletproofs
    bulletproof = None
    BULLETPROOF_AVAILABLE = False
try:  # pragma: no cover - optional dependency
    from . import zksnark
    ZKSNARK_AVAILABLE = True
except Exception:  # pragma: no cover - handle missing PySNARK
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
    "pbkdf2_encrypt",
    "pbkdf2_decrypt",
    "ascon_encrypt",
    "ascon_decrypt",
    "encrypt_file",
    "decrypt_file",
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
    "generate_ec_keypair",
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
    "blake2b_hash",
    "derive_key_scrypt",
    "derive_key_pbkdf2",
    "verify_derived_key_scrypt",
    "verify_derived_key_pbkdf2",
    "generate_salt",
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
]

# Export post-quantum utilities only when pqcrypto is available
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

# Zero-knowledge proofs
if BULLETPROOF_AVAILABLE:
    __all__.append("bulletproof")
if ZKSNARK_AVAILABLE:
    __all__.append("zksnark")
