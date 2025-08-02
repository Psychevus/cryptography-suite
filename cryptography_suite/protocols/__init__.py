"""Protocol-related cryptographic utilities."""

from .otp import generate_totp, verify_totp, generate_hotp, verify_hotp
from .secret_sharing import create_shares, reconstruct_secret
from .pake import SPAKE2Client, SPAKE2Server
from .key_management import (
    generate_aes_key,
    rotate_aes_key,
    generate_random_password,
    secure_save_key_to_file,
    load_private_key_from_file,
    load_public_key_from_file,
    key_exists,
    KeyManager,
)

__all__ = [
    "generate_totp",
    "verify_totp",
    "generate_hotp",
    "verify_hotp",
    "create_shares",
    "reconstruct_secret",
    "SPAKE2Client",
    "SPAKE2Server",
    "generate_aes_key",
    "rotate_aes_key",
    "generate_random_password",
    "secure_save_key_to_file",
    "load_private_key_from_file",
    "load_public_key_from_file",
    "key_exists",
    "KeyManager",
]
