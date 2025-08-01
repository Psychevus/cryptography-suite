from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import ed25519

from ...asymmetric.signatures import verify_signature
from ...errors import SignatureVerificationError


def verify_signed_prekey(
    signed_prekey: bytes,
    signature: bytes,
    identity_key: ed25519.Ed25519PublicKey,
) -> None:
    """Verify that *signed_prekey* was signed with *identity_key*."""

    if not verify_signature(signed_prekey, signature, identity_key):
        raise SignatureVerificationError("Invalid signed_prekey signature")
