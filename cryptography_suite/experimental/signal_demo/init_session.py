"""Session initialization helpers for the Signal demo."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING or os.getenv("CRYPTOSUITE_ALLOW_EXPERIMENTAL"):
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
else:  # pragma: no cover - executed when experimental disabled
    raise ImportError(
        "Signal demo is experimental. Set CRYPTOSUITE_ALLOW_EXPERIMENTAL=1 to enable."
    )
