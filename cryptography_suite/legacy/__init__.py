"""Legacy APIs for :mod:`cryptography_suite`.

These helpers are retained for backward compatibility but are not part of the
recommended public interface. Prefer alternatives in the core API for new
code.
"""

from ..asymmetric.signatures import (
    generate_ed448_keypair,
    sign_message_ed448,
    verify_signature_ed448,
)
from ..hashing import blake3_hash_v2

_BLS_EXPORTS = {
    "generate_bls_keypair",
    "bls_sign",
    "bls_verify",
    "bls_aggregate",
    "bls_aggregate_verify",
}

__all__ = [
    "generate_bls_keypair",
    "bls_sign",
    "bls_verify",
    "bls_aggregate",
    "bls_aggregate_verify",
    "generate_ed448_keypair",
    "sign_message_ed448",
    "verify_signature_ed448",
    "blake3_hash_v2",
]


def __getattr__(name: str):
    if name in _BLS_EXPORTS:
        from ..asymmetric import bls

        return getattr(bls, name)
    raise AttributeError(name)
