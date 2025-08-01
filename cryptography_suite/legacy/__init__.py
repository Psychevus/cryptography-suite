"""Legacy APIs for :mod:`cryptography_suite`.

These helpers are retained for backward compatibility but are not part of the
recommended public interface. Prefer alternatives in the core API for new
code.
"""

from ..asymmetric.bls import (
    bls_aggregate,
    bls_aggregate_verify,
    bls_sign,
    bls_verify,
    generate_bls_keypair,
)

from ..asymmetric.signatures import (
    generate_ed448_keypair,
    sign_message_ed448,
    verify_signature_ed448,
)

from ..hashing import blake3_hash_v2

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

