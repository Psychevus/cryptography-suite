from __future__ import annotations

"""BLS signature primitives using BLS12-381."""

from os import urandom
from typing import Iterable, List, Sequence, Tuple

from py_ecc.bls import G2Basic


def generate_bls_keypair(seed: bytes | None = None) -> Tuple[int, bytes]:
    """Generate a BLS12-381 key pair.

    Parameters
    ----------
    seed:
        Optional 32 byte seed. If not provided a secure random seed is used.

    Returns
    -------
    Tuple[int, bytes]
        Private key as integer and public key as bytes.
    """
    if seed is not None and len(seed) == 0:
        raise ValueError("Seed cannot be empty.")

    ikm = seed if seed is not None else urandom(32)
    sk = G2Basic.KeyGen(ikm)
    pk = G2Basic.SkToPk(sk)
    return sk, pk


def bls_sign(message: bytes, private_key: int) -> bytes:
    """Sign a message using BLS12-381."""
    if not message:
        raise ValueError("Message cannot be empty.")
    if not isinstance(private_key, int):
        raise TypeError("Private key must be an int.")
    return G2Basic.Sign(private_key, message)


def bls_verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify a BLS12-381 signature."""
    if not message:
        raise ValueError("Message cannot be empty.")
    if not signature:
        raise ValueError("Signature cannot be empty.")
    if not isinstance(public_key, (bytes, bytearray)):
        raise TypeError("Public key must be bytes.")
    return G2Basic.Verify(public_key, message, signature)


def bls_aggregate(signatures: Iterable[bytes]) -> bytes:
    """Aggregate multiple BLS signatures into one."""
    sig_list: List[bytes] = list(signatures)
    if not sig_list:
        raise ValueError("No signatures provided for aggregation.")
    return G2Basic.Aggregate(sig_list)


def bls_aggregate_verify(
    public_keys: Sequence[bytes],
    messages: Sequence[bytes],
    signature: bytes,
) -> bool:
    """Verify an aggregated BLS signature against multiple messages."""
    if not public_keys or not messages:
        raise ValueError("Public keys and messages cannot be empty.")
    if len(public_keys) != len(messages):
        raise ValueError("Number of public keys must match number of messages.")
    if not signature:
        raise ValueError("Signature cannot be empty.")
    return G2Basic.AggregateVerify(list(public_keys), list(messages), signature)

