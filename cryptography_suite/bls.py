from __future__ import annotations

"""BLS signature primitives using BLS12-381.

This module provides helper functions for generating keys, signing messages,
and verifying signatures using the Basic scheme defined in the
`draft-irtf-cfrg-bls-signature` specification.  The implementation relies on
the ``py_ecc`` library which offers a well-vetted pairing implementation.
"""

from os import urandom
from typing import Iterable, List, Sequence, Tuple

from py_ecc.bls import G2Basic


def generate_bls_keypair(seed: bytes | None = None) -> Tuple[int, bytes]:
    """Generate a BLS12-381 key pair.

    Parameters
    ----------
    seed : bytes | None, optional
        Optional 32-byte seed used as input key material. When ``None`` a
        cryptographically secure random seed is generated.

    Returns
    -------
    Tuple[int, bytes]
        The private key as an integer and the corresponding public key as
        a byte string.
    """
    if seed is not None and len(seed) == 0:
        raise ValueError("Seed cannot be empty.")

    ikm = seed if seed is not None else urandom(32)
    sk = G2Basic.KeyGen(ikm)
    pk = G2Basic.SkToPk(sk)
    return sk, pk


def bls_sign(message: bytes, private_key: int) -> bytes:
    """Sign a message using the BLS signature scheme.

    Parameters
    ----------
    message : bytes
        Message to sign.
    private_key : int
        Private key generated via :func:`generate_bls_keypair`.

    Returns
    -------
    bytes
        Signature for ``message``.
    """
    if not message:
        raise ValueError("Message cannot be empty.")
    if not isinstance(private_key, int):
        raise TypeError("Private key must be an int.")
    return G2Basic.Sign(private_key, message)


def bls_verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify a BLS signature.

    Parameters
    ----------
    message : bytes
        Signed message.
    signature : bytes
        Signature to verify.
    public_key : bytes
        Signer's public key.

    Returns
    -------
    bool
        ``True`` if the signature is valid, otherwise ``False``.
    """
    if not message:
        raise ValueError("Message cannot be empty.")
    if not signature:
        raise ValueError("Signature cannot be empty.")
    if not isinstance(public_key, (bytes, bytearray)):
        raise TypeError("Public key must be bytes.")
    return G2Basic.Verify(public_key, message, signature)


def bls_aggregate(signatures: Iterable[bytes]) -> bytes:
    """Aggregate multiple BLS signatures into one.

    Parameters
    ----------
    signatures : Iterable[bytes]
        Individual signatures to aggregate.

    Returns
    -------
    bytes
        Aggregated signature value.
    """
    sig_list: List[bytes] = list(signatures)
    if not sig_list:
        raise ValueError("No signatures provided for aggregation.")
    return G2Basic.Aggregate(sig_list)


def bls_aggregate_verify(
    public_keys: Sequence[bytes],
    messages: Sequence[bytes],
    signature: bytes,
) -> bool:
    """Verify an aggregated BLS signature against multiple messages.

    Parameters
    ----------
    public_keys : Sequence[bytes]
        Public keys used to sign each message.
    messages : Sequence[bytes]
        Messages that were individually signed.
    signature : bytes
        Aggregated signature to verify.

    Returns
    -------
    bool
        ``True`` if the aggregated signature is valid, otherwise ``False``.
    """
    if not public_keys or not messages:
        raise ValueError("Public keys and messages cannot be empty.")
    if len(public_keys) != len(messages):
        raise ValueError("Number of public keys must match number of messages.")
    if not signature:
        raise ValueError("Signature cannot be empty.")
    return G2Basic.AggregateVerify(list(public_keys), list(messages), signature)
