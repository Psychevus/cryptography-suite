from __future__ import annotations

"""BLS signature primitives using BLS12-381.

This module provides helper functions for generating keys, signing messages,
and verifying signatures using the Basic scheme defined in the
`draft-irtf-cfrg-bls-signature` specification.  The implementation relies on
the ``py_ecc`` library which offers a well-vetted pairing implementation.
"""

from os import urandom
from typing import Iterable, List, Sequence, Tuple, Union
import base64

from py_ecc.bls import G2Basic
from ..errors import KeyDerivationError, SignatureVerificationError
from ..utils import KeyVault


def generate_bls_keypair(
    seed: bytes | None = None, *, sensitive: bool = True
) -> Tuple[Union[int, KeyVault], bytes]:
    """Generate a BLS12-381 key pair.

    Parameters
    ----------
    seed : bytes | None, optional
        Optional 32-byte seed used as input key material. When ``None`` a
        cryptographically secure random seed is generated.
    sensitive : bool, optional
        If ``True`` (default) the private key is returned wrapped in
        :class:`KeyVault` for zeroization after use. Set to ``False`` to
        receive the key as a Python integer.

    Returns
    -------
    Tuple[Union[int, KeyVault], bytes]
        The private key as either an integer or a :class:`KeyVault`-wrapped
        byte string, and the corresponding public key.
    """
    if seed is not None and len(seed) == 0:
        raise KeyDerivationError("Seed cannot be empty.")

    ikm = seed if seed is not None else urandom(32)
    sk = G2Basic.KeyGen(ikm)
    pk = G2Basic.SkToPk(sk)
    if sensitive:
        sk_bytes = sk.to_bytes(32, "big")
        return KeyVault(sk_bytes), pk
    return sk, pk


def bls_sign(
    message: bytes, private_key: Union[int, bytes, bytearray, KeyVault], *, raw_output: bool = False
) -> str | bytes:
    """Sign a message using the BLS signature scheme.

    Parameters
    ----------
    message : bytes
        Message to sign.
    private_key : int | bytes | KeyVault
        Private key generated via :func:`generate_bls_keypair`. It may be
        provided as a :class:`KeyVault` instance or raw integer/bytes.

    Returns
    -------
    bytes
        Signature for ``message``.
    """
    if not message:
        raise SignatureVerificationError("Message cannot be empty.")
    if isinstance(private_key, KeyVault):
        private_key = int.from_bytes(bytes(private_key), "big")
    elif isinstance(private_key, (bytes, bytearray)):
        private_key = int.from_bytes(private_key, "big")
    if not isinstance(private_key, int):
        raise TypeError("Private key must be an int or bytes.")
    sig = G2Basic.Sign(private_key, message)
    if raw_output:
        return sig
    return base64.b64encode(sig).decode()


def bls_verify(message: bytes, signature: bytes | str, public_key: bytes) -> bool:
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
        raise SignatureVerificationError("Message cannot be empty.")
    if not signature:
        raise SignatureVerificationError("Signature cannot be empty.")
    if not isinstance(public_key, (bytes, bytearray)):
        raise TypeError("Public key must be bytes.")
    if isinstance(signature, str):
        try:
            signature = base64.b64decode(signature)
        except Exception:
            return False
    return G2Basic.Verify(public_key, message, signature)


def bls_aggregate(
    signatures: Iterable[bytes], *, raw_output: bool = False
) -> str | bytes:
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
    sig_list: List[bytes] = []
    for sig in signatures:
        if isinstance(sig, str):
            try:
                sig = base64.b64decode(sig)
            except Exception:
                raise SignatureVerificationError("Invalid signature")
        sig_list.append(sig)
    if not sig_list:
        raise SignatureVerificationError("No signatures provided for aggregation.")
    agg = G2Basic.Aggregate(sig_list)
    if raw_output:
        return agg
    return base64.b64encode(agg).decode()


def bls_aggregate_verify(
    public_keys: Sequence[bytes],
    messages: Sequence[bytes],
    signature: bytes | str,
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
        raise SignatureVerificationError("Public keys and messages cannot be empty.")
    if len(public_keys) != len(messages):
        raise SignatureVerificationError(
            "Number of public keys must match number of messages."
        )
    if not signature:
        raise SignatureVerificationError("Signature cannot be empty.")
    if isinstance(signature, str):
        try:
            signature = base64.b64decode(signature)
        except Exception:
            return False
    return G2Basic.AggregateVerify(list(public_keys), list(messages), signature)
