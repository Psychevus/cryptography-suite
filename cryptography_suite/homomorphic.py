"""Homomorphic Encryption Wrapper using Pyfhel.

Provides simple APIs for key generation, encryption, decryption,
and arithmetic on ciphertexts using either the CKKS or BFV scheme.
"""

from __future__ import annotations

from typing import Iterable, List, Union
from .errors import EncryptionError

try:  # pragma: no cover - optional dependency
    from Pyfhel import PyCtxt, Pyfhel
except Exception as exc:  # pragma: no cover - gracefully handle missing package
    raise ImportError(
        "Pyfhel is required for homomorphic encryption features"
    ) from exc

Number = Union[int, float]


def keygen(scheme: str = "CKKS") -> Pyfhel:
    """Generate keys for the chosen FHE scheme.

    Parameters
    ----------
    scheme:
        Either ``"CKKS"`` for approximate arithmetic on real numbers or
        ``"BFV"`` for exact integer arithmetic.

    Returns
    -------
    Pyfhel
        Configured ``Pyfhel`` instance with generated keys.
    """
    scheme = scheme.upper()
    he = Pyfhel()
    if scheme == "CKKS":
        he.contextGen(scheme="CKKS", n=2**14, scale=2**30, qi_sizes=[60, 30, 30, 60])
    elif scheme == "BFV":
        he.contextGen(scheme="BFV", n=2**14, t_bits=20)
    else:
        raise EncryptionError("Unsupported scheme: %s" % scheme)
    he.keyGen()
    he.scheme = scheme  # type: ignore[attr-defined]
    return he


def encrypt(he: Pyfhel, value: Union[Number, Iterable[Number]]) -> PyCtxt:
    """Encrypt a value using the provided ``Pyfhel`` instance."""
    if he.scheme == "CKKS":  # type: ignore[attr-defined]
        return he.encryptFrac(value)
    return he.encryptInt(value)


def decrypt(he: Pyfhel, ctxt: PyCtxt) -> Union[Number, List[Number]]:
    """Decrypt a ciphertext using the provided ``Pyfhel`` instance."""
    if he.scheme == "CKKS":  # type: ignore[attr-defined]
        res = he.decryptFrac(ctxt)
        if isinstance(res, list) and len(res) == 1:
            return float(res[0])
        return res
    return he.decryptInt(ctxt)


def add(_: Pyfhel, c1: PyCtxt, c2: PyCtxt) -> PyCtxt:
    """Add two ciphertexts."""
    return c1 + c2


def multiply(_: Pyfhel, c1: PyCtxt, c2: PyCtxt) -> PyCtxt:
    """Multiply two ciphertexts."""
    return c1 * c2
