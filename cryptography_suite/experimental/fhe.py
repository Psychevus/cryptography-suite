"""Experimental homomorphic encryption helpers.

These wrappers are intentionally opt-in and are not part of the stable
production API. Context serialization uses Pyfhel's native byte APIs only; no
pickle fallback is provided.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, TypeAlias

from ..errors import EncryptionError, MissingDependencyError, UnsupportedOperationError

try:  # pragma: no cover - optional dependency
    from Pyfhel import PyCtxt, Pyfhel

    PYFHEL_AVAILABLE = True
except Exception:  # pragma: no cover - allow import without Pyfhel
    Pyfhel = None  # type: ignore[assignment]
    PyCtxt = Any  # type: ignore[misc]
    PYFHEL_AVAILABLE = False

FHE_AVAILABLE = PYFHEL_AVAILABLE
Number: TypeAlias = int | float
BytesLike: TypeAlias = bytes | bytearray | memoryview

_SERIALIZE_UNAVAILABLE = (
    "Safe Pyfhel context serialization is unavailable in this Pyfhel version; "
    "pickle fallback is disabled."
)
_DESERIALIZE_UNAVAILABLE = (
    "Safe Pyfhel context deserialization is unavailable in this Pyfhel version; "
    "pickle fallback is disabled."
)


@dataclass
class HEParams:
    """Parameters for an experimental homomorphic encryption context."""

    scheme: str = "CKKS"
    options: dict[str, Any] = field(default_factory=dict)


class HEBackend:
    """Abstract homomorphic encryption backend."""

    def keygen(self, params: HEParams) -> Any:  # pragma: no cover - interface
        raise NotImplementedError

    def encrypt(
        self, ctx: Any, value: Number | Iterable[Number]
    ) -> Any:  # pragma: no cover - interface
        raise NotImplementedError

    def decrypt(self, ctx: Any, ctxt: Any) -> Number | list[Number]:  # pragma: no cover
        raise NotImplementedError

    def add(self, ctx: Any, c1: Any, c2: Any) -> Any:  # pragma: no cover - interface
        raise NotImplementedError

    def multiply(self, ctx: Any, c1: Any, c2: Any) -> Any:  # pragma: no cover
        raise NotImplementedError

    def serialize_context(self, ctx: Any) -> bytes:  # pragma: no cover - interface
        raise NotImplementedError

    def load_context(self, data: BytesLike) -> Any:  # pragma: no cover - interface
        raise NotImplementedError


class PyfhelBackend(HEBackend):
    """Backend implementation using the optional Pyfhel library."""

    def __init__(self) -> None:
        if Pyfhel is None:  # pragma: no cover - dependency missing
            raise MissingDependencyError(
                "Pyfhel is required for experimental homomorphic encryption features"
            )

    _CKKS_DEFAULTS: dict[str, Any] = {
        "n": 2**14,
        "scale": 2**30,
        "qi_sizes": [60, 30, 30, 60],
    }
    _BFV_DEFAULTS: dict[str, Any] = {"n": 2**14, "t_bits": 20}

    def keygen(self, params: HEParams) -> Pyfhel:
        scheme = params.scheme.upper()
        he = Pyfhel()
        opts = params.options.copy()
        if scheme == "CKKS":
            base = self._CKKS_DEFAULTS.copy()
        elif scheme == "BFV":
            base = self._BFV_DEFAULTS.copy()
        else:  # pragma: no cover - validation
            raise EncryptionError(f"Unsupported scheme: {params.scheme}")
        base.update(opts)
        he.contextGen(scheme=scheme, **base)
        he.keyGen()
        he.scheme = scheme  # type: ignore[attr-defined]
        return he

    def encrypt(self, he: Pyfhel, value: Number | Iterable[Number]) -> PyCtxt:
        if he.scheme == "CKKS":  # type: ignore[attr-defined]
            return he.encryptFrac(value)
        return he.encryptInt(value)

    def decrypt(self, he: Pyfhel, ctxt: PyCtxt) -> Number | list[Number]:
        if he.scheme == "CKKS":  # type: ignore[attr-defined]
            res = he.decryptFrac(ctxt)
            if isinstance(res, list) and len(res) == 1:
                return float(res[0])
            return res
        return he.decryptInt(ctxt)

    def add(self, he: Pyfhel, c1: PyCtxt, c2: PyCtxt) -> PyCtxt:
        return c1 + c2

    def multiply(self, he: Pyfhel, c1: PyCtxt, c2: PyCtxt) -> PyCtxt:
        return c1 * c2

    def serialize_context(self, he: Pyfhel) -> bytes:
        serializer = getattr(he, "to_bytes_context", None)
        if serializer is None:
            raise UnsupportedOperationError(_SERIALIZE_UNAVAILABLE)
        try:
            data = serializer()
        except Exception as exc:  # pragma: no cover - backend-specific
            raise UnsupportedOperationError(
                "Pyfhel context serialization failed without exposing context data."
            ) from exc
        if not isinstance(data, bytes | bytearray | memoryview):
            raise UnsupportedOperationError(
                "Pyfhel context serialization returned a non-bytes value."
            )
        return bytes(data)

    def load_context(self, data: BytesLike) -> Pyfhel:
        serialized = _validated_context_bytes(data)
        he = Pyfhel()
        loader = getattr(he, "from_bytes_context", None)
        if loader is None:
            raise UnsupportedOperationError(_DESERIALIZE_UNAVAILABLE)
        try:
            loader(serialized)
            he.keyGen()
        except Exception as exc:
            raise UnsupportedOperationError(
                "Serialized Pyfhel context could not be loaded safely."
            ) from exc
        return he


def _validated_context_bytes(data: BytesLike) -> bytes:
    if not isinstance(data, bytes | bytearray | memoryview):
        raise UnsupportedOperationError(
            "Safe Pyfhel context loading requires serialized bytes."
        )
    serialized = bytes(data)
    if not serialized:
        raise UnsupportedOperationError(
            "Safe Pyfhel context loading requires non-empty serialized bytes."
        )
    return serialized


__backend: HEBackend | None = None


def _get_backend() -> HEBackend:
    global __backend
    if __backend is None:
        __backend = PyfhelBackend()
    return __backend


def keygen(scheme: str = "CKKS", **options: Any) -> Any:
    """Generate an experimental homomorphic encryption context."""

    params = HEParams(scheme=scheme, options=options)
    return _get_backend().keygen(params)


def encrypt(he: Any, value: Number | Iterable[Number]) -> Any:
    """Encrypt ``value`` using the provided experimental context."""

    return _get_backend().encrypt(he, value)


def decrypt(he: Any, ctxt: Any) -> Number | list[Number]:
    """Decrypt ``ctxt`` using the provided experimental context."""

    return _get_backend().decrypt(he, ctxt)


def add(he: Any, c1: Any, c2: Any) -> Any:
    """Add two experimental FHE ciphertexts."""

    return _get_backend().add(he, c1, c2)


def multiply(he: Any, c1: Any, c2: Any) -> Any:
    """Multiply two experimental FHE ciphertexts."""

    return _get_backend().multiply(he, c1, c2)


def serialize_context(he: Any) -> bytes:
    """Serialize an FHE context only through Pyfhel's native safe byte API."""

    return _get_backend().serialize_context(he)


def load_context(data: BytesLike) -> Any:
    """Load an FHE context only through Pyfhel's native safe byte API."""

    return _get_backend().load_context(data)


fhe_keygen = keygen
fhe_encrypt = encrypt
fhe_decrypt = decrypt
fhe_add = add
fhe_multiply = multiply
fhe_serialize_context = serialize_context
fhe_load_context = load_context

__all__ = [
    "FHE_AVAILABLE",
    "PYFHEL_AVAILABLE",
    "HEParams",
    "HEBackend",
    "PyfhelBackend",
    "keygen",
    "encrypt",
    "decrypt",
    "add",
    "multiply",
    "serialize_context",
    "load_context",
    "fhe_keygen",
    "fhe_encrypt",
    "fhe_decrypt",
    "fhe_add",
    "fhe_multiply",
    "fhe_serialize_context",
    "fhe_load_context",
]
