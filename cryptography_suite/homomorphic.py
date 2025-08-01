"""Homomorphic encryption helpers with pluggable backends."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, List, Union

from .errors import EncryptionError, MissingDependencyError

try:  # pragma: no cover - optional dependency
    from Pyfhel import PyCtxt, Pyfhel
    PYFHEL_AVAILABLE = True
except Exception:  # pragma: no cover - allow module import without Pyfhel
    Pyfhel = None  # type: ignore[assignment]
    PyCtxt = Any  # type: ignore[misc]
    PYFHEL_AVAILABLE = False

Number = Union[int, float]


@dataclass
class HEParams:
    """Parameters for a homomorphic encryption context."""

    scheme: str = "CKKS"
    options: dict[str, Any] = field(default_factory=dict)


class HEBackend:
    """Abstract homomorphic encryption backend."""

    def keygen(self, params: HEParams) -> Any:  # pragma: no cover - interface
        raise NotImplementedError

    def encrypt(self, ctx: Any, value: Union[Number, Iterable[Number]]) -> Any:  # pragma: no cover - interface
        raise NotImplementedError

    def decrypt(self, ctx: Any, ctxt: Any) -> Union[Number, List[Number]]:  # pragma: no cover - interface
        raise NotImplementedError

    def add(self, ctx: Any, c1: Any, c2: Any) -> Any:  # pragma: no cover - interface
        raise NotImplementedError

    def multiply(self, ctx: Any, c1: Any, c2: Any) -> Any:  # pragma: no cover - interface
        raise NotImplementedError

    def serialize_context(self, ctx: Any) -> bytes:  # pragma: no cover - interface
        raise NotImplementedError

    def load_context(self, data: bytes) -> Any:  # pragma: no cover - interface
        raise NotImplementedError


class PyfhelBackend(HEBackend):
    """Backend implementation using the Pyfhel library."""

    def __init__(self) -> None:
        if Pyfhel is None:  # pragma: no cover - dependency missing
            raise MissingDependencyError(
                "Pyfhel is required for homomorphic encryption features"
            )

    _CKKS_DEFAULTS = {"n": 2**14, "scale": 2**30, "qi_sizes": [60, 30, 30, 60]}
    _BFV_DEFAULTS = {"n": 2**14, "t_bits": 20}

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

    def encrypt(self, he: Pyfhel, value: Union[Number, Iterable[Number]]) -> PyCtxt:
        if he.scheme == "CKKS":  # type: ignore[attr-defined]
            return he.encryptFrac(value)
        return he.encryptInt(value)

    def decrypt(self, he: Pyfhel, ctxt: PyCtxt) -> Union[Number, List[Number]]:
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
        if hasattr(he, "to_bytes_context"):
            return he.to_bytes_context()  # pragma: no cover - depends on backend
        import pickle

        return pickle.dumps({"scheme": he.scheme})

    def load_context(self, data: bytes) -> Pyfhel:
        he = Pyfhel()
        if hasattr(he, "from_bytes_context"):
            he.from_bytes_context(data)  # pragma: no cover
        else:
            import pickle

            meta = pickle.loads(data)
            he.contextGen(scheme=meta.get("scheme", "CKKS"))
        he.keyGen()
        return he


__backend: HEBackend | None = None


def _get_backend() -> HEBackend:
    global __backend
    if __backend is None:
        __backend = PyfhelBackend()
    return __backend


def keygen(scheme: str = "CKKS", **options: Any) -> Any:
    """Generate a homomorphic encryption context."""

    params = HEParams(scheme=scheme, options=options)
    return _get_backend().keygen(params)


def encrypt(he: Any, value: Union[Number, Iterable[Number]]) -> Any:
    """Encrypt ``value`` using the provided context."""

    return _get_backend().encrypt(he, value)


def decrypt(he: Any, ctxt: Any) -> Union[Number, List[Number]]:
    """Decrypt ``ctxt`` using the provided context."""

    return _get_backend().decrypt(he, ctxt)


def add(he: Any, c1: Any, c2: Any) -> Any:
    """Add two ciphertexts."""

    return _get_backend().add(he, c1, c2)


def multiply(he: Any, c1: Any, c2: Any) -> Any:
    """Multiply two ciphertexts."""

    return _get_backend().multiply(he, c1, c2)


def serialize_context(he: Any) -> bytes:
    """Serialize a homomorphic context for storage."""

    return _get_backend().serialize_context(he)


def load_context(data: bytes) -> Any:
    """Load a homomorphic context from serialized ``data``."""

    return _get_backend().load_context(data)


__all__ = [
    "PYFHEL_AVAILABLE",
    "HEParams",
    "keygen",
    "encrypt",
    "decrypt",
    "add",
    "multiply",
    "serialize_context",
    "load_context",
]

