"""Experimental and optional features of :mod:`cryptography_suite`.

These APIs are not part of the stable public interface and may change or be
removed without notice. Import them explicitly, e.g.::

    from cryptography_suite.experimental import kyber_encrypt
"""

from typing import Any

DEPRECATED_MSG = (
    "This function is deprecated and will be removed in v4.0.0. For reference/education only. DO NOT USE IN PRODUCTION."
)

# Signal protocol ------------------------------------------------------------
try:  # pragma: no cover - pure Python experimental feature
    from .signal import (
        SignalSender,
        SignalReceiver,
        initialize_signal_session,
        x3dh_initiator,
        x3dh_responder,
    )

    SIGNAL_AVAILABLE = True
except Exception:  # pragma: no cover - shouldn't happen but keep consistent
    SignalSender = SignalReceiver = initialize_signal_session = None  # type: ignore
    x3dh_initiator = x3dh_responder = None  # type: ignore
    SIGNAL_AVAILABLE = False

# Post-quantum cryptography --------------------------------------------------
try:  # pragma: no cover - optional dependency
    from ..pqc import (
        PQCRYPTO_AVAILABLE,
        SPHINCS_AVAILABLE,
        dilithium_sign,
        dilithium_verify,
        generate_dilithium_keypair,
        generate_kyber_keypair,
        generate_sphincs_keypair,
        kyber_decrypt,
        kyber_encrypt,
        sphincs_sign,
        sphincs_verify,
    )
except Exception:  # pragma: no cover - fallback when pqcrypto is missing
    PQCRYPTO_AVAILABLE = False
    SPHINCS_AVAILABLE = False
    dilithium_sign = dilithium_verify = None  # type: ignore
    generate_dilithium_keypair = None  # type: ignore
    generate_kyber_keypair = None  # type: ignore
    generate_sphincs_keypair = None  # type: ignore
    kyber_decrypt = kyber_encrypt = None  # type: ignore
    sphincs_sign = sphincs_verify = None  # type: ignore

# Homomorphic encryption -----------------------------------------------------
fhe_add: Any
fhe_decrypt: Any
fhe_encrypt: Any
fhe_keygen: Any
fhe_load_context: Any
fhe_multiply: Any
fhe_serialize_context: Any
try:  # pragma: no cover - optional dependency
    from ..homomorphic import (
        add as fhe_add,
        decrypt as fhe_decrypt,
        encrypt as fhe_encrypt,
        keygen as fhe_keygen,
        load_context as fhe_load_context,
        multiply as fhe_multiply,
        serialize_context as fhe_serialize_context,
        PYFHEL_AVAILABLE as _PYFHEL_AVAILABLE,
    )

    FHE_AVAILABLE = _PYFHEL_AVAILABLE
except Exception:  # pragma: no cover - handle missing Pyfhel
    fhe_add = (
        fhe_decrypt
    ) = (
        fhe_encrypt
    ) = (
        fhe_keygen
    ) = (
        fhe_load_context
    ) = (
        fhe_multiply
    ) = (
        fhe_serialize_context
    ) = None  # type: ignore[assignment]
    FHE_AVAILABLE = False

# Zero-knowledge proofs ------------------------------------------------------
bulletproof: Any
try:  # pragma: no cover - optional dependency
    from ..zk import bulletproof as bulletproof_module

    bulletproof = bulletproof_module
    BULLETPROOF_AVAILABLE = True
except Exception:  # pragma: no cover - handle missing dependency
    bulletproof = None
    BULLETPROOF_AVAILABLE = False

zksnark: Any
try:  # pragma: no cover - optional dependency
    from ..zk import zksnark as zksnark_module

    zksnark = zksnark_module
    ZKSNARK_AVAILABLE = getattr(zksnark_module, "ZKSNARK_AVAILABLE", False)
except Exception:  # pragma: no cover - handle missing dependency
    zksnark = None
    ZKSNARK_AVAILABLE = False

# Visualization widgets ------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from ..viz import HandshakeFlowWidget, KeyGraphWidget, SessionTimelineWidget
except Exception:  # pragma: no cover - widgets may be unavailable
    HandshakeFlowWidget = KeyGraphWidget = SessionTimelineWidget = None  # type: ignore

__all__ = [
    # PQC
    "PQCRYPTO_AVAILABLE",
    "SPHINCS_AVAILABLE",
    "dilithium_sign",
    "dilithium_verify",
    "generate_dilithium_keypair",
    "generate_kyber_keypair",
    "generate_sphincs_keypair",
    "kyber_decrypt",
    "kyber_encrypt",
    "sphincs_sign",
    "sphincs_verify",
    # Signal
    "SIGNAL_AVAILABLE",
    "SignalSender",
    "SignalReceiver",
    "initialize_signal_session",
    "x3dh_initiator",
    "x3dh_responder",
    # Homomorphic
    "FHE_AVAILABLE",
    "fhe_keygen",
    "fhe_encrypt",
    "fhe_decrypt",
    "fhe_add",
    "fhe_multiply",
    "fhe_serialize_context",
    "fhe_load_context",
    # ZK proofs
    "BULLETPROOF_AVAILABLE",
    "bulletproof",
    "ZKSNARK_AVAILABLE",
    "zksnark",
    # Visualization
    "HandshakeFlowWidget",
    "KeyGraphWidget",
    "SessionTimelineWidget",
]

def __getattr__(name: str) -> Any:
    if name in {"salsa20_encrypt", "salsa20_decrypt", "ascon_encrypt", "ascon_decrypt"}:
        raise RuntimeError(DEPRECATED_MSG)
    raise AttributeError(name)
