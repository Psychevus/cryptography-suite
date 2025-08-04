"""Experimental and optional features of :mod:`cryptography_suite`."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING or os.getenv("CRYPTOSUITE_ALLOW_EXPERIMENTAL"):
    from .signal_demo import (
        SIGNAL_AVAILABLE,
        SignalSender,
        SignalReceiver,
        initialize_signal_session,
        x3dh_initiator,
        x3dh_responder,
    )
    from .fhe import (
        FHE_AVAILABLE,
        fhe_add,
        fhe_decrypt,
        fhe_encrypt,
        fhe_keygen,
        fhe_load_context,
        fhe_multiply,
        fhe_serialize_context,
    )
    from .zk import (
        BULLETPROOF_AVAILABLE,
        ZKSNARK_AVAILABLE,
        bulletproof,
        zksnark,
    )
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

    try:  # pragma: no cover - optional dependency
        from ..viz import HandshakeFlowWidget, KeyGraphWidget, SessionTimelineWidget
    except Exception:  # pragma: no cover - widgets may be unavailable
        HandshakeFlowWidget = KeyGraphWidget = SessionTimelineWidget = None  # type: ignore

    DEPRECATED_MSG = (
        "This function is deprecated and will be removed in v4.0.0. For reference/education only. DO NOT USE IN PRODUCTION."
    )

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
else:  # pragma: no cover - executed when experimental disabled
    raise ImportError(
        "Experimental features require CRYPTOSUITE_ALLOW_EXPERIMENTAL=1 to import."
    )
