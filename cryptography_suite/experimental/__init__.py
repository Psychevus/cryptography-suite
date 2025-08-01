"""Experimental and optional features of :mod:`cryptography_suite`.

These APIs are not part of the stable public interface and may change or be
removed without notice. Import them explicitly, e.g.::

    from cryptography_suite.experimental import kyber_encrypt
"""

from typing import Any

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
try:  # pragma: no cover - optional dependency
    from ..homomorphic import (
        add as fhe_add,
        decrypt as fhe_decrypt,
        encrypt as fhe_encrypt,
        keygen as fhe_keygen,
        multiply as fhe_multiply,
    )

    FHE_AVAILABLE = True
except Exception:  # pragma: no cover - handle missing Pyfhel
    fhe_add = fhe_decrypt = fhe_encrypt = fhe_keygen = fhe_multiply = None  # type: ignore
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
    # Homomorphic
    "FHE_AVAILABLE",
    "fhe_keygen",
    "fhe_encrypt",
    "fhe_decrypt",
    "fhe_add",
    "fhe_multiply",
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
