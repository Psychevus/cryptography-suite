# Feature Maturity

This table summarizes the stability of major optional components. Items marked
as *experimental* are **not** production-ready.

| Feature | Module | Maturity | Notes |
| --- | --- | --- | --- |
| Signal Protocol (X3DH + Double Ratchet) | `cryptography_suite.experimental.signal` | Experimental | Lacks multi-session support, message counters, and long-term key storage |
| Homomorphic Encryption (Pyfhel) | `cryptography_suite.experimental.fhe` | Experimental | Opt-in only; no pickle deserialization; context serialization requires Pyfhel native byte APIs |
| Zero-Knowledge Proof Helpers | `cryptography_suite.zk` via `cryptography_suite.experimental` | Experimental | Requires optional deps; limited error handling |
| Core symmetric/asymmetric primitives | core modules | Stable | Production-ready |

