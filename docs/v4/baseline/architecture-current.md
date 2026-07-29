# Current architecture

## Runtime shape

The current release is a broad cryptographic toolkit. Its actual dependency
direction is approximately:

```text
cryptography_suite.__init__ (111 root exports)
 ├─ symmetric / asymmetric / hashing / hybrid / PQC
 ├─ protocols / key management / OTP / PAKE / secret sharing
 ├─ keystores ── local / mock HSM / PKCS#11 / AWS KMS
 ├─ crypto_backends ── registry + pyca adapter
 ├─ pipeline ── primitive-oriented DSL + formal-text exporters
 ├─ audit / core settings / logging / operations
 └─ experimental / FHE / ZK / Signal / visualization / code generation
```

Static AST accounting found 82 tracked Python files in the four runtime source
trees, 196 internal import statements (175 unique source/target pairs), and
24 modules importing pyca/cryptography. `cryptography_suite.cli` has the largest
internal fan-out (25 import statements), followed by `pipeline` (13) and the
`src/cryptography_suite` wrapper (13).

Package-level internal edges are:

| Source | Direct internal dependency groups |
| --- | --- |
| package root | symmetric, asymmetric, signatures, hashing, hybrid, protocols, utils, X.509, audit, errors, crypto backends |
| `aead` / AEAD plugin | nonce/exceptions; plugin uses upstream primitives directly |
| `asymmetric` | errors, utils |
| `cli` | core operations/logging, codegen, backends, errors, hashing, keystores, pipeline, protocols, symmetric |
| `codegen` | errors |
| `core` / config / debug | core errors/settings/logging; config snapshots core settings |
| `crypto_backends` | AEAD/KDF protocols, pyca adapter, symmetric implementations |
| `experimental` / homomorphic / ZK | errors, constants, utils, optional third-party backends |
| `hashing` | errors |
| `hybrid` | asymmetric, errors, utils |
| `keystores` | audit, core logging/operations, asymmetric/signatures, errors, utils, atomic key-file writer |
| `pipeline` | core logging, rich logging, symmetric KDF/AES, asymmetric, hybrid, PQC |
| `pqc` | errors, symmetric HKDF, utils/KeyVault |
| `protocols` | asymmetric, errors, utils, atomic key-file writer |
| `symmetric` | constants, debug, errors, utils |
| `viz` | pipeline descriptions |
| `src/cryptography_suite` | mutates paths and dynamically aliases `src/crypto_suite` |
| `src/crypto_suite` | alternate AEAD/nonce/exceptions, protobuf handshake, zeroize |
| `src/suite` | alternate experimental warnings |

## Current subsystems

| Area | Current responsibility | v4 direction |
| --- | --- | --- |
| Package root | Re-exports primitives, protocols, utilities, errors, and backend controls | Replace with a small high-level envelope API |
| Symmetric/asymmetric/hash/protocol modules | Low-level and example primitives | Move to labs, except explicit legacy decrypt/migration adapters |
| `symmetric/aes.py` | Password-based one-shot and streaming CSF file format | Preserve decrypt compatibility only; replace encryption with v4 envelopes |
| Keystores | Local files, mock HSM, PKCS#11, AWS KMS | Rewrite as provider interfaces with conformance tests and no raw long-term key export |
| Backend registry | Context-local mutable implementation selection | Replace with explicit provider/configuration objects |
| Pipeline | Runtime composition and simplistic formal exporters | Move to labs |
| Audit | Optional decorator and encrypted-line logger | Rewrite as structured, secret-free audit events |
| CLI | Primitive, file, plugin, migration, codegen, export, fuzz commands | Rewrite around seal/open/inspect/rewrap/providers/policies/migration |
| Experimental/research | PQC, FHE, ZK, Signal, BLS, visualization | Separate labs distribution |

## State and control flow

The v3 code mixes global process state with context-local state:

- settings are cached and also copied into module globals;
- backend selection uses `ContextVar`, but registration is a global dictionary;
- keystore plugins and load failures use global mutable collections;
- the pipeline module has a global class registry;
- the audit logger is a global singleton;
- CLI output format, operational metrics, cancellation, warning guards, and
  optional-module availability are process state.

This prevents a single, explicit v4 application context from owning provider,
policy, audit, and lifecycle state. Phase 2 should define that ownership before
Phase 3 moves files.

## Source-of-truth conflicts

The built package comes from `cryptography_suite/`, while the desired v4
architecture requires `src/cryptography_suite/`. The existing
`src/cryptography_suite/__init__.py` is not a canonical implementation: it
mutates search paths and imports/aliases modules from `src/crypto_suite/`.
The excluded trees contain behavior differences, including nonce tracking and
AEAD construction. They cannot be merged mechanically without explicit API and
format decisions.

## Dependency shape

The core dependency is pyca/cryptography. Optional modules dynamically import
`aiofiles`, `blake3`, `boto3`, `cffi`, `ipywidgets`, `jinja2`, `networkx`,
`pkcs11`, `pqcrypto`, `py_ecc`, `pybulletproofs`, `pysnark`, `requests`,
`rich`, `spake2`, and `yaml`. Experimental legacy code also imports
PyCryptodome/`Crypto` and third-party Ascon/Salsa20 packages.
