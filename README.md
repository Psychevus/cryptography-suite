# Cryptography Suite

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-informational)](<>)
[![PyPI Version](https://img.shields.io/pypi/v/cryptography-suite)](https://pypi.org/project/cryptography-suite/)
[![Build Status](https://github.com/Psychevus/cryptography-suite/actions/workflows/quality-gate.yml/badge.svg)](https://github.com/Psychevus/cryptography-suite/actions)
[![Testing Docs](https://img.shields.io/badge/testing-docs-blue)](docs/testing.md)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](CONTRIBUTING.md)

**Cryptography Suite** is a Python cryptography learning and research toolkit
under active hardening. It brings together practical examples for encryption,
hashing, signatures, key handling, pipelines, and optional research modules in
one repository, with tests and documentation that are being tightened before a
future v4 line.

This project is serious about reducing surprises, but it is not independently
audited and is not recommended for protecting production secrets yet. For
production systems, prefer mature audited libraries such as
`pyca/cryptography`, platform key management services, and hardware-backed key
storage where appropriate.

## Project Status

| Area | Current position |
| --- | --- |
| Status | Pre-v4 hardening; experimental educational suite |
| Security | Not independently audited |
| Production use | Not recommended for production secrets |
| Core example areas | Hashing, KDF helpers, common symmetric/asymmetric examples, file encryption format handling, CLI secret-input hardening, private-key serialization defaults |
| Experimental modules | PQC/ML-KEM and Dilithium, FHE, ZK, Signal demo, BLS, visualization, code generation, fuzzing demos |
| Recommended production choice | Use mature audited libraries and platform KMS/HSM controls where appropriate |
| Contribution focus | Tests, documentation accuracy, hardening, focused review |

## Vision & Scope

The near-term goal is to make the existing package honest, teachable, and
reviewable: keep useful examples working, isolate optional experiments, document
sharp edges, and remove claims that are not backed by tests, review, or release
evidence.

The `cryptography_suite.experimental` namespace is for opt-in research and demo
code. Importing experimental modules requires explicit acknowledgement through
the documented environment guard. The non-experimental public helpers are still
best treated as learning APIs unless you have performed your own threat review.

See [Vision details](docs/vision.md) for expansion.

## Documentation

[View Full Documentation](https://psychevus.github.io/cryptography-suite/)

- [Interoperability notes for pyca/cryptography users](docs/migration-from-pyca.md)
- [Current API cheat sheet](docs/cheatsheets/recipes.md)
- [Feature maturity](docs/feature_maturity.md)
- [Security policy](SECURITY.md)
- [No Surprises standardization guide](docs/no_surprises.md)
- [API/CLI Contract](API_CLI_CONTRACT.md)
- [Maintainer style guide](STYLEGUIDE.md)

______________________________________________________________________

## Key Capabilities

- **Learning APIs for common primitives**: symmetric encryption, asymmetric
  encryption, signatures, hashing, key handling, secret sharing, PAKE, and OTP.
- **Hardening work already landed**: authenticated file-decrypt writes, redacted
  verbose/debug output, safer private-key serialization defaults, isolated FHE
  context loading, and sealed ML-KEM envelope helpers.
- **Post-quantum demos**: experimental ML-KEM/Kyber compatibility wrappers,
  Dilithium signatures, and SPHINCS+ helpers (enable via
  `pip install "cryptography-suite[pqc]"`).
- **Signal Protocol demo**: minimal X3DH plus Double Ratchet demonstration under
  `cryptography_suite.experimental.signal_demo`.
- **Homomorphic encryption and ZK demos**: optional Pyfhel, Bulletproof, and
  zk-SNARK helpers exposed through experimental modules.
- **Testing posture**: Behavioral, negative, property, and regression tests are
  used to validate security-sensitive behavior. Project-wide coverage claims
  are withheld until backed by meaningful test evidence.

## 🔍 Support Matrix

<!-- SUPPORT-MATRIX-START -->

| Feature | Module | Pipeline? | CLI? | Keystore? | Status | Extra |
| --- | --- | --- | --- | --- | --- | --- |
| AESGCMDecrypt | cryptography_suite.pipeline | Yes | No | No | core example | |
| AESGCMEncrypt | cryptography_suite.pipeline | Yes | No | No | core example | |
| BULLETPROOF_AVAILABLE | | No | Yes | No | experimental | |
| ECIESX25519Decrypt | cryptography_suite.pipeline | Yes | No | No | core example | |
| ECIESX25519Encrypt | cryptography_suite.pipeline | Yes | No | No | core example | |
| FHE_AVAILABLE | | No | No | No | experimental | |
| HandshakeFlowWidget | cryptography_suite.viz.widgets | No | No | No | experimental | |
| HybridDecrypt | cryptography_suite.pipeline | Yes | No | No | core example | |
| HybridEncrypt | cryptography_suite.pipeline | Yes | No | No | core example | |
| KeyGraphWidget | cryptography_suite.viz.widgets | No | No | No | experimental | |
| KyberDecrypt | cryptography_suite.pipeline | Yes | No | No | experimental | |
| KyberEncrypt | cryptography_suite.pipeline | Yes | No | No | experimental | |
| MLKEMDecrypt | cryptography_suite.pipeline | Yes | No | No | experimental | |
| MLKEMEncrypt | cryptography_suite.pipeline | Yes | No | No | experimental | |
| PQCRYPTO_AVAILABLE | | No | Yes | No | experimental | |
| RSADecrypt | cryptography_suite.pipeline | Yes | No | No | core example | |
| RSAEncrypt | cryptography_suite.pipeline | Yes | No | No | core example | |
| SIGNAL_AVAILABLE | | No | No | No | experimental | |
| SPHINCS_AVAILABLE | | No | Yes | No | experimental | |
| SessionTimelineWidget | cryptography_suite.viz.widgets | No | No | No | experimental | |
| SignalReceiver | cryptography_suite.experimental.signal_demo | No | No | No | experimental | |
| SignalSender | cryptography_suite.experimental.signal_demo | No | No | No | experimental | |
| ZKSNARK_AVAILABLE | | No | Yes | No | experimental | |
| blake3_hash_v2 | cryptography_suite.hashing | No | No | No | deprecated | |
| bls_aggregate | cryptography_suite.asymmetric.bls | No | No | No | deprecated | |
| bls_aggregate_verify | cryptography_suite.asymmetric.bls | No | No | No | deprecated | |
| bls_sign | cryptography_suite.asymmetric.bls | No | No | No | deprecated | |
| bls_verify | cryptography_suite.asymmetric.bls | No | No | No | deprecated | |
| bulletproof | | No | Yes | No | experimental | |
| dilithium_sign | | No | No | No | experimental | |
| dilithium_verify | | No | No | No | experimental | |
| fhe_add | cryptography_suite.experimental | No | No | No | experimental | |
| fhe_decrypt | cryptography_suite.experimental | No | No | No | experimental | |
| fhe_encrypt | cryptography_suite.experimental | No | No | No | experimental | |
| fhe_keygen | cryptography_suite.experimental | No | No | No | experimental | |
| fhe_load_context | cryptography_suite.experimental | No | No | No | experimental | |
| fhe_multiply | cryptography_suite.experimental | No | No | No | experimental | |
| fhe_serialize_context | cryptography_suite.experimental | No | No | No | experimental | |
| generate_bls_keypair | cryptography_suite.asymmetric.bls | No | No | No | deprecated | |
| generate_dilithium_keypair | | No | Yes | No | experimental | |
| generate_ed448_keypair | cryptography_suite.asymmetric.signatures | No | No | No | deprecated | |
| generate_kyber_keypair | | No | Yes | No | experimental | |
| generate_ml_kem_keypair | | No | Yes | No | experimental | |
| generate_sphincs_keypair | | No | Yes | No | experimental | |
| initialize_signal_session | cryptography_suite.experimental.signal_demo | No | No | No | experimental | |
| kyber_decrypt | | No | No | No | experimental | |
| kyber_encrypt | | No | No | No | experimental | |
| ml_kem_decrypt | | No | No | No | experimental | |
| ml_kem_encrypt | | No | No | No | experimental | |
| sign_message_ed448 | cryptography_suite.asymmetric.signatures | No | No | No | deprecated | |
| sphincs_sign | | No | No | No | experimental | |
| sphincs_verify | | No | No | No | experimental | |
| verify_signature_ed448 | cryptography_suite.asymmetric.signatures | No | No | No | deprecated | |
| x3dh_initiator | cryptography_suite.experimental.signal_demo | No | No | No | experimental | |
| x3dh_responder | cryptography_suite.experimental.signal_demo | No | No | No | experimental | |
| zksnark | | No | Yes | No | experimental | |

<!-- SUPPORT-MATRIX-END -->

______________________________________________________________________

## Version 3.0.0 Highlights

Version 3.0.0 introduced the current pipeline-oriented structure and several
developer tooling experiments. These features are useful for exploration, but
they do not constitute an audit or a production-secrets recommendation.

- **Backend Registry Foundation** – backend selection APIs are available for
  future pluggable engine support.
- **Declarative Pipeline DSL** for composing and exporting workflow examples.
- **Mypy Plugin Experiment** for catching selected misuse patterns in typed
  code.
- **Zeroization Tools** – `KeyVault` and
  `secure_zero` enable best-effort memory wiping, but plain `bytes` may
  persist until garbage collection.
- **Formal Model Export** to lightweight ProVerif and Tamarin stubs that still
  require manual review and modeling.
- **Stub Generator** to scaffold new applications and services.
- **Rich Logging, Progress Bars & Interactive Widgets** for real-time insight.
- **Keystore Plugin Hooks** for local, mock HSM, PKCS#11, and AWS KMS
  experiments.
- **Integrated Fuzzing Harness** with deterministic seeds.
- **Release Tooling** for SBOM, signatures, and in-toto provenance metadata when
  the release workflow is run.
- **Pipeline Visualizer** for quick ASCII diagrams of your workflow.

Example pipeline configuration:

```python
from cryptography_suite import use_backend
from cryptography_suite.pipeline import (
    Pipeline,
    AESGCMEncrypt,
    AESGCMDecrypt,
    list_modules,
)

with use_backend("pyca"):
    p = (
        Pipeline()
        >> AESGCMEncrypt(password="pass")
        >> AESGCMDecrypt(password="pass")
    )
    assert p.run("data") == "data"
    print(list_modules())  # ['AESGCMDecrypt', 'AESGCMEncrypt']
```

Backend selection is context-local in the registry layer: each thread or async
task maintains its own active backend when using :func:`use_backend` as a
context manager. Pipeline AES modules currently do not dispatch through that
registry and ignore ``backend=...`` (with a runtime warning).

*Contributors*: new pipeline modules can be exposed with the
`@register_module` decorator in `cryptography_suite.pipeline`.

Visualize and export the pipeline:

```python
from cryptography_suite.pipeline import PipelineVisualizer

viz = PipelineVisualizer(p)
print(viz.render_ascii())  # AESGCMEncrypt -> AESGCMDecrypt
print(p.to_proverif())    # formal model stub
```

## ✨ Version 2.0.2 Highlights

- **Signed Prekey Verification** ensures X3DH session setup fails when the
  sender's prekey signature is invalid.
- **Optional One-Time Prekeys** can be mixed into the shared secret for extra
  forward secrecy.

## ✨ Version 2.0.1 Highlights

- ✅ **OTP Auto-Padding Fix**: Base32 secrets for TOTP/HOTP are now auto-padded internally to prevent decoding errors.
- 🧪 **Expanded Test Coverage** for OTP edge cases.
- 🛠 Internal cleanup and doc updates.

## ✨ Version 2.0.0 Highlights

- **Post-Quantum Readiness**: experimental ML-KEM/Kyber KEM and Dilithium signature helpers.
- **Hybrid Encryption**: Combine asymmetric encryption with AES-GCM.
- **XChaCha20-Poly1305**: Modern stream cipher support when available.
- **Key Management Enhancements**: `KeyVault` context manager and `KeyManager` utilities.
- **Audit Logging**: Decorators for tracing operations with optional encrypted logs.

______________________________________________________________________

## Installation

### Install via pip

Install the latest published release from PyPI:

```bash
pip install cryptography-suite
```

For optional functionality install extras:

```bash
pip install "cryptography-suite[pqc,fhe,zk]"
```

To include deprecated stream ciphers:

> pip install cryptography-suite[legacy]

The **SPHINCS+** signature helpers are included in the `pqc` extra and are experimental/demo-only.

> **Note**: Requires Python 3.10 or higher. Homomorphic encryption features are disabled by default, require `CRYPTOSUITE_ALLOW_EXPERIMENTAL=1`, and need `Pyfhel` installed separately if the `fhe` extra is not used.

### Install from Source

Clone the repository and install manually:

```bash
git clone https://github.com/Psychevus/cryptography-suite.git
cd cryptography-suite
pip install .
# Optional extras for development (pytest, mypy, etc.) and PQC
pip install -e ".[dev,pqc]"
```

### Quick Start CLI

```bash
pip install cryptography-suite

# Encrypt a file
cryptography-suite file encrypt --in input.txt --out encrypted.bin

# Decrypt it back
cryptography-suite file decrypt --in encrypted.bin --out output.txt

# Export a lightweight formal model stub
cryptography-suite export examples/formal/pipeline.yaml --format proverif
```

### Keystore Migration

```bash
cryptography-suite keystore migrate --from local --to mock_hsm --dry-run
# Note: aws-kms does not support raw private-key import/export migration in this CLI.
```

Omit `--key` to stream all keys. Migration is allowed only when both backends
advertise raw private-key export/import support (for example `local` ↔ `mock_hsm`).
Encrypted private-key PEMs remain encrypted during migration. Plaintext private-key
migration is refused unless `--unsafe-allow-unencrypted-private-key` is supplied for
controlled development/testing migration. Migrating between different algorithms is
not supported.

### Fuzzing

Execute the fuzz harness locally:

```bash
cryptosuite-fuzz --runs 1000
```

______________________________________________________________________

## Feature Overview

- **Symmetric Encryption**: AES-GCM and ChaCha20-Poly1305 with Argon2 key derivation by default (PBKDF2 and Scrypt also supported).
- **Asymmetric Encryption**: RSA encryption/decryption, key generation, serialization, and loading.
- **Digital Signatures**: Ed25519 and ECDSA examples, Ed448 legacy
  compatibility helpers, and BLS demo helpers.
- **Hashing Functions**: Implements SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-512, BLAKE2b, and BLAKE3 hashing algorithms.
- **Key Management**: Key generation, encrypted serialization, loading, and
  rotation helpers with stricter private-key defaults.
- **Secret Sharing**: Implementation of Shamir's Secret Sharing scheme for splitting and reconstructing secrets.
- **Hybrid Encryption**: Combine RSA/ECIES with AES-GCM for performance and security.
- **Post-Quantum Cryptography**: experimental ML-KEM/Kyber compatibility
  envelopes and Dilithium signatures for post-quantum learning demos.
- **XChaCha20-Poly1305**: Modern stream cipher support when `cryptography` exposes `XChaCha20Poly1305`.
- **Salsa20 and Ascon**: Deprecated and provided for reference only. **Not recommended for production**, removed from public imports, and scheduled for removal in v4.0.0. Use authenticated ciphers like `chacha20_encrypt`/`xchacha_encrypt` or `AESGCMEncrypt` instead.
- **Audit Logging**: Decorators and helpers for structured operation logs.
- **KeyVault Management**: Context manager for best-effort in-memory key
  cleanup.
- **Password-Authenticated Key Exchange (PAKE)**: SPAKE2 protocol examples for
  password-based key exchange.
- **One-Time Passwords (OTP)**: HOTP and TOTP algorithms for generating and verifying one-time passwords.
  > ⚠️ Secrets used for OTP (TOTP/HOTP) will now be auto-padded to prevent base32 decoding issues. No manual padding is required.
- **Utility Functions**: Includes Base62 encoding/decoding, random string
  generation, and memory-zeroing helpers.
- **Homomorphic Encryption**: Opt-in Pyfhel wrapper for CKKS and BFV schemes.
  It is experimental/demo-only.
- **Zero-Knowledge Proofs**: Bulletproof range proofs and zk-SNARK preimage proofs (optional dependencies, experimental).

______________________________________________________________________

## Backend Matrix

| Primitive | Backend | Notes |
| --- | --- | --- |
| AES-GCM | pyca/cryptography | Primary backend |
| ChaCha20-Poly1305 / XChaCha20-Poly1305 | pyca/cryptography | Primary backend |
| Salsa20 | PyCryptodome (optional) | Deprecated; provided for reference only |
| Ascon-128a | Pure Python | Experimental |
| RSA, ECDSA, Ed25519, Ed448 | pyca/cryptography | Primary backend |
| BLS12-381 | py_ecc | Optional |
| SHA-2, SHA-3, BLAKE2b | pyca/cryptography | Primary backend |
| BLAKE3 | blake3 | Primary backend |
| Argon2id, Scrypt, PBKDF2, HKDF | pyca/cryptography | Primary backend |
| Kyber, Dilithium (PQC) | pqcrypto (optional) | Optional |

See [`docs/backend_consistency.md`](docs/backend_consistency.md) for
policies on backend usage.

## Security Considerations

- **Experimental/Insecure Primitives**: Functions like `salsa20_encrypt` or `ascon_encrypt` are for research/education only and will be removed in v4.0.0. They are NOT supported for production use. If you depend on them, migrate now.
- **Audit status**: The project is not independently audited. Treat the package
  as educational/research software unless you have performed your own review.
- **Side-channel status**: The suite makes no side-channel guarantee and no
  timing-behavior guarantee across modules or platforms.
- **Verbose Mode**: Verbose and debug paths redact secret-bearing fields and no
  longer print derived keys, nonces, private keys, plaintext, or ciphertext
  internals. Keep verbose logging disabled in production unless you have a
  specific operational need.
- **Private Key Protection**: Private keys should always be stored encrypted, either with a strong
  password or in a hardware-backed keystore (HSM, KMS, etc.). Unencrypted PEMs are only acceptable
  for controlled testing or one-time migration. Use `to_encrypted_private_pem`,
  `serialize_private_key`, or `KeyManager.save_private_key(..., password=...)` for private key
  export/storage. The explicitly named `to_unencrypted_private_pem_unsafe` helper is the only
  utility path for plaintext private-key PEM export and emits a warning.
- **LocalKeyStore**: `LocalKeyStore` is for development/testing unless wrapped
  by your own filesystem, backup, monitoring, and lifecycle controls. It refuses
  plaintext private-key writes by default and preserves encrypted PEMs during
  import/export/migration.
- **Strict Key Storage**: By default, unencrypted key files trigger a warning. Set
  `CRYPTOSUITE_STRICT_KEYS=error` to refuse loading or saving unencrypted private
  keys (raising an error). To disable these checks entirely, set
  `CRYPTOSUITE_STRICT_KEYS=0` or `CRYPTOSUITE_STRICT_KEYS=false`.
- **TOTP/HOTP Hash Choice**: TOTP and HOTP use SHA-1 by default for RFC compatibility,
  but stronger hash functions are supported. These algorithms are suitable for
  second-factor authentication, NOT as general-purpose hash functions.

### Signal Protocol: Experimental Demo Only

This module is not a full Signal implementation. It lacks critical security
properties and should never be used for production or high-assurance
messaging.

______________________________________________________________________

## Migration to Pipeline API

Legacy one-shot helpers such as `aes_encrypt` and `rsa_encrypt` are now
**deprecated**. New code should build pipelines using modules like
`AESGCMEncrypt` and `RSAEncrypt`. See `docs/migration_pipeline_api.md` for
full details.

```
from cryptography_suite.pipeline import Pipeline, AESGCMEncrypt, AESGCMDecrypt

p = Pipeline() >> AESGCMEncrypt(password="pw") >> AESGCMDecrypt(password="pw")
assert p.run("secret") == "secret"
```

For a catalog of built-in modules see [docs/pipeline_catalog.md](docs/pipeline_catalog.md).

______________________________________________________________________

## 💡 Usage Examples

### Symmetric Encryption

Encrypt and decrypt messages using AES-GCM with password-derived keys.

```python
from cryptography_suite.pipeline import AESGCMEncrypt, AESGCMDecrypt

message: str = "Highly Confidential Information"
password: str = "ultra_secure_password"

encrypted_message: str = AESGCMEncrypt(password=password).run(message)
print(f"Encrypted: {encrypted_message}")

decrypted_message: str = AESGCMDecrypt(password=password).run(encrypted_message)
print(f"Decrypted: {decrypted_message}")

scrypt_encrypted: str = AESGCMEncrypt(password=password, kdf="scrypt").run(message)
print(AESGCMDecrypt(password=password, kdf="scrypt").run(scrypt_encrypted))
```

Argon2id support is provided by the `cryptography` package and requires no
additional dependencies.

### File Encryption

Stream files of any size with AES-GCM in bounded memory. New files use the v2
streaming format:

`CSF! || version=2 || KDF id || salt length || nonce length || chunk size || salt || nonce || ciphertext || tag`

The complete v2 header is authenticated as AES-GCM additional authenticated
data (AAD). During decryption, plaintext is written to a temporary file in the
same output directory and moved into place only after the GCM tag verifies.
Wrong passwords, corruption, or malformed headers never overwrite or delete a
pre-existing output path.

```python
from cryptography_suite.symmetric import encrypt_file, decrypt_file

password: str = "file_password"
encrypt_file("secret.txt", "secret.enc", password, kdf="argon2")
decrypt_file("secret.enc", "secret.out", password)
```

Legacy v1 and raw files (`salt || nonce || ciphertext+tag`) are decrypt-only
compatibility formats and must be requested explicitly:

```python
decrypt_file("legacy.enc", "legacy.out", password, allow_legacy_format=True)
```

For asynchronous applications install `aiofiles` and use the async variants:

```python
from cryptography_suite.symmetric import encrypt_file_async, decrypt_file_async
import asyncio

password = "file_password"

async def main():
    await encrypt_file_async("secret.txt", "secret.enc", password)
    await decrypt_file_async("secret.enc", "secret.out", password)

asyncio.run(main())
```

The async file helpers use the same v2 streaming format and the same
authenticate-before-replace failure behavior as the sync helpers. Legacy files
require `allow_legacy_format=True`.

### Asymmetric Encryption

Generate RSA key pairs and perform encryption/decryption.

Ciphertext and related binary outputs are returned as Base64 strings by
default. Pass `raw_output=True` to obtain raw bytes instead.

```python
from cryptography_suite.asymmetric import (
    ec_encrypt,
    generate_rsa_keypair,
    ec_decrypt,
    generate_x25519_keypair,
)
from cryptography_suite.pipeline import RSAEncrypt, RSADecrypt

private_key, public_key = generate_rsa_keypair()
message: bytes = b"Secure Data Transfer"

encrypted_message: str = RSAEncrypt(public_key=public_key).run(message)
print(f"Encrypted: {encrypted_message}")

decrypted_message: bytes = RSADecrypt(private_key=private_key).run(encrypted_message)
print(f"Decrypted: {decrypted_message}")

# Non-blocking key generation using a ThreadPoolExecutor. The call returns a
# ``Future`` which resolves to ``(private_key, public_key)``.
from cryptography_suite.asymmetric import generate_rsa_keypair_async

future = generate_rsa_keypair_async(key_size=2048)
private_async, public_async = future.result()

# Serializing keys
from cryptography_suite.utils import (
    load_encrypted_private_pem,
    load_public_pem,
    pem_to_json,
    to_encrypted_private_pem,
    to_public_pem,
)

key_password = "use-a-secret-manager-for-this"
pem_priv: str = to_encrypted_private_pem(private_key, key_password)
pem_pub: str = to_public_pem(public_key)
loaded_priv = load_encrypted_private_pem(pem_priv, key_password)
loaded_pub = load_public_pem(pem_pub)
json_pub: str = pem_to_json(public_key)
```

### Key Exchange

```python
from cryptography_suite.asymmetric import (
    generate_x25519_keypair,
    derive_x25519_shared_key,
    generate_x448_keypair,
    derive_x448_shared_key,
)

# X25519 exchange
alice_priv, alice_pub = generate_x25519_keypair()
bob_priv, bob_pub = generate_x25519_keypair()
shared_a: bytes = derive_x25519_shared_key(alice_priv, bob_pub)
shared_b: bytes = derive_x25519_shared_key(bob_priv, alice_pub)
print(shared_a == shared_b)

# X448 exchange
a_priv, a_pub = generate_x448_keypair()
b_priv, b_pub = generate_x448_keypair()
print(
    derive_x448_shared_key(a_priv, b_pub)
    == derive_x448_shared_key(b_priv, a_pub)
)
```

### Digital Signatures

Sign and verify messages using Ed25519, Ed448 or BLS.

```python
from cryptography_suite.asymmetric.signatures import (
    generate_ed25519_keypair,
    generate_ed448_keypair,
    sign_message,
    sign_message_ed448,
    verify_signature,
    verify_signature_ed448,
)

# Generate Ed25519 key pair
ed_priv, ed_pub = generate_ed25519_keypair()
signature: str = sign_message(b"Authenticate this message", ed_priv)
print(verify_signature(b"Authenticate this message", signature, ed_pub))

# Ed448 usage
ed448_priv, ed448_pub = generate_ed448_keypair()
sig448: str = sign_message_ed448(b"Authenticate this message", ed448_priv)
print(verify_signature_ed448(b"Authenticate this message", sig448, ed448_pub))

from cryptography_suite.asymmetric.bls import generate_bls_keypair, bls_sign, bls_verify

# BLS is included as a demo/legacy helper.
bls_sk, bls_pk = generate_bls_keypair()
bls_sig: bytes = bls_sign(b"Authenticate this message", bls_sk)
print(bls_verify(b"Authenticate this message", bls_sig, bls_pk))
```

### Secret Sharing

Split and reconstruct secrets using Shamir's Secret Sharing.

```python
from cryptography_suite.protocols import create_shares, reconstruct_secret

secret: int = 1234567890
threshold: int = 3
num_shares: int = 5

# Create shares
shares = create_shares(secret, threshold, num_shares)

# Reconstruct the secret
selected_shares = shares[:threshold]
recovered_secret: int = reconstruct_secret(selected_shares)
print(f"Recovered secret: {recovered_secret}")
```

### Homomorphic Encryption

Perform arithmetic over encrypted values using Pyfhel. These helpers are
experimental, disabled by default, and require
`CRYPTOSUITE_ALLOW_EXPERIMENTAL=1` before importing
`cryptography_suite.experimental`.

Context serialization uses Pyfhel's native byte APIs only. The project does
not deserialize FHE context data with `pickle`; `fhe_serialize_context` and
`fhe_load_context` raise `UnsupportedOperationError` when safe Pyfhel context
serialization is unavailable.

```python
from cryptography_suite.experimental import (
    fhe_keygen,
    fhe_encrypt,
    fhe_decrypt,
    fhe_add,
    fhe_multiply,
)

he = fhe_keygen("CKKS")

ct1: bytes = fhe_encrypt(he, 10.5)
ct2: bytes = fhe_encrypt(he, 5.25)

sum_ct: bytes = fhe_add(he, ct1, ct2)
prod_ct: bytes = fhe_multiply(he, ct1, ct2)

print(f"Sum: {fhe_decrypt(he, sum_ct)}")
print(f"Product: {fhe_decrypt(he, prod_ct)}")
```

### Zero-Knowledge Proofs

Prove knowledge of a SHA-256 preimage without revealing it. These
functions require the optional `PySNARK` dependency.

```python
from cryptography_suite.experimental import zksnark

# Zero-knowledge helpers are experimental and require PySNARK.
zksnark.setup()
hash_hex: str
proof_file: str
hash_hex, proof_file = zksnark.prove(b"secret")
print(zksnark.verify(hash_hex, proof_file))
```

### Post-Quantum Cryptography

Explore experimental ML-KEM (formerly Kyber) and Dilithium helpers for
post-quantum learning demos. These PQC helpers are not independently audited.
ML-KEM encryption returns a sealed envelope; KEM shared secrets remain internal
and are never returned by the envelope APIs. See [`tests/test_pqc.py`](tests/test_pqc.py)
for regression tests.

```python
from cryptography_suite.pqc import (
    generate_ml_kem_keypair,
    ml_kem_encrypt,
    ml_kem_decrypt,
    generate_dilithium_keypair,
    dilithium_sign,
    dilithium_verify,
)

ml_kem_pub, ml_kem_priv = generate_ml_kem_keypair()
envelope = ml_kem_encrypt(ml_kem_pub, b"hello pqc")
assert ml_kem_decrypt(ml_kem_priv, envelope) == b"hello pqc"

dl_pub, dl_priv = generate_dilithium_keypair()
sig = dilithium_sign(dl_priv, b"package")
assert dilithium_verify(dl_pub, b"package", sig)
```

### Hybrid Encryption

Combine asymmetric keys with AES-GCM for efficient encryption. See
[`tests/test_hybrid.py`](tests/test_hybrid.py).

```python
from cryptography_suite.hybrid import HybridEncryptor
from cryptography_suite.asymmetric import generate_rsa_keypair

encryptor = HybridEncryptor()
priv, pub = generate_rsa_keypair()
payload = b"hybrid message"
encrypted = encryptor.encrypt(payload, pub)
decrypted = encryptor.decrypt(priv, encrypted)

from cryptography_suite.utils import encode_encrypted_message, decode_encrypted_message

blob: str = encode_encrypted_message(encrypted)
parsed = decode_encrypted_message(blob)
```

### XChaCha20-Poly1305

Additional stream cipher available when `cryptography` exposes
`XChaCha20Poly1305`. Tested in
[`tests/test_xchacha.py`](tests/test_xchacha.py).

```python
from cryptography_suite.symmetric import xchacha_encrypt, xchacha_decrypt

key: bytes = os.urandom(32)
nonce: bytes = os.urandom(24)
data = xchacha_encrypt(b"secret", key, nonce)
plain = xchacha_decrypt(data["ciphertext"], key, data["nonce"])
```

### Secure Key Vault

Use `KeyVault` to erase keys from memory after use. Unit tests are
located in [`tests/test_utils.py`](tests/test_utils.py).

```python
from cryptography_suite.utils import KeyVault

key_material = b"supersecretkey"
with KeyVault(key_material) as buf:
    use_key(buf)
```

### Zeroization & Memory Safety

This library provides tools (`KeyVault`, `secure_zero`) for explicit
zeroization of secrets. However, due to Python's memory model, secrets
stored as plain `bytes` may remain in memory until garbage collected.
For tighter lifecycle control, use `KeyVault` or the `sensitive=True`
option on key-generation functions when handling private keys or session
secrets.

```python
from cryptography_suite.protocols import generate_aes_key

with generate_aes_key() as key_bytes:
    use_key(key_bytes)
```

### KeyManager File Handling

Persist key pairs to disk with the high-level `KeyManager` helper.

```python
from cryptography_suite.protocols import KeyManager, generate_random_password

km = KeyManager()
password = generate_random_password()
km.generate_rsa_keypair_and_save("rsa_priv.pem", "rsa_pub.pem", password)
km.generate_ec_keypair_and_save("ec_priv.pem", "ec_pub.pem", password)
```

## Advanced Protocols

### SPAKE2 Key Exchange

```python
from cryptography_suite.protocols import SPAKE2Client, SPAKE2Server

c = SPAKE2Client("pw")
s = SPAKE2Server("pw")
ck: bytes = c.compute_shared_key(s.generate_message())
sk: bytes = s.compute_shared_key(c.generate_message())
print(ck == sk)
```

Requires the optional `spake2` package.

### ECIES Encryption

```python
from cryptography_suite.asymmetric import ec_encrypt, ec_decrypt, generate_x25519_keypair

priv, pub = generate_x25519_keypair()
# ``cipher`` is Base64 encoded by default. Use ``raw_output=True`` for bytes.
cipher: str = ec_encrypt(b"secret", pub)
print(ec_decrypt(cipher, priv))
```

### Signal Protocol Messaging

> **Note**: The Signal Protocol helpers are experimental and intended for demonstrations only.

```python
from cryptography_suite.experimental.signal_demo import initialize_signal_session

sender, receiver = initialize_signal_session()
demo_msg: bytes = sender.encrypt(b"demo")  # demo-only data
print(receiver.decrypt(demo_msg))
```

## Hashing

Generate message digests with standard algorithms.

```python
from cryptography_suite.hashing import (
    sha256_hash,
    sha3_256_hash,
    sha3_512_hash,
    blake2b_hash,
    blake3_hash,
)

data = "The quick brown fox jumps over the lazy dog"
data: str = "The quick brown fox jumps over the lazy dog"
print(sha256_hash(data))
print(sha3_256_hash(data))
print(sha3_512_hash(data))
print(blake2b_hash(data))
print(blake3_hash(data))
```

______________________________________________________________________

## Running Tests

Run the behavioral, regression, and coverage checks locally:

```bash
pytest --ignore=tests/generated --cov=cryptography_suite --cov-branch --cov-report=term-missing
```

Some tests rely on optional dependencies such as `petlib` for zero-knowledge proofs.
Install extras before running them:

```bash
pip install .[zk]
```

No project-wide coverage percentage is currently claimed. Coverage should come
from meaningful behavioral, negative, property, and regression tests, not from
generated smoke tests or no-op execution.

## 🖥 Command Line Interface

Two console scripts are provided for zero-knowledge proofs:

```bash
cryptosuite-bulletproof 42
cryptosuite-zksnark secret
```

Run each command with `-h` for detailed help.

File encryption and decryption are available via the main CLI:

```bash
cryptography-suite file encrypt --in secret.txt --out secret.enc --kdf argon2
cryptography-suite file decrypt --in secret.enc --out decrypted.txt
```

______________________________________________________________________

## 🔒 Security Best Practices

- **Secure Key Storage**: Store private keys securely, using encrypted files or hardware security modules (HSMs).
- **Password Management**: Use strong, unique passwords and consider integrating with secret management solutions.
- **Key Rotation**: Regularly rotate cryptographic keys to minimize potential exposure.
- **Secret Input**: Prefer interactive prompts, stdin, or file descriptors for
  CLI passwords. Environment variables are supported for automation but are less
  safe because they can be inherited or exposed by process tooling.
- **Regular Updates**: Keep dependencies up to date to benefit from the latest security patches.
- **Post-Quantum Algorithms**: ML-KEM/Kyber and Dilithium helpers are experimental/demo-only and not independently audited; note their larger key sizes.
- **Hybrid Encryption**: Combine classical and PQC schemes during migration to mitigate potential weaknesses.

______________________________________________________________________

## 🛠 Advanced Usage & Customization

- **Custom Encryption Modes**: Extend the suite by implementing additional encryption algorithms or modes tailored to your needs.
- **Adjustable Key Sizes**: Customize RSA or AES key sizes to meet specific security and performance requirements.
- **Integration with Other Libraries**: Seamlessly integrate with other Python libraries and frameworks for enhanced functionality.
- **Optimized Performance**: Utilize performance profiling tools to optimize cryptographic operations in high-load environments.

______________________________________________________________________

## External Key Source Demos

### External Key Sources

Some examples can be adapted to keys managed outside this package by providing
wrapper classes that mimic the standard private-key interface. This is a demo
integration shape only; choose mature platform KMS/HSM tooling for real secret
protection.

```python
from cryptography_suite.asymmetric import rsa_decrypt
from my_hsm_wrapper import load_rsa_private_key

private_key = load_rsa_private_key("enterprise-key-id")
plaintext = rsa_decrypt(ciphertext, private_key)
```

______________________________________________________________________

## Release Artifact Verification

The release workflow is configured to build artifacts, generate a CycloneDX
SBOM, emit in-toto provenance metadata, and sign distributable files with
`cosign`. Treat these as verification aids for releases where the corresponding
assets are present; they are not a compliance certification.

### Verifying Downloads

1. Verify the wheel's signature:

   ```bash
   export CERT_IDENTITY="https://github.com/Psychevus/cryptography-suite/.github/workflows/release.yml@refs/tags/v3.0.0"
   export CERT_ISSUER="https://token.actions.githubusercontent.com"
   cosign verify-blob \
     --certificate-identity "$CERT_IDENTITY" \
     --certificate-oidc-issuer "$CERT_ISSUER" \
     --signature dist/<wheel>.sig \
     --certificate dist/<wheel>.cert \
     dist/<wheel>
   ```

1. Verify the source distribution, SBOM, and provenance signatures:

   ```bash
   cosign verify-blob --certificate-identity "$CERT_IDENTITY" --certificate-oidc-issuer "$CERT_ISSUER" --signature dist/<sdist>.sig --certificate dist/<sdist>.cert dist/<sdist>
   cosign verify-blob --certificate-identity "$CERT_IDENTITY" --certificate-oidc-issuer "$CERT_ISSUER" --signature dist/sbom.json.sig --certificate dist/sbom.json.cert dist/sbom.json
   cosign verify-blob --certificate-identity "$CERT_IDENTITY" --certificate-oidc-issuer "$CERT_ISSUER" --signature dist/provenance.intoto.jsonl.sig --certificate dist/provenance.intoto.jsonl.cert dist/provenance.intoto.jsonl
   ```

1. Inspect the provenance metadata:

   ```bash
   jq -r '.payload' dist/provenance.intoto.jsonl | base64 -d | jq '.statement.subject[] | .name'
   ```

The SBOM (`dist/sbom.json`) can be inspected via `cyclonedx-bom` or `pip sbom`.
Reproducibility checks run in CI via `reproducibility.yml`. See
[release process documentation](docs/release_process.md) for details on
verifying artifacts and SBOM contents.

______________________________________________________________________

## Project Structure

```plaintext
cryptography-suite/
├── cryptography_suite/
│   ├── __init__.py
│   ├── asymmetric/
│   ├── audit.py
│   ├── cli.py
│   ├── debug.py
│   ├── errors.py
│   ├── hashing/
│   ├── experimental/
│   │   ├── fhe.py
│   │   └── ...
│   ├── hybrid.py
│   ├── pqc/
│   ├── protocols/
│   │   ├── __init__.py
│   │   ├── key_management.py
│   │   ├── otp.py
│   │   ├── pake.py
│   │   ├── secret_sharing.py
│   │   └── signal/
│   ├── symmetric/
│   ├── utils.py
│   ├── x509.py
│   └── zk/
├── tests/
│   ├── test_audit.py
│   ├── test_hybrid.py
│   ├── test_pqc.py
│   ├── test_xchacha.py
│   └── ...
├── README.md
├── example_usage.py
├── demo_homomorphic.py
├── setup.py
└── .github/
    └── workflows/
        └── python-app.yml
```

______________________________________________________________________

## 🛤 Migration Guide from v1.x to v2.0.0

- **Package Layout**: Functions are now organized in subpackages such as
  `cryptography_suite.pqc` and `cryptography_suite.protocols`.
- **New Exceptions**: `MissingDependencyError` and `ProtocolError` extend
  `CryptographySuiteError`.
- **Return Types**: Encryption helpers may return `bytes` when
  `raw_output=True`.
- **Audit and Key Vault**: Use `audit_log` and `KeyVault` for logging and
  secure key handling.
- **ML-KEM/Kyber API Updates**: `ml_kem_encrypt` returns a sealed envelope and
  `ml_kem_decrypt` opens it without caller-visible KEM shared secrets. The old
  `kyber_encrypt`/`kyber_decrypt` names are compatibility wrappers; this breaks
  code that unpacked `(ciphertext, shared_secret)` or passed `shared_secret` to
  decrypt.
- **Key Management**: `KeyManager` now provides `generate_rsa_keypair_and_save`.
  The standalone `generate_rsa_keypair_and_save` helper is deprecated and will
  be removed in v4.0.0.
- **KDF Naming**: `derive_pbkdf2` is deprecated and will be removed in v4.0.0.
  Use `kdf_pbkdf2` instead.

## 🛤 Migration Guide from v2.x to v3.0.0

Version 3.0.0 introduces several breaking changes. To upgrade from 2.x:

- **Backend Selection Is Experimental**: `use_backend` currently scopes backend
  state in the registry layer only; pipeline AES modules do not yet dispatch
  through selected backends.
- **Pipeline API** replaces chained helper calls.
- **KeyManager Interfaces Updated** for persistent key handling.
- **Deprecated Helpers Removed** in favor of pipeline stages.
- See [migration_3.0.md](docs/migration_3.0.md) for full details.

______________________________________________________________________

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

______________________________________________________________________

## 🤝 Contributions

We welcome contributions from the community. See [CONTRIBUTING.md](CONTRIBUTING.md) for full guidelines and [API stability](docs/api-stability.md) expectations. To contribute:

1. **Fork the Repository**: Click on the 'Fork' button at the top right corner of the repository page.
1. **Create a New Branch**: Use a descriptive name for your branch (e.g., `feature/new-algorithm`).
1. **Commit Your Changes**: Make sure to write clear, concise commit messages.
1. **Push to GitHub**: Push your changes to your forked repository.
1. **Submit a Pull Request**: Open a pull request to the `main` branch of the original repository.

Please ensure that your contributions adhere to the project's coding standards and include relevant tests.

______________________________________________________________________

## 📬 Contact

For support or inquiries:

- **Email**: [psychevus@gmail.com](mailto:psychevus@gmail.com)
- **GitHub Issues**: [Create an Issue](https://github.com/Psychevus/cryptography-suite/issues)

______________________________________________________________________

## 🌟 Acknowledgements

Special thanks to all contributors and users who have helped improve this project through feedback and collaboration.

______________________________________________________________________

*Empower your applications with secure and reliable cryptographic functions using Cryptography Suite.*

## Operational Profiles and Configuration

The suite now uses typed settings loaded from environment variables:

- `CRYPTOSUITE_ENV`: `dev|test|prod` (default: `dev`)
- `CRYPTOSUITE_STRICT_KEYS`: `warn|error|true|false|1|0` (default: `warn`)
- `CRYPTOSUITE_LOG_LEVEL`: logging level (default: `INFO`)

### Run locally

```bash
python -m pip install -e .[dev]
pytest
```

### Run in CI

```bash
ruff format --check .
black --check .
ruff check .
mypy --follow-imports=skip --ignore-missing-imports cryptography_suite
bandit -q -r cryptography_suite -x tests,docs,examples -s B101,B110,B301,B311,B403,B404,B413,B603,B701
pip-audit -r requirements.txt --strict
pytest --ignore=tests/generated --cov=cryptography_suite --cov-branch
```

### Stricter local profile

These settings exercise stricter key handling and logging defaults. They are
useful for review and staging-like checks, but they do not make this package a
recommended home for production secrets.

```bash
export CRYPTOSUITE_ENV=prod
export CRYPTOSUITE_STRICT_KEYS=error
export CRYPTOSUITE_LOG_LEVEL=INFO
python -c "import cryptography_suite as cs; print(cs.__version__)"
```

For architecture details and migration plan, see [docs/architecture.md](docs/architecture.md).
