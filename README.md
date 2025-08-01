# Cryptography Suite

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-macOS%20|%20Linux%20|%20Windows-informational)]()
[![Version](https://img.shields.io/badge/version-3.0.0-blue)](https://github.com/Psychevus/cryptography-suite/releases/tag/v3.0.0)
[![PyPI Version](https://img.shields.io/pypi/v/cryptography-suite)](https://pypi.org/project/cryptography-suite/)
[![PyPI Downloads](https://img.shields.io/pypi/dm/cryptography-suite)](https://pypi.org/project/cryptography-suite/)
[![Build Status](https://github.com/Psychevus/cryptography-suite/actions/workflows/python-app.yml/badge.svg)](https://github.com/Psychevus/cryptography-suite/actions)
[![Coverage Status](https://coveralls.io/repos/github/Psychevus/cryptography-suite/badge.svg?branch=main)](https://coveralls.io/github/Psychevus/cryptography-suite?branch=main)
[![Provenance](https://img.shields.io/badge/provenance-signed-blue)](docs/release_process.md)
[![Signed Releases](https://img.shields.io/badge/releases-signed-brightgreen)](docs/release_process.md)
[![Fuzzed & Property-Tested](https://img.shields.io/badge/fuzzed--property--tested-true-brightgreen)](docs/fuzzing.md)
[![Misuse-Resistant](https://img.shields.io/badge/misuse--resistant-enabled-success)](docs/mypy_plugin.md)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](CONTRIBUTING.md)

**Cryptography Suite** is an advanced cryptographic toolkit for Python, meticulously engineered for applications demanding robust security and seamless integration. It offers a comprehensive set of cryptographic primitives and protocols, empowering developers and organizations to implement state-of-the-art encryption, hashing, key management, digital signatures, and more.

## 📚 Documentation

👉 [View Full Documentation](https://psychevus.github.io/cryptography-suite/)

---

## 🔑 Key Features

- **Comprehensive Functionality**: Symmetric and asymmetric encryption, digital signatures, key management, secret sharing, password-authenticated key exchange (PAKE), and one-time passwords (OTP).
- **Post-Quantum Primitives**: Kyber KEM, Dilithium signatures, and **experimental SPHINCS+** support (enable via `pip install "cryptography-suite[pqc]"` – demo-only, not production-grade). These are available under ``cryptography_suite.experimental``.
- **Signal Protocol Demo**: Minimal X3DH + Double Ratchet implementation located in ``cryptography_suite.experimental.signal`` (**experimental, not production-ready**).
- **Homomorphic Encryption**: Pyfhel-based helpers exposed via ``cryptography_suite.experimental`` (**experimental, demo-only**).
- **Zero-Knowledge Proof Helpers**: Bulletproof range proofs and zk-SNARK examples under ``cryptography_suite.experimental`` (**experimental**).
- **Developer-Friendly API**: Intuitive, well-documented interfaces that simplify integration and accelerate development.
- **Cross-Platform Compatibility**: Fully compatible with macOS, Linux, and Windows environments.
- **Rigorous Testing**: ~**99%** test coverage as of v3.0.0, ensuring reliability and robustness.

---

## ✨ Version 3.0.0 Highlights

Version 3.0.0 ushers in a modular design centered on formal verification and
pipeline-driven workflows. Major enhancements include:

- **Backend-Agnostic Core** – switch effortlessly between cryptographic
  libraries or hardware modules.
- **Declarative Pipeline DSL** for composing verifiable workflows.
- **Misuse-Resistant Type System** via a dedicated mypy plugin.
- **Automatic Zeroization & Constant-Time Operations** to protect secrets in
  memory.
- **Formal Verification Export** to ProVerif and Tamarin for rigorous analysis.
- **Stub Generator** to scaffold new applications and services.
- **Rich Logging, Progress Bars & Interactive Widgets** for real-time insight.
- **Extensible Plugin Architecture** for HSM and cloud KMS providers.
- **Integrated Fuzzing Harness** with deterministic seeds.
- **Supply-Chain Attestation** delivering SLSA-compliant releases.
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

Backend selection is context-local: each thread or async task maintains its
own active backend when using :func:`use_backend` as a context manager.

*Contributors*: new pipeline modules can be exposed with the
`@register_module` decorator in ``cryptography_suite.pipeline``.

Visualize and export the pipeline:

```python
from cryptography_suite.pipeline import PipelineVisualizer

viz = PipelineVisualizer(p)
print(viz.render_ascii())  # AESGCMEncrypt -> AESGCMDecrypt
print(p.to_proverif())    # formal model output
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

- **Post-Quantum Readiness**: Kyber KEM and Dilithium signature helpers.
- **Hybrid Encryption**: Combine asymmetric encryption with AES-GCM.
- **XChaCha20-Poly1305**: Modern stream cipher support when available.
- **Key Management Enhancements**: `KeyVault` context manager and `KeyManager` utilities.
- **Audit Logging**: Decorators for tracing operations with optional encrypted logs.

---

## 📦 Installation

### Install via pip

Install the latest stable release from PyPI:

```bash
pip install cryptography-suite
```

For optional functionality install extras:

```bash
pip install "cryptography-suite[pqc,fhe,zk]"
```

The **SPHINCS+** signature helpers are included in the `pqc` extra and are experimental/demo-only.

> **Note**: Requires Python 3.10 or higher. Homomorphic encryption features need `Pyfhel` installed separately if the `fhe` extra is not used.

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
cryptography-suite file encrypt --in input.txt --out encrypted.bin --password mypass

# Decrypt it back
cryptography-suite file decrypt --in encrypted.bin --out output.txt --password mypass

# Export a pipeline for formal verification
cryptography-suite export examples/formal/pipeline.yaml --format proverif
```

### Fuzzing

Execute the fuzz harness locally:

```bash
cryptosuite-fuzz --runs 1000
```

---


## 🔑 Key Features

- **Symmetric Encryption**: AES-GCM and ChaCha20-Poly1305 with Argon2 key derivation by default (PBKDF2 and Scrypt also supported).
- **Asymmetric Encryption**: RSA encryption/decryption, key generation, serialization, and loading.
- **Digital Signatures**: Support for Ed25519, **Ed448**, ECDSA, and BLS (BLS12-381) algorithms for secure message signing and verification.
- **Hashing Functions**: Implements SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-512, BLAKE2b, and BLAKE3 hashing algorithms.
- **Key Management**: Secure generation, storage, loading, and rotation of cryptographic keys.
- **Secret Sharing**: Implementation of Shamir's Secret Sharing scheme for splitting and reconstructing secrets.
- **Hybrid Encryption**: Combine RSA/ECIES with AES-GCM for performance and security.
- **Post-Quantum Cryptography**: Kyber key encapsulation and Dilithium signatures for quantum-safe workflows.
- **XChaCha20-Poly1305**: Modern stream cipher support when ``cryptography`` exposes ``XChaCha20Poly1305``.
- **Salsa20 and Ascon**: Deprecated and provided for reference only. **Not recommended for production**, removed from public imports, and scheduled for removal in v4.0.0. Use authenticated ciphers like ``chacha20_encrypt``/``xchacha_encrypt`` or ``AESGCMEncrypt`` instead.
- **Audit Logging**: Decorators and helpers for encrypted audit trails.
- **KeyVault Management**: Context manager to safely handle in-memory keys.
- **Password-Authenticated Key Exchange (PAKE)**: SPAKE2 protocol implementation for secure password-based key exchange.
 - **One-Time Passwords (OTP)**: HOTP and TOTP algorithms for generating and verifying one-time passwords.
   > ⚠️ Secrets used for OTP (TOTP/HOTP) will now be auto-padded to prevent base32 decoding issues. No manual padding is required.
- **Utility Functions**: Includes Base62 encoding/decoding, secure random string generation, and memory zeroing.
- **Homomorphic Encryption**: Wrapper around Pyfhel supporting CKKS and BFV schemes. *(experimental)*
- **Zero-Knowledge Proofs**: Bulletproof range proofs and zk-SNARK preimage proofs (optional dependencies, experimental).

---

## Backend Matrix

| Primitive | Backend | Notes |
| --- | --- | --- |
| AES-GCM | pyca/cryptography | Authoritative |
| ChaCha20-Poly1305 / XChaCha20-Poly1305 | pyca/cryptography | Authoritative |
| Salsa20 | PyCryptodome (optional) | Deprecated; provided for reference only |
| Ascon-128a | Pure Python | Experimental |
| RSA, ECDSA, Ed25519, Ed448 | pyca/cryptography | Authoritative |
| BLS12-381 | py_ecc | Optional |
| SHA-2, SHA-3, BLAKE2b | pyca/cryptography | Authoritative |
| BLAKE3 | blake3 | Authoritative |
| Argon2id, Scrypt, PBKDF2, HKDF | pyca/cryptography | Authoritative |
| Kyber, Dilithium (PQC) | pqcrypto (optional) | Optional |

See [`docs/backend_consistency.md`](docs/backend_consistency.md) for
policies on backend usage.

## ⚠️ Security Considerations

- **Insecure Ciphers**: Optional helpers like `salsa20_encrypt` provide no
  authentication and should only be used for educational purposes.
  The deprecated `salsa20_encrypt` will be removed in v4.0.0.
- **Verbose Mode**: Enabling `VERBOSE_MODE` leaks sensitive information to stdout; never
  enable it in production.
- **Private Key Protection**: Always supply a password when saving private keys to PEM
  with `serialize_private_key` or `KeyManager.save_private_key`.

---

## Migration to Pipeline API

Legacy one-shot helpers such as ``aes_encrypt`` and ``rsa_encrypt`` are now
**deprecated**. New code should build pipelines using modules like
``AESGCMEncrypt`` and ``RSAEncrypt``. See ``docs/migration_pipeline_api.md`` for
full details.

```
from cryptography_suite.pipeline import Pipeline, AESGCMEncrypt, AESGCMDecrypt

p = Pipeline() >> AESGCMEncrypt(password="pw") >> AESGCMDecrypt(password="pw")
assert p.run("secret") == "secret"
```

---

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

Stream files of any size with AES-GCM. The functions read and write in
chunks, so even large files can be processed efficiently.

```python
from cryptography_suite.symmetric import encrypt_file, decrypt_file

password: str = "file_password"
encrypt_file("secret.txt", "secret.enc", password)
decrypt_file("secret.enc", "secret.out", password)
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

### Asymmetric Encryption

Generate RSA key pairs and perform encryption/decryption.

Ciphertext and related binary outputs are returned as Base64 strings by
default. Pass ``raw_output=True`` to obtain raw bytes instead.

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
from cryptography_suite.utils import to_pem, from_pem, pem_to_json

pem_priv: str = to_pem(private_key)
loaded_priv = from_pem(pem_priv)
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

from cryptography_suite.bls import generate_bls_keypair, bls_sign, bls_verify

# Generate BLS key pair
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
experimental.

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

Leverage Kyber and Dilithium for quantum-resistant operations. See
[`tests/test_pqc.py`](tests/test_pqc.py) for thorough unit tests.

```python
from cryptography_suite.pqc import (
    generate_kyber_keypair,
    kyber_encrypt,
    kyber_decrypt,
    generate_dilithium_keypair,
    dilithium_sign,
    dilithium_verify,
)

ky_pub, ky_priv = generate_kyber_keypair()
ct, ss = kyber_encrypt(ky_pub, b"hello pqc")
assert kyber_decrypt(ky_priv, ct, ss) == b"hello pqc"

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

Additional stream cipher available when ``cryptography`` exposes
``XChaCha20Poly1305``. Tested in
[`tests/test_xchacha.py`](tests/test_xchacha.py).

```python
from cryptography_suite.symmetric import xchacha_encrypt, xchacha_decrypt

key: bytes = os.urandom(32)
nonce: bytes = os.urandom(24)
data = xchacha_encrypt(b"secret", key, nonce)
plain = xchacha_decrypt(data["ciphertext"], key, data["nonce"])
```

### Secure Key Vault

Use ``KeyVault`` to erase keys from memory after use. Unit tests are
located in [`tests/test_utils.py`](tests/test_utils.py).

```python
from cryptography_suite.utils import KeyVault

key_material = b"supersecretkey"
with KeyVault(key_material) as buf:
    use_key(buf)
```

### KeyManager File Handling

Persist key pairs to disk with the high-level ``KeyManager`` helper.

```python
from cryptography_suite.protocols import KeyManager

km = KeyManager()
km.generate_rsa_keypair_and_save("rsa_priv.pem", "rsa_pub.pem", "password")
km.generate_ec_keypair_and_save("ec_priv.pem", "ec_pub.pem", "password")
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
from cryptography_suite.experimental.signal import initialize_signal_session

sender, receiver = initialize_signal_session()
msg: bytes = sender.encrypt(b"hi")
print(receiver.decrypt(msg))
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

---

## 🧪 Running Tests

Ensure the integrity of the suite by running comprehensive tests:

```bash
coverage run -m unittest discover
coverage report -m
```

Some tests rely on optional dependencies such as `petlib` for zero-knowledge proofs.
Install extras before running them:

```bash
pip install .[zkp]
```

Our test suite achieves **99% code coverage**, guaranteeing reliability and robustness.

## 🖥 Command Line Interface

Two console scripts are provided for zero-knowledge proofs:

```bash
cryptosuite-bulletproof 42
cryptosuite-zksnark secret
```

Run each command with `-h` for detailed help.

File encryption and decryption are available via the main CLI:

```bash
cryptography-suite file encrypt --in secret.txt --out secret.enc --password mypass
cryptography-suite file decrypt --in secret.enc --out decrypted.txt --password mypass
```

---

## 🔒 Security Best Practices

- **Secure Key Storage**: Store private keys securely, using encrypted files or hardware security modules (HSMs).
- **Password Management**: Use strong, unique passwords and consider integrating with secret management solutions.
- **Key Rotation**: Regularly rotate cryptographic keys to minimize potential exposure.
- **Environment Variables**: Use environment variables for sensitive configurations to prevent hardcoding secrets.
- **Regular Updates**: Keep dependencies up to date to benefit from the latest security patches.
- **Post-Quantum Algorithms**: Use Kyber and Dilithium for data requiring long-term secrecy, noting their larger key sizes.
- **Hybrid Encryption**: Combine classical and PQC schemes during migration to mitigate potential weaknesses.

---

## 🛠 Advanced Usage & Customization

- **Custom Encryption Modes**: Extend the suite by implementing additional encryption algorithms or modes tailored to your needs.
- **Adjustable Key Sizes**: Customize RSA or AES key sizes to meet specific security and performance requirements.
- **Integration with Other Libraries**: Seamlessly integrate with other Python libraries and frameworks for enhanced functionality.
- **Optimized Performance**: Utilize performance profiling tools to optimize cryptographic operations in high-load environments.

---

## 🏢 Enterprise Features

### External Key Sources

You can inject keys managed by hardware security modules (HSMs) or cloud key
management services (KMS) by providing wrapper classes that mimic the standard
private key interface. These wrappers allow the suite to call ``decrypt`` on the
external key just like a locally generated one.

```python
from cryptography_suite.asymmetric import rsa_decrypt
from my_hsm_wrapper import load_rsa_private_key

private_key = load_rsa_private_key("enterprise-key-id")
plaintext = rsa_decrypt(ciphertext, private_key)
```

---

## 🔐 Supply Chain Security

This project provides deterministic builds and signed release artifacts.
Every GitHub release includes a CycloneDX SBOM and a `cosign` signature.
Reproducibility is tested in CI via `reproducibility.yml`. See
[release process documentation](docs/release_process.md) for details on
verifying artifacts with `tools/verify_artifact.py`.

---

## 📚 Project Structure

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
│   ├── homomorphic.py
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

---

## 🛤 Migration Guide from v1.x to v2.0.0

- **Package Layout**: Functions are now organized in subpackages such as
  ``cryptography_suite.pqc`` and ``cryptography_suite.protocols``.
- **New Exceptions**: ``MissingDependencyError`` and ``ProtocolError`` extend
  ``CryptographySuiteError``.
- **Return Types**: Encryption helpers may return ``bytes`` when
  ``raw_output=True``.
- **Audit and Key Vault**: Use ``audit_log`` and ``KeyVault`` for logging and
  secure key handling.
- **Kyber API Updates**: ``kyber_encrypt`` and ``kyber_decrypt`` accept a
  ``level`` parameter (512/768/1024). ``kyber_decrypt`` now computes the shared
  secret automatically when omitted.
- **Key Management**: ``KeyManager`` now provides ``generate_rsa_keypair_and_save``.
  The standalone ``generate_rsa_keypair_and_save`` helper is deprecated and will
  be removed in v4.0.0.
- **KDF Naming**: ``derive_pbkdf2`` is deprecated and will be removed in v4.0.0.
  Use ``kdf_pbkdf2`` instead.

## 🛤 Migration Guide from v2.x to v3.0.0

Version 3.0.0 introduces several breaking changes. To upgrade from 2.x:

- **Backend Selection Required** via ``use_backend``; the library emits a
  runtime warning if no backend is explicitly selected.
- **Pipeline API** replaces chained helper calls.
- **KeyManager Interfaces Updated** for persistent key handling.
- **Deprecated Helpers Removed** in favor of pipeline stages.
- See [migration_3.0.md](docs/migration_3.0.md) for full details.

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributions

We welcome contributions from the community. To contribute:

1. **Fork the Repository**: Click on the 'Fork' button at the top right corner of the repository page.
2. **Create a New Branch**: Use a descriptive name for your branch (e.g., `feature/new-algorithm`).
3. **Commit Your Changes**: Make sure to write clear, concise commit messages.
4. **Push to GitHub**: Push your changes to your forked repository.
5. **Submit a Pull Request**: Open a pull request to the `main` branch of the original repository.

Please ensure that your contributions adhere to the project's coding standards and include relevant tests.

---

## 📬 Contact

For support or inquiries:

- **Email**: [psychevus@gmail.com](mailto:psychevus@gmail.com)
- **GitHub Issues**: [Create an Issue](https://github.com/Psychevus/cryptography-suite/issues)

---

## 🌟 Acknowledgements

Special thanks to all contributors and users who have helped improve this project through feedback and collaboration.

---

*Empower your applications with secure and reliable cryptographic functions using Cryptography Suite.*
