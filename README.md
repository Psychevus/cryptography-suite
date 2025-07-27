# Cryptography Suite

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-informational)]()
[![Version](https://img.shields.io/badge/version-3.0.0-blue)](https://github.com/Psychevus/cryptography-suite/releases/tag/v3.0.0)
[![PyPI Version](https://img.shields.io/pypi/v/cryptography-suite)](https://pypi.org/project/cryptography-suite/)
[![Coverage Status](https://img.shields.io/badge/coverage-100%25-brightgreen)]()
[![Provenance](https://img.shields.io/badge/provenance-SBOM%20verified-blue)](docs/threat_model.md)
[![Signed Releases](https://img.shields.io/badge/signed%20releases-yes-brightgreen)](docs/release_process.md)
[![Fuzzed & Tested](https://img.shields.io/badge/fuzzed%20%26%20property--tested-yes-blueviolet)](docs/fuzzing.md)
[![Misuse Resistant](https://img.shields.io/badge/misuse--resistant-mypy%20plugin-lightgrey)](docs/mypy_plugin.md)
[![Contributions](https://img.shields.io/badge/contributions-welcome-blue)](CONTRIBUTING.md)

Cryptography Suite is a backend-agnostic, audit-friendly library delivering advanced cryptographic workflows in Python. Version 3.0.0 adds a composable pipeline framework, runtime backend selection, and reproducible signed artifacts.

## Documentation

- [Full Documentation](https://psychevus.github.io/cryptography-suite)
- [API Reference](https://psychevus.github.io/cryptography-suite/api/modules.html)
- [Changelog](CHANGELOG.md)
- [Migration Guide](docs/migration_3.0.md)

## Why Choose Cryptography Suite 3.0.0?

- **Backend-Agnostic Core** – choose crypto providers at runtime via a plugin system.
- **Pipeline DSL** – build composable, declarative pipelines with type safety.
- **Misuse-Resistant API** – mypy plugin enforces correct parameter usage.
- **Zeroization & Constant-Time Guarantees** – protects secrets from side channels.
- **Formal Verification Export** – generate ProVerif or Tamarin models from pipelines.
- **Auto-Stub Generator** – create FastAPI, Flask, Node or gRPC stubs from pipeline definitions.
- **Rich Logging & Jupyter Visualization** – monitor operations and render interactive graphs.
- **HSM & Cloud KMS Integration** – operate with PKCS#11, AWS, Azure and GCP key stores.
- **Fuzzing & Property Testing** – CI harnesses provide coverage and regression tests.
- **Supply-Chain Security** – signed, reproducible builds with SBOM and provenance.

## Installation

```bash
pip install cryptography-suite
```

Optional extras:

```bash
pip install "cryptography-suite[pqc,fhe,zk,docs,viz]"
```

From source:

```bash
git clone https://github.com/Psychevus/cryptography-suite.git
cd cryptography-suite
pip install .
```

Requires Python 3.10 or newer.

## Quick Start

```python
from cryptography_suite import use_backend
from cryptography_suite.pipeline import Pipeline, CryptoModule
from cryptography_suite.symmetric import aes_encrypt, aes_decrypt

use_backend("pyca")

class EncryptStage(CryptoModule[bytes, bytes]):
    def __init__(self, password: str) -> None:
        self.password = password
    def run(self, data: bytes) -> bytes:
        return aes_encrypt(data.decode(), self.password).encode()

class DecryptStage(CryptoModule[bytes, bytes]):
    def __init__(self, password: str) -> None:
        self.password = password
    def run(self, data: bytes) -> bytes:
        return aes_decrypt(data.decode(), self.password).encode()

pipeline = Pipeline() >> EncryptStage("p@ss") >> DecryptStage("p@ss")
print(pipeline.run(b"secret message"))
```

## CLI Usage

```bash
cryptography-suite backends list
cryptography-suite keygen rsa --private priv.pem --public pub.pem --password pass
cryptography-suite keystore test
cryptography-suite export pipeline.yaml --format tamarin --track secret_key
cryptography-suite fuzz --pipeline pipeline.yaml --runs 100
```

## Key Features (v3.0.0)

- Symmetric and asymmetric primitives with hybrid workflows.
- Post-quantum schemes: Kyber, Dilithium and SPHINCS+.
- Zero-knowledge proofs and homomorphic encryption modules.
- Declarative pipelines with visual and formal export.
- Audit logging and keystore plugins.
- Rich logging and Jupyter widgets for visualization.
- Fuzzing and property tests integrated with CI.
- Hardware and cloud key management modules.
- Reproducible signed releases with SBOM provenance.

## Usage Patterns

Detailed guides and additional patterns are in the [documentation](https://psychevus.github.io/cryptography-suite).

### Encryption & Decryption

```python
from cryptography_suite.symmetric import aes_encrypt, aes_decrypt
cipher = aes_encrypt("hello", "password")
print(aes_decrypt(cipher, "password"))
```

### Key Management

```python
from cryptography_suite.protocols.key_management import KeyManager
km = KeyManager()
km.generate_rsa_keypair_and_save("rsa_priv.pem", "rsa_pub.pem", password="strongpass")
km.rotate_keys("./keys")
```

### Post-Quantum Cryptography

```python
from cryptography_suite.pqc import generate_kyber_keypair, kyber_encrypt, kyber_decrypt
pk, sk = generate_kyber_keypair()
ct, ss = kyber_encrypt(pk, b"hello")
kyber_decrypt(sk, ct, ss)
```

### Hybrid Encryption

```python
from cryptography_suite.hybrid import HybridEncryptor
from cryptography_suite.asymmetric import generate_rsa_keypair

priv, pub = generate_rsa_keypair()
hybrid = HybridEncryptor()
ct = hybrid.encrypt(b"secret", pub)
print(hybrid.decrypt(priv, ct))
```
### Keystore and Audit Logging

```python
from cryptography_suite.keystores.local import LocalKeyStore
from cryptography_suite.audit import set_audit_logger, InMemoryAuditLogger
audit = InMemoryAuditLogger()
set_audit_logger(audit)

ks = LocalKeyStore()
ks.sign("my-key", b"data")
for entry in audit.logs:
    print(entry)
```

### Visualization

```python
from cryptography_suite.pipeline import PipelineVisualizer
PipelineVisualizer(pipeline).render_ascii()
```
### Formal Verification Export

```bash
cryptography-suite export examples/formal/pipeline.yaml --format tamarin
```

### Fuzzing

```bash
cryptosuite-fuzz --runs 500 --pipeline examples/formal/pipeline.yaml
```

## Security Best Practices

- Store private keys in encrypted files or dedicated keystores.
- Rotate keys regularly and enforce strong passphrases.
- Enable zeroization and constant-time operations for sensitive data.
- Audit cryptographic operations using the provided logging hooks.
- Verify formal models and test coverage in CI.

## Contributing & Security

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. Security issues may be reported privately to [psychevus@gmail.com](mailto:psychevus@gmail.com). Vulnerabilities are disclosed responsibly.

## License

Released under the [MIT](LICENSE) license.

## Migration

Version 3 introduces breaking changes. Refer to [migration_3.0.md](docs/migration_3.0.md).

```python
# v2.x
cipher = aes_encrypt("data", "pass")
plain = aes_decrypt(cipher, "pass")

# v3.0.0
from cryptography_suite import Pipeline, use_backend
from cryptography_suite.pipeline import CryptoModule

use_backend("pyca")

class AESGCMEncrypt(CryptoModule[bytes, bytes]):
    def __init__(self, password: str) -> None:
        self.password = password
    def run(self, data: bytes) -> bytes:
        return aes_encrypt(data.decode(), self.password).encode()

class AESGCMDecrypt(CryptoModule[bytes, bytes]):
    def __init__(self, password: str) -> None:
        self.password = password
    def run(self, data: bytes) -> bytes:
        return aes_decrypt(data.decode(), self.password).encode()

pipe = Pipeline() >> AESGCMEncrypt("pass") >> AESGCMDecrypt("pass")
plain = pipe.run(b"data")
```

## Acknowledgements

Thanks to the open-source and academic communities whose work has made this suite possible.

**Secure by architecture. Auditable by design. Production-ready.**
