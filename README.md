# Cryptography Suite

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-macOS%20|%20Linux%20|%20Windows-informational)]()
[![Version](https://img.shields.io/badge/version-3.0.0-blue)](https://github.com/Psychevus/cryptography-suite/releases/tag/v3.0.0)
[![PyPI Version](https://img.shields.io/pypi/v/cryptography-suite)](https://pypi.org/project/cryptography-suite/)

Cryptography Suite is a production-ready toolkit delivering strong cryptographic
primitives, protocol implementations and a composable pipeline framework. Version
3.0.0 introduces a backend-agnostic architecture and a suite of development
features aimed at secure, reproducible deployments.

## Key Features

- **Backend-Agnostic Core** via a Crypto Abstraction Layer
- **Pipeline DSL for Crypto Workflows**
- **Misuse-Resistant API** with an optional mypy plugin
- **Zeroization & Constant-Time Guarantees**
- **Formal Verification Export** for ProVerif and Tamarin
- **Auto-Stub Generator** for application skeletons
- **Rich Logging & Jupyter Widgets for Visualization**
- **HSM, YubiKey, PKCS#11, Cloud KMS Plugin Architecture**
- **Fuzzing Harness & Property-Based Testing**
- **Supply-Chain Attestation, SLSA, and Reproducible Builds**

## Quick Start

```python
from cryptography_suite import Pipeline, select_backend
from cryptography_suite.crypto_backends import cryptography_backend

select_backend(cryptography_backend())

pipeline = (
    Pipeline()
    >> SomeEncryptor()
    >> SomeSigner()
)
result = pipeline.run(b"important data")
```

## Installation

```bash
pip install cryptography-suite
```

For optional components:

```bash
pip install "cryptography-suite[pqc,fhe,zk,docs,viz]"
```

Supported on Python 3.10 and later.

## Documentation

Full documentation is available at
[https://psychevus.github.io/cryptography-suite](https://psychevus.github.io/cryptography-suite).
See the [Migration Guide](docs/migration_3.0.md) for upgrading from 2.x and the
[CHANGELOG](CHANGELOG.md) for detailed release history.

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on bug reports,
feature proposals and security disclosure.

## License

Cryptography Suite is released under the MIT license. Software Bill of Materials
and signed release artifacts are provided for provenance.

