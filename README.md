# Cryptography Suite

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Build Status](https://github.com/Psychevus/cryptography-suite/actions/workflows/quality-gate.yml/badge.svg)](https://github.com/Psychevus/cryptography-suite/actions/workflows/quality-gate.yml)

Cryptography Suite is a declaration-only v4 development skeleton. It provides
no operational encryption or decryption and is not suitable for protecting
production secrets.

Phase 3 establishes the package boundary, immutable value models, public
protocols, typed errors, and fail-closed orchestration signatures needed for
later reviewed implementation work. The package version remains `3.0.0` while
that incompatible v4 architecture is developed on the main branch.

## Current status

- No operational cryptography is implemented.
- No envelope codec or cryptographic suite is implemented.
- No command-line interface or console entry point is shipped.
- No concrete key-provider implementation is shipped.
- No policy engine or policy evaluation is implemented.
- No legacy parser, format autodetection, or migration implementation is
  shipped.
- No filesystem transactional sink is implemented.
- The project has not completed an independent security audit.

The public `Protector` methods intentionally raise `NotImplementedError` before
cryptographic, provider, filesystem, audit-sink, or network side effects.

## Stable Phase 3 surface

The package root exposes only the approved v4 declarations:

- typed error classes and `ErrorCode`;
- `EncryptionContext`, `Envelope`, and `EnvelopeMetadata`;
- `KeyProvider` and `KeyRef`;
- `Policy` and the non-operational `Protector`.

Supporting declarations live in named submodules:

- `cryptography_suite.audit`;
- `cryptography_suite.envelope`;
- `cryptography_suite.legacy`;
- `cryptography_suite.lifecycle`;
- `cryptography_suite.providers`;
- `cryptography_suite.streaming`.

The legacy namespace contains declarations only. Importing the package root
does not import the legacy or lifecycle namespaces.

## Installation for development and review

Python 3.10 or newer is required.

```bash
python -m pip install .
```

Installing the package does not provide encryption, decryption, a CLI, a
provider implementation, or migration behavior.

Repository-maintenance dependencies are available through the `dev` extra, and
documentation dependencies through the `docs` extra:

```bash
python -m pip install -e ".[dev]"
python -m pip install -e ".[docs]"
```

## Validation

The required checks include:

```bash
python -m pytest
python -m mypy src/cryptography_suite
python -m ruff check src/cryptography_suite tests
python -m black --check src/cryptography_suite tests
python -m build
```

Artifact tests verify the exact wheel and source-distribution boundaries,
absence of console entry points, exact root exports, fail-closed behavior, and
installation from outside the repository checkout.

## Historical v3 code

The historical v3 implementation and examples remain available only through
Git history and historical tags. They are not included in the current wheel or
source distribution and are not compatibility fallbacks for the v4 skeleton.

## Architecture and security documentation

- [Phase 2 RFCs](docs/v4/rfcs/)
- [Architecture documents](docs/v4/architecture/)
- [Phase 3 evidence](docs/v4/phase-3/)
- [Security policy](SECURITY.md)
- [Contributing guide](CONTRIBUTING.md)

Phase 4 implementation work has not started.
