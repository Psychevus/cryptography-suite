# Vision v4.0.0

<!-- markdownlint-disable MD013 -->

## Problem Statement

Python developers need approachable cryptography examples that are explicit
about risk. This project explores that space while it hardens docs, tests,
secret handling, and experimental-module boundaries before a future v4 line.

## UX Principles

- Prefer conservative examples and make risky paths explicit.
- Keep the public surface small and predictable.
- Fail closed on invalid parameters where practical.
- Put warnings in both documentation and API boundaries.
- Avoid claims that are not backed by tests, review, or release evidence.

## Current Layering

The current package is organized around the real `cryptography_suite` namespace:

- `cryptography_suite.symmetric`, `cryptography_suite.asymmetric`, and
  `cryptography_suite.protocols` hold learning APIs for common primitives and
  protocols.
- `cryptography_suite.pipeline` composes selected helpers into workflow
  examples and lightweight model exports.
- `cryptography_suite.core` contains hardening utilities such as settings,
  structured logging, typed errors, and subprocess wrappers.
- `cryptography_suite.experimental` isolates opt-in research and demo modules.

## Non-goals

- Re-implementing every historical algorithm.
- Acting as a drop-in replacement for `pyca/cryptography`.
- Promising stability for experimental modules.
- Presenting release metadata, tests, or model exports as a security audit.

## Trust Model v1

Keys are handled as opaque objects with explicit lifecycle guidance.
Randomness is drawn from the OS CSPRNG and only injectable for tests. KDFs
surface parameters and warn or fail on weak settings where checks exist.
Authenticated encryption is preferred in examples. Unsafe options require
deliberately named flags or helpers.

## Compatibility Notes

The suite should teach how common Python cryptography workflows fit together,
while recommending mature audited libraries for production systems. Migration
guides should describe current `cryptography_suite` examples honestly and avoid
promising future APIs as if they already exist.
