# Vision v4.0.0

<!-- markdownlint-disable MD013 -->

## Problem Statement

pyca/cryptography dominates Python cryptography but exposes sharp edges and uneven defaults.
Projects need a suite that defaults to safe parameters, layers APIs for different skill levels,
and still allows research explorations.

## UX Principles

- Safe by default and explicit about risk.
- Small, predictable surface area.
- Errors fail closed with clear guidance.
- Documentation and warnings embedded in the API.

## API Layering Philosophy

`suite.recipes` provides narrow, opinionated helpers for common tasks.
`suite.core` exposes primitives with explicit parameters and documented trade-offs.
`suite.experimental` isolates research features and demands explicit opt-in.

## Non-goals

- Re-implementing every historical algorithm.
- Guaranteeing stability for experimental modules.
- Acting as a drop-in replacement for arbitrary third‑party extensions.

## Trust Model v1

Keys are handled as opaque objects with explicit lifecycle management.
Randomness is drawn from the OS CSPRNG and only injectable for tests.
KDFs surface parameters like iterations or memory cost but warn on weak settings.
Padding and mode choices default to authenticated encryption.
Configuration is limited to reduce foot-guns; unsafe options require deliberate flags.

## Compatibility & Migration

| pyca/cryptography use-case | Planned suite API |
| --- | --- |
| `AESGCM.encrypt` for AEAD | `suite.recipes.aead.encrypt` or `suite.core.aead.AESGCM` |
| RSA signing via `hazmat.primitives.asymmetric.rsa` | `suite.recipes.sign` or `suite.core.signatures.RSA` |
| `PBKDF2HMAC` for password derivation | `suite.recipes.kdf.derive` or `suite.core.kdf.pbkdf2` |
| Fernet token handling | `suite.recipes.tokens.fernet` |

The suite will provide adapters and guides to migrate existing pyca/cryptography code.
Common patterns such as AEAD encryption, RSA signatures, PBKDF2, and Fernet tokens map
directly to the planned APIs above.
