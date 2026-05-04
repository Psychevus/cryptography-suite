# API Stability Policy

## Stability Levels

| Module | Stability | Compatibility expectation |
| --- | --- | --- |
| `cryptography_suite` public facade | Learning API under hardening | Backward compatibility is intended within a major release, but security-sensitive callers should review changes closely. |
| `cryptography_suite.symmetric`, `cryptography_suite.asymmetric`, `cryptography_suite.protocols`, `cryptography_suite.pipeline` | Stable-ish with deprecations | Existing helpers generally follow SemVer; deprecations should remain functional for **two minor releases** before removal when practical. |
| `cryptography_suite.core` | Internal hardening utilities | Available to contributors, but not positioned as a standalone public cryptography API. |
| `cryptography_suite.experimental` | Unstable | May change or be removed at any time without notice. |

## Deprecation Policy

- Announce deprecations in the changelog with a `Deprecated` section.
- Emit `DeprecationWarning` at runtime.
- Removal occurs after **two minor releases**.
- Provide migration notes in `docs/migration_*.md` as applicable.

## Naming and Parameter Conventions

- Functions use verb phrases (`encrypt_message`); classes use nouns.
- Binary data accepts `bytes`. Textual parameters accept `str` with explicit encoding arguments.
- Time values are in seconds; size values are in bytes.
- Parameter names must state units (`timeout_s`, `length_bytes`).

This policy clarifies compatibility expectations for consumers of cryptography-suite.
