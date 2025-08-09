# API Stability Policy

## Stability Levels

| Module | Stability | Guarantee |
| --- | --- | --- |
| `suite.recipes` | Stable | Backward-compatible within a major release. Breaking changes only with a new major version. |
| `suite.core` | Stable-with-deprecations | Follows semver; features may be deprecated but remain functional for **two minor releases** before removal. |
| `suite.experimental` | Unstable | May change or be removed at any time without notice. |

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
