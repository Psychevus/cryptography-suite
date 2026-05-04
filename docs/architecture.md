# Architecture Hardening Plan

## Target Structure

```text
cryptography_suite/
  core/                    # Pure domain primitives (errors, settings, structured logging)
  application/             # Service orchestration, use-cases, workflows
  crypto_backends/         # Backend adapters (pyca, HSM, cloud KMS)
  asymmetric/              # Interface-facing crypto modules
  symmetric/
  protocols/
  keystores/
  cli.py                   # CLI interface layer
  __init__.py              # Public API facade only
```

### Boundary Rules

1. `core` has no dependency on adapters (`crypto_backends`, `keystores`) or interface code (`cli`).
2. `application` may depend on `core` and domain modules, but not vice versa.
3. Interface and adapter layers (`cli`, `crypto_backends`, `keystores`) can depend inward only.
4. Public facade (`__init__.py`) should re-export symbols without operational side effects.

## Implemented in this refactor

- Added typed runtime settings in `cryptography_suite.core.settings` with explicit `dev/test/prod` separation.
- Added typed error codes in `cryptography_suite.core.errors` and connected public exceptions.
- Added structured logging + correlation IDs in `cryptography_suite.core.logging`.
- Hardened pipeline module registration to be idempotent and deterministic.

## Safe Incremental Refactor Plan (commit-sized)

1. **Create core primitives**: settings, error code model, structured logging.
2. **Compatibility bridge**: keep `cryptography_suite.config` and `cryptography_suite.errors` API stable.
3. **Migrate hot paths**: switch pipeline logging and registry semantics.
4. **Enforce in CI**: formatting, lint, typing, tests on push/PR.
5. **Continue migration**: move orchestration code into `application/` without changing public API.

## Runtime Profiles

- `CRYPTOSUITE_ENV=dev`: local defaults, with verbose diagnostics still subject
  to secret redaction.
- `CRYPTOSUITE_ENV=test`: deterministic test profile.
- `CRYPTOSUITE_ENV=prod`: stricter profile with stronger validation and stable
  structured logs. This setting is not a deployment-safety claim.

## Error Handling Standard

All new operational errors should inherit from `SuiteError` with:

- Stable `ErrorCode` enum values.
- Human-readable message.
- Optional structured `details` map for diagnostics.

## Logging Standard

- Correlation ID attached to each log record (context local).
- Action-oriented event names (e.g., `pipeline.module.run`).
- Structured key/value payloads for machine parsing.
