# Security Policy

## Scope

Production security guarantees apply to `suite.recipes` and `suite.core` only. The `suite.experimental` package is research-only and excluded from support. Importing experimental modules emits an explicit runtime warning.

## Responsible disclosure

Please report suspected vulnerabilities privately to **psychevus@gmail.com** with subject line `SECURITY: cryptography-suite`.

- Preferred contact: [psychevus@gmail.com](mailto:psychevus@gmail.com)
- Public tracker (non-sensitive reports only): [GitHub Security Advisories](https://github.com/Psychevus/cryptography-suite/security/advisories)

Please do **not** open public GitHub issues for exploitable vulnerabilities before coordinated disclosure.

### Disclosure process targets

- Initial acknowledgment: within 5 business days
- Status update cadence: at least every 14 days while triaging/fixing
- Coordinated disclosure target: within 90 days when feasible

## Risk acceptance & limitations

- No side-channel hardening claims are made unless explicitly stated.
- Constant-time hardening is ongoing and may vary by backend/platform.
- Deployments must provide cryptographically secure randomness and adequate entropy.
- Private keys should be encrypted with a strong password or kept in an HSM/KMS. Normal PEM helpers do not export plaintext private keys; `to_unencrypted_private_pem_unsafe` and LocalKeyStore plaintext import/write flags are for controlled testing or one-time migration only.
- `LocalKeyStore` is a development/testing backend unless you add production controls around filesystem permissions, backup handling, monitoring, and secret lifecycle management. Set `CRYPTOSUITE_STRICT_KEYS=error` in production-sensitive environments.

## Version support

Only latest minor releases in the most recent major line receive security fixes.

See [CONTRIBUTING.md](CONTRIBUTING.md) for patch requirements and [API stability](docs/api-stability.md) for support levels.
