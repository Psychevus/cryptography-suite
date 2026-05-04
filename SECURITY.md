# Security Policy

## Scope

`cryptography-suite` is an educational/research cryptography suite under active
hardening. It is not independently audited and is not recommended for protecting
production secrets yet.

Security fixes are accepted for the maintained package surface. Experimental
modules, optional demos, generated examples, visualization helpers, and fuzzing
harnesses are not covered by production-style support commitments. Importing
experimental modules requires the documented opt-in guard.

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

- No side-channel claims are made unless a specific module has been
  reviewed and documented for that property.
- There is no constant-time guarantee across the package; timing behavior may
  vary by backend, dependency, Python runtime, and platform.
- Deployments must provide cryptographically secure randomness and adequate entropy.
- Private keys should be encrypted with a strong password or kept in an HSM/KMS. Normal PEM helpers do not export plaintext private keys; `to_unencrypted_private_pem_unsafe` and LocalKeyStore plaintext import/write flags are for controlled testing or one-time migration only.
- `LocalKeyStore` is a development/testing backend unless you add production controls around filesystem permissions, backup handling, monitoring, and secret lifecycle management. Set `CRYPTOSUITE_STRICT_KEYS=error` in production-sensitive environments.
- CLI, verbose, debug, dry-run, and structured logging paths must not print
  passwords, derived keys, raw/private keys, shared secrets, plaintext, nonces,
  or ciphertext internals. Report any suspected secret disclosure as a security
  issue.
- Prefer prompt, stdin, or file-descriptor password input. Environment variable
  and password-file inputs are supported for automation but require additional
  process and filesystem controls.
- Homomorphic encryption helpers are experimental-only under
  `cryptography_suite.experimental.fhe`. They require explicit
  `CRYPTOSUITE_ALLOW_EXPERIMENTAL=1` opt-in and do not use pickle for context
  deserialization.
- PQC helpers, including ML-KEM/Kyber compatibility wrappers and Dilithium, are
  experimental. ML-KEM encryption returns a sealed envelope and the package does
  not expose caller-visible KEM shared secrets through the current envelope APIs.
- The Signal demo, FHE helpers, ZK helpers, BLS helpers, visualization widgets,
  code generators, and fuzzing demos require independent review before any
  high-assurance use.

## Version support

Only latest minor releases in the most recent major line receive security fixes.

See [CONTRIBUTING.md](CONTRIBUTING.md) for patch requirements and [API stability](docs/api-stability.md) for support levels.
