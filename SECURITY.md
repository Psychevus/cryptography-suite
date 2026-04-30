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
- CLI, verbose, debug, dry-run, and structured logging paths must not print
  passwords, derived keys, raw/private keys, shared secrets, plaintext, nonces,
  or ciphertext internals. Report any suspected secret disclosure as a security
  issue.
- Prefer prompt, stdin, or file-descriptor password input. Environment variable
  and password-file inputs are supported for automation but require additional
  process and filesystem controls.
- Homomorphic encryption helpers are experimental-only under
  `cryptography_suite.experimental.fhe`. They require explicit
  `CRYPTOSUITE_ALLOW_EXPERIMENTAL=1` opt-in, are excluded from production
  security guarantees, and do not use pickle for context deserialization.

## Version support

Only latest minor releases in the most recent major line receive security fixes.

See [CONTRIBUTING.md](CONTRIBUTING.md) for patch requirements and [API stability](docs/api-stability.md) for support levels.
