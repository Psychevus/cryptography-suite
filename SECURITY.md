# Security Policy

## Scope

Production security guarantees apply to `suite.recipes` and `suite.core` only. The `suite.experimental` package is research-only and excluded from support.

## Responsible disclosure

Please report suspected vulnerabilities to [security@example.com](mailto:security@example.com). Encrypt reports using PGP key `0xDEADBEEF` (placeholder). We aim to coordinate disclosure within 90 days.

## Risk acceptance & limitations

- No side-channel hardening claims are made unless explicitly stated.
- Constant-time implementations for critical paths are planned but not yet complete.
- The library requires platforms to provide cryptographically secure randomness; deployments must ensure adequate entropy.

## Version support

Only the latest minor releases within the most recent major version receive security fixes.

See [CONTRIBUTING.md](CONTRIBUTING.md) for requirements on submitting security fixes and [API stability](docs/api-stability.md) for module support levels.

## Threat scenarios

| Scenario | Risk | Mitigation in library | User responsibilities |
| --- | --- | --- | --- |
| Misuse of KDF parameters | Deriving weak keys | Recipes enforce safe defaults; core documents tunable ranges | Choose strong passwords and tune parameters for target hardware |
| Nonce reuse | Loss of confidentiality or integrity | AEAD APIs auto-generate nonces and reject repeats | Persist nonces or delegate management to the library |
| Weak padding | Padding oracle attacks | Recipes use authenticated modes without padding; core offers safe padding helpers | Avoid custom padding and verify data lengths |
| Password-only encryption with low entropy | Offline brute-force | High default iteration counts; warnings for low-entropy inputs | Provide high-entropy secrets or combine with additional factors |
| Supply-chain tampering | Malicious code insertion | Signed, reproducible releases | Verify signatures and hashes before deployment |

## Out of scope

- TLS termination
- Network protocols
- HSM drivers
- FIPS validation
