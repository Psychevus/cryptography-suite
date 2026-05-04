# RFC-0001: Layered Architecture

## Context

Need to serve beginners, professionals, and researchers without cross-contamination of risk.

## Historical Decision

This RFC originally proposed a three-layer API design. That namespace layout was
not implemented as written. Current docs should describe the real
`cryptography_suite` package surface instead of promising the proposed names.

## Consequences

**Pros**

- Tailored interfaces reduce accidental misuse.
- Clear demarcation supports review.
- Maps to familiar high-level versus low-level API patterns.

**Cons**

- Increases maintenance and coordination overhead.
- Requires separate documentation per layer.
- Risk of divergence between layers if boundaries erode.

## API Design Rules

### Learning helpers

- Conservative examples.
- Minimal parameters.
- Explicit safe algorithms only.
- Stability documented per module.

### Contributor hardening utilities

- Explicit parameters.
- Documented trade-offs.
- Not positioned as a standalone public cryptography API.

### Experimental modules

- Behind feature flags or extras.
- Marked unstable.
- Warning banners.

## Parameter Strategy

### Key Derivation Functions

| Parameter | Default | Allowed Range |
|---------------|----------|-------------------------|
| Algorithm | Argon2id | Argon2id, scrypt, PBKDF2|
| Memory cost | 64 MiB | 32–1024 MiB |
| Time cost | 3 | 1–10 |

### Padding

| Parameter | Default | Allowed Range |
|-------------|---------|----------------------|
| Scheme | PKCS7 | PKCS7, none |
| Block size | 128-bit | 64–256-bit |

### Nonces

| Parameter | Default | Allowed Range |
|--------------|-----------|---------------|
| Length | 96 bits | 64–128 bits |
| Reuse policy | Forbid | N/A |

### Random Number Generation

| Parameter | Default | Allowed Range |
|-------------|----------------------------|-------------------------|
| Source | `os.urandom` via `secrets` | System CSPRNG only |
| Reseed | None | None |

### Key Sizes

| Key Type | Default | Allowed Range |
|----------|------------|------------------|
| AES | 256 bits | 128, 192, 256 |
| RSA | 2048 bits | 2048–4096 |
| ECC | P-256 | P-256, P-384, P-521 |

## Error Model

- Base `SuiteError` for all package errors.
- `ParameterError` for invalid sizes or ranges.
- `MisuseError` for nonce reuse or unsafe options.
- `UnsupportedAlgorithmError` for unavailable primitives.
  All errors provide actionable messages.

## Versioning

- Semantic Versioning.
- Deprecations announced and removed after two minor releases.
- Stability notes:
  - public facade and common helpers: learning API under hardening.
  - `cryptography_suite.core`: contributor hardening utilities.
  - `cryptography_suite.experimental`: unstable; breaking changes permitted at any time.
