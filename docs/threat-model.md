# Threat Model

## Trust Model v1

- **Keys**: generated or imported through documented sources; the library
  provides best-effort cleanup helpers but assumes applications keep keys
  confidential.
- **Randomness**: relies on the operating system's CSPRNG; deployments must ensure sufficient entropy.
- **KDF parameters**: conservative defaults are provided; tuning is bounded by documented ranges.
- **Padding choices**: authenticated modes are preferred; explicit padding helpers validate lengths.
- **Configuration surface**: minimal knobs to reduce foot-guns; unsafe switches require explicit opt-in.

## Misuse-Resistance Principles

### Must

- Prefer conservative defaults for documented examples.
- Fail closed on invalid or missing parameters.
- Emit clear warnings when leaving secure operating envelopes.

### Should

- Offer contextual documentation and hints.
- Encourage composition patterns that avoid nonce and key reuse.

## Abuser Stories

- **Developer reuses a nonce**: examples should prefer APIs that generate or
  validate nonces.
- **Developer picks trivial KDF iterations**: helpers should reject or warn on
  weak settings where policy checks exist.
- **Developer encrypts with password only**: docs should call out password
  entropy and KDF parameters.
- **Developer transmits unauthenticated data**: examples should prefer
  authenticated modes.
