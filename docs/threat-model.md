# Threat Model

## Trust Model v1

- **Keys**: generated or imported through vetted sources; the library attempts to zeroise secrets after use but assumes applications keep keys confidential.
- **Randomness**: relies on the operating system's CSPRNG; deployments must ensure sufficient entropy.
- **KDF parameters**: conservative defaults are provided; tuning is bounded by documented ranges.
- **Padding choices**: authenticated modes are preferred; explicit padding helpers validate lengths.
- **Configuration surface**: minimal knobs to reduce foot-guns; unsafe switches require explicit opt-in.

## Misuse-Resistance Principles

### Must

- Provide safe defaults for all cryptographic parameters.
- Fail closed on invalid or missing parameters.
- Emit clear warnings when leaving secure operating envelopes.

### Should

- Offer contextual documentation and hints.
- Encourage composition patterns that avoid nonce and key reuse.

## Abuser Stories

- **Developer reuses a nonce**: high-level APIs auto-generate nonces and track uniqueness.
- **Developer picks trivial KDF iterations**: recipes lock in conservative iteration counts; core validates minimums.
- **Developer encrypts with password only**: APIs require explicit opt-in for weak schemes and warn about low entropy.
- **Developer transmits unpadded data**: recipes default to authenticated modes; padding helpers in core verify lengths.
