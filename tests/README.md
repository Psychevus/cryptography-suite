# Tests

This directory hosts unit tests, fuzz harnesses, and property-based tests for the cryptographic primitives.

## Fuzzing vs Property Testing

- **Fuzzing (Atheris)** explores malformed inputs to trigger crashes and parsing errors.
- **Property-based tests (Hypothesis)** check semantic properties such as `decrypt(encrypt(x)) == x` and that tampered data or invalid keys raise errors.
- **Limitations:** These techniques do not prove cryptographic security; they merely increase confidence by exercising many paths.

New algorithms or backend integrations must include unit tests, an Atheris fuzz harness, and Hypothesis property tests before being merged.
