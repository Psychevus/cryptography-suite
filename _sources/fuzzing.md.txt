# Fuzzing and Property Testing

This project includes fuzzing harnesses powered by [Google Atheris](https://github.com/google/atheris) and property-based tests built with [Hypothesis](https://hypothesis.readthedocs.io/).

Atheris primarily helps surface memory corruption and input-parsing issues by exercising functions with large volumes of malformed data. Hypothesis targets semantic properties and invariants such as round-trip encryption and correct error handling. Neither technique can prove cryptographic soundness; they only increase confidence by exploring a wide range of behaviours.

## Local Usage

```bash
pip install -e .[dev]
cryptosuite-fuzz --runs 500
```

Use `--pipeline pipeline.yaml` to fuzz a custom pipeline.

## Continuous Integration

GitHub Actions runs the fuzzing harness weekly and on demand. Crashes are stored as workflow artifacts for regression checking.

Coverage from fuzzing is merged with the standard coverage report when possible.

## Limitations

- Atheris focuses on finding crashes and unexpected exceptions. It does not reason about protocol correctness or key strength.
- Hypothesis checks logical properties but cannot exhaust the entire input space.
- No fuzzing strategy can guarantee cryptographic security.
- Argon2-based functionality is skipped when the underlying cryptography backend does not provide Argon2.

## Test Coverage Matrix

| Primitive        | Unit Tests                     | Fuzz Harness           | Property Tests                |
|------------------|--------------------------------|------------------------|-------------------------------|
| AES-GCM          | `tests/test_encryption.py`     | `fuzz/fuzz_aes.py`     | `tests/test_aes_property.py`  |
| RSA              | `tests/test_asymmetric.py`     | `fuzz/fuzz_rsa.py`     | `tests/test_rsa_property.py`  |
| ECIES            | `tests/test_asymmetric.py`     | `fuzz/fuzz_ecies.py`   | `tests/test_ecies_property.py`|
| Pipeline modules | `tests/test_pipeline.py`       | `fuzz/fuzz_pipeline.py`| `tests/test_pipeline_property.py` |

## Contribution Requirements

New cryptographic primitives or backend implementations must include unit tests, an Atheris fuzzing harness, and Hypothesis property tests before they can be merged.
