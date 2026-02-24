# Fuzzing and Property Testing

This project uses [Google Atheris](https://github.com/google/atheris) fuzz harnesses and [Hypothesis](https://hypothesis.readthedocs.io/) property tests.

- **Atheris** stresses parsing and edge-case execution paths to find crashes and unexpected exceptions.
- **Hypothesis** validates invariants such as encrypt/decrypt round-trips and error behavior across broad input spaces.

Neither approach proves cryptographic soundness, but together they reduce implementation risk.

## Local usage

```bash
pip install -e .[dev]
python -m pip install atheris
cryptosuite-fuzz --runs 500
```

Use `--pipeline pipeline.yaml` to fuzz a custom pipeline.

## Continuous Integration

GitHub Actions workflow `.github/workflows/fuzz.yml` runs weekly and on manual dispatch.

- Python versions: 3.11 and 3.12
- Current CI harness execution: `python fuzz/fuzz_aes.py -runs=1000`
- Crash artifacts are uploaded for triage/regression

## Limitations

- Atheris prioritizes crash discovery, not protocol proofs.
- Hypothesis checks representative properties, not exhaustive state space.
- No fuzzing strategy alone guarantees cryptographic security.
- Argon2 functionality is skipped when backend support is unavailable.

## Coverage matrix

| Primitive | Unit tests | Fuzz harness | Property tests |
|---|---|---|---|
| AES-GCM | `tests/test_encryption.py` | `fuzz/fuzz_aes.py` | `tests/test_aes_property.py` |
| RSA | `tests/test_asymmetric.py` | `fuzz/fuzz_rsa.py` | `tests/test_rsa_property.py` |
| ECIES | `tests/test_asymmetric.py` | `fuzz/fuzz_ecies.py` | `tests/test_ecies_property.py` |
| Pipeline modules | `tests/test_pipeline.py` | `fuzz/fuzz_pipeline.py` | `tests/test_pipeline_property.py` |
