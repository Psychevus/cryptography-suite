# Testing Guide

This guide explains how to run the project's tests locally and how they map to the continuous integration (CI) matrix.

## Quick start

```bash
pip install -e .[dev,fuzz]
pytest -m property
python -m atheris fuzz/fuzz_aes.py
```

The commands above install the development and fuzzing dependencies, execute property-based tests, and run a sample Atheris fuzz harness.

## Extending the fuzz harness

1. **Create a new harness** in the `fuzz/` directory, using `fuzz/fuzz_aes.py` as a template.
2. **Import the target functions** and set up `atheris.instrument_all()` to cover relevant inputs.
3. **Register the entry point** via `atheris.Setup` and call `atheris.Fuzz()`.
4. Optionally, update `.github/workflows/fuzz.yml` to schedule the harness in CI.

## CI matrix overview

| Job | Python versions | Operating systems | Purpose |
| --- | --- | --- | --- |
| `lint` | 3.10, 3.11 | Ubuntu, macOS, Windows | Static analysis (flake8, mypy, pylint, bandit, vulture) |
| `tests` | 3.10–3.12 | Ubuntu, macOS, Windows | Unit tests with coverage |
| `tests-extras` | 3.11 | Ubuntu | Tests with optional dependencies |
| `pkcs11-tests` | 3.11 | Ubuntu | SoftHSM-backed PKCS#11 tests |
| `fuzz` | 3.11, 3.12 | Ubuntu | Weekly Atheris fuzzing |

