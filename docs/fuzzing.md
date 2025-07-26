# Fuzzing and Property Testing

This project includes fuzzing harnesses powered by [Google Atheris](https://github.com/google/atheris) and property-based tests built with [Hypothesis](https://hypothesis.readthedocs.io/).

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

Argon2-based functionality is skipped when the underlying cryptography backend does not provide Argon2.
