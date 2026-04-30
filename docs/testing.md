# Testing Guide

This guide explains how to run tests locally and how local checks map to CI workflows.

## Quick start

```bash
pip install -e .[dev]
python -m pip install atheris
pytest --ignore=tests/generated
pytest --ignore=tests/generated -m property
pytest --ignore=tests/generated --cov=cryptography_suite --cov-branch --cov-report=term-missing
python fuzz/fuzz_aes.py -runs=1000
```

The commands above install development dependencies, add Atheris for fuzzing
harnesses, run the main test suite, execute property-based tests, measure
branch coverage from real tests, and run a sample fuzz target.

## Coverage policy

Coverage must be earned by tests that assert behavior. Valid coverage evidence
comes from:

- behavioral tests for supported success paths,
- negative tests for invalid inputs, authentication failures, and rejected
  unsafe states,
- property tests for invariants and round trips,
- regression tests tied to bugs, vulnerabilities, or compatibility guarantees.

Generated smoke tests that call public symbols with placeholder arguments,
swallow broad exceptions, execute no-op code, or otherwise mark lines as
covered without checking behavior are not acceptable. Do not add placeholder
tests to raise a percentage. Project-wide coverage claims should be restored
only after the coverage command is backed by meaningful tests and the reported
percentage is reproducible in CI.

## Extending fuzz harnesses

1. Create a new harness in `fuzz/` (use `fuzz/fuzz_aes.py` as a template).
2. Import target functions and instrument inputs with Atheris.
3. Register the entry point via `atheris.Setup` and call `atheris.Fuzz()`.
4. Update `.github/workflows/fuzz.yml` if the harness should run in CI.

## CI workflow mapping

| Workflow | File | Trigger | Purpose |
| --- | --- | --- | --- |
| Quality Gate | `.github/workflows/quality-gate.yml` | push/PR to `main` | `ruff format --check`, `black --check`, `ruff check`, `mypy`, `bandit`, `pip-audit`, pytest with branch coverage report from real tests, docs-drift script |
| Build | `.github/workflows/build.yml` | push to `main`, PR | wheel builds + `pip-audit` + `trivy` filesystem scan |
| Fuzzing | `.github/workflows/fuzz.yml` | weekly schedule + manual dispatch | Atheris fuzz run (`fuzz/fuzz_aes.py`) on Python 3.11/3.12 |
| Release | `.github/workflows/release.yml` | SemVer tags | release validation + quality checks + publish |

## Operational reliability artifacts

- Test plan matrix: `docs/testing_plan_matrix.md`
- Contributor playbook: `docs/testing_playbook.md`
- Coverage threshold helper: `tools/check_coverage_thresholds.py`
