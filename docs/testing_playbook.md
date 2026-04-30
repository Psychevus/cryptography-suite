# Testing Playbook

## Goals
- Keep tests deterministic, fast, and meaningful.
- Treat coverage as branch/path confidence, not a vanity line metric.
- Validate boundaries (CLI, subprocess, filesystem, optional HTTP) with contract tests.

## Layered strategy
- **Unit:** pure functions, validators, parsing, typed errors.
- **Integration:** cross-module flows (e.g., config facade + settings loader).
- **Contract:** boundary behavior that external callers depend on (CLI output, exit codes, file formats).
- **E2E:** only for critical user journeys; keep sparse and high-value.

## Required checks for new public APIs
1. Happy path behavior.
2. Edge cases (empty values, casing, whitespace, min/max inputs).
3. Invalid inputs and exception assertions (including error codes).
4. Timeout/retry coverage when retries are implemented.
5. Concurrency behavior when shared state/caches are involved.

## Determinism rules
- Use deterministic test data and explicit assertions.
- Control time with `freezegun` for timestamp/expiry behavior.
- Use Hypothesis for parser/validator/transform invariants.
- Keep I/O hermetic via `tmp_path` and subprocess-local environments.

## Coverage policy
- Run coverage with branch tracking enabled.
- Do not publish a project-wide percentage until the reported value is backed
  by meaningful behavioral, negative, property, and regression tests.
- Guard critical modules with per-module line+branch thresholds via `tools/check_coverage_thresholds.py`.
- Exclude template code listed in `.coveragerc`, and ignore generated tests in
  test runners so they cannot inflate coverage.

## Local workflow
```bash
pip install -e .[dev]
coverage run --rcfile=.coveragerc -m pytest -p no:cov --ignore=tests/generated cryptography_suite tests
coverage xml --fail-under=0
coverage json
python tools/check_coverage_thresholds.py
```
