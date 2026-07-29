# Test and build baseline

## Assurance and isolation

**Deep Security Scan status: BLOCKED BY TOOLING FAILURE**

Reason: A discovery worker failed to create its required `threat_model.md`
artifact, and deterministic artifact validation terminated with `ENOENT`.

Consequences:

- no Deep Security Scan result was accepted;
- no candidate from the failed run may be treated as validated;
- no no-findings conclusion may be made;
- independent security scanning remains a release blocker.

All build/test commands used archived copies of HEAD outside the repository.
Generated caches, coverage, wheels, sdists, sites, and virtual environments were
written below
`C:\Users\Mojta\AppData\Local\Temp\cryptography-suite-phase1-fb8b0f3-20260729`.
The repository remained documentation-only.

The archive contained the 284 materializable Windows files. The tracked
`docs/security.md` symlink (`../SECURITY.md`) failed Windows `tar` extraction
with `Invalid argument`; isolated documentation copies used `SECURITY.md` as a
regular file at that path.

## Command result matrix

| Baseline | Reproducible command shape | Result |
| --- | --- | --- |
| Clean environment | `py -3.12 -m venv <cleanenv>` then `<clean-python> -m pip install .` | PASS; installed `cryptography-suite 3.0.0`, `cryptography 49.0.0`, `cffi 2.1.0`, `pycparser 3.0` |
| Editable environment | `py -3.12 -m venv <venv>` then `pip install -e ".[dev,cli,async,docs]"` | PASS |
| Build | `python -m build --outdir <artifacts>` | PASS; wheel and sdist built |
| Wheel install | fresh venv then `pip install <built-wheel>` | PASS |
| External import | from temp parent, `python -c "import cryptography_suite; ..."` | PASS; version 3.0.0 loaded from wheel site-packages |
| Complete tests | `python -m pytest --ignore=tests/generated` | PASS; 460 passed, 42 skipped, 22 warnings in 210.48 s |
| Branch coverage | `pytest --ignore=tests/generated --cov=cryptography_suite --cov-branch --cov-report=term-missing --cov-report=json:<path>` | PASS; 460 passed, 42 skipped, 22 warnings in 118.65 s; total 74% |
| Ruff lint | `ruff check <all 197 tracked Python files>` | FAIL; 208 errors |
| Ruff format | `ruff format --check <all 197 tracked Python files>` | FAIL; 49 would be reformatted, 148 already formatted |
| Black | `black --check <all 197 tracked Python files>` | FAIL; 52 would be reformatted, 145 unchanged |
| Strict mypy | `mypy --strict --no-incremental cryptography_suite src/cryptography_suite src/crypto_suite src/suite` | FAIL before full checking; duplicate module `cryptography_suite` at both root and `src/cryptography_suite/__init__.py` |
| Bandit, no skips | `bandit -r cryptography_suite src -f txt` | FAIL; 17 issues across 9,256 lines |
| Core dependency audit | `pip-audit --strict -r <requirements containing cryptography>=46.0.5>` | PASS; no known vulnerabilities in resolved set |
| Optional-extra audits | one `pip-audit --strict -r` requirements set per extra | 16 resolved sets clean; `zk` and `legacy` collection failed |
| Built-wheel CLI | version/help plus representative functional commands | Mixed; basic/hash/OTP/file pass, keystore and migration fail |
| Fuzz harness smoke | install Atheris; each `fuzz/*.py -runs=20 -max_total_time=5` | BLOCKED on Windows; Atheris build failed `[WinError 193]`; all four harnesses then failed import |
| Sphinx | `sphinx -W -b html docs <external-output>` | FAIL; 54 warnings treated as errors |
| MkDocs | `mkdocs build --strict --site-dir <external-output>` | FAIL; 3 link warnings |
| Config syntax | parse `pyproject.toml` with `tomllib`, workflows with `yaml.safe_load`, tracked JSON with `json` | PASS |

The first coverage invocation was malformed by PowerShell argument construction:
pytest treated `json:<path>` as a file and exited 4 with zero tests. The corrected
command above was rerun and is the accepted coverage result.

## Coverage detail

Coverage.py reported:

- 3,928 statements, 851 missed;
- 1,098 branches, 204 partial;
- 74% total branch-aware coverage.

`.coveragerc` omits code-generation templates and
`cryptography_suite/experimental/*`, so 74% is not coverage of every shipped
wheel module. No coverage threshold is configured (`tox.ini` passes
`--fail-under=0`).

## Static-analysis detail

Ruff’s 208 findings and the Ruff/Black format deltas apply to the authoritative
197-file `git ls-files '*.py'` set, including sources, tests, tools, fuzz, and
`docs/conf.py`. The normal quality workflow checks formatting, Ruff, and mypy
only on changed Python files.

Strict mypy could not proceed past the parallel root/`src` duplicate package.
The existing config also has differing Python targets (`pyproject.toml` 3.10,
`setup.cfg` 3.12) and multiple per-module `ignore_errors` sections, so no
repository-wide strict-type conclusion is possible.

Bandit, with no skipped families, reported:

| Rule | Count | Phase 1 triage |
| --- | ---: | --- |
| B101 assert | 3 | Implementation invariant checks; review/remove from runtime paths |
| B110 try/except/pass | 9 | Hidden errors; inspect individually in later work |
| B311 non-crypto PRNG | 1 | Retry jitter in `core/operations.py`, not cryptographic randomness |
| B404 subprocess import | 1 | Generic operations wrapper |
| B603 subprocess without shell | 1 | Sequence argv with `shell=False`; caller trust still matters |
| B413 deprecated PyCrypto | 2 | Legacy Salsa20 imports; confirms labs/removal disposition |

Bandit’s severity summary was 15 Low and 2 High (the two B413 legacy imports).
These scanner classifications were not promoted directly into manual security
findings.

## Dependency audits

Audits resolved each declared extra’s direct requirements and their current
transitive dependencies separately. Successful sets—`core`, `cli`,
`hashing-extra`, `bls`, `pake`, `pqc`, `fhe`, `codegen`, `network`, `dev`,
`async`, `docs`, `viz`, `kms`, `aws`, and `hsm`—reported no known
vulnerabilities on 2026-07-29.

Two sets have no accepted audit result:

- `zk`: `pybulletproofs` failed package metadata generation, so dependency
  collection terminated;
- `legacy`: `salsa20>=0.9` could not resolve because the configured index
  offered only 0.3.0.

These audits used unpinned declared requirements and current index resolution;
they are a dated baseline, not a lockfile guarantee.

## CLI and package smoke detail

Success from the installed wheel:

- all parser help surfaces and `--version`;
- `backends list`;
- SHA3-256 file hashing;
- OTP generation (with a SHA-1 compatibility warning at the default);
- PBKDF2 file encrypt/decrypt through `--password-stdin`, with an exact
  plaintext round trip.

Failures:

- `keystore list`: `AttributeError: Namespace has no attribute password` at
  `cryptography_suite/cli.py:1069`;
- `migrate-keys --from file --to hsm --dry-run`: `FileNotFoundError` for
  excluded `site-packages/src/cryptography_suite/cli/migrate_keys.py`;
- `export` and `gen` in the core-only wheel environment returned their intended
  missing-extra errors.

The wheel contains 71 tracked package files; the sdist contains those plus six
tracked packaging/root files. Exact content is in `package-content.md` and the
inventory CSV.

## Documentation and workflow checks

Sphinx failed with 54 warnings, including missing `_static`, duplicate
`index`/`security` documents, an experimental autodoc import blocked by the
environment guard, MyST heading issues, many documents outside a toctree, and
broken references.

MkDocs strict mode failed on three links: `migration_3.0.md` to `index.html`,
and the materialized security document to `CONTRIBUTING.md` and
`docs/api-stability.md`.

TOML/YAML/JSON syntax parsing passed. `actionlint` was not installed, so GitHub
Actions expression/schema semantics were not independently checked.

## Preserved evidence

Raw command stdout/stderr, coverage JSON, archive lists, and built artifacts
remain in the external temporary baseline directory named above. They are not
committed because Phase 1 permits documentation only and those artifacts are
machine-specific.
