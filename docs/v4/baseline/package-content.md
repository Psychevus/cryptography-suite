# Current package content

## Packaging decision in the repository

`pyproject.toml` uses setuptools package discovery with `where = ["."]` and
`include = ["cryptography_suite*"]`. The current canonical *shipped* source is
therefore the repository-root `cryptography_suite/` tree, not any `src/` tree.
The project version resolves to 3.0.0 and the only mandatory runtime dependency
is `cryptography>=46.0.5`.

Console entry points are:

- `cryptography-suite = cryptography_suite.cli:main`
- `cryptosuite-fuzz = cryptography_suite.cli:fuzz_cli`

The distribution also registers
`cryptosuite.aead:gcm-sst = cryptography_suite.aead_plugins:aes_gcm_sst_encrypt`.
Package data explicitly includes `py.typed` and the code-generation templates.

## Built artifacts

`python -m build --outdir <external-temp>\artifacts` succeeded and produced:

- `cryptography_suite-3.0.0-py3-none-any.whl`
- `cryptography_suite-3.0.0.tar.gz`

The wheel contains 77 archive entries: 71 tracked `cryptography_suite/` files
and six generated `.dist-info`/license entries. It includes the experimental,
PQC, FHE, ZK, visualization, code-generation, provider, and primitive modules;
optional dependencies do not exclude their Python modules.

The sdist contains 105 archive entries. Of these, 77 are tracked files:
all 71 tracked files under `cryptography_suite/`, plus `LICENSE`,
`MANIFEST.in`, `README.md`, `pyproject.toml`, `setup.cfg`, and `setup.py`.
The remaining sdist entries are generated metadata/directories.

The following are source-checkout-only:

- all of `src/cryptography_suite/`, `src/crypto_suite/`, and `src/suite/`;
- tests, docs, workflows, tools, fuzz harnesses, examples, notebook, and the
  protobuf schema;
- repository-root governance and maintainer files not named above.

The exact per-file wheel/sdist decision is recorded in
`repository-inventory.csv` and `file-disposition-proposal.csv`.

## Parallel layouts and consequences

| Layout | Tracked files | Current distribution status | Assessment |
| --- | ---: | --- | --- |
| `cryptography_suite/` | 71 | wheel and sdist | Actual v3 runtime package; contrary to the desired v4 `src/` layout |
| `src/cryptography_suite/` | 3 | excluded | Wrapper plus dynamically loaded migration CLI; not available in an installed wheel |
| `src/crypto_suite/` | 9 | excluded | Alternate AEAD, nonce, handshake, protobuf, and zeroization implementations |
| `src/suite/` | 4 | excluded | Alternate experimental-warning namespace |

Relative-name overlaps include four `__init__.py` roots, two `aead.py`
implementations, two `nonce.py` implementations, two
`experimental/aes_gcm_sst.py` implementations, and multiple experimental and
utility package initializers. These are separate implementations, not generated
mirrors.

## Installed-wheel behavior

A fresh Python 3.12 environment installed the built wheel successfully.
Importing from outside the repository loaded
`...\wheelenv\Lib\site-packages\cryptography_suite\__init__.py` and reported
version 3.0.0.

The installed wheel exposes a broken `migrate-keys` path:
`cryptography_suite/cli.py:1088-1102` computes
`site-packages/src/cryptography_suite/cli/migrate_keys.py`, but the `src/` tree
is excluded. An installed-wheel dry run failed with `FileNotFoundError`.
`keystore list` also failed at `cryptography_suite/cli.py:1069` because the
top-level parser never defines `args.password`.

## Extras

Declared extras are `cli`, `hashing-extra`, `bls`, `pake`, `pqc`, `fhe`, `zk`,
`codegen`, `network`, `dev`, `async`, `docs`, `viz`, `kms`, `aws`, `hsm`, and
`legacy`. `kms` and `aws` both contain `boto3`. Optional imports are distributed
in the core wheel, so import guards and error handling—not package separation—
currently enforce feature availability.
