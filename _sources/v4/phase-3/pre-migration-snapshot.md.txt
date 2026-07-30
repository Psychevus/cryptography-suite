# Phase 3 pre-migration snapshot

- **Captured:** 2026-07-30, Asia/Tehran
- **Phase 3 branch:** `refactor/v4-phase-3-canonical-package`
- **Phase 3 base and rollback checkpoint:** `def6fe31329ada2b112b09fff3f31ff1965a3ffb`
- **Phase 2 merge SHA:** `def6fe31329ada2b112b09fff3f31ff1965a3ffb`
- **Phase 2 base SHA:** `693b4731f08819be63f7ba5812d7b82828950f7b`
- **Phase 1 historical anchor:** `fb8b0f39c4c598adbd8ffb85667acf3f37174b77`
- **Initial branch divergence from `origin/main`:** `0 0`
- **Initial tracked working tree:** clean
- **Tracked-file count:** 317

The fetch completed without DNS, TLS, authentication, proxy, or remote errors.
`origin/main` contains the Phase 2 merge. No repository-local HTTP or HTTPS Git
proxy is configured. The branch was created by detaching at the fetched
`origin/main` and creating the Phase 3 branch without changing local `main`.

## Package and interpreter declarations

- Distribution: `cryptography-suite`
- Version: `3.0.0`
- Python: `>=3.10`
- Mandatory dependency: `cryptography>=46.0.5`
- Optional extras: `async`, `aws`, `bls`, `cli`, `codegen`, `dev`, `docs`,
  `fhe`, `hashing-extra`, `hsm`, `kms`, `legacy`, `network`, `pake`, `pqc`,
  `viz`, and `zk`
- Discovery: setuptools `where = ["."]`,
  `include = ["cryptography_suite*"]`
- Package data: `cryptography_suite/py.typed` and
  `cryptography_suite.codegen/templates/**`
- Console scripts:
  `cryptography-suite = cryptography_suite.cli:main` and
  `cryptosuite-fuzz = cryptography_suite.cli:fuzz_cli`
- Other entry-point group:
  `cryptosuite.aead:gcm-sst =
  cryptography_suite.aead_plugins:aes_gcm_sst_encrypt`

No dependency version or package version change is authorized or needed for
Phase 3 packaging mechanics.

## Source identities

The tree digests below are SHA-256 over sorted
`relative-path<TAB>file-sha256` records:

| Tree | Tracked files | SHA-256 |
| --- | ---: | --- |
| `cryptography_suite/` | 71 | `8b9d0c2e6a106f513e6b9641a84f07ba746a304855809464be150b68bf3e25e8` |
| `src/cryptography_suite/` | 3 | `fe8203cfbc665866808939e4807d2e629cbb4d914609b312c1d515b1fffde037` |
| `src/crypto_suite/` | 9 | `23dd33514f16d4c20e8ecbc22fd17e7906c14ce099a651621d4ec3e55768f52d` |
| `src/suite/` | 4 | `99b387c403557b61b1834af5aa2ed87cd9f575ca81f20760d0c92ab807bb4f39` |
| `protocol/` | 1 | `26fbeb3f1c571328631575e473ad2a68dd368b0d0bfa3d9909083cfbcbe46ee5` |
| `tests/` | 93 | `7e481c56bc0500560fda2402f22822ffad2bfe3911ad6339e3c0fd85cc939104` |

Duplicate relative modules are:

- `__init__.py` across all four package roots;
- `aead.py` in the root package and `src/crypto_suite`;
- `experimental/__init__.py` in three roots;
- `experimental/aes_gcm_sst.py` in two roots;
- `nonce.py` in two roots; and
- `utils/__init__.py` in `src/crypto_suite` and `src/suite`.

Per-file SHA-256 values, Phase 1 proposals, Phase 2 binding dispositions,
planned actions, destinations, and deletion prerequisites are in
`source-tree-manifest.csv`. The corresponding deletion gate is in
`disposition-verification.csv`.

## Dynamic and ambient loading baseline

Active pre-migration mechanisms were classified as follows:

| Mechanism | Locations | Phase 2 class / Phase 3 action |
| --- | --- | --- |
| Package `__path__` mutation | `src/cryptography_suite/__init__.py:19-20` | dead wrapper; replace |
| `sys.path` mutation | `src/cryptography_suite/__init__.py:27-28` | dead wrapper; replace |
| Dynamic source execution | `cryptography_suite/cli.py:1095-1102` | obsolete CLI; delete |
| Built-in keystore scanning | `cryptography_suite/keystores/__init__.py:43` | provider implementation/ambient registry; delete |
| CWD plugin loading | `cryptography_suite/keystores/__init__.py:54-68` | forbidden; delete |
| Keystore entry-point scan | `cryptography_suite/keystores/__init__.py:77` | forbidden ambient provider discovery; delete |
| Generated descriptor registration | `src/crypto_suite/handshake_pb2.py` | labs-generated only; delete |

The final stable runtime must contain none of these mechanisms. Historical
Phase 1 documentation may retain literal evidence strings.

## Built artifacts before migration

- Wheel: `cryptography_suite-3.0.0-py3-none-any.whl`
- Wheel SHA-256:
  `17580f47809fc54c079ca14e0b3d70bbc84cce68fb8fb5db2112172867dce985`
- Wheel entries: 77
- Sdist: `cryptography_suite-3.0.0.tar.gz`
- Sdist SHA-256:
  `714ee154712bf56f22f0e390a8954747045d21842dec9a262de2c5e27f8398cf`
- Sdist entries: 106
- Isolated installed-wheel origin:
  `wheel-env/Lib/site-packages/cryptography_suite/__init__.py`
- Installed distribution version: `3.0.0`
- Installed `pip check`: pass

The complete deterministic inventories are in `artifact-before.txt`. Every
wheel runtime module came from repository-root `cryptography_suite/`. All three
`src` package trees and `protocol/handshake.proto` were absent from the wheel.
The sdist contained the same v3 runtime tree plus packaging files and generated
distribution metadata.

## Root API before migration

The isolated wheel exposed 111 names through root `__all__`, matching
`docs/v4/baseline/public-api-inventory.md`. `__version__` was additionally
readable as `3.0.0`. A normal import loaded 31
`cryptography_suite` modules, including primitive, backend, audit, settings,
protocol, and X.509 modules.

The exact 111-name list is preserved by the Phase 1 inventory and isolated
command evidence. Phase 3 replaces it with the exact RFC-0004 15-symbol
snapshot; it does not retain compatibility aliases.

## Documentation preservation baseline

At the rollback checkpoint:

- all 16 Phase 1 files under `docs/v4/baseline/` exist;
- all ten Phase 2 RFCs exist;
- all five Phase 2 architecture files exist; and
- `docs/v4/phase-2-summary.md` exists.

These inputs are compared byte-for-byte to the rollback checkpoint after the
migration. They must not be edited by Phase 3.

## Deletion gate

The rollback checkpoint and all relevant file hashes were recorded before any
runtime deletion, movement, or rewrite. Labs-bound code is not copied because
no external-repository transfer workflow was authorized; recoverability is
provided by the immutable checkpoint and Git history. Old implementations may
be deleted only after their references are classified and artifact/source
allowlist tests are established.

The Deep Security Scan remains **BLOCKED BY TOOLING FAILURE**. No failed-run
manifest, partial artifact, candidate, or threat model is used here.
