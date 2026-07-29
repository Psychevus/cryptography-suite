# Phase 3 deletion and disposition report

- **Rollback checkpoint:** `def6fe31329ada2b112b09fff3f31ff1965a3ffb`
- **Pre-deletion evidence commit:** `e3feafb`
- **Destructive checkpoint commit:** `23caa01`
- **Result:** stable runtime and artifacts contain only the approved skeleton

## Deleted runtime trees

| Tree | Tracked files before | Disposition |
| --- | ---: | --- |
| `cryptography_suite/` | 71 | v3 runtime deleted after artifact exclusion proof |
| `src/crypto_suite/` | 9 | dead duplicate deleted |
| `src/suite/` | 4 | dead duplicate deleted |
| `protocol/` | 1 | labs protobuf schema deleted from stable repository |

The old dynamic `src/cryptography_suite` wrapper and migration-demo CLI were
also deleted. The wrapper path was replaced by a new canonical facade; no
implementation code was promoted.

## Labs-bound and maintainer paths

The following stable-excluded material was deleted and remains recoverable from
the rollback checkpoint and Git history:

- primitives, KDFs, raw AEAD, nonce APIs, asymmetric and signature helpers;
- OTP, PAKE, secret sharing, X.509, PQC, FHE, ZK, BLS, and Signal demos;
- pipeline, visualization, formal exporters, and executable code-generation
  templates;
- AWS, PKCS#11, local, and mock keystore implementations;
- protobuf-generated handshake code and schema;
- old examples, demonstration scripts, formal example input, notebook, and
  v3 primitive fuzz harnesses; and
- the obsolete vulture whitelist tied to removed APIs.

No external labs repository was created because no repository-transfer workflow
was authorized. No code was copied. Recoverability is provided by the immutable
base and normal Git history.

## Legacy disposition

`cryptography_suite.legacy` exists only as an explicit declaration namespace
containing `LegacyFormat` identifiers and a non-operational `LegacyAdapter`
protocol. It is absent from root-import closure. It contains no parser,
autodetection, fallback, source deletion, old primitive API, migration backend,
or encryption path. Operational legacy support remains deferred to Phase 9.

## Retained foundations

No v3 Python implementation was mechanically retained. The only moved
foundation is the zero-byte `py.typed` marker. All Python source in the
canonical tree was authored as Phase 3 declarations from the Phase 2
contracts.

Retained repository tooling received only mechanical source-path/boundary
updates. The package version, mandatory dependency, optional dependency
versions, setup shim, and unrelated release machinery were not upgraded.

## Test dispositions

Ninety-two old Python tests and `tests/README.md` were retired because their
subjects were removed v3 primitives, providers, labs features, CLI commands,
duplicate packages, or compatibility behavior rejected by Phase 2. They were
replaced by 25 focused tests covering:

- immutable models and redacted errors;
- exact root exports and signatures;
- AST dependency and import boundaries;
- fail-closed `Protector` behavior;
- package discovery and package-data allowlists;
- exact wheel runtime contents and bounded sdist contents;
- installed-wheel import from outside the checkout;
- sdist-to-wheel inventory equivalence;
- prohibited imports and entry points;
- unsupported trust-claim text; and
- Phase 1/2 Git-blob preservation.

The final full suite passes: 25 passed.

## Deletion proof

Before deletion, every tracked runtime/schema/template file had a SHA-256,
Phase 1 proposal, Phase 2 class, action, destination, and deletion prerequisite
recorded. The intermediate canonical build proved old trees were absent before
the destructive commit.

Final proof:

- wheel: 23 entries, exactly 18 allowlisted runtime/data files plus five
  distribution/license entries;
- sdist: 40 entries, restricted to packaging roots, canonical source, and
  generated egg metadata;
- active stable imports of removed modules: zero;
- active stable prohibited-loading mechanisms: zero;
- templates, protobuf, provider SDKs, fake/mock providers, labs, tests,
  duplicate trees, and CLI modules in artifacts: zero; and
- `disposition-verification.csv` and `source-tree-manifest.csv` contain final
  per-path results.

Rollback is `git revert` of Phase 3 commits in reverse order, or creation of a
new recovery branch at
`def6fe31329ada2b112b09fff3f31ff1965a3ffb`. No public rollback tag was created.
