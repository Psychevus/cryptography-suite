# Phase 3 canonical package migration

- **Branch:** `refactor/v4-phase-3-canonical-package`
- **Base / rollback checkpoint:** `def6fe31329ada2b112b09fff3f31ff1965a3ffb`
- **Validated implementation HEAD before evidence commit:** `095ba0e`
- **Package version:** `3.0.0`
- **Goal:** one canonical stable source and an exact non-cryptographic v4 API
  skeleton

## Outcome

The sole runtime source is `src/cryptography_suite/`. Setuptools discovery is:

```toml
[tool.setuptools]
package-dir = {"" = "src"}
include-package-data = false

[tool.setuptools.packages.find]
where = ["src"]
include = ["cryptography_suite*"]
namespaces = false

[tool.setuptools.package-data]
"cryptography_suite" = ["py.typed"]
```

Before Phase 3, the wheel came from repository-root `cryptography_suite/`,
three conflicting `src` trees existed, package data included executable
templates, and root `__all__` contained 111 names. After Phase 3, duplicate
trees are deleted, the wheel has the exact approved skeleton, package data is
only `py.typed`, and root `__all__` is:

```text
AuthenticationError
ContextMismatchError
CryptographySuiteError
EncryptionContext
Envelope
EnvelopeError
EnvelopeMetadata
ErrorCode
KeyProvider
KeyRef
MigrationError
Policy
PolicyError
Protector
ProviderError
```

`__version__` remains readable and is not a root export.

## Scope and explicit non-operational status

Phase 3 implements declarations, immutable value semantics, bounded context
storage, enums, protocols, redacted error formatting, and explicit
`NotImplementedError` failures. It implements no operational cryptography,
provider, policy evaluator, legacy parser, migration, rewrap, CLI operation,
or filesystem transaction.

No v3 implementation was promoted. `py.typed` is the only moved foundation.
All other canonical Python code was authored from the Phase 2 contracts.

## CLI and entry-point decision

All v3 console scripts and the `cryptosuite.aead` entry-point group were
removed. The Phase 3 wheel has no entry-point metadata and no CLI module. A
deprecation launcher was unnecessary. The RFC-0009 command tree remains
unimplemented for its later authorized phase.

## Artifact comparison

| Artifact | Before | After |
| --- | ---: | ---: |
| Wheel entries | 77 | 23 |
| Sdist entries | 106 | 40 |
| Wheel runtime/data files | 71 | 18 |
| Console/other entry points | 3 | 0 |

Final artifacts:

- `cryptography_suite-3.0.0-py3-none-any.whl`
  (`8ceac0dd89ca11f600c98cdeb65d2a571b372e15b995e476ff75c27ce9d9894f`)
- `cryptography_suite-3.0.0.tar.gz`
  (`7a1c08db3d42163470837c1508216394eb38a94f7e814da490c311089536b948`)

The wheel contains only the approved Python modules, `py.typed`, distribution
metadata, and license. The sdist adds only required packaging files, canonical
source layout, and generated egg metadata. Exact inventories are in
`artifact-before.txt` and `artifact-after.txt`.

## Deleted and excluded content

Deleted duplicate/runtime trees are repository-root `cryptography_suite/`,
`src/crypto_suite/`, `src/suite/`, the old dynamic canonical wrapper/demo CLI,
and `protocol/`. Old demos, labs examples, notebook, primitive fuzz harnesses,
and 92 v3-only test files were also retired after disposition evidence.

Labs code was not transferred or copied; it remains recoverable in Git history.
Provider SDK implementations and fake/mock providers are absent. The explicit
legacy namespace contains declarations only and is not root-imported.

## Validation

| Check | Result |
| --- | --- |
| Fresh `python -m build` | pass |
| Wheel allowlist | pass; 23 entries |
| Sdist allowlist | pass; 40 entries |
| Sdist-built wheel inventory | identical |
| Installed-wheel unrelated-directory import | pass; site-packages origin |
| Exact root API/signatures | pass |
| Root import closure / forbidden imports | pass |
| AST dependency graph | pass |
| No path mutation/dynamic source/CWD/provider discovery in runtime | pass |
| Fail-closed skeleton/no side effects | pass |
| Full pytest suite | 25 passed |
| Changed-file Ruff lint/format | pass |
| Changed-file Black | pass |
| Strict mypy on canonical source | pass; 17 files |
| Bandit on canonical source | pass; zero findings and zero suppressions |
| `pip check` | pass |
| `pip-audit -r requirements.txt --strict` | pass; no known vulnerabilities |
| Unsupported trust-claim test | pass |
| Documentation-reference check | pass |
| Modified-workflow actionlint | pass; see CI note |
| Phase 1 document Git blobs | identical |
| Phase 2 document Git blobs | identical |

Actionlint 1.7.12 was downloaded to a temporary directory from its official
release and its archive SHA-256 matched the published checksum. Two pre-existing
notices for `actions/checkout@v3` and `actions/setup-python@v4` in the modified
Formal workflow were ignored only in the local invocation because Phase 3
forbids unrelated action upgrades. All other actionlint rules passed; no
repository suppression or CI exception was added.

Narrow workflow changes:

- Quality Gate and Release scan `src/cryptography_suite` and run the focused
  installed-artifact suite.
- Formal Model now proves formal exporters are absent from stable artifacts
  because those exporters moved outside the stable boundary.
- The obsolete primitive fuzz schedule now runs stable fail-closed/import
  negative checks; cryptographic fuzzing is deferred until cryptography exists.

Remote PR checks are recorded after draft publication. No existing failure is
suppressed.

## Documentation preservation

All 16 Phase 1 baseline files, all ten Phase 2 RFCs, all five architecture
files, the Phase 2 summary, and the Phase 1 historical anchor text match the
base Git blobs exactly.

## Assurance status

**Deep Security Scan status: BLOCKED BY TOOLING FAILURE**

No failed manifest, partial worker artifact, candidate, or incomplete threat
model was reused. No scan result, no-findings result, independent review, or
security completion claim is made.

## Definition of Done

| Requirement | Result |
| --- | --- |
| PR #195 merged before branch creation | met |
| Fresh branch at current fetched `origin/main` | met |
| One canonical runtime source | met |
| Exact 15-symbol root | met |
| Stable artifacts exclude labs/providers/fakes/templates/protobuf/tests/duplicates/old CLI | met |
| Declaration-only operations fail closed | met |
| Legacy explicit, non-operational, and not root-imported | met |
| No ambient loading/path mutation | met |
| Installed-wheel and sdist rebuild validation | met |
| API/import/artifact/preservation tests | met |
| Package version unchanged | met |
| Phase 1/2 documents unchanged | met |
| Draft PR open, auto-merge disabled, checks passing | pending publication |
| Phase 4/remediation not started | met |

## Deferred work and Phase 4 prerequisites

Deferred work includes the normative envelope constants/constructions,
cryptographic implementation, provider packages and conformance, policy
evaluation, streaming/atomic services, lifecycle operations, legacy adapters,
migration, stable CLI, cross-language vectors, and all assurance/remediation
gates assigned to later phases.

Phase 4 must begin only under separate authorization and only after its design
and security prerequisites are satisfied, including a fresh independent Deep
Security Scan. This task stops at the Phase 3 skeleton.

## Rollback

Create a recovery branch at
`def6fe31329ada2b112b09fff3f31ff1965a3ffb`, or revert Phase 3 commits in reverse
order. The pre-migration hashes and artifact inventory are in commit `e3feafb`.
No public tag was created.
