# Phase 4A implementation summary

- **Branch:** `feat/v4-phase-4a-safe-filesystem`
- **Base and rollback SHA:** `fc50585b280dd9bb76c7671f1932a6d80bc4f06e`
- **Implementation SHA:** `3c51950fb090475229f1206e685aaa59a9fe50a9`
- **Goal:** private transactional filesystem publication with explicit failure
  outcomes and no operational cryptography

## Scope and architecture

Phase 4A adds:

- a private standard-library OS boundary in
  `cryptography_suite._internal.filesystem`;
- the private `AtomicFileSink` implementation and its internal options, states,
  outcomes, and typed error in `cryptography_suite.streaming.atomic`;
- path, state, link, race, permission, fault, import, artifact, and
  installed-wheel tests;
- a Linux/Windows/macOS filesystem-boundary workflow; and
- the Phase 4A contract and evidence set.

`StandardFilesystemOS` implements the `FilesystemOS` injection protocol.
`AtomicFileSink` structurally satisfies the unchanged public
`TransactionalSink` protocol. The root continues to export exactly 15 approved
declarations, and public streaming exports remain exactly `SinkState` and
`TransactionalSink`. No new public exception, option, state, or sink was added.

The caller supplies an existing absolute trusted root and an untrusted relative
destination. Components are validated lexically and traversed through
no-follow directory descriptors on POSIX or retained non-reparse handles on
Windows. Source/destination and owned-staging identity use device/inode on
POSIX and volume/file-index values on Windows. Existing overwrite destinations
are retained by handle through revalidation and replacement, preventing inode
or file-index reuse from hiding a namespace replacement. Symlink/reparse
destinations, linked parents, directories, and existing files with multiple
hardlinks are rejected.

No overwrite is the default. POSIX uses same-directory `linkat` semantics and
Windows uses handle-based no-replace rename. Exactly one synchronized
no-overwrite process wins. Overwrite requires both internal policy authority
and explicit operation intent; it uses same-directory `renameat` replacement
or Windows handle replacement only after destination revalidation. A
destination that appears or changes after staging is preserved.

POSIX staging and final files are verified as `0600`, including under a
permissive umask. Windows creates and verifies the documented protected
owner-only DACL on local NTFS. File durability uses `fsync` or
`FlushFileBuffers`; containing-directory durability uses parent `fsync` on
POSIX and the documented write-through/post-rename handle barrier on Windows.

Pre-publication failure produces `NOT_PUBLISHED` and leaves abort available.
Post-publication durability failure produces
`PUBLISHED_DURABILITY_UNCERTAIN`; cleanup/close failure produces
`CLEANUP_INCOMPLETE`. Abort is idempotent, retries safe owned cleanup, never
deletes a caller source, and never converts a published uncertain result into
an aborted result.

## Files

Added:

- `.github/workflows/filesystem-boundary.yml`
- `docs/v4/phase-4a/artifact-inventory.txt`
- `docs/v4/phase-4a/failure-injection-evidence.md`
- `docs/v4/phase-4a/filesystem-contract.md`
- `docs/v4/phase-4a/phase-4a-summary.md`
- `docs/v4/phase-4a/platform-capability-matrix.md`
- `src/cryptography_suite/_internal/__init__.py`
- `src/cryptography_suite/_internal/filesystem.py`
- `src/cryptography_suite/streaming/atomic.py`
- `tests/integration/test_atomic_concurrency.py`
- `tests/negative/test_atomic_paths.py`
- `tests/unit/test_atomic_failures.py`
- `tests/unit/test_atomic_sink.py`

Modified:

- `README.md`
- `pyproject.toml`
- `tests/artifact/test_artifact_contract.py`
- `tests/contract/test_import_boundaries.py`
- `tests/integration/test_installed_wheel.py`
- `tests/unit/test_public_submodules.py`

No package version, root export, public streaming export, cryptographic,
envelope, provider, policy, CLI, legacy, or migration implementation changed.

## Validation and artifacts

Local Windows/Python 3.12 evidence:

- focused core filesystem suite: 75 collected, 71 passed, 4 explicitly
  justified Windows capability/platform skips;
- final full suite with branch coverage: 125 collected, 121 passed, 4 explicit
  Windows capability/platform skips, 76% aggregate branch coverage;
- strict mypy: pass for 20 source files;
- Ruff format and lint: pass;
- Black: pass;
- wheel: 26 entries, 21 runtime files;
- sdist: 33 files, 21 runtime files;
- isolated non-editable wheel stage/abort/commit: pass;
- rebuilt-sdist wheel runtime inventory: exact match;
- `pip check`: no broken requirements.

The dedicated workflow runs the focused suite, installed-wheel smoke, artifact
contract, capability report, typing, and lint on Ubuntu, Windows, and macOS.
Final platform conclusions are recorded after GitHub completes the draft PR
checks.

Binding Phase 1 and Phase 2 documents and historical Phase 3 evidence remain
byte-identical. The package remains at `3.0.0`. The independent Deep Security
Scan remains **BLOCKED BY TOOLING FAILURE** and was not retried.

## Definition of Done

| Requirement | Result |
| --- | --- |
| Explicit root and strict relative path model | Complete |
| No-follow parent traversal and final-link rejection | Complete |
| Owned same-directory staging and identity-safe cleanup | Complete |
| Bounded exact writes and deterministic states | Complete |
| Atomic default no-overwrite and two-gate overwrite | Complete |
| Source/destination identity and hardlink rejection | Complete |
| POSIX owner-only mode and Windows protected DACL | Complete |
| File and containing-directory durability contract | Complete |
| Typed uncertain and cleanup-incomplete outcomes | Complete |
| Real synchronized multi-process race | Complete |
| Deterministic facade failure injection | Complete |
| Exact wheel/sdist and installed-wheel boundary | Complete |
| Linux, Windows, and macOS CI | Pending final GitHub conclusions |
| Independent Deep Security Scan | **BLOCKED BY TOOLING FAILURE** |
| Phase 4 overall | Incomplete; Phase 4B, 4C, and 4D not started |

## Deferred work and rollback

Phase 4B streaming transforms, Phase 4C envelope/cryptographic integration, and
Phase 4D orchestration were not started. Backups, stale-transaction scanning,
cross-filesystem copy transactions, network filesystems, alternate ACL models,
CLI behavior, provider behavior, policy evaluation, envelope codecs, and
migration remain out of scope.

Rollback is a branch-level revert to
`fc50585b280dd9bb76c7671f1932a6d80bc4f06e`, or reviewable reverts of the ten
Phase 4A commits in reverse order. No data migration, published format, public
API, or package-version rollback is required.
