# RFC-0003: Canonical Package and Source Layout

- **Status:** Proposed for v4 implementation
- **Owner:** Package architecture and release engineering
- **Last updated:** 2026-07-29

## Context

v3 packages the repository-root `cryptography_suite/`; three excluded `src/`
trees contain wrappers, alternate implementations, and demo code. v4 needs one
source of truth.

## Phase 1 evidence

[Package content](../baseline/package-content.md) proves the wheel contains 71
tracked root-tree files while all `src/` trees are excluded. [Import evidence](../baseline/import-and-plugin-surface.md)
shows path mutation, dynamic aliases, registry mutation, and source-file loading.

## Problem statement

Parallel implementations make imports, type checking, review, installed-wheel
behavior, and packaging non-deterministic.

## Goals

Select one canonical layout, minimize modules, make dependency rules enforceable,
and make installed artifacts the test authority.

## Non-goals

No file is moved, deleted, or stubbed in Phase 2. This RFC does not choose
byte-level envelope constants.

## Binding decision

The sole v4 runtime source root MUST be:

```text
src/cryptography_suite/
    __init__.py
    protector.py
    context.py
    policy.py
    errors.py
    envelope/
        __init__.py
        models.py
        codec.py
        suites.py
    providers/
        __init__.py
        base.py
        models.py
        retry.py
    lifecycle/
        __init__.py
        service.py
        models.py
    streaming/
        __init__.py
        service.py
        sinks.py
        atomic.py
    audit/
        __init__.py
        events.py
        sinks.py
        redaction.py
    legacy/
        __init__.py
        service.py
        formats/
    cli/
        __init__.py
        main.py
        schemas.py
    _internal/
        limits.py
        secrets.py
    py.typed
```

Only `__init__.py`, `protector`, `context`, `policy`, `errors`, and documented
symbols from `envelope`, `providers`, `lifecycle`, `audit`, and `streaming` are
public. The stable `streaming` submodule includes the `TransactionalSink`
protocol but does not add it to the package root. `codec`, `suites`, `retry`,
`atomic`, `redaction`, `legacy.formats`, `cli`, and `_internal` are
implementation details. `legacy` is public only as an explicit migration
namespace and is never imported by the package root.

Provider SDK integrations MUST be separate distributions with their own
dependencies and support tier. Stable core contains only provider-neutral
types. A local development provider may be a separate explicitly installed
development distribution; the fake provider exists only in tests.

The repository-root `cryptography_suite/` and excluded
`src/crypto_suite/`/`src/suite/` trees MUST be retired in Phase 3 only after
inventory, semantic disposition, installed-wheel checks, and rollback
checkpoints. The existing `src/cryptography_suite/` contents MUST NOT be treated
as the new foundation; Phase 3 replaces its dynamic wrapper rather than merging
it. The Phase 1 anchor `fb8b0f39c4c598adbd8ffb85667acf3f37174b77`
and all baseline documents MUST remain unchanged.

Runtime code MUST NOT mutate `sys.path`/`__path__`, load source by filesystem
path, depend on the current working directory, scan entry points, or select a
provider by registry insertion order. Package data is allowlisted to `py.typed`
and approved, language-neutral format schemas/vectors only; templates,
executables, private fixtures, keys, and labs schemas are forbidden.

## API or architecture implications

Imports follow [dependency rules](../architecture/dependency-rules.md).
`Protector` orchestrates public services; codecs remain pure and providers never
parse envelopes. CLI calls public application services.

## Security consequences

Allowlisted discovery and artifact inspection reduce source-confusion and
ambient-code execution. Separate provider dependencies reduce stable-core
supply-chain scope.

## Privacy consequences

No package data may contain real keys, credentials, production identifiers, or
captured envelopes.

## Compatibility consequences

Private module paths are not compatible. Only RFC-0004 symbols and explicitly
documented submodule contracts receive v4 stability.

## Operational consequences

Builds and tests must run from installed wheels outside the checkout. Provider
packages require explicit construction and their own version/support reporting.

## Failure behavior

Missing optional providers fail during explicit configuration. Imports MUST NOT
fall back to repository-root or neighboring source files.

## Alternatives considered

Keep the root tree; mechanically promote the current `src/cryptography_suite`;
merge all `src` trees; use the canonical layout above.

## Rejected alternatives

The first three preserve divergent or excluded behavior. The canonical layout
is selected.

## Implementation constraints

Phase 3 is mechanical and ordered:

1. record `origin/main`, file hashes, wheel inventory, and rollback tag;
2. create canonical directories and a non-cryptographic API skeleton;
3. configure packaging exclusively for `src/cryptography_suite`;
4. add import-boundary, root-export, and installed-wheel tests;
5. rewrite accepted foundations one responsibility at a time;
6. isolate explicit legacy adapters without default imports;
7. remove dynamic file loading, path mutation, and ambient registries;
8. exclude and then remove root/duplicate trees after semantic comparison;
9. build wheel/sdist and prove labs, duplicates, and templates absent;
10. checkpoint, verify Phase 1 documents unchanged, and retain a revertable
    commit before implementation work.

No cryptography is implemented by this skeleton.

## Test and validation requirements

CI MUST enforce import graphs, one discovered package root, no duplicate module
names, exact artifact allowlists, external-directory wheel imports, package-data
allowlists, root API snapshots, and absence tests for every excluded group.

## Migration implications

Provider distributions and labs are migrated after stable boundaries exist.
Downstream import migration follows RFC-0004 and RFC-0008; no automatic module
aliases are provided.

## Unresolved questions

Exact internal filenames MAY change before Phase 3 only through an amendment
that preserves responsibilities and dependency directions.

## Explicitly deferred work

Packaging edits, skeleton creation, code porting, tests, file deletion, and
distribution publication are Phase 3 or later.

## Acceptance criteria

- Exactly one source root and one `cryptography_suite` package are discoverable.
- Installed-wheel imports prove source authority.
- Stable artifacts contain only allowlisted modules/data.
- Phase 1 evidence remains historically accurate.

## Supersession rules

Changing source root, provider packaging, public/private status, or allowed
package data requires a superseding architecture RFC and migration/rollback
plan.
