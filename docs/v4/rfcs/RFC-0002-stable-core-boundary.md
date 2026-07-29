# RFC-0002: Stable Core Boundary

- **Status:** Proposed for v4 implementation
- **Owner:** Product architecture
- **Last updated:** 2026-07-29

## Context

The v3 wheel ships primitives, research modules, providers, tooling, and demos
together. This RFC accepts, modifies, or rejects every important Phase 1
disposition and defines the v4 distribution boundary.

## Phase 1 evidence

[Public API inventory](../baseline/public-api-inventory.md) groups every current
root export and public submodule. [File dispositions](../baseline/file-disposition-proposal.csv)
classify 88 runtime/schema/template paths as five core candidates, 26 rewrites,
two legacy-decrypt-only, 46 labs, 12 dead duplicates, and one generated file.

## Problem statement

An optional dependency or import warning does not prevent excluded code from
shipping, being imported, or expanding the stable audit surface.

## Goals

- Give every current capability group exactly one destination.
- Keep stable installation, imports, docs, and entry points free of labs.
- Preserve only necessary, time-bounded ciphertext migration.

## Non-goals

This RFC does not move files, promise labs compatibility, or approve any current
implementation as a v4 foundation.

## Binding decision

| Current capability group | Binding class | Decision on Phase 1 proposal |
| --- | --- | --- |
| Root facade, file protection, provider abstraction, policy/config, lifecycle, structured audit, CLI, errors, atomic file utility, typing marker | Stable v4 core, rewritten | Accept rewrite/core-candidate roles, but no current code is accepted without review and tests |
| Envelope codec, cryptographic suite adapter, redaction, quotas, retry classification, internal secret buffers | Internal implementation | Modify broad “rewrite” proposals into non-public modules |
| CSF v2/v1, raw legacy AES, selected password AES, PEM/DER and local metadata readers | Opt-in legacy decrypt/migration | Accept only the exact matrix in RFC-0008 |
| AEAD/raw primitives, symmetric/asymmetric/signature/hash/KDF helpers, hybrid, nonce manager, key/protocol helpers, OTP, PAKE, secret sharing, X.509, PQC/ML-KEM, FHE, ZK, BLS, Signal, pipeline, formal exporters, codegen, visualization | Separate labs distribution | Accept Phase 1 labs direction |
| Fuzz entry point/harnesses, mypy experiment, release/docs/test tools, debug/progress utilities | Maintainer tooling | Modify any runtime rewrite proposal: exclude from stable runtime |
| `src/crypto_suite/`, `src/suite/`, dynamic wrapper/aliases, duplicate nonce/AEAD/warning utilities | Delete/dead code after proof | Accept |
| Generated `handshake_pb2.py` | Labs-generated only if schema retained | Accept; stable wheel MUST NOT contain it |
| Current local and mock HSM implementations | Development/test providers, rewritten outside core provider-neutral package | Modify; mock is test-only and local is never production |
| Current AWS and PKCS#11 implementations | Replace, do not migrate mechanically | Modify; new integrations require separate provider packages and conformance |

This table resolves every group in the Phase 1 public API inventory. Individual
files inherit the group disposition; where Phase 1 labeled logging, debug,
operations, constants, KDF, utilities, or keystore code “rewrite,” only the
narrow responsibilities named here survive, in new code after review.

Labs MUST live in a separate repository and separately versioned
`cryptography-suite-labs` distribution. It MAY depend on documented stable-core
public APIs or copied/published language-neutral specifications. Stable core
MUST NOT depend on labs, share a namespace package with it, discover it, or
include its modules/templates/schemas in wheel or sdist.

Stable provider integrations are separately versioned distributions (for
example `cryptography-suite-provider-aws`) that implement the explicit provider
contract. They are not labs, are never auto-discovered, and are instantiated by
application code.

## API or architecture implications

`cryptography_suite` owns only the modules in RFC-0003. The package root is the
15-symbol facade in RFC-0004. No compatibility `__getattr__`, source-path alias,
or ambient entry-point scan is allowed.

## Security consequences

The stable review boundary becomes enumerable. Separating labs prevents
experimental code and dependencies from becoming stable attack surface merely
through installation.

## Privacy consequences

Labs and provider packages MUST have independent privacy documentation.
Stable-core telemetry MUST NOT reveal which excluded/labs components are
installed.

## Compatibility consequences

Source compatibility for removed APIs is rejected. The labs project may offer
its own migration names, but stable core MUST NOT re-export them. Legacy format
support follows RFC-0008 dates.

## Operational consequences

Users install provider packages and labs deliberately. Dependency inventories,
SBOMs, vulnerability handling, and support status must distinguish each
distribution.

## Failure behavior

Importing a removed stable symbol MUST raise normal `ImportError`/`AttributeError`
without dynamically loading labs. A missing provider package MUST produce a
typed configuration error, never a fallback provider.

## Alternatives considered

One monorepo with two distributions; one wheel with extras/import guards; a
namespace-plugin architecture; separate repositories.

## Rejected alternatives

One wheel and namespace plugins preserve ambient execution and packaging
leakage. Same-repository dual distributions increase accidental inclusion risk.
The separate-repository option is selected despite coordination cost.

## Implementation constraints

Phase 3 MUST use allowlisted package discovery and wheel-content assertions.
Excluded implementations MUST be copied nowhere into the canonical stable tree.

## Test and validation requirements

CI MUST inventory wheel/sdist contents, import from an isolated installed wheel,
assert labs/duplicates/templates are absent, snapshot root exports, reject
forbidden imports, and test missing-provider behavior.

## Migration implications

Phase 3 must first record checksums and semantic tests for any small foundation
considered for rewrite, then author new code or explicitly port reviewed pieces.
Labs extraction and deletion occur only at rollback checkpoints.

## Unresolved questions

The labs repository owner and initial release number are deferred to the labs
project; they do not affect the stable boundary.

## Explicitly deferred work

Repository creation, code movement/deletion, provider package publication, and
dependency changes are deferred.

## Acceptance criteria

- Every Phase 1 API/file group has the destination above.
- Stable artifacts contain no labs or dead duplicate.
- Stable import never executes third-party or source-path code.

## Supersession rules

A superseding RFC requires security-owner and release-owner approval, a full
artifact/API disposition diff, and a migration plan.
