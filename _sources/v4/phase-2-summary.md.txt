# Phase 2 Product and Architecture Contracts

- **Status:** Proposed for v4 implementation
- **Last updated:** 2026-07-29
- **Base:** `origin/main` at `693b4731f08819be63f7ba5812d7b82828950f7b`

## Outcome

Phase 2 converts the Phase 1 baseline into binding proposed contracts without
changing runtime code, tests, dependencies, packaging, workflows, release
automation, or version. Phase 1 remains anchored at
`fb8b0f39c4c598adbd8ffb85667acf3f37174b77`; its documents were not rewritten.

The product is a small policy-driven envelope-encryption/key-lifecycle SDK, not
a broader primitive suite. The selected envelope representation is a strict
binary preamble/record framing with deterministic CBOR protected metadata.
One-shot and streaming are compatible profiles. Final byte labels and the
cryptographic suite require a normative format review before implementation.
Application context is represented only by an opaque keyed commitment: seal
canonically encodes context, derives a context-binding key from the envelope
DEK, and stores the keyed commitment in protected metadata. Providers bind
wrap/unwrap to protected-header bytes and never receive plaintext context. Open
recomputes and compares the commitment after DEK unwrap. The exact
KDF/commitment construction remains assigned to the normative format/security
review.

Labs is a separate repository and separately versioned
`cryptography-suite-labs` distribution. Stable core never depends on or imports
it. Provider integrations are also separate explicit distributions, not ambient
plugins.

## Binding surface

The exact stable root is:

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

`Protector` owns sync seal/open/inspect/rewrap and bounded stream orchestration.
Both safe stream methods require the public-submodule `TransactionalSink`;
bounded writes remain uncommitted until final authentication, commit occurs
once, and every failure invokes idempotent abort. Pipes, sockets, stdout, and
arbitrary `BinaryIO` outputs are outside the safe stable path. High-level
callers never provide nonces, algorithms, KDF tuning, raw DEKs, or long-term
private keys. Provider contract methods are `wrap_data_key`,
`unwrap_data_key`, `describe_key`, and `health_check`. Key states are `PENDING`,
`PRIMARY`, `DECRYPT_ONLY`, `DISABLED`, and `DESTROYED`, with provider
confirmation and CAS required for promotion.

The optional portable password profile ships separately enabled in stable v4,
is absent from the root, serializes/authenticates all KDF parameters, enforces
policy floors/ceilings, and is disabled by `Policy.enterprise()`.

Stable legacy adapters are explicit, migration-oriented, deadline-bound, and
never fallback after v4 parse failure. CSF v2 remains through v4 support (not
before 2031-12-31 removal); CSF v1/raw/one-shot password/local metadata adapters
target 2029-12-31 end; hybrid, ML-KEM, pipeline/demo/audit and other research
formats are labs/external only. Sources are never automatically deleted.

The stable CLI is:

```text
cryptosuite encrypt
cryptosuite decrypt
cryptosuite inspect
cryptosuite rewrap
cryptosuite migrate
cryptosuite provider health
cryptosuite policy validate
cryptosuite doctor
```

It has stable exit codes and `cryptosuite-status/1`, no secret argv/environment
values, no overwrite by default, transactional atomic file outputs, explicit
legacy format, and no protected-output stdout path.

## Phase 1 proposal resolution

- Five core candidates are accepted only as responsibilities requiring review,
  not current code approval.
- Twenty-six “rewrite” paths are narrowed into public services, internal
  implementations, provider packages, or maintainer tooling.
- Two legacy-decrypt proposals are accepted and expanded only by the explicit
  RFC-0008 matrix.
- All 46 labs proposals, 12 dead-duplicate proposals, and the labs-only
  generated-file proposal are accepted.
- Current local/mock/AWS/PKCS#11 code is not mechanically promoted. Local is
  development-only, fake is tests-only, cloud integrations need separate
  packages/conformance, and PKCS#11 remains experimental pending hardware and
  mechanism review.

[The decision register](architecture/decision-register.md) resolves all 15
Phase 1 open decisions or assigns owner/target to bounded deferred evidence.

## Ordered mechanical Phase 3 plan

Phase 3 MUST execute no cryptographic behavior:

1. Pin the Phase 2 base/head, record all four source-tree hashes, current wheel
   inventory, and a rollback tag/checkpoint.
2. Establish empty canonical `src/cryptography_suite/` directories from
   RFC-0003 and a non-cryptographic typed API skeleton.
3. Change packaging to discover only that source root and allowlisted package
   data; make one focused rollback commit.
4. Add source-discovery and import-boundary tests before porting foundations.
5. Add isolated installed-wheel/sdist tests outside the checkout.
6. Add exact root API/error/signature snapshots.
7. Rewrite or port accepted small foundations only after file-by-file semantic
   review; do not implement cryptography.
8. Create the explicit `legacy` namespace/service boundary without parser
   implementations or default imports.
9. Remove dynamic source loading, `sys.path`/`__path__` mutation, CWD/entry-point
   discovery, and insertion-ordered selection.
10. Exclude repository-root and duplicate trees from artifacts; prove every
    excluded Phase 1 path cannot enter the wheel before deletion.
11. Remove root `cryptography_suite/`, `src/crypto_suite/`, and `src/suite/`
    only after equivalence/disposition review and a separate rollback checkpoint.
12. Build/install artifacts and prove labs, fake/demo providers, templates,
    duplicate modules, tests, caches, and unapproved data are absent.
13. Verify all Phase 1 documents and historical anchor text are byte-unchanged.
14. Stop at the skeleton/migration boundary; publish a Phase 3 evidence report
    before any implementation or remediation phase.

## Assurance status

### Deep Security Scan status: BLOCKED BY TOOLING FAILURE

The previous scan failed because a discovery worker did not create its required
`threat_model.md`; deterministic validation ended with `ENOENT`. Its manifest,
partial worker artifacts, and candidates are not reused or validated, and no
no-findings result is claimed. A fresh successful independent scan is required
for Phase 4 completion and stable release. An external independent audit,
validated remediation, design-partner soak, installed-wheel tests, migration
rollback, provenance/signing, and two-person release approval are also future
gates—not current controls.

## Definition of Done matrix

| Requirement | Result / authority |
| --- | --- |
| 10 RFCs exist with mandatory sections/status | Met; `docs/v4/rfcs/RFC-0001` through `RFC-0010` |
| Five architecture docs and summary exist | Met; `docs/v4/architecture/` plus this file |
| Product charter and refusal boundary | Met; RFC-0001 |
| Stable/internal/legacy/labs/tooling/dead boundaries | Met; RFC-0002 |
| Canonical `src/cryptography_suite/` and Phase 3 plan | Met; RFC-0003 and plan above |
| Exact root API, typed errors, and transactional stream sink | Met; RFC-0004 and exact list above |
| Envelope encoding, keyed context commitment, quotas, critical fields, stream failure | Met at requirements level; RFC-0005; byte/commitment constructions explicitly deferred before implementation |
| Password-derived encryption decision | Met; explicit stable optional profile, enterprise-disabled |
| Provider interface, credentials, retry, idempotency | Met; RFC-0006 |
| Lifecycle states/transitions/rollback/partial failure | Met; RFC-0006 and `state-machines.md` |
| Immutable policy, file/audit behavior | Met; RFC-0007 |
| Every current serialized format decided | Met; RFC-0008 matrix |
| CLI commands, codes, JSON, secrets, overwrite | Met; RFC-0009 |
| Support/release/audit/supply-chain gates | Met as future gates; RFC-0010 |
| All 15 open decisions resolved/deferred with owner/target | Met; `decision-register.md` |
| Every current public API group has destination | Met; RFC-0002 classification |
| Deep Scan failure accurately retained | Met; no failed-run reuse/no no-findings claim |
| Phase 3/remediation not started | Met by scope; only these documents are authorized |
| Runtime/tests/dependencies/packaging/workflows/version unchanged | Met; staged diff contains only the 16 Phase 2 documents |
| Links, RFC sections, Mermaid, whitespace, exact 16-file scope | Met; deterministic checks and manual Mermaid review completed before commit |
| Focused draft PR opened, not merged/auto-merged | External publication gate; must be confirmed in the final report |

## Material disagreements

There is no material disagreement with the requested preferred direction.
Where the task allowed alternatives, this phase chose the strongest separation:
labs in a separate repository, concrete provider SDKs in separate distributions,
and no legacy fallback. The portable password profile is retained only as an
explicit stable optional profile, not as an enterprise-default/root primitive.
