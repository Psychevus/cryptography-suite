# RFC-0010: Release, Support, and Assurance Contract

- **Status:** Proposed for v4 implementation
- **Owner:** Release engineering, security, and support
- **Last updated:** 2026-07-29

## Context

v4 needs evidence-based support and release gates. This RFC defines targets; it
does not claim current CI or governance satisfies them.

## Phase 1 evidence

[Test/build baseline](../baseline/test-and-build-baseline.md) reports Python
3.12/3.13 local evidence, passing tests/build but failing repository-wide
lint/type/docs/security baselines, two broken wheel CLI paths, unresolved fuzz
smoke, unpinned dependencies, and a failed Deep Security Scan artifact run.
[Security findings](../baseline/security-findings.md) records mutable/fetched CI
dependencies.

## Problem statement

Version classifiers, workflow intent, and self-run tests cannot establish
platform/provider support, artifact provenance, independent audit, or
single-maintainer-safe release governance.

## Goals

Define supported matrices, stability/deprecation/LTS windows, staged releases,
approval/audit/incident requirements, and non-negotiable blockers.

## Non-goals

This RFC does not modify workflows, claim certification/compliance, accept scan
results, or release v4.

## Binding decision

At stable GA, core support targets 64-bit CPython 3.12, 3.13, and 3.14 on:

- Ubuntu 24.04 LTS x86-64 and arm64;
- Windows 11 and Windows Server 2025 x86-64; and
- macOS 14+ on Apple silicon and x86-64 while upstream CPython/cryptography
  wheels support it.

Each tuple requires installed-wheel tests. Other Python implementations,
32-bit systems, mobile/WASM, and unlisted OS releases are unsupported until an
RFC and CI evidence add them. The lowest Python minor may be removed only in a
v4 minor after upstream EOL, 180 days' notice, and at least one supported
replacement; never during an LTS maintenance line without a documented security
exception.

Provider tiers are:

1. **Tier 1 Supported:** live integration/fault tests on release candidates,
   on-call owner, conformance, security review, documented regions/products.
2. **Tier 2 Preview:** conformance plus sandbox tests; no production support
   promise and not enabled by enterprise defaults.
3. **Development/Test:** local/fake only; never production labeled.
4. **External:** third-party package; core compatibility only.

No provider is Tier 1 by this RFC. AWS, Google, Azure, and Vault are Tier 2
targets until their evidence exists. PKCS#11 is experimental/preview only until
RFC-0006 hardware/mechanism gates pass.

### Stability and support

- Envelope major 4 is readable for the entire v4 security-support window.
  Frozen format bytes/semantics begin at RC1; incompatible reinterpretation is
  forbidden. New suites/critical fields require negotiated support and vectors.
- Root Python API, documented public submodules, CLI command/options/exit codes,
  and JSON schema freeze at RC1. SemVer governs changes.
- Deprecations require warning, changelog/migration guide, replacement when
  applicable, at least two minor releases and 12 months before removal; unsafe
  functionality may be disabled sooner by a security release with an advisory.
- Regular v4 minors receive fixes for 18 months or six months after the next
  minor, whichever is longer. `4.0` is the initial LTS line: security fixes for
  36 months after GA and critical migration-reader fixes for 48 months.
  Published dates MUST be recorded at GA.
- Vulnerabilities follow `SECURITY.md` private reporting initially: acknowledge
  within five business days, status at least every 14 days, coordinated target
  90 days when feasible. A security lead assigns severity, embargo, supported
  versions, advisory/CVE need, and backport/release plan.

### Staged release sequence

| Release | Required maturity |
| --- | --- |
| `4.0.0a1` | canonical skeleton, root/API/error drafts, no crypto readiness claim |
| `4.0.0a2` | normative envelope spec and parser prototype/vectors |
| `4.0.0a3` | streaming/atomic paths and initial provider conformance |
| `4.0.0b1` | provider and policy contracts functional; migration dry-run |
| `4.0.0b2` | supported provider candidates, cross-language vectors, rollback/fault tests |
| `4.0.0rc1` | public API, CLI, JSON, and envelope format frozen |
| `4.0.0rc2` | independent audit complete; remediation landed and validation underway |
| `4.0.0rc3` | remediation independently validated; design-partner soak and release rehearsal complete |
| `4.0.0` | every stable gate below evidenced and approved |

Alpha APIs/formats may change. Beta requires functional provider/policy
contracts. RC freeze exceptions require security/API/format owner approval and
restart the affected interoperability/audit evidence.

### Stable release gates

Stable is blocked unless all are evidenced:

- external independent design/code audit after freeze; remediation independently
  validated;
- a fresh successful independent security scan; no reuse of the failed Phase 1
  manifest/partial artifacts and no no-findings inference;
- no unresolved Critical or High release-blocking finding; lower accepted risks
  have owner, rationale, expiry, and compensating control;
- design-partner soak with incident/rollback report;
- cross-language format vectors, malformed corpora, parser fuzzing, provider
  conformance/live tier tests, installed-wheel matrix, migration rollback, API/
  CLI snapshots, redaction, and failure-atomic file tests pass;
- immutable full-SHA GitHub Action pins and no mutable fetched executable;
  locked/audited build inputs with governed exceptions;
- trusted publishing, signed wheel/sdist and attestations, SBOM, trusted
  provenance, protected release environment/tags, CODEOWNERS, two-person review,
  and independent/reproducible release builders;
- artifact contents prove no labs/demo/fake provider; no unsupported FIPS/HSM/
  audit/production claim; and release docs match evidence.

At least release engineering plus an independent security approver must approve
the exact artifact digests. A single maintainer MUST NOT publish stable
unreviewed. Emergency releases use the same two-person approval unless an
incident policy names a time-bounded break-glass path with post-event review;
break glass cannot introduce a new format/suite.

Design review is mandatory for format, cryptographic suite, provider mechanism,
lifecycle/policy widening, legacy parser, secret handling, and release pipeline
changes. Incident readiness requires severity matrix, contact rotation,
artifact/key revocation, provider compromise, ciphertext migration, audit
preservation, customer notice, and postmortem runbooks exercised before RC3.

## API or architecture implications

Runtime exposes support/conformance versions without network calls. Provider
packages publish independent matrices compatible with core version bounds.

## Security consequences

Independent and two-person gates reduce self-attestation and publishing risk.
They do not make Python memory side-channel safe or create certification.

## Privacy consequences

Soak, incident, telemetry, and audit evidence must use synthetic/redacted data
and documented retention/access controls.

## Compatibility consequences

Freeze and support windows make removals predictable while allowing emergency
disablement of unsafe behavior with advisory/migration support.

## Operational consequences

Maintainers need provider test accounts/hardware, independent auditors/builders,
protected publishing, support/on-call capacity, and evidence retention.

## Failure behavior

Any missing/ambiguous gate blocks promotion. Failed artifacts are quarantined,
not republished under the same version. A release incident pauses publishing and
initiates the signed revocation/advisory runbook.

## Alternatives considered

Best-effort releases, self-audit, rolling stable without freeze, and staged
evidence-gated release.

## Rejected alternatives

The first three cannot substantiate stable assurances or compatibility.

## Implementation constraints

Controls must be independently inspectable and tied to commit/artifact digests.
CI success alone is insufficient where the gate requires human or external
evidence.

## Test and validation requirements

Release rehearsal verifies every gate, approval, protected environment,
reproducible independent build, signature/provenance/SBOM, rollback/revocation,
support matrix, and clean installed artifacts.

## Migration implications

RC/stable notes must include v3 API/CLI/labs/legacy mapping, deadlines, backup/
rollback steps, and policy/provider prerequisites.

## Unresolved questions

Named external auditor, design partners, release builders, and provider Tier 1
set are unresolved assurance work owned by the security/release leads, due
before beta planning (providers) or RC1 (audit/build partners).

## Explicitly deferred work

CI/release changes, audits, scans, provider certification, support staffing, and
actual prereleases are deferred.

## Acceptance criteria

- Each release stage has linked evidence and approvals.
- Stable satisfies every gate with exact artifact digests.
- Published support dates/matrices and security contacts are current.

## Supersession rules

Weakening a stable gate, support window, freeze rule, or approval requirement
requires a governance RFC approved by security and release owners; it cannot be
changed solely in workflow code.
