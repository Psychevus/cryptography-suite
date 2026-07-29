# RFC-0001: v4 Product Charter

- **Status:** Proposed for v4 implementation
- **Owner:** Product architecture and security architecture
- **Last updated:** 2026-07-29

## Context

Cryptography Suite v3 is a broad educational/research toolkit. The v4 mission is
a production-oriented, misuse-resistant, policy-driven envelope-encryption and
key-lifecycle SDK for Python applications. “Envelope” means a versioned object
containing authenticated metadata, wrapped per-envelope data-encryption keys
(DEKs), and authenticated ciphertext.

## Phase 1 evidence

[The Phase 1 summary](../baseline/phase-1-summary.md) records 111 explicit root
exports, 71 shipped runtime files, four conflicting source trees, ten manual
security candidates, broken installed-wheel CLI paths, and no accepted Deep
Security Scan result. [The claim audit](../baseline/documentation-claim-audit.md)
also identifies assurances that exceed evidence.

## Problem statement

Adding more primitives to the existing surface would preserve unsafe choices,
ambient state, format ambiguity, and an unreviewable stable wheel. Organizations
instead need a small integration boundary that makes provider, policy, context,
format, and lifecycle decisions explicit.

## Goals

- Serve Python application teams, platform-security teams, SaaS operators, and
  regulated organizations that need portable application-level envelope
  encryption.
- Support byte and bounded-file encryption, provider-backed DEK wrapping,
  inspection, rotation/rewrap, controlled migration, and secret-free audit
  events.
- Make secure behavior the shortest path and misuse visible as typed failure.
- Publish language-neutral format specifications and test vectors.
- Establish reviewable enterprise-readiness gates without claiming they exist.

## Non-goals

The stable product is not a general primitive library, protocol framework,
certificate toolkit, secrets manager, KMS, HSM, compliance product, or formal
verification system. It does not protect against a compromised host/runtime,
malicious cryptographic provider, or plaintext misuse after successful open.

## Binding decision

The stable core MUST provide only:

1. authenticated versioned envelope encryption with a fresh DEK per envelope;
2. explicit provider/key reference and immutable policy integration;
3. one-shot and bounded streaming profiles;
4. authenticated application context and inspection without decryption;
5. rewrap without exposing plaintext to callers where the selected suite and
   provider permit it;
6. lifecycle state and rotation orchestration;
7. explicit legacy decrypt/migration adapters;
8. structured, secret-free audit events; and
9. the small Python and CLI surfaces defined by
   [RFC-0004](RFC-0004-public-python-api.md) and
   [RFC-0009](RFC-0009-cli-contract.md).

The stable product MUST refuse raw primitive helpers, caller-supplied nonces,
caller-selected modes/tag sizes/KDF tuning, raw long-term private-key
import/export, generic provider private-key decryption, global backend mutation,
ambient plugin discovery, automatic legacy fallback, executable generation,
pipeline composition, OTP, PAKE, secret sharing, X.509 conveniences, standalone
sign/hash helpers, PQC research, FHE, ZK, BLS, Signal demos, visualization,
formal-text exporters, and maintainer fuzz commands.

Labs MUST be a separate repository and separately versioned distribution named
`cryptography-suite-labs`. Stable core MUST NOT depend on or import labs. Legacy
is not labs: only reviewed decrypt/migration adapters listed in
[RFC-0008](RFC-0008-legacy-and-migration-policy.md) may ship in the stable wheel,
and they MUST remain opt-in.

Enterprise-ready means all stable gates in
[RFC-0010](RFC-0010-release-support-and-assurance.md) have evidence, including
independent audit/scanning, provider conformance, installed-wheel and format
interoperability tests, migration rollback tests, release provenance/signing,
and two-person stable-release approval.

The project MUST NOT claim completed formal verification, completed independent
security assessment, FIPS validation, HSM certification, production approval,
zero-knowledge capability, post-quantum security, or compliance unless
separately scoped evidence supports the exact claim.

## API or architecture implications

All stable operations flow through `Protector`, explicit `KeyProvider`, immutable
`Policy`, and `EncryptionContext`. The canonical source and dependency shape are
defined in [RFC-0003](RFC-0003-package-and-source-layout.md).

## Security consequences

The narrow surface removes caller control over nonce, DEK, algorithm, and
fallback decisions. It does not make implementation correct by declaration;
Phase 4 validation and external audit remain mandatory.

## Privacy consequences

Provider identifiers, key references, sizes, timing, and caller-approved context
may be observable. Plaintext and sensitive plaintext-derived metadata MUST NOT
enter envelope metadata, logs, telemetry, errors, or audit events.

## Compatibility consequences

v4 is intentionally breaking. Unsafe v3 Python/CLI surfaces receive migration
documentation, not stable aliases. Ciphertext compatibility is format-specific
and opt-in under RFC-0008.

## Operational consequences

Applications own provider credentials/configuration, policy selection, audit
sink configuration, destination paths, backups, and incident response. The SDK
owns envelope parsing, DEK/nonce generation, redaction, quotas, and atomic file
promotion.

## Failure behavior

Operations MUST fail closed with stable error codes. Provider, policy, format,
context, authentication, I/O, cancellation, and migration failures MUST remain
distinguishable. No failure may commit unauthenticated plaintext or silently
select a weaker path.

## Alternatives considered

- Continue the broad v3 toolkit and harden incrementally.
- Offer low-level and high-level APIs in one wheel.
- Keep labs behind import guards or extras.

## Rejected alternatives

All three retain an oversized audit boundary or allow stable installation to
ship excluded implementations. Import guards and optional dependencies are not
distribution boundaries.

## Implementation constraints

Phase 3 MUST create structure only; cryptographic implementation begins in later
authorized phases. Maintained libraries and standardized constructions MUST be
used. No custom primitive is authorized.

## Test and validation requirements

Release evidence MUST cover negative/misuse cases, provider conformance,
installed wheels, cross-language vectors, malformed corpora, bounded parsers,
atomic file failure, redaction, lifecycle concurrency, and explicit legacy
selection.

## Migration implications

Existing users must inventory formats and API use before v4. Migration MUST use
RFC-0008 workflows and MUST NOT delete sources automatically.

## Unresolved questions

No product-boundary question remains. Exact byte assignments, production
provider certification, and final performance limits require later evidence.

## Explicitly deferred work

Implementation, remediation, a normative byte-level format specification,
provider certification, documentation-site rewrite, and labs extraction are
deferred to their authorized phases.

## Acceptance criteria

- Every shipped stable capability maps to this charter and RFC-0002.
- Root API and CLI contain no refused capability.
- Release claims are evidence-linked and pass RFC-0010 gates.

## Supersession rules

Only an accepted RFC that names this RFC, documents security and migration
impact, and receives product and security-owner approval may supersede it.
