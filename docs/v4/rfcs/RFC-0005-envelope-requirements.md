# RFC-0005: Envelope and Portable Password Profile Requirements

- **Status:** Proposed for v4 implementation
- **Owner:** Cryptographic format architecture
- **Last updated:** 2026-07-29

## Context

v4 needs a portable, inspectable, bounded envelope before implementation.
“Deterministic CBOR” below means the core deterministic encoding requirements of
RFC 8949, not an application-defined synonym.

## Phase 1 evidence

[Serialized formats](../baseline/serialized-format-inventory.md) records
versioned CSF, raw/password AES, hybrid JSON/Base64, ML-KEM, keys, audit,
pipeline, protobuf, and generated formats. CSF omits KDF work factors; generic
JSON/Base64 is unbounded.

## Problem statement

The format must authenticate every interpretation-critical field, stream
without unauthenticated output, support rewrap and future recipients, and be
implementable consistently across languages.

## Goals

Deterministic metadata, strict critical fields, bounded parsing, one-shot and
streaming profiles, cross-language vectors, and safe recipient/key evolution.

## Non-goals

This RFC does not assign final magic bytes, integer labels, IANA registrations,
or claim interoperability before the normative format specification/vectors.

## Binding decision

Deterministically encoded CBOR is selected for headers and small manifests,
framed by a strict binary preamble and ciphertext records.

| Criterion | Deterministic CBOR | Protocol Buffers | Strict custom binary |
| --- | --- | --- | --- |
| Deterministic canonical bytes | RFC 8949 profile can require/reject non-determinism | Default serialization is not canonical across binaries/languages | Possible but entirely custom |
| Cross-language availability | Broad; schema can be CDDL | Excellent, but requires schema/compiler/runtime | Requires new parsers everywhere |
| Unknown/critical behavior | Application defines explicit critical-label set | Unknown fields normally skip/preserve; criticality needs extra rules | Fully controllable |
| Parser/canonicalization complexity | Moderate; strict subset required | Moderate plus generated-code semantics | Highest design/review burden |
| Quotas/streaming | Application framing required | Length-delimited framing still application work | Native to design |
| Extensibility/inspection | Strong with integer labels and maps | Strong schema evolution, weak canonical bytes | Possible at high maintenance cost |

Primary references: [RFC 8949 sections 4.2 and 5](https://www.rfc-editor.org/rfc/rfc8949.html),
[CDDL, RFC 8610](https://www.rfc-editor.org/rfc/rfc8610.html), the
[official Protocol Buffers encoding guide](https://protobuf.dev/programming-guides/encoding/),
and [COSE structures, RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html).
COSE informs protected-header/recipient analysis but is not adopted wholesale;
the v4 streaming, lifecycle, and rewrap requirements need a dedicated profile.

### Structural requirements

Every envelope MUST have:

1. a fixed unambiguous magic value and explicit major/minor envelope version;
2. profile and flags plus bounded header length in a fixed-size preamble;
3. a deterministic-CBOR protected header using definite lengths, shortest
   encodings, sorted integer keys, no floats/tags/indefinite items, no duplicate
   map keys, and no semantically equivalent alternative encodings;
4. an algorithm-suite identifier, profile, policy identifier, creation metadata
   only when policy permits, context digest, plaintext/ciphertext bounds, chunk
   parameters, and a sorted `critical` label set;
5. one or more bounded recipient entries containing explicit provider id,
   logical key id when allowed, immutable key version, wrapping algorithm id,
   and opaque wrapped-DEK bytes;
6. a fresh random DEK generated internally for every seal, including empty
   plaintext, and internally generated suite-specific nonces;
7. framed ciphertext with authenticated index/profile/header binding and a
   final authenticated record/manifest;
8. an authenticated recipient manifest that permits rewrap by a party holding
   unwrap/wrap capability without returning plaintext to callers; and
9. exact end-of-envelope recognition.

The initial implementation MUST expose one mandatory algorithm suite chosen in
the later cryptographic design review from maintained-library AEAD and key-wrap
constructions. No caller algorithm selection is allowed; policy may permit a
registered suite. Algorithm identifiers MUST define key size, nonce derivation,
tag size, record AAD, limits, and provider-wrap binding as one indivisible suite.

Interpretation-critical metadata and external application context MUST be
cryptographically bound. Context is supplied out-of-band; only a
domain-separated deterministic digest is stored. Unknown labels listed in
`critical` MUST fail with `CRITICAL_FIELD_UNSUPPORTED`; unknown noncritical
labels MAY be retained byte-for-byte but MUST NOT change interpretation.
Non-deterministic encodings, duplicate labels, unsupported versions/profiles,
and trailing data MUST fail deterministically.

### Profiles and quotas

One-shot and streaming use the same envelope family with compatible profiles,
not unrelated formats. One-shot has a single data record and final record;
streaming has sequential records plus final manifest.

Hard implementation ceilings, which policy may only lower, are:

| Resource | Hard ceiling | Enterprise default |
| --- | ---: | ---: |
| Protected header | 1 MiB | 64 KiB |
| Context encoding before digest | 1 MiB | 64 KiB |
| Recipients | 32 | 4 |
| One recipient entry | 64 KiB | 16 KiB |
| One-shot plaintext | 64 MiB | 16 MiB |
| Streaming plaintext/envelope | 1 TiB | 100 GiB |
| Chunk size | 4 MiB | 1 MiB |
| Chunk count | 2^32 - 1 | policy-derived lower bound |
| Nesting depth / map entries | 8 / 128 | 6 / 64 |

The parser MUST read the fixed preamble into fixed memory, validate lengths by
checked arithmetic against hard and policy limits, and only then allocate.
Provider calls MUST occur only after complete structural/policy validation.

Each chunk authenticates envelope identity, zero-based index, declared length,
final/nonfinal flag, and protected-header digest. Missing final record is
truncation. Skipped, reordered, or duplicate indices; zero-length nonfinal
records; extra records; length mismatch; or bytes after final record fail.
Streaming open MUST stage plaintext until the final record authenticates. It
MUST NOT commit partial plaintext on corruption, cancellation, provider
failure, quota failure, or truncation.

### Password-derived profile

A portable password profile IS included in stable v4 as a separately enabled
`cryptography_suite.passwords` profile installed through a `password` extra. It
is not a root primitive, is disabled by `Policy.enterprise()`, and MUST be
explicitly allowed by policy and operation configuration. Provider-backed
envelopes remain the primary enterprise path.

The initial password profile MUST use one reviewed password KDF (target:
Argon2id) and the mandatory envelope content suite. Salt, KDF id, memory,
iterations, parallelism, output length, and profile version MUST be serialized
in the protected header and authenticated. Defaults and floors come from the
explicit policy; ambient environment variables MUST NOT affect interpretation.
Enterprise minimum target floors are 64 MiB memory, three iterations, one lane,
and 16-byte random salt, subject to later benchmark/security review. Parameters
below policy floors, above resource ceilings, or unsupported by the runtime fail
before expensive allocation. Password values never appear in argv, metadata,
logs, errors, audit, or telemetry.

## API or architecture implications

`Envelope` is opaque bytes; `inspect` returns redacted structural data.
`Protector` selects the policy-approved suite. Password operations live outside
the root/provider constructor and use equivalent context and failure semantics.

## Security consequences

Deterministic protected bytes eliminate representation ambiguity in AAD.
Chunk/final binding detects truncation/reordering. Rewrap changes recipient
metadata, not ciphertext; its manifest authenticator is recomputed using the
internally unwrapped DEK. Content authentication is preserved but not claimed
reverified unless actually checked.

## Privacy consequences

Format, size, provider id, key reference/version, recipient count, and allowed
timestamps may be visible. Context values, plaintext-derived names, DEKs,
passwords, and raw KDF inputs MUST NOT be visible.

## Compatibility consequences

Unknown major versions and critical fields fail closed. Minor-version additions
must be noncritical and ignorable without semantic change. v3 formats are never
autodetected after v4 failure; RFC-0008 governs them.

## Operational consequences

Cross-language implementers need the future normative CDDL/framing spec and
vectors. Large decryptions require same-filesystem staging capacity.

## Failure behavior

Parser errors map deterministically to format, unsupported, quota, critical,
authentication, context, or trailing-data codes. Authentication failures reveal
no failing chunk in ordinary messages. Operation-owned temporary data is removed
best-effort and never promoted.

## Alternatives considered

Canonical/deterministic CBOR, Protocol Buffers, and strict custom binary were
evaluated above; unframed JSON and adopting COSE wholesale were also considered.

## Rejected alternatives

Protobuf lacks portable canonical serialization; custom binary creates an
unnecessary new parser specification; JSON is larger and easier to parse
ambiguously; unmodified COSE does not define the required failure-atomic
streaming/lifecycle profile.

## Implementation constraints

Use a maintained CBOR library only after conformance review. Decode into a
restricted token model, not arbitrary tagged/native objects. Exact constants and
cryptographic constructions require the pre-implementation format/security
review.

## Test and validation requirements

Publish positive and negative vectors in at least Python plus one independent
language; round-trip deterministic bytes; reject alternate encodings, duplicates,
unknown critical fields, integer overflow, quota edges, truncation/reorder/
duplicate/trailing data; maintain malformed corpora; fuzz parser and state
machine; test no provider call before validation and no committed partial output.

## Migration implications

Legacy readers produce plaintext only into the v4 migration transaction. No
legacy header is reinterpreted as v4.

## Unresolved questions

Final magic bytes, integer labels, suite construction/ids, recipient-manifest
construction, CDDL, and exact benchmark-derived defaults are owned by the
format/security leads and MUST be resolved before cryptographic implementation.

## Explicitly deferred work

Normative byte-level specification, implementation, vectors, registrations,
benchmarks, and cryptographic review are deferred to the format-spec phase.

## Acceptance criteria

- The normative spec resolves every unresolved byte/suite item before code.
- Independent decoders produce identical protected bytes.
- All quota, critical-field, streaming, and password-profile tests pass.

## Supersession rules

Envelope changes require a format RFC, new vectors, compatibility classification,
security review, and RFC-0010 release-stage approval. Stable major bytes are
never silently reinterpreted.
