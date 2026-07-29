# v4 Target Architecture

- **Status:** Proposed for v4 implementation
- **Last updated:** 2026-07-29
- **Authority:** [RFC-0001](../rfcs/RFC-0001-product-charter.md) through
[RFC-0010](../rfcs/RFC-0010-release-support-and-assurance.md)

## System context

The SDK protects application bytes/files. The application owns plaintext
purpose, provider credentials/configuration, key aliases, policy selection,
audit sink, and final data retention. The provider owns long-term wrapping keys
and authoritative version/state. The SDK owns envelope parsing, quotas,
DEK/nonce generation, authenticated context binding, staging, and redaction.

```mermaid
flowchart LR
    App["Python application or cryptosuite CLI"]
    Core["Stable v4 SDK<br/>Protector + policy + envelope + lifecycle"]
    Provider["Explicit key-provider package<br/>KMS, Vault, or HSM"]
    Store["Application ciphertext storage"]
    Audit["Application-owned audit sink<br/>and trusted checkpoint"]
    Labs["Separate labs distribution"]

    App -->|"plaintext, context, policy, KeyRef"| Core
    Core -->|"wrap/unwrap/describe/health<br/>bounded requests"| Provider
    Core -->|"canonical envelope or atomic file"| Store
    Core -->|"redacted cs-audit/1 events"| Audit
    Labs -.->|"may call stable public API"| Core
```

There is no stable-core-to-labs edge. Ciphertext storage is untrusted. Provider
responses are authenticated by provider SDK/transport but still schema-checked
and policy-checked. Audit availability/integrity is policy-defined and does not
substitute for cryptographic authentication.

## Runtime components and trust boundaries

| Component | Responsibility | Trust boundary |
| --- | --- | --- |
| `Protector` | Orchestrate seal/open/inspect/rewrap | Validates caller models; never exposes DEK |
| Policy evaluator | Pure deterministic authorization/quotas | Treat policy documents and provider descriptions as untrusted data until validated |
| Envelope codec | Fixed preamble, restricted deterministic CBOR, records | Treat all envelope bytes as attacker-controlled |
| Suite adapter | Maintained-library AEAD/key-wrap binding | Receives internal DEK/nonce; no caller algorithm controls |
| Provider adapter | Four-method normalized provider contract | Network/SDK/token errors and metadata are untrusted |
| Lifecycle service | CAS state, rotation, reconciliation, destroy gates | Durable application store may be stale/concurrent |
| Streaming/atomic service | Bounded chunks, staging, fsync/promotion | Filesystem names, links, mounts, capacity, and crashes are hostile conditions |
| Legacy service | One explicitly named bounded parser at a time | Legacy bytes/metadata/password inputs are hostile and weaker |
| Audit service | Build/redact/deliver structured events | Sink may fail or be unavailable; never receives secrets |
| CLI | Parse explicit configuration and map output/errors | argv, stdin, config, TTY, signals, and output paths are untrusted |

## Seal data flow

```mermaid
sequenceDiagram
    participant A as Application
    participant P as Protector
    participant Y as Policy
    participant K as KeyProvider
    participant E as Envelope/Suite
    participant U as Audit

    A->>P: seal(plaintext, context)
    P->>Y: validate operation, bounds, context, primary KeyRef
    Y-->>P: allow + effective policy id
    P->>K: describe_key(alias, deadline)
    K-->>P: immutable version + capabilities/state
    P->>P: generate fresh DEK and internal nonce
    P->>K: wrap_data_key(DEK, version, binding)
    K-->>P: WrappedKey
    P->>E: canonical header + authenticated ciphertext
    E-->>P: Envelope
    P->>U: redacted seal.completed
    P-->>A: immutable Envelope
```

No provider call occurs before structural/policy validation. The internal DEK
exists only for the operation and provider call; Python zeroization is best
effort, not guaranteed.

## Open data flow

```mermaid
sequenceDiagram
    participant A as Application
    participant P as Protector
    participant E as Envelope parser
    participant Y as Policy
    participant K as KeyProvider
    participant S as Staging output

    A->>P: open(envelope, context)
    P->>E: bounded parse and canonical validation
    E-->>P: protected model + records
    P->>Y: validate version/suite/quotas/context/key state
    P->>K: unwrap_data_key(pinned version, binding)
    K-->>P: internal DEK
    P->>S: decrypt into uncommitted memory/staging
    P->>P: verify final authentication/context
    P-->>A: plaintext or atomic promotion
```

Any failure discards staging. Authentication and context mismatch have distinct
codes but equally non-oracular default messages.

## Inspect and rewrap data flow

`inspect` performs fixed framing, restricted-CBOR, quota, critical-field, and
policy checks only. It makes no provider/network call and returns redacted
metadata with `authentication_status = not_verified`.

```mermaid
sequenceDiagram
    participant A as Application
    participant P as Protector
    participant O as Old provider/key
    participant N as Destination provider/key
    participant E as Envelope

    A->>P: rewrap(envelope, destination_key)
    P->>E: bounded parse + policy/recipient-auth validation
    P->>O: unwrap DEK using immutable old version
    O-->>P: internal DEK
    P->>N: describe and wrap DEK to immutable new version
    N-->>P: new WrappedKey
    P->>E: replace recipient section/authenticator only
    P-->>A: envelope with identical ciphertext records
```

Rewrap reports content authentication as preserved, not reverified, unless the
content tag was actually verified. Failure leaves the original envelope valid.

## Streaming behavior and failure boundary

Seal reads one policy-bounded chunk, encrypts/authenticates its index/length/
header binding, and writes to SDK-owned staging. It appends a final authenticated
manifest, fsyncs, then atomically promotes. Open parses and decrypts records into
staging, rejects missing/duplicate/reordered/trailing records, verifies the final
record, fsyncs, then promotes. Cancellation is checked before provider calls,
every chunk, and promotion.

Caller-provided generic streams are treated as uncommitted staging sinks; the
SDK cannot promise rollback for arbitrary sinks. File APIs provide the complete
no-overwrite/link/fsync/same-filesystem contract from
[RFC-0007](../rfcs/RFC-0007-policy-model.md).

## Migration data flow

```mermaid
flowchart TD
    I["Inventory and source digest"] --> D["Dry run: named parser, quotas, policy"]
    D --> B["Caller-confirmed backup checkpoint"]
    B --> T["Exclusive temporary destination + durable transaction"]
    T --> L["Legacy decrypt into protected staging"]
    L --> V4["Seal v4 with fresh DEK and pinned key version"]
    V4 --> Q["Independent reopen and stream verification"]
    Q --> R["Atomic promotion + fsync"]
    R --> C["Redacted receipt + audit checkpoint"]
    C --> X["Source retained"]
```

Failures before promotion remove only owned staging and retain the transaction
record. Failures after promotion retain source and destination for explicit
rollback/reconciliation.

## Policy and provider interaction

Evaluation order is hard limits, policy validity, format/profile, quotas,
context, operation permission, provider allowlist, fresh key description/effective
state, then provider call. Provider health is advisory and cannot override
operation results. Provider selection is constructor-owned, never ambient or
insertion-ordered.

## Audit event generation

The orchestrator emits start/result/transition events to the audit service. The
redactor uses a field allowlist; sinks never receive plaintext, context values,
passwords, credentials, DEKs, wrapped bytes, nonces, ciphertext, full paths, or
raw provider exceptions. Required sink failure blocks before mutation or enters
durable `AUDIT_PENDING` reconciliation after an irreversible external mutation.

## Secret and metadata ownership

| Asset | Owner at rest | SDK handling |
| --- | --- | --- |
| Plaintext | Application | Operation memory/staging only; never logs/metadata |
| DEK | No caller persistence; wrapped in envelope | Fresh per envelope, internal mutable buffer, best-effort release |
| Long-term wrapping key/credentials | Provider/application | Never exported or serialized by core |
| Context values | Application | Canonically digested/authenticated; values not stored |
| Wrapped DEK/key version | Envelope/application storage | Visible bounded metadata; policy-redacted on inspect/audit |
| Policy document | Application governance | Validated/canonicalized; identifier stored |
| Audit events/checkpoints | Application audit system | Allowlisted redacted schema |

## Assurance status

This is a target contract, not implemented architecture. The previous Deep
Security Scan failed because a discovery worker did not produce required
`threat_model.md`; its manifest/partials are rejected. A fresh successful
independent scan and external audit remain Phase 4/stable prerequisites.
