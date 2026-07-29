# v4 Module Boundaries

- **Status:** Proposed for v4 implementation
- **Last updated:** 2026-07-29

The canonical layout is [RFC-0003](../rfcs/RFC-0003-package-and-source-layout.md).
“Public” means a documented v4 contract; it does not imply a package-root export.

| Module | Responsibility / status | Allowed dependencies | Forbidden dependencies | Owned data / secrets | Failure behavior and required tests |
| --- | --- | --- | --- | --- | --- |
| `__init__` | Exact 15-symbol facade; public | Public models/protocols/errors only | CLI, legacy, codecs, providers SDKs, labs, import hooks | None | Side-effect-free import; root snapshot and no-ambient-import tests |
| `protector` | Seal/open/inspect/rewrap orchestration; public `Protector` | context, policy, errors, envelope services, provider protocol, audit, streaming | Provider SDKs, legacy parser internals, labs | Plaintext and internal DEK transiently | Transactional typed failure; end-to-end misuse/redaction/cancel tests |
| `context` | Frozen deterministic external context; public | errors, hard limits | providers, envelope codec, environment | Context values transiently; digest | Reject duplicate/invalid/oversized values; canonical-vector tests |
| `policy` | Frozen schema/composition/evaluator; public | errors, value models, hard limits | providers/SDKs, I/O/network, environment at import | Nonsecret policy docs/ids | Pure fail-closed evaluation; canonical/composition property tests |
| `errors` | Stable error codes/types/redaction; public | standard library only | all operational modules | Redacted details only | Never throw while rendering; code/serialization/redaction tests |
| `envelope.models` | Frozen envelope/metadata/recipient models; public subset | errors, provider value models | provider calls, filesystem | Envelope bytes, visible metadata, wrapped DEK | Validate hard bounds; immutable/type tests |
| `envelope.codec` | Restricted CBOR/framing parse/encode; internal | models, errors, `_internal.limits` | providers, policy decisions, I/O beyond supplied stream, legacy | Attacker-controlled bytes; no plaintext/DEK | Deterministic errors; vectors, malformed corpus, fuzz/quota tests |
| `envelope.suites` | Approved maintained-library suite adapters; internal | models, errors, `_internal.secrets`, cryptographic dependency | CLI, policy parsing, providers, labs | DEK, nonce, plaintext/ciphertext transiently | Uniform auth failure; KAT/negative/limit/zeroization-best-effort tests |
| `providers.base/models` | Four-method protocol and frozen request/result models; public | errors, secret buffer type | envelope parsing, legacy, SDK implementations | DEK at wrap boundary; opaque wrapped bytes | Normalize/cancel/deadline rules; shared conformance tests |
| `providers.retry` | Bounded classification/idempotency; internal | provider models/errors, clock | provider selection, global state, envelope | No secret payloads | Preserve permanent/transient distinction; deterministic clock/fault tests |
| `lifecycle.models/service` | Key state/CAS/rotation/destroy/rewrap reconciliation; public service/models | providers protocol, policy, audit, errors | provider SDK types, envelope codec, legacy | Key refs/versions and transition state; no raw keys | Durable partial states; concurrency/idempotency/transition tests |
| `streaming.service` | Chunk state and bounded seal/open; public service | envelope services, policy, provider protocol, audit, errors | legacy auto-detection, provider SDKs | Plaintext/DEK in bounded buffers | No commit before final auth; truncation/reorder/cancel tests |
| `streaming.atomic` | Same-directory temp/fsync/link/promotion; internal | policy file rules, errors, OS facade | envelope parsing, providers, labs | Plaintext/ciphertext temporary files | Preserve existing destination; crash/race/platform tests |
| `audit.events/sinks` | `cs-audit/1` models and explicit sink protocol; public | errors, standard library | envelope content, provider SDKs, logging globals | Allowlisted redacted metadata | Policy-driven unavailable/pending behavior; schema/sink tests |
| `audit.redaction` | Field allowlist/pseudonymization; internal | audit models, deployment redaction key interface | plaintext/secret inspection heuristics as primary control | Identifier pseudonyms only | Reject forbidden fields; adversarial nested/error tests |
| `legacy.service` | Explicit adapter selection and migration transaction; public opt-in | policy, streaming, protector, audit, errors | package root import, providers parsing, labs | Legacy plaintext in protected staging; passwords transiently | No fallback/source deletion; matrix/crash/receipt tests |
| `legacy.formats` | One bounded parser per approved format; internal | errors, hard limits, maintained crypto libs | provider/network, other parsers, CLI | Legacy secret inputs/plaintext transiently | Exact declared format only; vectors, quotas, corruption tests |
| `cli.main/schemas` | Stable command tree, status/progress schemas; interface | public services, explicit provider constructors, errors | codec/suite/legacy internals, labs, ambient discovery | Secret source handles; never secret values in output | Stable exit/schema/TTY/signal/process-list/installed-wheel tests |
| `_internal.limits` | Absolute parser/resource ceilings | standard library | policy/provider/CLI | None | Checked arithmetic; overflow/boundary tests |
| `_internal.secrets` | Internal mutable secret buffer and prompt release | standard library/maintained memory primitives | public root, serialization/logging | DEK/password material | Best effort only; copy/redaction/lifetime tests without zeroization claims |

## Cross-cutting ownership rules

- Models validate local invariants; orchestration validates operation policy.
- Codecs establish structure, not trust/authenticity.
- Providers establish key operation results, not envelope validity.
- Audit receives allowlisted events, never arbitrary `details` dictionaries.
- CLI/file helpers may strengthen but never weaken public service semantics.
- Legacy and labs are leaf dependencies; stable default imports never reach them.

Phase 3 import-boundary tests MUST encode the edges in
[dependency rules](dependency-rules.md). Phase 4 tests MUST validate failure
behavior before any module is called stable.
