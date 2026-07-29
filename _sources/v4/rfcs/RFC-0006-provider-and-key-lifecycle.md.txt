# RFC-0006: Provider Contract and Key Lifecycle

- **Status:** Proposed for v4 implementation
- **Owner:** Provider and key-lifecycle architecture
- **Last updated:** 2026-07-29

## Context

Providers protect envelope DEKs and remain authoritative for key existence,
version, capability, and operational state. SDK lifecycle metadata coordinates
intent but cannot promote or destroy provider keys by assertion.

## Phase 1 evidence

[Architecture](../baseline/architecture-current.md) and
[trust boundaries](../baseline/trust-boundaries.md) show heterogeneous local,
mock, AWS, and PKCS#11 behavior, mutable registries, ambient credentials, raw
operations, and no conformance suite. SF-05 and SF-07 record PKCS#11 and plugin
risks.

## Problem statement

A broad keystore interface, ambient discovery, and inconsistent retry/lifecycle
semantics can select the wrong key, expose raw material, hide permanent errors,
or create false `PRIMARY` state.

## Goals

Define a narrow provider-neutral wrap contract, explicit configuration,
normalized failures, provider tiers, exact lifecycle states, and concurrency/
recovery rules.

## Non-goals

The base provider is not a generic KMS, signing API, arbitrary decrypt API,
credential store, or universal lifecycle control plane.

## Binding decision

The stable protocol has exactly four required operations:

```python
class KeyProvider(Protocol):
    @property
    def provider_id(self) -> str: ...

    def wrap_data_key(
        self,
        data_key: ReadOnlySecret,
        *,
        key: KeyRef,
        binding: bytes,
        request: ProviderRequest,
    ) -> WrappedKey: ...

    def unwrap_data_key(
        self,
        wrapped_key: WrappedKey,
        *,
        binding: bytes,
        request: ProviderRequest,
    ) -> SecretBuffer: ...

    def describe_key(
        self, key: KeyRef, *, request: ProviderRequest
    ) -> KeyDescription: ...

    def health_check(
        self, *, request: ProviderRequest
    ) -> ProviderHealth: ...
```

Supporting frozen models live in `cryptography_suite.providers`. `ProviderRequest`
contains deadline, cancellation check, operation/correlation id, and optional
idempotency key; never credentials. `WrappedKey` contains provider id, immutable
key id/version, wrapping algorithm id, opaque bytes, and provider-safe metadata.
`describe_key` returns resolved immutable version, capabilities, provider state,
and freshness time. Provider ids are lowercase reverse-DNS identifiers;
`KeyRef` ids are opaque provider-owned UTF-8 strings with no path semantics.

`wrap_data_key` and `unwrap_data_key` are limited to suite-approved DEK sizes.
Their `binding` is the deterministic protected-header bytes; providers MUST NOT
receive plaintext `EncryptionContext` values or the derived context-binding
key. Generic ciphertext decrypt, raw private-key export, silent
selection/fallback, unbounded retry, swallowed failure, and credential
persistence by the SDK are forbidden.

Capability discovery is explicit through `KeyDescription.capabilities`.
Lifecycle operations are separate optional protocols (`KeyCreator`,
`KeyVersionPromoter`, `KeyDestroyScheduler`) because no credible universal
contract exists. Applications must test support before use; absence never
falls back locally.

### Provider ownership and failure rules

- Applications construct providers and SDK clients, choose region/endpoint,
  supply credentials through the provider SDK's documented credential owner,
  and set provider-specific transport controls.
- Stable core owns normalized errors, end-to-end deadlines, cancellation,
  retry budget, audit events, and envelope binding.
- Providers MUST be thread-safe or declare instance affinity; they MUST NOT be
  assumed process-safe after fork. Conformance metadata states both.
- Retries are limited to timeout, unavailable, rate-limit, and explicitly safe
  provider codes; auth, permission, invalid request, unsupported capability,
  not-found, disabled/destroyed, and integrity failures are permanent.
- Default budget is three attempts within the caller deadline, honoring bounded
  server retry hints with jitter. An attempt is retried only when the operation
  is read-only or the provider accepts a stable idempotency key. Unwrap is
  logically idempotent; wrap must either be idempotent or return no ambiguous
  success.
- Rate limiting maps to `PROVIDER_RATE_LIMITED` with safe retry metadata.
  Secrets, SDK request dumps, endpoints with embedded credentials, raw key ids
  when policy marks them sensitive, and provider payloads are redacted.

Health states are `HEALTHY`, `DEGRADED`, `UNAVAILABLE`, `MISCONFIGURED`, and
`UNKNOWN`; health is advisory and MUST NOT override an operation failure or
policy. Network health checks are never performed by import or `inspect`.

### Provider support decisions

| Provider | v4 disposition | Production claim requirements |
| --- | --- | --- |
| Local development | Separate explicit development package; wrap-only test key under OS/file controls | Never production tier in v4 |
| Fake/mock | Test fixtures only; absent from wheels | None |
| AWS KMS | Separate provider package; target supported tier after conformance/integration review | Live integration, IAM/region/alias/version semantics, rate-limit and outage tests |
| Google Cloud KMS | Separate provider package, same gate | Live version/state/IAM integration |
| Azure Key Vault/Managed HSM | Separate packages or explicit product modes | Live version/state/identity integration; tiers stated separately |
| HashiCorp Vault Transit | Separate provider package | Version pinning, mount/namespace, token, rotation and HA failure tests |
| PKCS#11/HSM | Experimental provider package until separate mechanism policy and review | Real hardware tests, session/PIN design, approved wrap mechanisms, side-channel/error review |

PKCS#11 receives no production support claim merely because a code path exists.
RSA PKCS#1 v1.5 generic decrypt is forbidden.

### Lifecycle state machine

The exact states are `PENDING`, `PRIMARY`, `DECRYPT_ONLY`, `DISABLED`, and
`DESTROYED`.

| From | To | Preconditions and authority |
| --- | --- | --- |
| — | `PENDING` | Provider creation accepted; immutable version not yet confirmed usable |
| `PENDING` | `PRIMARY` | Provider `describe_key` confirms exact version, wrap/unwrap capability and enabled state; compare-and-swap (CAS) makes it sole primary |
| `PENDING` | `DISABLED` | Creation abandoned; provider confirms disable or non-use |
| `PRIMARY` | `DECRYPT_ONLY` | New version is confirmed `PRIMARY`; CAS retires old version |
| `DECRYPT_ONLY` | `PRIMARY` | Explicit rollback, provider confirms enabled/capable, policy allows, CAS removes competing primary |
| `DECRYPT_ONLY` | `DISABLED` | Decrypt retention elapsed or incident action; provider confirms state |
| `DISABLED` | `DECRYPT_ONLY` | Explicit recovery before destruction, provider confirms re-enable, policy/dual control allow |
| `DISABLED` | `DESTROYED` | Destruction deadline and retention/approval gates met; provider confirms irreversible destruction |

All other transitions, including `PRIMARY` directly to `DESTROYED`, are invalid.
`DESTROYED` is terminal. Exactly one version per logical key may be `PRIMARY`.
A key never becomes `PRIMARY` merely because local metadata was written.
Provider state is authoritative for cryptographic usability; SDK state is
authoritative for application selection when it is stricter. Effective state is
the more restrictive result.

Every envelope records both logical key id (when policy permits) and immutable
provider version. Open/rewrap uses the immutable version only. Aliases are
resolved before wrapping.

Rotation is: create `PENDING`; provider-confirm; CAS promote; demote old primary;
enqueue idempotent rewrap inventory; observe; then disable/destroy only after
retention gates. Concurrent rotation uses logical-key generation/CAS and one
stable idempotency key; losers reconcile, never create two primaries. A partial
promotion with uncertain provider result enters reconciliation, does not retry
blindly, and blocks further promotion.

Rewrap creates a new envelope transaction and atomically records old/new
envelope digest, versions, status, and idempotency key. Existing ciphertext
remains recoverable until verification/promotion. Stale metadata triggers fresh
`describe_key`; permanent mismatch fails. Rollback selects the previous
decrypt-capable version and never reverses `DESTROYED`.

Destroy scheduling requires explicit earliest timestamp, retention/policy check,
inventory proving no required envelope depends solely on the version, dual
approval where policy requires, provider confirmation, and an audit checkpoint.

## Audit events

Required event types include `provider.call`, `provider.retry`,
`provider.health`, `key.created`, `key.promoted`, `key.demoted`, `key.disabled`,
`key.destroy_scheduled`, `key.destroyed`, `rotation.started/reconciled/completed`,
and `rewrap.started/completed/failed`. Events contain operation id, provider id,
hashed/redacted key reference, version, transition, attempt/result, latency
bucket, policy id, and idempotency hash—never DEK/wrapped bytes/credentials.

## API or architecture implications

Providers do not parse envelopes or legacy data. Lifecycle service coordinates
provider optional capabilities and durable application-owned state. Detailed
transitions also appear in [state machines](../architecture/state-machines.md).

## Security consequences

Version pinning prevents alias drift; binding prevents cross-envelope/key
substitution. Narrow operations reduce oracle and raw-key exposure.

## Privacy consequences

Provider/key identifiers may be sensitive operational metadata. Policy controls
clear vs hashed audit/inspection representation.

## Compatibility consequences

Current `KeyStore`, backend registries, raw migration, sign/decrypt, and plugin
interfaces are not compatible. Provider packages version against this protocol
and advertise a conformance version.

## Operational consequences

Deployments need durable lifecycle/CAS storage, provider credentials, deadlines,
rate-limit budgets, rewrap inventory, dual-control workflows, and recovery
runbooks.

## Failure behavior

Transient and permanent errors remain distinct. Ambiguous mutating results enter
reconciliation. Audit-sink failure follows policy and never converts a provider
failure to success.

## Alternatives considered

Universal keystore; provider-native APIs only; ambient entry-point plugins;
narrow wrap protocol plus optional lifecycle capabilities.

## Rejected alternatives

Universal interfaces invent false portability, provider-native APIs fragment
envelope semantics, and ambient plugins execute unselected code.

## Implementation constraints

No provider credential may be serialized in policy/envelope. Provider packages
must pin a minimum core conformance version and isolate SDK exceptions.

## Test and validation requirements

A shared conformance kit MUST test version resolution, binding, wrong-key
failure, errors, deadlines, cancellation, retry/idempotency, rate limits,
thread safety, health, redaction, and every declared lifecycle capability.
Production tiers require live fault-injection tests.

## Migration implications

Existing keystore metadata is input to RFC-0008 inventory only. Raw long-term
key movement is not replaced; migration should decrypt/re-encrypt envelopes or
use provider-native approved import processes outside this API.

## Unresolved questions

No base-contract or lifecycle-state question remains. Each provider package
must resolve its version syntax, wrap mechanism, credential model, and support
tier before beta.

## Explicitly deferred work

Provider implementations, conformance kit, lifecycle store schema, PKCS#11
design, live testing, and operational certification are deferred.

## Acceptance criteria

- All required methods and normalized errors pass conformance.
- Promotion/destruction cannot succeed on local metadata alone.
- State/CAS/partial-failure/recovery and audit tests cover every transition.

## Supersession rules

Base methods, state transitions, retry semantics, or version identity may change
only through an accepted provider RFC with provider-package migration and
security review.
