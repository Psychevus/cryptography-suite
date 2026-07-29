# v4 Dependency Rules

- **Status:** Proposed for v4 implementation
- **Last updated:** 2026-07-29

## Normative graph

```text
interfaces (package facade, CLI)
        ↓
application services (Protector, lifecycle, streaming, legacy service)
        ↓
domain models/policy/errors/audit events
        ↓
internal codecs/suites/atomic/retry/limits/secrets

explicit provider distributions → provider protocol/models
labs → stable public API (optional)
```

An arrow means “may import.” Reverse edges are forbidden unless explicitly
listed in [module boundaries](module-boundaries.md).

## Enforceable rules

1. Policy models/evaluation MUST NOT import providers, SDKs, network, CLI, or
   read environment at import.
2. Envelope parsing/encoding MUST NOT make provider/network/filesystem calls,
   choose policy, import legacy, or deserialize arbitrary tagged/native objects.
3. Cryptographic suite adapters MUST NOT expose primitive controls or select
   themselves from environment/global registries.
4. Providers and provider packages MUST NOT parse stable/legacy envelopes,
   import CLI, select fallback providers, or expose generic private-key decrypt/
   export.
5. Lifecycle MAY depend on provider protocols and policy but MUST NOT depend on
   concrete SDKs or claim provider state from local writes.
6. CLI MUST call public application services; it MUST NOT import codecs,
   suites, atomic internals, or legacy format modules directly.
7. Legacy adapters MUST be imported only by explicit legacy service dispatch,
   never by root/default `Protector` imports, provider code, or v4 parse failure.
8. Audit sinks/redaction MUST NOT receive or import plaintext, passwords,
   credentials, DEKs, nonces, wrapped-key bytes, ciphertext, or raw provider
   exceptions.
9. Labs MUST NOT share the stable namespace or be imported/dependent upon by
   stable core/provider packages.
10. Stable core MUST NOT mutate `sys.path`/`__path__`, dynamically execute
    source files, scan current-working-directory modules/entry points, or depend
    on current working directory.
11. Provider choice MUST be explicit and MUST NOT depend on name collision,
    import order, insertion order, or silent capability fallback.
12. Only `src/cryptography_suite/` is a runtime package root; no duplicate
    `cryptography_suite`, `crypto_suite`, or `suite` runtime tree may enter
    wheel/sdist.
13. Package root MUST import only the exact RFC-0004 facade and MUST have no
    operational side effects.
14. Package data MUST be allowlisted (`py.typed`, approved public schemas/
    vectors); codegen templates, keys, private fixtures, labs schemas, and
    executables are forbidden.
15. Runtime behavior MUST NOT depend on source checkout layout. Installed-wheel
    behavior outside the checkout is authoritative.
16. Provider SDK dependencies MUST live in separately versioned provider
    distributions; stable core must install/import without them.
17. Context canonicalization MUST NOT compute or expose a public deterministic
    hash of context values. The suite layer derives the context-binding key from
    the DEK and verifies the opaque commitment after unwrap. Providers receive
    protected-header bytes for binding and MUST NOT receive plaintext context.
18. Safe `seal_stream` and `open_stream` output MUST depend on the public
    `TransactionalSink` protocol. Pipes, sockets, stdout, and arbitrary
    `BinaryIO` destinations are forbidden in the safe stable path; filesystem
    output is implemented by the internal atomic sink.

## Phase 3 enforcement

Phase 3 MUST add, before moving implementations:

- an AST import-graph checker with layer/module allowlists and forbidden-edge
  diagnostics;
- tests importing the facade in a clean subprocess with empty provider/labs
  environment and recording imported modules;
- source discovery asserting one package directory and rejecting duplicate
  relative module names;
- forbidden-token checks for `sys.path`, `__path__`, `spec_from_file_location`,
  `exec_module`, ambient entry-point scans, and current-working-directory loads
  in stable runtime;
- exact `__all__` and documented public-submodule snapshots;
- signature and import checks proving both safe stream methods require
  `TransactionalSink`, with no arbitrary-output overload;
- isolated wheel/sdist build inventories compared to explicit allowlists and
  negative patterns for labs, demos, templates, duplicate trees, fake provider,
  tests, caches, and source paths;
- install-wheel tests from an unrelated temporary directory with the repository
  absent from `PYTHONPATH`;
- package-data and optional-dependency ownership assertions; and
- provider conformance imports proving concrete packages depend inward only.

## Later CI gates

From Phase 4 onward CI MUST run graph/artifact checks on every change, plus:

- architecture tests on all tracked Python files, not only changed files;
- cycle detection and public/internal API diff review;
- reproducible artifact comparison and SBOM component ownership;
- parser tests proving no provider call before structural/policy acceptance;
- audit event schema tests rejecting forbidden values at construction;
- keyed context-commitment/provider-nondisclosure tests and transactional-sink
  conformance tests;
- legacy no-fallback/import tests; and
- platform installed-wheel matrices from RFC-0010.

Suppressions require path, rule id, rationale, owner, expiry, and linked RFC.
Expired or wildcard suppressions fail CI. These controls are future gates; this
document does not claim current CI implements them.
