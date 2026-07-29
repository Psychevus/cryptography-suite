# Open decisions after Phase 1

1. Define the exact v4 package-root symbols and typed error taxonomy.
2. Choose the v4 envelope encoding, canonicalization, size quotas, and
   authenticated application-context semantics.
3. Define provider capabilities, key-id/version semantics, conformance tests,
   retry/idempotency rules, and explicit provider selection.
4. Decide which current CSF v1/v2, raw AES, hybrid, ML-KEM, and key formats are
   supported for decrypt/migration and for how long.
5. Decide whether password-derived encryption exists in stable v4; if it does,
   serialize all KDF parameters and enforce policy floors.
6. Define overwrite, symlink/hardlink, permission, fsync, rename, crash, and
   cross-filesystem behavior for every file operation.
7. Define rotation and rewrap state machines, rollback, partial-failure, and
   audit semantics.
8. Define the audit event schema, secret-redaction contract, sink failure
   policy, integrity model, and external checkpoint expectations.
9. Decide whether any third-party provider plugin mechanism remains in stable
   v4 and how enablement, signing, allowlists, and name conflicts work.
10. Select the labs package/repository boundary and compatibility plan for
    primitives, PQC, FHE, ZK, Signal, BLS, pipeline, codegen, visualization,
    formal stubs, fuzz demos, and caller-managed nonces.
11. Resolve all four source trees into canonical `src/cryptography_suite/`
    without importing excluded duplicates.
12. Define supported Python/platform/provider matrices and test them from built
    wheels.
13. Decide dependency locking, optional-extra ownership, audit exceptions, and
    immutable CI action/script pinning.
14. Define stable CLI commands, JSON schemas, exit codes, overwrite defaults,
    secret-input policy, and legacy namespace.
15. Run a successful independent Deep Security Scan and external release audit;
    decide which findings block Phase 4 completion, beta, RC, and stable.

No decision here authorizes implementation in Phase 1.
