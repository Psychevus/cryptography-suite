# Documentation claim audit

| Claim | Evidence | Assessment / required disposition |
| --- | --- | --- |
| “A full, safe-by-default Python cryptography stack.” (`docs/index.md:3`) | 111 root exports, low-level choices, manual findings, no independent audit | Unsupported; replace with the README’s educational/pre-v4 warning |
| README says not independently audited and not recommended for production secrets (`README.md:17-32`) | Matches current assurance | Accurate; retain until audit and release gates complete |
| Experimental modules require explicit acknowledgement (`README.md:42-45`) | Some experimental namespace imports are guarded; many experimental/labs modules are shipped and importable through other paths | Partially accurate; describe exact namespaces, not the whole wheel |
| CSF v2 header is authenticated and decrypt writes replace only after tag validation (`docs/file_encryption.md:3-19`) | `aes.py:144-154,431-454,558-581` | Accurate for decryption; does not imply encryption is failure-atomic |
| Migration demo audit is tamper-evident and signed (`docs/usage.md:41-49`) | signer is regenerated per process; no trusted key/checkpoint/verifier (`migrate_keys.py:152-246`) | Overstated; describe as a demo hash chain only |
| Formal exports are lightweight stubs and do not prove secrecy/authentication (`docs/formal.md:3-20`) | exporter emits names/text; workflow only invokes export (`formal.yml:21-24`) | Accurate and appropriately caveated |
| Quality Gate table lists formatting/lint/type/security/tests (`docs/testing.md:45-52`) | workflow does those categories, but formatting/lint/mypy are changed-file-only and mypy disables errors; Bandit skips nine families (`quality-gate.yml:44-79`) | Incomplete; state scope and exclusions |
| README local CI example shows Bandit skips (`README.md:1097-1106`) | Matches workflow | Accurate command, but it is not a comprehensive security scan |
| PKCS#11 documentation describes production hardware use (`docs/pkcs11.md`) | implementation says status `production`, uses RSA_PKCS decrypt and env/TOML PIN | Add mechanism, PIN, session, and non-audit caveats; do not claim provider conformance |
| LocalKeyStore is development/testing (`docs/keystore.md:28-30`) | class status `testing` and local filesystem behavior | Accurate |
| Local CWD plugins are disabled by default (`docs/keystore_plugins.md:45-54`) | loader requires explicit directory or env flag | Accurate; add silent name-replacement warning |
| `migrate-keys` examples are available via installed CLI (`docs/usage.md`) | built wheel cannot find excluded `src/.../migrate_keys.py` | False for wheel; fix only in later CLI/package work |
| README lists `cryptosuite-bulletproof` and `cryptosuite-zksnark` console scripts (`README.md:860-869`) | `pyproject.toml` defines only `cryptography-suite` and `cryptosuite-fuzz` | Stale/false |
| README project tree lists removed/nonexistent layout and `python-app.yml` (`README.md:965-1006`) | tracked inventory differs | Stale |
| Release workflow generates SBOM, signatures, and provenance when run (`README.md:922-960`) | `release.yml:107-212` contains those steps | Conditionally accurate; does not establish that a particular release has assets |
| Reproducibility checks run in CI (`README.md:959-960`) | workflow builds twice and diffs hashes (`reproducibility.yml:20-30`) | Accurate as workflow intent; no Phase 1 CI-run evidence |
| “never use pickle” for FHE (`docs/no_surprises.md:34-37`) | static sink search and tests found no pickle use in runtime FHE | Supported at this revision |
| Root API/CLI are stable (`API_CLI_CONTRACT.md`) | installed-wheel command failures and planned v4 contraction | Current v3 contract exists, but v4 requires an explicit breaking-change policy |

Documentation edits outside `docs/v4/baseline/` are intentionally deferred.
Phase 1 records the corrections; later focused documentation/product phases
must implement them.
