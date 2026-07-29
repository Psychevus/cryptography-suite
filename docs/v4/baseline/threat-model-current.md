# Current threat model

## Scope and assurance

This model describes HEAD
`fb8b0f39c4c598adbd8ffb85667acf3f37174b77`. It is a manual Phase 1 model, not
a Deep Security Scan artifact and not a security certification.

**Deep Security Scan status: BLOCKED BY TOOLING FAILURE**

A discovery worker failed to create its required `threat_model.md` artifact,
and deterministic artifact validation terminated with `ENOENT`. Consequently,
no Deep Security Scan result was accepted, no candidate from that run is
treated as validated, and no no-findings conclusion is made.

## Security objectives

1. Plaintext and private/data keys remain confidential against unauthorized
   readers of ciphertext, logs, process output, and persistent storage.
2. Ciphertext, envelope metadata, and application context are authenticated
   before plaintext becomes visible at the requested destination.
3. A key/nonce pair is never reused for AEAD encryption.
4. Provider operations are bound to the intended provider, key id/version,
   algorithm, purpose, and policy.
5. Legacy/experimental behavior cannot be selected implicitly.
6. Untrusted inputs are bounded and rejected without uncontrolled resource use,
   partial destination replacement, or secret-bearing diagnostics.
7. Audit events are complete enough for operations, omit secrets, and have an
   explicitly documented integrity/availability model.
8. Built artifacts match reviewed source and do not gain ambient executable
   code through plugins or source-layout accidents.

## Assets

- plaintext, ciphertext, authenticated metadata, and application context;
- data-encryption keys, provider key references/versions, local private keys,
  HSM PINs, passwords, OTP secrets, and KEM shared secrets;
- policy/configuration, provider capability decisions, and migration state;
- audit events, correlation identifiers, logs, and forensics reports;
- package/release artifacts, SBOM/provenance/signatures, and publishing
  credentials.

## Threat actors and assumptions

| Actor | Capability considered |
| --- | --- |
| Malicious ciphertext/file supplier | Controls serialized bytes, lengths, names, and parse frequency |
| Local unprivileged user | May control CWD, selected files, environment inherited by a process, and accessible output paths |
| Compromised application caller | Can call public low-level APIs with unsafe combinations; is not assumed able to break upstream cryptography |
| Plugin/package supplier | Can publish an entry point or place code in an explicitly enabled plugin directory |
| Network/provider adversary | Can cause provider/network failures and observe metadata; TLS/provider authentication is delegated to maintained SDKs |
| CI/supply-chain adversary | Can target mutable third-party actions, fetched install scripts, or dependency resolution |

Operating-system compromise, malicious native cryptography/HSM implementations,
and physical memory acquisition are outside what this Python package can
prevent. The model does not assume that documentation labels such as
“production” prove provider safety.

## Attack surfaces

- 111 explicit package-root exports plus public submodules;
- main CLI and fuzz entry point;
- CSF/legacy files, hybrid/PQC messages, PEM/DER/JSON/YAML/protobuf, and
  audit/migration formats;
- local keystore paths and key identifiers;
- provider APIs, environment/TOML configuration, and cached sessions;
- registry decorators, entry points, explicit/local Python plugin loading;
- code generation and formal-text export;
- subprocess wrapper and webhook/AWS network calls;
- build/release workflows and package discovery.

## Priority abuse cases for later phases

- escape the local keystore directory through a crafted key id;
- destroy an existing file or input through a failed/in-place encryption;
- change ambient KDF costs across encryption/decryption deployments;
- reuse a counter nonce after restart or across manager instances under one key;
- expose an RSA PKCS#1 v1.5 decryption distinction through a service/provider;
- execute code through an enabled plugin directory or generated application;
- exhaust resources through an unbounded encoded-message input;
- mistake a freshly re-signed migration log for durable tamper evidence;
- publish artifacts from mutable/fetched CI dependencies.

Each abuse case requires Phase 4 validation against the new architecture or an
explicit decision to remove the affected feature.
