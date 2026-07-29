# Manual security findings

## Assurance statement

**Deep Security Scan status: BLOCKED BY TOOLING FAILURE**

Reason: A discovery worker failed to create its required `threat_model.md`
artifact, and deterministic artifact validation terminated with `ENOENT`.

Consequences:

- no Deep Security Scan result was accepted;
- no candidate from the failed run may be treated as validated;
- no no-findings conclusion may be made;
- independent security scanning remains a release blocker.

The items below come only from manual inspection and local baseline commands.
None is Deep-Scan validated. “Implementation fact” is directly supported by the
named lines. “Exploitability assumption” records what is *not* established by
the repository alone. No severity is assigned in Phase 1.

## SF-01 — Local keystore identifiers are not confined to the keystore directory

**Label: Confirmed by direct code inspection**

Implementation facts:

- `_load_key` and `export_key` join caller-provided `key_id` into
  `self.dir / f"{key_id}.pem"` at
  `cryptography_suite/keystores/local.py:58-63` and `:160-165`.
- `_allocate_import_path` repeats the same join without an identifier grammar,
  resolution, or parent check at `:239-248`.
- dictionary migration metadata supplies `meta["id"]` directly to that helper
  at `:302-311`, then writes the PEM and adjacent JSON at `:311-321`.

Consequence: identifiers containing parent/path components can resolve outside
the configured directory for reads or writes. Exploitability assumes an
attacker can influence the key id or imported metadata and that the process has
filesystem access to the target. Symlink/hardlink and concurrent path changes
are separate unresolved races.

## SF-02 — File encryption is destructive rather than failure-atomic

**Label: Confirmed by direct code inspection**

Implementation facts:

- synchronous encryption opens the destination with `"wb"` before streaming
  (`cryptography_suite/symmetric/aes.py:366-379`);
- its exception path removes whatever is at the destination path (`:380-384`);
- asynchronous encryption also writes directly and removes the output on error
  (`cryptography_suite/symmetric/aes.py:466-516`);
- decryption, in contrast, uses a same-directory temporary file and calls
  `os.replace` only after GCM finalization
  (`cryptography_suite/symmetric/aes.py:431-454,558-581`).

Consequence: an existing destination is truncated before encryption succeeds,
and input equal to output can destroy the input. A crash can leave a partial
ciphertext; a handled error can delete a pre-existing destination. No attacker
is required for the data-loss path. Whether an attacker can choose paths is
application-specific.

## SF-03 — CSF ciphertexts omit the KDF parameters used to derive their keys

**Label: Confirmed by direct code inspection**

Implementation facts:

- the CSF header stores a one-byte KDF id but no work factors
  (`cryptography_suite/symmetric/aes.py:33-62`);
- Scrypt and PBKDF2 factors are module constants
  (`cryptography_suite/constants.py:13-19`,
  `cryptography_suite/symmetric/kdf.py:53-105`);
- Argon2 factors are environment-derived at import
  (`cryptography_suite/symmetric/kdf.py:37-45,113-137`).

Consequence: changing deployed defaults can make existing data undecryptable.
Lowering ambient values weakens newly encrypted data without changing the
authenticated format description. Exploitability as a security downgrade
assumes an attacker or misconfiguration can influence the encryption process
environment.

## SF-04 — Counter nonce uniqueness is process/instance local

**Label: Confirmed by direct code inspection**

Implementation facts:

- `cryptography_suite/nonce.py:39-64` defaults the counter to zero and stores
  seen values only in an in-memory set/ordered dictionary;
- `next()` returns monotonically increasing 12-byte values at `:66-73`; the root
  implementation does not add returned values to the replay cache;
- LRU mode evicts old remembered values at `:88-94`;
- excluded `src/crypto_suite/nonce.py:34-59` is a different implementation that
  remembers returned values but still defaults to in-memory state at zero.

Consequence: restart, multiple manager instances, or multiple processes can
repeat a nonce. Cryptographic compromise additionally requires reuse under the
same AEAD key and use of this API by an encryption path; that reachability is
not established for every application.

## SF-05 — PKCS#11 decrypt uses RSA PKCS#1 v1.5 and ambient PIN storage

**Label: Requires dynamic validation**

Implementation facts are confirmed: the provider labels itself `production`
(`cryptography_suite/keystores/pkcs11.py:33-46`), reads PIN/library/token values
from arguments, environment, or `~/.cryptosuite.toml`
(`cryptography_suite/keystores/pkcs11.py:83-110`), caches a logged-in session
(`cryptography_suite/keystores/pkcs11.py:113-119`), and decrypts with
`Mechanism.RSA_PKCS` (`cryptography_suite/keystores/pkcs11.py:172-178`).

Potential consequence: PKCS#1 v1.5 decryption can become an oracle when an
application exposes distinguishable responses or timing. Dynamic validation
requires a real token/library and a calling service that exposes repeated
attacker-controlled ciphertexts. Environment/TOML PIN exposure depends on host
permissions and process inspection.

## SF-06 — Code generation interpolates pipeline text into executable source

**Label: Candidate**

Implementation facts: `cryptography_suite/codegen/__init__.py:31-56` parses
YAML with `safe_load`, treats its values as `steps`, and renders them into
templates. FastAPI, Flask, and Node templates insert each value directly into
`value = {{ step }}(value)` at
`cryptography_suite/codegen/templates/fastapi/app.py.j2:12-15`,
`cryptography_suite/codegen/templates/flask/app.py.j2:8-11`, and
`cryptography_suite/codegen/templates/node/app.ts.j2:9-12`.

Potential consequence: a crafted pipeline value can generate arbitrary
Python/TypeScript syntax or code. The generator does not execute the output;
exploitability assumes the pipeline is untrusted and a user later runs or
deploys generated code without review.

## SF-07 — Provider registries silently replace names; enabled local plugins execute Python

**Label: Candidate**

Implementation facts: keystore registration assigns without a conflict check
(`cryptography_suite/keystores/__init__.py:18-23`); backend
registration/selection does the same
(`cryptography_suite/crypto_backends/__init__.py:24-31,82-98`). The keystore
loader executes every Python file from an explicit directory or opt-in
`cwd/keystores` (`cryptography_suite/keystores/__init__.py:52-69`) and loads
entry points (`cryptography_suite/keystores/__init__.py:75-82`).

Potential consequence: an enabled plugin can replace a trusted name or run with
process authority. Local CWD discovery is disabled by default; exploitability
requires explicit directory use, the opt-in environment flag, or installation
of a malicious entry-point distribution.

## SF-08 — Migration-demo audit signatures do not establish durable tamper evidence

**Label: Candidate**

Implementation facts: every `AuditLogger` instance generates a new Ed25519 key
(`src/cryptography_suite/cli/migrate_keys.py:152-169`), loads only the last
untrusted digest from the existing file (`:178-187`), appends a chain/digest
signature (`:189-197`), and exports the newly generated public key with the
report (`:214-246`). No trusted public key persistence or verification routine
is present. The separate main audit logger writes independent Fernet lines and
has no hash chain (`cryptography_suite/audit.py:33-44`).

Potential consequence: a party able to rewrite the log can start a new process,
construct a new chain, and present its new public key/report unless a verifier
has an independently trusted key or checkpoint. The repository does not show
such a verifier or external checkpoint.

## SF-09 — Generic encrypted-message decoding has no resource quota

**Label: Candidate**

Implementation facts: `cryptography_suite/utils.py:451-480` Base64-decodes the
complete input, JSON-decodes it, and Base64-decodes every string value before
checking exact field sets. There is no maximum encoded size, decoded size,
member count, or depth. `cryptography_suite/hybrid.py:105-141` accepts this
string form.

Potential consequence: large crafted input can consume memory/CPU. The
repository does not establish an unauthenticated remote route, request limit,
or concurrency model, so service-level exploitability requires dynamic
validation.

## SF-10 — CI uses mutable/fetched executable dependencies

**Label: Candidate**

Implementation facts: workflows use major-version action tags such as
`actions/checkout@v4`, `actions/setup-python@v5`, and third-party
`tj-actions/changed-files@v45`
(`.github/workflows/quality-gate.yml:23-66`).
`.github/workflows/build.yml:57-63` downloads a remote Trivy installer from a
mutable tag and pipes it to `sh`. `.github/workflows/build.yml:55-56` also
ignores one specific dependency CVE without an in-file risk/expiry record.

Potential consequence: upstream tag/script compromise can affect CI, and a
stale exception can hide a relevant advisory. Exploitability depends on
upstream compromise or the ignored advisory applying to the audited
environment. Phase 10 should pin immutable action/script digests and govern
exceptions.

## Required next assurance

Phase 4 must independently validate or reject the surviving candidates,
establish attack paths in the chosen v4 architecture, and close release-blocking
findings. The failed Deep Security Scan remains an unresolved prerequisite for
Phase 4 and the v4 stable release.
