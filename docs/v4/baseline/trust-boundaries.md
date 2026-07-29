# Current trust boundaries

| Boundary | Inputs / sinks | Evidence | Current controls and gaps |
| --- | --- | --- | --- |
| Python caller → crypto API | plaintext, ciphertext, keys, passwords, nonces, KDF names/parameters | broad root and submodule APIs | Type/length checks vary; many low-level choices remain caller-controlled |
| CLI argv/stdin/env/files/fds | paths, OTP secret, provider names, password source selectors | `cli.py:116-187,810-1130` | Password values avoid argv by default; OTP secret is required in argv; environment/file sources inherit OS exposure |
| Environment → process policy | strict-key mode, runtime/log levels, Argon2 costs, experimental/local-plugin gates, audit config, PKCS#11 config | `core/settings.py`, `constants.py`, `symmetric/kdf.py`, `audit.py`, keystore loader | Values are ambient, some read at import, and no single configuration owner exists |
| Filesystem → parsers | encrypted files, PEM/DER/JSON/YAML/protobuf, pipeline definitions | AES, utils, local keystore, CLI/codegen | Some framed parsers validate lengths; generic JSON/Base64 and YAML consumers have no explicit byte quota |
| Process → destination filesystem | encrypted/decrypted files, keys, metadata, audit logs, generated source | `symmetric/aes.py`, `_key_files.py`, local keystore, audit, codegen | Decrypt and key writes use temp/replace; encryption writes directly; directory durability and link/race policy are incomplete |
| Key identifier → path | local keystore key id and imported metadata id | `keystores/local.py:58-71,160-180,239-248,302-323` | No identifier grammar or resolved-path confinement |
| Plugin code → process | built-in modules, explicit/local directory Python, entry points | `keystores/__init__.py:36-84` | Local CWD discovery is opt-in, but enabled paths execute arbitrary Python; registry conflicts are silent |
| Provider → SDK | AWS KMS API, PKCS#11 library/token/session, local/mock stores | `keystores/*` | Provider capabilities exist but no conformance suite; retry/audit behavior differs |
| SDK → network | AWS APIs; migration audit webhook | `aws_kms.py`; `src/.../migrate_keys.py:30-38,203-212` | Boto3 uses provider defaults; webhook accepts a caller URL and suppresses most delivery failures |
| SDK → subprocess | fuzz CLI and generic operations wrapper | `core/operations.py:154-197`, `cli.py` | `shell=False` via sequence argv; wrapper logs complete argv and stderr, so callers must not pass secrets |
| Runtime → logging/audit | command names, operation names, provider errors, audit action/status | core logging, operations, audit, migration demo | Redaction is key-name/message heuristic; audit is optional; duplicate CLI logs observed |
| Build → wheel/sdist | package discovery, manifest, package data | `pyproject.toml`, `MANIFEST.in` | Root tree ships; three `src/` trees do not; installed behavior diverges |
| GitHub event → CI/release | PR/push/tag content, third-party actions, remote install script, PyPI publication | `.github/workflows/*` | Permissions are partly scoped; actions use mutable major tags and build workflow pipes a fetched script to shell |
| Documentation → user expectations | security, audit, format, testing, release claims | README/docs | Several claims exceed or differ from installed/code behavior; see claim audit |

## Assets crossing boundaries

Assets include plaintext, ciphertext, data-encryption keys, long-term
private/provider keys, passwords/PINs, OTP secrets, key identifiers and
versions, envelope context/metadata, policy decisions, audit events, generated
source, release credentials, and signed artifacts.

## v4 boundary rule

Every v4 high-level operation should accept an explicit provider, policy, and
application context; generate its own data key and nonce; authenticate metadata
and context; enforce parser quotas before allocation or provider calls; write
failure-atomically; and emit a typed, redacted audit event. Ambient plugin,
algorithm, KDF, and raw-key authority should not enter the stable path.
