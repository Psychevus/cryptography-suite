# RFC-0009: Stable Command-Line Contract

- **Status:** Proposed for v4 implementation
- **Owner:** CLI and operations architecture
- **Last updated:** 2026-07-29

## Context

The CLI is a thin interface over public services, suitable for safe file
operations and automation. The executable is `cryptosuite`.

## Phase 1 evidence

[CLI inventory](../baseline/cli-contract-inventory.md) records primitive,
OTP, codegen, fuzz, registry, raw migration, and file commands; installed-wheel
keystore/migration failures; duplicate logs; and an argv OTP secret.

## Problem statement

The current surface lacks stable schemas/exit distinctions and exposes
out-of-scope or broken behavior.

## Goals

Exact commands, secret sources, JSON schema, exit codes, atomic I/O, progress,
signals, legacy opt-in, and noninteractive safety.

## Non-goals

No primitive keygen/hash/OTP, pipeline/export/codegen/fuzz, backend mutation,
raw-key migration, demo backend, or secret value in argv.

## Binding decision

The stable command tree is exactly:

```text
cryptosuite encrypt
cryptosuite decrypt
cryptosuite inspect
cryptosuite rewrap
cryptosuite migrate
cryptosuite provider health
cryptosuite policy validate
cryptosuite doctor
```

Global options are `--help`, `--version`, `--output {text,json}`,
`--status-file PATH`, `--policy PATH`, `--provider-config PATH`,
`--timeout SECONDS`, `--non-interactive`, `--quiet`, and `--log-level
{error,warning,info}`. No debug mode may emit secret-bearing payloads.
Provider type/package is named in nonsecret config and instantiated explicitly;
there is no discovery/list command.

`encrypt/decrypt` require `--input PATH|-` and a filesystem `--output PATH`.
`encrypt` requires `--key-ref` through config/file/stdin-safe structured input,
not a secret, plus repeatable `--context-file`; `decrypt` requires equivalent
context. `rewrap` requires input/output and destination key reference.
`inspect` accepts input and emits only RFC-0004 metadata with
`authentication_status: "not_verified"`. `migrate` requires
`--legacy-format`, `--receipt PATH`, explicit context, and defaults to `--dry-run`;
live execution requires `--execute`. `provider health` performs only the
configured provider check. `policy validate` is offline. `doctor` checks
versions/config/file capabilities without encrypting, decrypting, creating keys,
printing credentials, or sending telemetry.

Overwrite is denied by default. `--overwrite` is accepted only when policy
allows it and still uses same-directory exclusive staging, link checks, fsync,
atomic replace, and directory fsync. Input=output, symlinks, hardlinked
destinations and cross-filesystem atomic claims are rejected. Encrypt, decrypt,
rewrap, and migrate outputs use an SDK-owned filesystem `TransactionalSink`.
Pipes, sockets, stdout, and arbitrary already-open streams cannot satisfy the
safe commit/abort contract and MUST NOT be accepted as output by these stable
commands. An unsafe/uncommitted streaming interface would require a separate
non-default proposal and is not part of this CLI.

### Secret and context input

Secrets may come only from hidden TTY prompt, inherited file descriptor
(`--secret-fd`), stdin when stdin is not data (`--secret-stdin`), or an
OS/provider credential mechanism owned by the configured provider. Secret
values, passwords, PINs, tokens, private keys, DEKs, and plaintext MUST NOT be
argv option values, environment variables introduced by this CLI, config JSON,
status/progress, logs, errors, metrics, receipts, or audit. Secret-file paths
are not supported by the stable generic CLI; provider SDK mechanisms are
documented separately.

Context values use bounded JSON files or a dedicated nonsecret FD, never
repeatable `key=value` argv. The operator is warned that context may be
sensitive; output may contain only an opaque context-commitment identifier.

TTY prompts are used only when stdin/stdout roles permit and
`--non-interactive` is absent. Noninteractive mode never prompts, guesses,
overwrites, enables legacy, accepts unsafe stdout, or retries permanent errors.

### JSON/status contract

JSON is one UTF-8 object per final status, schema:

```json
{
  "schema_version": "cryptosuite-status/1",
  "command": "encrypt",
  "status": "ok",
  "operation_id": "opaque",
  "result": {},
  "warnings": [],
  "error": null
}
```

On error, `status` is `"error"` and `error` contains exactly `code`,
`category`, `message`, `retryable`, and redacted `details`; `result` is null.
Keys are emitted in the documented order, unknown additive result keys may be
ignored within schema major 1, and secret fields are forbidden. Protected binary
output is written only to the transactional filesystem destination. Final
status uses stdout or `--status-file`; logs use stderr. Text output is
human-facing and not parsed/stable except command names, exit codes, and the
promise that secrets are absent.

Machine progress is newline-delimited `cryptosuite-progress/1` JSON sent only to
`--status-file`; fields are schema version, operation id, phase, completed bytes,
total bytes if nonsecret/known, and UTC time. It never includes paths, context,
key ids, or payload rates precise enough to violate policy. Text progress is
TTY-only and disabled by `--quiet`.

Stable exit codes are:

| Code | Meaning |
| ---: | --- |
| 0 | Success, including successful dry run |
| 2 | Usage/config schema error |
| 3 | Input/envelope/legacy format or quota error |
| 4 | Authentication or context mismatch |
| 5 | Policy/key-state/legacy denial |
| 6 | Permanent provider/auth/key/capability failure |
| 7 | Transient provider timeout/unavailable/rate limit exhausted |
| 8 | I/O, output exists, link, or atomic-promotion failure |
| 9 | Cancelled/interrupted; no final output committed |
| 10 | Migration incomplete/conflict/verification failure |
| 70 | Redacted internal error |

SIGINT/SIGTERM set cooperative cancellation. A second SIGINT may terminate
immediately after best-effort cleanup. Exit 9 never implies provider mutations
were rolled back; the status/receipt identifies reconciliation requirement.
Retries follow RFC-0006 and respect `--timeout`.

Every operation emits RFC-0007 audit events when required. Logs go to stderr
and contain operation/code/category only at default level.

The v3 `cryptography-suite` binary and hidden aliases are not v4 stable
commands. A packaging-only deprecation launcher MAY exist in pre-release builds
but MUST be removed by RC1 and MUST NOT expose old behavior.

## API or architecture implications

CLI imports public application services, provider package constructors selected
from explicit config, and schema serializers; it MUST NOT import codecs,
primitives, legacy adapters directly, or labs.

## Security consequences

No secret argv/environment path, no protected-output stdout path, and no
unauthenticated plaintext release. Explicit legacy and overwrite controls remain
policy-gated.

## Privacy consequences

Status/progress/audit use opaque operation ids and redacted metadata. Paths and
context values are not emitted.

## Compatibility consequences

Command names, long options, exit codes, and JSON schema major are stable from
RC1. Text wording and field ordering are not semantic input. Breaking JSON
changes require schema major and CLI major.

## Operational consequences

Automation must provide explicit config/policy/context/status channels and
handle reconciliation/exit classes.

## Failure behavior

Exactly one final status is attempted. Broken status sinks do not make a failed
crypto operation successful; mandatory audit/status policies may block before
mutation. Temporary output is never promoted on error.

## Alternatives considered

Preserve v3 commands; expose secrets via environment/file; allow uncommitted
pipe/stdout outputs; the narrow tree above.

## Rejected alternatives

They retain out-of-scope behavior or leak/commit secrets unsafely.

## Implementation constraints

Argument parsing must not echo secret sources. Config files are bounded,
permission-checked where supported, and contain references only.

## Test and validation requirements

Snapshot help/tree/options/codes/schemas; test every error mapping, TTY and
noninteractive matrix, rejection of pipe/socket/stdout output, transactional
commit/abort, signals at each state, no-overwrite/link/atomic crash behavior,
redaction/process-list checks, no provider discovery, and installed-wheel entry
points.

## Migration implications

v3 command mappings are documented as v4, explicit RFC-0008 migration, labs, or
removal. No old command silently changes meaning.

## Unresolved questions

No command/schema/exit decision remains. Provider-specific config schemas are
owned by provider packages before beta.

## Explicitly deferred work

CLI code, schemas, completion/man pages, provider configs, and tests are deferred.

## Acceptance criteria

- Installed wheel exposes only the command tree above.
- All secret-channel, JSON, code, signal, and atomic-output tests pass.
- Removed commands are absent by RC1.

## Supersession rules

Stable command/option/code/schema changes require a CLI RFC, compatibility
classification, migration note, and security review.
