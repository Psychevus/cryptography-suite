# Operational Hardening Guide

## Risk Register

| Risk | Impact | Mitigation Implemented |
|---|---|---|
| Unsafe destructive key migrations | Key loss or accidental overwrite | Keystore migrations now default to safe mode and require explicit `--apply` for live writes. |
| Unbounded/unsafe subprocess execution | Hung processes, hidden failures, unclear diagnostics | Centralized subprocess runner with timeout, exit-code checks, redacted structured logging, and explicit failures. |
| Secret leakage through logs or CLI arguments | Password/key/plaintext exposure in process lists, CI logs, or audit trails | CLI password values are read by prompt/stdin/fd/env/file sources, structured logs redact sensitive fields, and verbose/dry-run output never prints intermediate secrets. |
| Transient network errors in AWS KMS workflows | Flaky production behavior, partial outages | Retry-with-backoff wrapper with jitter and bounded retry budget around KMS API calls. |
| Poor observability during incidents | Slow triage and weak postmortems | Structured logs with command context, correlation IDs, and basic metrics counters/timers hooks. |
| Abrupt termination (SIGINT/SIGTERM) | Incomplete operations and inconsistent state | Signal handlers set cancellation state, emit structured shutdown logs, and fail in-progress retries clearly. |
| Invalid CLI/file inputs | Runtime crashes or unsafe behavior | Added input validation for file and pipeline paths, run bounds (`--runs`), and timeout validation. |

## Runbook

### 1. Quick health checks

1. Run `python -m cryptography_suite.cli --help` to confirm CLI is loading.
2. Use `--show-metrics` on a representative command to validate metrics flow.
3. Confirm logs include `correlation_id=` and operation events.

### 2. Common failure patterns

- **`Refusing live key migration without --apply`**
  - Cause: safety guard blocked a destructive operation.
  - Action: run with `--dry-run` first; then repeat with `--apply` only after validating migration table output.

- **`fuzz_runner failed with exit code ...`**
  - Cause: child harness failed or timed out.
  - Action: reproduce locally or in CI artifacts; `subprocess_failed` records the exit code with stderr redacted. Increase `--timeout` if needed.

- **`... failed after N attempts` (AWS KMS)**
  - Cause: transient or persistent KMS/API/auth/network issue.
  - Action: verify AWS credentials, region, IAM permissions, and network egress. Retry budget is intentionally capped.

- **`Operation cancelled by signal`**
  - Cause: SIGINT/SIGTERM received.
  - Action: check preceding `shutdown_requested` log event and re-run command.

### 3. Interpreting logs

Each important action emits machine-readable fields (`operation`, `attempts`, `sleep_s`, `returncode`) with a correlation ID. Sensitive fields such as argv, stdout, stderr, passwords, keys, nonces, plaintext, and ciphertext are redacted. During incidents:

1. Group all lines by `correlation_id`.
2. Look for `retrying` / `retry_exhausted` events.
3. For subprocess incidents, inspect `subprocess_failed`, exit status, and CI/job artifacts that are governed by the relevant retention policy.

## Security Notes

### Threat model assumptions

- Local machine/user running CLI is trusted, but inputs (paths, args, environment) are not.
- Networked dependencies (e.g., AWS KMS) are unreliable and may fail transiently.
- Child processes may fail, hang, or return malformed output.

### Trust boundaries

- **Untrusted boundary**: CLI flags, path inputs, environment-provided runtime conditions, and network calls.
- **Trusted boundary**: internal crypto operations after validation and controlled execution wrappers.

### Safe usage guidance

- Always run key migration with `--dry-run` first.
- Set explicit `--timeout` for long-running fuzzing in CI.
- Do not pass passwords as argv values. Prefer prompt, stdin, or file descriptor
  input; use environment variables only for controlled automation.
- Capture failure metadata centrally, but keep raw stdout/stderr out of
  structured logs unless it has been reviewed and redacted.
- Do not increase retry budgets without evaluating downstream blast radius.
