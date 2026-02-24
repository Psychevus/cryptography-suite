# API/CLI Contract

This document defines the compatibility contract for public Python and CLI interfaces.

## Compatibility policy

- Public Python imports exposed from `cryptography_suite` are considered stable unless marked experimental/deprecated.
- `cryptography_suite.experimental` is explicitly unstable.
- CLI subcommands and long-form flags are stable; hidden aliases may exist for backward compatibility.

## CLI contract

Primary binary: `cryptography-suite`

### Global options

- `--version`
- `--experimental gcm-sst` (repeatable)
- `--log-level {DEBUG,INFO,WARNING,ERROR}`
- `--show-metrics`
- `--output-format {text,json}`
- `--json` (deprecated alias for `--output-format json`)

### Stable commands

- `keygen`
- `hash`
- `otp`
- `export`
- `gen`
- `keystore`
- `migrate-keys`
- `file`
- `backends`
- `fuzz`

### Compatibility aliases

- `encrypt` -> `file encrypt`
- `decrypt` -> `file decrypt`

### Output contract

- Default output is human-readable text.
- JSON output uses deterministic key order and contains command-result fields.
- Error messages in JSON include `error` and `error_type`.

### Exit code contract

- `0`: command completed successfully.
- `1`: runtime/operation failure.
- `2`: argument parsing/usage failure (argparse default behavior).
- Commands that currently rely on argparse or explicit `sys.exit(1)` preserve existing behavior.

## Python API contract

- Semantic behavior of stable modules should remain backward compatible across minor versions.
- Deprecated functions remain available for one minor release with migration notes.
- Experimental modules may change at any time.

## Deprecations in this cycle

- `--json` is deprecated in favor of `--output-format json`.
- Existing behavior is preserved; deprecation is warning-only.
