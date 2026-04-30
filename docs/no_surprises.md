# No Surprises Standardization

This guide centralizes day-1 and day-2 operational docs for maintainers.

## Quickstart

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
pytest -q
```

Run CLI examples:

```bash
cryptography-suite hash README.md --algorithm blake3
cryptography-suite --output-format json hash README.md --algorithm blake3
cryptography-suite otp --secret JBSWY3DPEHPK3PXP
```

## Configuration reference

### Runtime / CLI knobs

- `--log-level`: controls structured log verbosity.
- `--experimental gcm-sst`: enables preview GCM-SST mode.
- `--show-metrics`: prints operation metrics snapshot.
- `--output-format {text,json}`: consistent human/machine output mode.
- `--json`: deprecated alias for JSON output mode.

### Packaging extras

- `pqc`: post-quantum algorithms.
- `fhe`: experimental homomorphic helpers. They still require
  `CRYPTOSUITE_ALLOW_EXPERIMENTAL=1` at runtime and never use pickle for
  context deserialization.
- `zk`: zero-knowledge helpers.

## Architecture overview

- `cryptography_suite/core`: settings/logging/operation wrappers.
- `cryptography_suite/symmetric`, `asymmetric`, `protocols`: cryptographic domains.
- `cryptography_suite/pipeline`: composable workflow model and exports.
- `cryptography_suite/keystores`: pluggable key persistence providers.
- `cryptography_suite/experimental`: unstable research APIs with warnings.

## Examples

### 1) Human-readable output (default)

```bash
cryptography-suite file encrypt --in plain.txt --out enc.bin
```

The command prompts for the password without echoing it. Scripts should prefer
`--password-stdin` or `--password-fd`; environment variables are supported only
for controlled automation where process exposure is understood.

### 2) Machine-readable output

```bash
cryptography-suite --output-format json hash README.md --algorithm sha3-256
```

### 3) Backward-compatible alias (deprecated)

```bash
cryptography-suite --json hash README.md --algorithm blake3
```

The command still works, but prints a deprecation warning advising
`--output-format json`.

## Migration / deprecation note

The file/keygen CLI no longer accepts passwords directly as command-line
arguments. Existing scripts should switch to prompt, stdin, fd, environment, or
file-based secret input.

The only deprecation is:

- `--json` -> `--output-format json`

Migration path: replace `--json` in scripts and keep behavior unchanged.
