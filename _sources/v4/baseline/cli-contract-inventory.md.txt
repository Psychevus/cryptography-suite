# Current CLI contract

## Entry points and global options

The built wheel installs `cryptography-suite` and `cryptosuite-fuzz`. The main
parser has global `--version`, repeatable `--experimental {gcm-sst}`,
`--log-level {DEBUG,INFO,WARNING,ERROR}`, `--show-metrics`,
`--output-format {text,json}`, and deprecated `--json`.

## Commands

| Command | Arguments and flags | Observed/current role | v4 disposition |
| --- | --- | --- | --- |
| `keygen` | `scheme {rsa,dilithium,kyber,sphincs}`, `--private`, `--public`, password source flags | Primitive/PQC key files | Move primitive forms to labs; replace with provider key lifecycle |
| `hash` | file; `--algorithm {sha3-256,sha3-512,blake2b,blake3}` | File hashing | Labs/general tooling |
| `otp` | required `--secret`; `--interval`, `--digits`, `--algorithm {sha1,sha256,sha512}` | TOTP generation | Labs; secret currently appears in argv |
| `export` | pipeline YAML; `--format {proverif,tamarin}`; repeatable `--track` | Emits formal-text stubs | Labs |
| `gen` | required `--target {fastapi,flask,node}`, required `--pipeline`, optional `--output` | Generates executable source | Labs |
| `backends` | optional action `list` | Lists crypto backend registry | Rewrite as explicit providers |
| `fuzz` | `--pipeline`, `--runs`, `--timeout` | Runs harness subprocess | Test/labs tooling |
| `keystore` | action `list|test|import|migrate`; file/name/from/to/key; `--dry-run`, `--apply`, unsafe unencrypted-key flag, password sources | Registry and raw-key migration | Rewrite around providers; no raw long-term key export in stable path |
| `migrate-keys` | required `--from {file,vault,hsm}`, `--to`; `--batch`, `--ignore-errors`, `--dry-run` | Dynamically loaded in-memory demo | Remove from stable CLI; replace with real migration |
| `file encrypt` | required `--in`, `--out`; `--kdf {argon2,scrypt,pbkdf2}`; password sources | CSF v2 password encryption | Replace with `seal`; no caller KDF choice |
| `file decrypt` | same plus `--allow-legacy-format` | CSF v2 and explicit legacy decrypt | Rewrite as `open` plus isolated legacy migration policy |
| hidden `encrypt` / `decrypt` | aliases of the file subcommands | Backward compatibility | Deprecate/remove through explicit migration plan |

Password source flags are `--password-stdin`, `--password-env NAME`,
`--password-file PATH`, and `--password-fd FD`; otherwise the CLI prompts
without echo. Environment/file inputs are documented as weaker. No password
value is accepted directly by the top-level file/keygen parsers.

## Installed-wheel smoke evidence

The built-wheel environment produced:

- success: `--version`, global and per-command help, `backends list`, SHA3 file
  hash, OTP generation, PBKDF2 file encrypt/decrypt, and byte-for-byte file
  round trip;
- expected missing-extra errors: `export` without PyYAML and `gen` without its
  codegen dependencies;
- failure: `keystore list` raised `AttributeError` at
  `cryptography_suite/cli.py:1069` for undefined `args.password`;
- failure: `migrate-keys --from file --to hsm --dry-run` raised
  `FileNotFoundError` because `src/cryptography_suite/cli/migrate_keys.py` is
  absent from the wheel.

The CLI emits each structured invocation log twice in this environment, showing
duplicate logger-handler/configuration behavior. This is an operational baseline
observation, not a security finding.

## v4 contract requirements

The replacement CLI should be limited to envelope operations, inspection,
rewrap/rotation, provider diagnostics, controlled migration, policy validation,
and machine-readable status. It should define stable exit codes and schemas,
avoid secret values and sensitive names in argv/logs, default to no overwrite,
use failure-atomic output, and keep all legacy behavior explicitly opt-in.
