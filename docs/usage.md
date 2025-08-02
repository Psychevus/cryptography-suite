# migrate-keys command

The `migrate-keys` CLI moves private keys between in-memory backends.
It supports an interactive wizard and a non-interactive batch mode.

## Interactive wizard

```bash
cryptography-suite migrate-keys --from file --to vault
```

Each key's algorithm family, security level, and SHA256 fingerprint are shown.
The wizard accepts `y`, `n`, `all`, or `skip` for each key.  RSA keys below
2048 bits are highlighted with a warning.  Post-quantum keys (e.g.,
CRYSTALS-Kyber, Dilithium) are detected automatically and a warning is emitted
if they operate in hybrid or legacy mode.

## Batch mode

```bash
cryptography-suite migrate-keys --from file --to hsm --batch \
    [--ignore-errors] [--dry-run]
```

Runs without prompts.  Stops on the first failure unless
`--ignore-errors` is supplied.  `--dry-run` logs actions without
writing any keys to the target.

## Security guarantees

- Keys are never written to disk; all migrations operate on in-memory
  representations only.
- Every action is appended to `audit.log` using a SHA256 hash chain,
  providing tamper-evident auditability.
- Supported backends: `file`, `vault`, and `hsm`.  Classical and
  NIST post-quantum algorithms are supported for migration in both
  interactive and batch modes.
