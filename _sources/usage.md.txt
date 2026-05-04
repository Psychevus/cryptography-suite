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
`--ignore-errors` is supplied.  `--dry-run` logs only key identifiers and
algorithm metadata; it does not print or persist private key material.

To export a signed forensics report or mirror logs to a SIEM:

```bash
cryptography-suite migrate-keys --from file --to hsm --batch --forensics-report report.json --syslog
# or
cryptography-suite migrate-keys --from file --to hsm --batch --webhook https://siem.example/ingest
```

## Safety notes

- The legacy `migrate-keys` demo operates on in-memory representations and
  should be reviewed before adapting it to persistent backends.
- Every action is appended to `audit.log` using a SHA256 hash chain,
  signed with an Ed25519 key and chained by SHA256, providing a
  tamper-evident local log format for the demo.
- Supported backends: `file`, `vault`, and `hsm`.  Classical and
  NIST post-quantum algorithm examples are supported for migration in both
  interactive and batch modes.
- Optional `--forensics-report` exports JSON evidence with a signed
  digest and public key for verification.  Log entries can also be
  forwarded to syslog or a webhook for SIEM integration.
