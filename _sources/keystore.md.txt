# Keystore Migration

The `cryptography-suite keystore` CLI can migrate key material between
registered keystore backends.

```bash
cryptography-suite keystore migrate --from local --to mock_hsm --dry-run
```

Omit `--key` to stream all available keys.  Use `--dry-run` to preview the
operations without writing to the destination, then repeat with `--apply` after
reviewing the migration table.

Only the following migrations are currently supported:

- LocalKeyStore ↔ MockHSM

`aws-kms` is intentionally excluded from raw key migration because this backend
does not support raw private-key import/export.

Encrypted private-key PEMs must remain encrypted end to end. If a source key is
plaintext, migration fails closed unless
`--unsafe-allow-unencrypted-private-key` is supplied for controlled
development/testing migration. Migrating between different algorithms is not
supported. Keys retain their original algorithm and may fail to import on
incompatible backends.

`LocalKeyStore` is a development/testing backend unless you add production
filesystem, backup, monitoring, and lifecycle controls. Prefer HSM/KMS-backed
stores for production private keys.
