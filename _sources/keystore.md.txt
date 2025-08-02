# Keystore Migration

The `cryptography-suite keystore` CLI can migrate key material between
registered keystore backends.

```bash
cryptography-suite keystore migrate --from local --to mock_hsm
```

Omit `--key` to stream all available keys.  Use `--dry-run` to preview the
operations without writing to the destination.

Only the following migrations are currently supported:

- LocalKeyStore → AWSKMS
- LocalKeyStore ↔ MockHSM

> ⚠️ Migrating between different algorithms is not supported.  Keys retain
their original algorithm and may fail to import on incompatible backends.
