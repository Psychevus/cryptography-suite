# Experimental Features

These APIs are unstable and may change or be removed without notice.

## AES-GCM-SST Preview

The `GCM-SST` mode introduces a synthetic IV derived with HKDF-SHA-512,
following the November 2024 draft of NIST SP 800-38D §6.3. It aims to
reduce nonce-misuse risks by mixing a public selector into the IV.

Enable this preview via the command line:

```bash
cryptography-suite --experimental gcm-sst <subcommand>
```

This flag monkey-patches `cryptography_suite.aead.DEFAULT` to `"GCM-SST"` so
that higher level helpers choose the new construction.

**Status:** prototype; performance optimized using the C-backed AES-GCM
implementation from the `cryptography` library and therefore suitable
for ~1&nbsp;Gbps throughput on x86-64.
