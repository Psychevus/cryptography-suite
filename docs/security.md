# Security Notes

This project aims to carefully handle sensitive data in memory. Key features:

- `KeyVault` now cleans up secrets not only on context exit but also when the
  object is garbage collected.
- `secure_zero` utilises `memset_s` from the system C library when available to
  erase memory. A fallback to `ctypes.memset` is used otherwise.
- `constant_time_compare` provides a timing-attack resistant equality check.

While these mechanisms help reduce residual secrets in memory, absolute
zeroization cannot be guaranteed on all operating systems and Python
implementations.

- Private keys should always be stored encrypted, either with a strong password or
  in a hardware-backed keystore (HSM, KMS, etc.). Unencrypted PEMs are only
  acceptable for testing or inside protected containers. By default the library
  emits a warning when encountering such files. Set the environment variable
  ``CRYPTOSUITE_STRICT_KEYS=error`` to refuse loading or saving unencrypted keys.
  To disable this protection entirely – which carries significant risk – set
  ``CRYPTOSUITE_STRICT_KEYS=0`` or ``CRYPTOSUITE_STRICT_KEYS=false``.
