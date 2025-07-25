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
