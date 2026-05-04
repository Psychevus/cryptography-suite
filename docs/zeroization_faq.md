# Zeroization in Python FAQ

### Can Python securely erase secrets from memory?

Not for arbitrary objects. Python's immutable ``bytes`` objects may be
copied or interned by the interpreter and are only released during garbage
collection. The library's :class:`~cryptography_suite.utils.KeyVault` and
:func:`~cryptography_suite.utils.secure_zero` helpers operate on mutable
``bytearray`` buffers so that sensitive data can be overwritten in place.

### What should I use for private keys or session secrets?

Generate keys with ``sensitive=True`` or wrap existing byte strings in
``KeyVault``. Access the underlying bytes within a ``with`` block:

```python
from cryptography_suite.protocols import generate_aes_key

with generate_aes_key() as key_bytes:
    use_key(key_bytes)
```

### Do native backends handle zeroization?

Some underlying libraries, such as OpenSSL, provide their own memory-management
and key-cleanup behavior. Treat those properties as backend-specific and consult
the upstream backend documentation for high-assurance requirements; Python
itself cannot directly guarantee cleanup for arbitrary objects.
