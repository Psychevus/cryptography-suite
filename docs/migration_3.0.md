# Migrating to Cryptography Suite 3.0.0

Version 3.0.0 introduces a redesigned, backend-agnostic architecture. Users of
2.x should review the following breaking changes and update their code
accordingly.

## Breaking Changes

- **Backend Selection** is now mandatory via `select_backend`. The default
  `cryptography` backend can be enabled with `select_backend(cryptography_backend())`.
- **Pipeline API** replaces ad-hoc helper chains. Compose operations using the
  `Pipeline` class.
- **Key Management Interfaces** have changed. Use `KeyManager` for all
  persistent key operations.
- **Deprecated Functions Removed.** Legacy helpers marked deprecated in 2.x have
  been deleted.

## Typical Upgrade Steps

1. Install version 3.0.0 and required extras.
2. Replace direct calls to helper functions with pipeline stages.
3. Configure a backend at application start-up.
4. Review new exceptions for misuse protection and update error handling.

## Example

```python
from cryptography_suite import Pipeline, select_backend
from cryptography_suite.crypto_backends import cryptography_backend
from cryptography_suite.pipeline import AESGCMEncrypt, AESGCMDecrypt

select_backend(cryptography_backend())

encrypt = AESGCMEncrypt(password="pass")
decrypt = AESGCMDecrypt(password="pass")

p = Pipeline() >> encrypt >> decrypt
assert p.run(b"msg") == b"msg"
```

See the [full documentation](index.html) for details on the new architecture and
plugin interfaces.

