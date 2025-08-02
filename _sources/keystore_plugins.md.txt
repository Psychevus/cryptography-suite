# KeyStore Plugin Development

The suite exposes a pluggable interface for hardware or cloud key
management systems.  Built-in backends include:

- ``local`` – file based storage for demos and tests
- ``mock_hsm`` – in-memory mock for tests
- ``aws-kms`` – AWS KMS backed, production ready
  (install with ``pip install cryptography-suite[aws]``)

## Writing a Plugin

Implement the :class:`~cryptography_suite.keystores.base.KeyStore`
protocol and register the class with
:func:`cryptography_suite.keystores.register_keystore`.

```python
from cryptography_suite.keystores import register_keystore
from cryptography_suite.audit import audit_log

@register_keystore("my-keystore")
class MyKeyStore:
    name = "my-keystore"
    status = "experimental"

    def list_keys(self):
        return ["example"]

    def test_connection(self) -> bool:
        return True

    @audit_log
    def sign(self, key_id: str, data: bytes) -> bytes:
        ...

    @audit_log
    def decrypt(self, key_id: str, data: bytes) -> bytes:
        ...

    @audit_log
    def unwrap(self, key_id: str, wrapped_key: bytes) -> bytes:
        return self.decrypt(key_id, wrapped_key)
```

Third party plugins can also be discovered through entry points using the
``cryptosuite.keystores`` group.

## AWS KMS Example

```python
@register_keystore("aws-kms")
class AWSKMSKeyStore:
    name = "aws-kms"
    status = "production"
    ...  # see cryptography_suite.keystores.aws_kms
```

## PKCS#11 Skeleton

```python
# from cryptography_suite.keystores import register_keystore
# from cryptography_suite.audit import audit_log

# @register_keystore("pkcs11")
class PKCS11KeyStore:
    name = "pkcs11"
    status = "experimental"

    def __init__(self, library_path: str, token_label: str, pin: str):
        raise NotImplementedError

    def list_keys(self) -> list[str]:
        raise NotImplementedError

    def test_connection(self) -> bool:
        raise NotImplementedError

    @audit_log
    def sign(self, key_id: str, data: bytes) -> bytes:
        raise NotImplementedError

    @audit_log
    def decrypt(self, key_id: str, data: bytes) -> bytes:
        raise NotImplementedError
```

Refer to :mod:`cryptography_suite.keystores.pkcs11` for a copy of this
skeleton in the source tree.

## Third-party plugin troubleshooting

If your plugin fails to load it will be listed as ``broken`` when running
``cryptography-suite keystore list``. The command exits with a non-zero status
to highlight the problem but still displays the table of other available
keystores. Inspect the logged error message and verify that all dependencies
for the plugin are installed correctly.
