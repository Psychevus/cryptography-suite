# Interoperability Notes for pyca/cryptography Users

`cryptography-suite` is not a replacement for `pyca/cryptography`. For
production systems, prefer mature audited libraries and platform key management
controls. This page maps a few familiar `pyca/cryptography` patterns to current
`cryptography_suite` learning examples so contributors can compare behavior and
write regression tests.

## AES-GCM style encryption

`pyca/cryptography` exposes AEAD classes directly. In this project, the pipeline
example wraps password-based AES-GCM encryption for demos and tests:

```python
from cryptography_suite.pipeline import AESGCMDecrypt, AESGCMEncrypt

password = "use-a-secret-manager-for-this"
token = AESGCMEncrypt(password=password).run("data")
assert AESGCMDecrypt(password=password).run(token) == "data"
```

## File encryption

The current file helpers authenticate the v2 header as AES-GCM AAD and replace
the output only after authentication succeeds:

```python
from cryptography_suite.symmetric import decrypt_file, encrypt_file

password = "use-a-secret-manager-for-this"
encrypt_file("plain.txt", "cipher.bin", password)
decrypt_file("cipher.bin", "plain.out", password)
```

Legacy raw file formats are decrypt-only compatibility inputs and require
`allow_legacy_format=True`.

## RSA-OAEP pipeline example

```python
from cryptography_suite.asymmetric import generate_rsa_keypair
from cryptography_suite.pipeline import RSADecrypt, RSAEncrypt

private_key, public_key = generate_rsa_keypair()
ciphertext = RSAEncrypt(public_key=public_key).run(b"data")
assert RSADecrypt(private_key=private_key).run(ciphertext) == b"data"
```

## Ed25519 sign/verify example

```python
from cryptography_suite.asymmetric.signatures import (
    generate_ed25519_keypair,
    sign_message,
    verify_signature,
)

private_key, public_key = generate_ed25519_keypair()
signature = sign_message(b"message", private_key)
assert verify_signature(b"message", signature, public_key)
```

## Key serialization

Normal private-key helpers prefer encrypted PEM output. Plaintext private-key
export is available only through an explicitly unsafe helper for controlled
testing or one-time migration.

```python
from cryptography_suite.asymmetric import generate_rsa_keypair
from cryptography_suite.utils import (
    load_encrypted_private_pem,
    to_encrypted_private_pem,
    to_public_pem,
)

private_key, public_key = generate_rsa_keypair()
password = "use-a-secret-manager-for-this"
private_pem = to_encrypted_private_pem(private_key, password)
public_pem = to_public_pem(public_key)
loaded_private_key = load_encrypted_private_pem(private_pem, password)
```

## What to keep in pyca/cryptography

Keep direct `pyca/cryptography` usage for production applications, bespoke
protocol work, certificate and X.509 operations, and cases where you need the
audited upstream API surface directly.
