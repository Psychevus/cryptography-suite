# Current API Cheat Sheet

Copy-paste-ready snippets for the current `cryptography_suite` namespace. These
examples are for learning and local experiments; review your own threat model
before handling real secrets.

## Encrypt and decrypt bytes

```python
from cryptography_suite.pipeline import AESGCMDecrypt, AESGCMEncrypt

password = "use-a-secret-manager-for-this"
token = AESGCMEncrypt(password=password).run("secret")
plaintext = AESGCMDecrypt(password=password).run(token)
```

## Encrypt and decrypt files

```python
from cryptography_suite.symmetric import decrypt_file, encrypt_file

password = "use-a-secret-manager-for-this"
encrypt_file("plain.txt", "cipher.bin", password)
decrypt_file("cipher.bin", "plain.out", password)
```

## Sign and verify messages

```python
from cryptography_suite.asymmetric.signatures import (
    generate_ed25519_keypair,
    sign_message,
    verify_signature,
)

private_key, public_key = generate_ed25519_keypair()
signature = sign_message(b"data", private_key)
assert verify_signature(b"data", signature, public_key)
```

## Key generation and encrypted serialization

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

## Pipeline composition

```python
from cryptography_suite.pipeline import AESGCMDecrypt, AESGCMEncrypt, Pipeline

pipeline = Pipeline() >> AESGCMEncrypt(password="pw") >> AESGCMDecrypt(password="pw")
assert pipeline.run("secret") == "secret"
```
