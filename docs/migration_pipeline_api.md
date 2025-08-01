# Migration to Pipeline API

Legacy one-shot helpers such as `aes_encrypt` and `rsa_encrypt` are deprecated in
favor of the composable Pipeline DSL.

## Replacing AES helpers

```python
from cryptography_suite.pipeline import AESGCMEncrypt, AESGCMDecrypt

ciphertext = AESGCMEncrypt(password="pw").run("secret")
plaintext = AESGCMDecrypt(password="pw").run(ciphertext)
```

## Replacing RSA helpers

```python
from cryptography_suite.asymmetric import generate_rsa_keypair
from cryptography_suite.pipeline import RSAEncrypt, RSADecrypt

priv, pub = generate_rsa_keypair()
ct = RSAEncrypt(public_key=pub).run(b"data")
pt = RSADecrypt(private_key=priv).run(ct)
```

After one major version, these legacy helpers will be removed. Always prefer
adding new functionality as Pipeline modules.
