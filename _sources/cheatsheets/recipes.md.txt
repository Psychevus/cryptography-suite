# Recipes Cheat Sheet

Copy-paste-ready snippets for common tasks using `suite.recipes`.

## Encrypt and decrypt bytes

```python
from suite.recipes import aesgcm_encrypt, aesgcm_decrypt, generate_aesgcm_key

key = generate_aesgcm_key()
nonce, ct = aesgcm_encrypt(key, b"secret")
pt = aesgcm_decrypt(key, nonce, ct)
```

## Encrypt and decrypt files

```python
from pathlib import Path
from suite.recipes import encrypt_file, decrypt_file, generate_aesgcm_key

key = generate_aesgcm_key()
encrypt_file(key, Path("plain.txt"), Path("cipher.bin"))
decrypt_file(key, Path("cipher.bin"), Path("plain.txt"))
```

## Password-based encryption

```python
from suite.recipes import password_encrypt, password_decrypt

token = password_encrypt("hunter2", b"secret")
plaintext = password_decrypt("hunter2", token)
```

## Sign and verify messages

```python
from suite.recipes import generate_ed25519_keypair, sign_message, verify_message

sk, pk = generate_ed25519_keypair()
sig = sign_message(sk, b"data")
verify_message(pk, sig, b"data")
```

## Key generation and serialization

```python
from suite.recipes import (
    generate_ed25519_keypair,
    serialize_private_key,
    load_private_key,
)

sk, pk = generate_ed25519_keypair()
pem = serialize_private_key(sk)
sk2 = load_private_key(pem)
```
