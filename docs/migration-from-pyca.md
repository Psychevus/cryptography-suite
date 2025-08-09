# Migration from pyca/cryptography

This guide shows how common `pyca/cryptography` tasks map to the upcoming `suite.recipes` helpers and the lower level `suite.core` APIs.

## Symmetric encryption

| Scenario | pyca/cryptography | `suite.recipes` | `suite.core` | Notes |
| --- | --- | --- | --- | --- |
| Fernet-like | \`\`\`python
from cryptography.fernet import Fernet

key = Fernet.generate_key()
f = Fernet(key)
token = f.encrypt(b"data")
assert f.decrypt(token) == b"data"
`|`python
from suite.recipes import aesgcm_encrypt, aesgcm_decrypt, generate_aesgcm_key

key = generate_aesgcm_key()
nonce, ct = aesgcm_encrypt(key, b"data")
pt = aesgcm_decrypt(key, nonce, ct)
`|`python
from suite.core import AESGCM
import os

key = AESGCM.generate_key(256)
aesgcm = AESGCM(key)
nonce = os.urandom(12)
ct = aesgcm.encrypt(nonce, b"data", None)
pt = aesgcm.decrypt(nonce, ct, None)
`` | `recipes` auto-generate a nonce and fix AES-256-GCM; `core` requires explicit nonce management. | | AES-GCM | ``python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

key = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(key)
nonce = os.urandom(12)
ct = aesgcm.encrypt(nonce, b"data", None)
pt = aesgcm.decrypt(nonce, ct, None)
`|`python
from suite.recipes import aesgcm_encrypt, aesgcm_decrypt, generate_aesgcm_key

key = generate_aesgcm_key()
nonce, ct = aesgcm_encrypt(key, b"data")
pt = aesgcm_decrypt(key, nonce, ct)
`|`python
from suite.core import AESGCM
import os

key = AESGCM.generate_key(256)
aesgcm = AESGCM(key)
nonce = os.urandom(12)
ct = aesgcm.encrypt(nonce, b"data", None)
pt = aesgcm.decrypt(nonce, ct, None)
\`\`\` | Identical to Fernet example but without token wrapper. `recipes` keep parameters fixed; `core` mirrors pyca API. |

## RSA-OAEP encrypt/decrypt

| pyca/cryptography | `suite.recipes` | `suite.core` | Notes |
| --- | --- | --- | --- |
| \`\`\`python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ct = priv.public_key().encrypt(
b"data",
padding.OAEP(
mgf=padding.MGF1(algorithm=hashes.SHA256()),
algorithm=hashes.SHA256(),
label=None,
),
)
pt = priv.decrypt(
ct,
padding.OAEP(
mgf=padding.MGF1(algorithm=hashes.SHA256()),
algorithm=hashes.SHA256(),
label=None,
),
)
`|`python
from suite.recipes import rsa_oaep_encrypt, rsa_oaep_decrypt, generate_rsa_keypair

priv, pub = generate_rsa_keypair()
ct = rsa_oaep_encrypt(pub, b"data")
pt = rsa_oaep_decrypt(priv, ct)
`|`python
from suite.core.asymmetric import RSA, OAEP, MGF1, SHA256

priv = RSA.generate_private_key(2048)
ct = priv.public_key().encrypt(
b"data",
OAEP(
mgf=MGF1(SHA256()),
algorithm=SHA256(),
label=None,
),
)
pt = priv.decrypt(ct, OAEP(mgf=MGF1(SHA256()), algorithm=SHA256(), label=None))
\`\`\` | `recipes` fix SHA-256 and sensible key sizes; `core` exposes padding parameters explicitly. |

## Ed25519 sign/verify

| pyca/cryptography | `suite.recipes` | `suite.core` | Notes |
| --- | --- | --- | --- |
| \`\`\`python
from cryptography.hazmat.primitives.asymmetric import ed25519

sk = ed25519.Ed25519PrivateKey.generate()
sig = sk.sign(b"msg")
sk.public_key().verify(sig, b"msg")
`|`python
from suite.recipes import ed25519_sign, ed25519_verify, generate_ed25519_keypair

sk, pk = generate_ed25519_keypair()
sig = ed25519_sign(sk, b"msg")
ed25519_verify(pk, sig, b"msg")
`|`python
from suite.core.signatures import Ed25519PrivateKey

sk = Ed25519PrivateKey.generate()
sig = sk.sign(b"msg")
sk.public_key().verify(sig, b"msg")
\`\`\` | APIs are nearly identical; `recipes` return tuple keypairs and handle types. |

## ECDSA (RFC 6979) sign/verify

| pyca/cryptography | `suite.recipes` | `suite.core` | Notes |
| --- | --- | --- | --- |
| \`\`\`python
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

sk = ec.generate_private_key(ec.SECP256R1())
sig = sk.sign(b"msg", ec.ECDSA(hashes.SHA256()))
sk.public_key().verify(sig, b"msg", ec.ECDSA(hashes.SHA256()))
`|`python
from suite.recipes import ecdsa_sign, ecdsa_verify, generate_ecdsa_keypair

sk, pk = generate_ecdsa_keypair()
sig = ecdsa_sign(sk, b"msg")
ecdsa_verify(pk, sig, b"msg")
`|`python
from suite.core.asymmetric import ECDSA, SECP256R1, SHA256

sk = ECDSA.generate_private_key(SECP256R1())
sig = sk.sign(b"msg", hash_alg=SHA256(), deterministic=True)
sk.public_key().verify(sig, b"msg", hash_alg=SHA256(), deterministic=True)
\`\`\` | `recipes` enforce RFC 6979; `core` exposes curve, hash, and deterministic flag. |

## KDF examples

| Algorithm | pyca/cryptography | `suite.recipes` | `suite.core` | Notes |
| --- | --- | --- | --- | --- |
| PBKDF2 | \`\`\`python
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os

salt = os.urandom(16)
kdf = PBKDF2HMAC(
algorithm=hashes.SHA256(),
length=32,
salt=salt,
iterations=390000,
)
key = kdf.derive(b"password")
`|`python
from suite.recipes import pbkdf2

key = pbkdf2(password=b"password")
`|`python
from suite.core.kdf import PBKDF2, SHA256
import os

salt = os.urandom(16)
kdf = PBKDF2(
algorithm=SHA256(),
length=32,
salt=salt,
iterations=390000,
)
key = kdf.derive(b"password")
`` | `recipes` select iteration count and salt length; `core` mirrors pyca API. | | scrypt | ``python
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import os

salt = os.urandom(16)
kdf = Scrypt(salt=salt, length=32, n=2\*\*14, r=8, p=1)
key = kdf.derive(b"password")
`|`python
from suite.recipes import scrypt

key = scrypt(password=b"password")
`|`python
from suite.core.kdf import Scrypt
import os

salt = os.urandom(16)
kdf = Scrypt(salt=salt, length=32, n=2\*\*14, r=8, p=1)
key = kdf.derive(b"password")
`` | `recipes` fix N, r, p to recommended values; `core` exposes all parameters. | | Argon2id | ``python
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
import os

salt = os.urandom(16)
kdf = Argon2id(time_cost=2, memory_cost=102400, parallelism=8, length=32, salt=salt)
key = kdf.derive(b"password")
`|`python
from suite.recipes import argon2id

key = argon2id(password=b"password")
`|`python
from suite.core.kdf import Argon2id
import os

salt = os.urandom(16)
kdf = Argon2id(time_cost=2, memory_cost=102400, parallelism=8, length=32, salt=salt)
key = kdf.derive(b"password")
\`\`\` | `recipes` hide tuning knobs; `core` exposes time, memory, and parallelism. |
