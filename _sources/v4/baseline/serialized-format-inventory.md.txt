# Serialized formats

| Format | Producer / consumer | Versioning and authenticated fields | Baseline disposition |
| --- | --- | --- | --- |
| CSF file v2 | `symmetric/aes.py:33-62,334-463` | `CSF!`, version 2, KDF id, salt/nonce lengths, fixed chunk size, salt, nonce; header is GCM AAD; ciphertext plus 16-byte tag | Legacy-decrypt/migration input after v4 envelope replaces encryption |
| CSF file v1 | same parser with `allow_legacy_format=True` | Same versioned framing, but header is not AAD | Legacy decrypt only |
| Raw legacy AES file | same parser | `salt || nonce || ciphertext || tag`; no magic/version; caller supplies KDF | Legacy decrypt only, most restrictive policy |
| One-shot password AES | `aes_encrypt` / `aes_decrypt` | `salt || nonce || AES-GCM ciphertext+tag`, optionally Base64; no version or KDF id | Labs/legacy compatibility only |
| ML-KEM envelope | `pqc/__init__.py:57-62,105-143,176-219` | Magic `CSKEM1`; `>HIII` level/KEM-ciphertext length/salt length/nonce length; header is AAD | Labs; not the v4 envelope |
| Hybrid message | `hybrid.py` and `utils.py:427-480` | Dataclass/dict with `encrypted_key`, `nonce`, `ciphertext`, `tag`; JSON with each bytes value Base64, then outer Base64; no version/algorithm id | Labs; parser lacks an input-size quota |
| Signal demo message | experimental Signal plus `utils.py` | `dh_public`, `nonce`, `ciphertext` through the same JSON/Base64 wrapper; no version | Labs |
| Private/public keys | asymmetric, utils, keystores | PKCS#8/SPKI PEM or DER; metadata sometimes JSON; encryption signaled by PEM and metadata | Provider-controlled or explicit migration only |
| Local keystore metadata | `keystores/local.py` | Per-key JSON: name, type, creation time, fingerprint, encryption flag; no schema version | Development/migration; rewrite |
| Generic PEM JSON | `utils.py:400-424` | JSON with PEM, encryption boolean, key type; no schema version | Labs/migration |
| Encrypted audit line | `audit.py:33-44` | One independent Fernet token per newline; no file header/version/chain | Replace |
| Migration audit log | `src/.../migrate_keys.py:152-246` | Pipe-delimited timestamp/action/details/digest/signature; SHA-256 chain; generated Ed25519 signer; no format version | Demo/labs; not accepted as durable tamper evidence |
| Migration forensics report | same | JSON entries, final digest, public key, signature; no schema version | Demo/labs |
| Pipeline description | `pipeline.py:123-180` | JSON list of module/parameter dictionaries; no schema version | Labs |
| Pipeline input | CLI/codegen | YAML list/objects via `yaml.safe_load`; no schema version | Labs |
| Handshake protobuf | `protocol/handshake.proto`, generated `src/crypto_suite/handshake_pb2.py` | Protobuf field numbers/types; no application envelope version | Labs |
| Formal exports | `pipeline.py:148-174`, CLI | ProVerif-like or Tamarin-like text stubs; no schema/tool version | Labs; not verification output |
| Generated applications | Jinja templates | Python/TypeScript source with YAML step text interpolated into expressions | Labs; executable artifact boundary |
| X.509 | `x509.py` | Standard PEM/DER certificate and CSR structures | Labs |
| OTP inputs | `protocols/otp.py` | Base32 secret plus HOTP counter/TOTP time parameters; not a persistent package format | Labs |
| FHE context | experimental FHE | Backend-defined serialized context; current tests prohibit pickle | Labs |

## CSF KDF portability gap

The CSF header stores only a KDF identifier
(`symmetric/aes.py:55-62`). Scrypt work factors and PBKDF2 iterations come from
module constants (`constants.py:13-19`); Argon2 memory/time/parallelism are read
from environment at import (`symmetric/kdf.py:37-45`). Those parameters are not
serialized. A format can therefore become undecryptable or derive a weaker new
key when deployment defaults change, even though the KDF id is authenticated.

## Parser observations

The CSF parser validates fixed lengths, version, KDF id, chunk size, and minimum
payload before emitting plaintext. The ML-KEM parser validates algorithm-defined
KEM length and fixed salt/nonce/tag bounds. The generic hybrid JSON/Base64
decoder decodes the entire supplied string and object without a size/depth
quota; reachability from an untrusted remote request is not established by this
repository.
