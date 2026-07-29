# Current public Python API

## Method

The inventory combines `API_CLI_CONTRACT.md`, documentation imports, package
`__all__` declarations, and static enumeration of public top-level classes and
functions in all four source trees. Imported third-party names that leak only
because a module lacks `__all__` are implementation leakage, not an intentional
contract; v4 must close that leakage with explicit exports.

No current API is declared v4-stable by this baseline. “Rewrite” means preserve
the product capability, not the current signature. “Labs” means move the API
out of the stable wheel.

## Package-root exports

`cryptography_suite/__init__.py` explicitly exports 111 names:

| Group | Exact current root names | v4 disposition |
| --- | --- | --- |
| Symmetric and file encryption | `chacha20_encrypt`, `chacha20_decrypt`, `chacha20_encrypt_aead`, `chacha20_decrypt_aead`, `xchacha_encrypt`, `xchacha_decrypt`, `scrypt_encrypt`, `scrypt_decrypt`, `argon2_encrypt`, `argon2_decrypt`, `pbkdf2_encrypt`, `pbkdf2_decrypt`, `encrypt_file`, `decrypt_file`, `encrypt_file_async`, `decrypt_file_async` | Primitive helpers to labs; current file formats decrypt/migrate-only |
| KDFs | `derive_key_scrypt`, `derive_key_pbkdf2`, `derive_key_argon2`, `derive_hkdf`, `kdf_pbkdf2`, `verify_derived_key_scrypt`, `verify_derived_key_pbkdf2`, `generate_salt` | Remove from root; internal policy-selected KDFs only |
| Asymmetric and hybrid | `generate_rsa_keypair`, `generate_rsa_keypair_async`, `serialize_private_key`, `serialize_public_key`, `load_private_key`, `load_public_key`, `generate_x25519_keypair`, `derive_x25519_shared_key`, `generate_x448_keypair`, `derive_x448_shared_key`, `generate_ec_keypair`, `ec_encrypt`, `ec_decrypt`, `hybrid_encrypt`, `hybrid_decrypt`, `HybridEncryptor` | Labs or internal migration adapters |
| Signatures | `generate_ed25519_keypair`, `sign_message`, `verify_signature`, `serialize_ed25519_private_key`, `serialize_ed25519_public_key`, `load_ed25519_private_key`, `load_ed25519_public_key`, `generate_ecdsa_keypair`, `sign_message_ecdsa`, `verify_signature_ecdsa`, `serialize_ecdsa_private_key`, `serialize_ecdsa_public_key`, `load_ecdsa_private_key`, `load_ecdsa_public_key` | Labs; provider-native signing is not a root primitive API |
| Hashes | `sha384_hash`, `sha256_hash`, `sha512_hash`, `sha3_256_hash`, `sha3_512_hash`, `blake2b_hash`, `blake3_hash` | Labs/ordinary application dependency |
| Key/protocol helpers | `generate_aes_key`, `rotate_aes_key`, `secure_save_key_to_file`, `load_private_key_from_file`, `load_public_key_from_file`, `key_exists`, `create_shares`, `reconstruct_secret`, `SPAKE2Client`, `SPAKE2Server`, `generate_totp`, `verify_totp`, `generate_hotp`, `verify_hotp`, `KeyManager` | Labs; replace key lifecycle with provider/version/rotation objects |
| Utilities and serialization | `base62_encode`, `base62_decode`, `secure_zero`, `constant_time_compare`, `ct_equal`, `generate_secure_random_string`, `KeyVault`, `to_pem`, `to_public_pem`, `to_encrypted_private_pem`, `to_unencrypted_private_pem_unsafe`, `from_pem`, `load_public_pem`, `load_encrypted_private_pem`, `pem_to_json`, `encode_encrypted_message`, `decode_encrypted_message` | Remove from root; retain only narrowly scoped internal utilities |
| X.509 and audit | `generate_csr`, `self_sign_certificate`, `load_certificate`, `audit_log`, `set_audit_logger` | X.509 to labs; rewrite audit as event sink interfaces |
| Errors | `CryptographySuiteError`, `EncryptionError`, `DecryptionError`, `KeyDerivationError`, `SignatureVerificationError`, `MissingDependencyError`, `ProtocolError`, `UnsupportedAlgorithm`, `UnsupportedOperationError`, `StrictKeyPolicyError` | Replace with a small typed v4 error taxonomy |
| Backend controls | `available_backends`, `use_backend`, `select_backend` | Replace with explicit provider configuration |

The grouped names above are the 111 entries in `__all__`. `__version__` is also
public in practice, so the effective package-root surface is at least 112 names.

The excluded `src/cryptography_suite/__init__.py` declares a different
105-name list and dynamically aliases `src/crypto_suite` modules. It omits some
new root utilities/errors and is not a distributable contract.

## Submodule surfaces

| Module/namespace | Current public surface | v4 disposition |
| --- | --- | --- |
| `aead` | `chacha20_encrypt_aead`, `chacha20_decrypt_aead`, `AESGCMContext` | Labs; caller-managed nonce/context API excluded |
| `aead_plugins` | `aes_gcm_sst_encrypt`, `aes_gcm_sst_decrypt` | Labs |
| `asymmetric` | RSA key generation/loading/serialization/encrypt/decrypt; X25519/X448 generation/derivation; EC generation/encrypt/decrypt | Labs |
| `asymmetric.signatures` | Ed25519, Ed448, ECDSA, and RSA generate/sign/verify/serialize/load helpers | Labs |
| `asymmetric.bls` | `generate_bls_keypair`, `bls_sign`, `bls_verify`, `bls_aggregate`, `bls_aggregate_verify` | Labs |
| `audit` | `AuditLogger`, `InMemoryAuditLogger`, `EncryptedFileAuditLogger`, `audit_log`, `set_audit_logger` | Rewrite |
| `codegen` | `generate` | Labs |
| `config` / `core.settings` | `SETTINGS`, `STRICT_KEYS`, `RUNTIME_ENV`, `LOG_LEVEL`, `RuntimeEnvironment`, `SuiteSettings`, `load_settings` | Rewrite into explicit immutable configuration |
| `constants` | key/nonce/salt sizes and Scrypt/PBKDF2/Argon2 defaults | Internal only |
| `core.errors` / `errors` / `exceptions` | `ErrorCode`, `SuiteError`, current public compatibility exceptions, `NonceReuseError`, `KeyRotationRequired` | Rewrite taxonomy |
| `core.logging` | structured logger configuration, correlation IDs, redaction helpers, `log_event` | Internal stable-core candidate after review |
| `core.operations` | retry policy, metrics, cancellation, subprocess wrapper | Split: provider retry candidate; subprocess/metrics general tooling excluded |
| `crypto_backends` | `register_backend`, `available_backends`, `use_backend`, `select_backend`, `get_backend`; `AEAD`, `KDF`, `PyCABackend` | Rewrite as provider contract |
| `debug` / `rich_logging` | verbose/redaction helpers, `get_rich_logger`, `PipelineProgress` | Tooling/labs |
| `experimental` | guarded AES-GCM-SST, Ascon, FHE, Salsa20, Signal, and ZK namespaces | Labs |
| `hashing` | SHA-2/SHA-3/BLAKE2/BLAKE3 and Scrypt/PBKDF2 helpers | Labs |
| `homomorphic` | FHE availability, backend/parameter models, keygen/encrypt/decrypt/arithmetic/context serialization | Labs |
| `hybrid` | `EncryptedHybridMessage`, `HybridEncryptor`, `hybrid_encrypt`, `hybrid_decrypt` | Labs; do not treat as the v4 envelope |
| `keystores` | `KeyStore`, `KeyStoreCapability`, `supports_capability`, registry/load functions; `LocalKeyStore`, `MockHSMKeyStore`, `PKCS11KeyStore`, `AWSKMSKeyStore` | Rewrite providers; mock remains tests; local remains development/migration only |
| `legacy` | BLS, Ed448, and `blake3_hash_v2` compatibility exports | Remove or labs; not stable v4 legacy-envelope support |
| `nonce` | `NonceManager` | Labs/remove from stable core |
| `pipeline` | `CryptoModule`, `Pipeline`, `PipelineVisualizer`, registry/list, AES/RSA/ECIES/hybrid/ML-KEM/Kyber stages | Labs |
| `pqc` | ML-KEM/Kyber generation/envelope helpers, Dilithium, SPHINCS+ | Labs |
| `protocols` | OTP, secret sharing, SPAKE2, key generation/rotation/file persistence, `KeyManager` | Labs/rewrite lifecycle concepts |
| `symmetric` | current file and one-shot AES, ChaCha/XChaCha, KDF helpers | Labs plus explicit legacy-decrypt adapters |
| `utils` | PEM conversion, encrypted-message encoding, zeroization, comparisons, random/base62, `KeyVault` | Internal candidates only; remove broad public module |
| `viz` | three widgets and HTML export | Labs |
| `x509` | CSR, self-signed certificate, certificate loading | Labs |
| `zk` | Bulletproof and zk-SNARK `setup`/`prove`/`verify` modules | Labs |
| `src/crypto_suite.aead` | `AesGcm` and alternate nonce/key-rotation behavior | Delete duplicate or move to labs after compatibility proof |
| `src/crypto_suite.handshake` | handshake dataclasses, enum, negotiation, context/error | Labs |
| `src/crypto_suite.nonce` | alternate `NonceManager`, storage protocol, local exceptions | Delete duplicate |
| `src/crypto_suite.utils.zeroize` | `secure_zero`, `secure_zero_pypy` | Evaluate internal implementation, then delete duplicate namespace |
| `src/cryptography_suite.cli.migrate_keys` | demo backends, migration wizard/batch, audit logger/report | Replace with real provider migration; demo to labs |
| `src/suite` | experimental-warning helper | Delete duplicate |

## Proposed v4 root

Phase 2 should specify a root no larger than high-level `seal`, `open`,
`inspect`, and `rewrap`, typed envelope/context/policy models, provider
interfaces, lifecycle operations, and a small error set. No current primitive,
nonce, KDF-parameter, raw-key, plugin-registration, or experimental symbol
should survive at the stable root merely for source compatibility.
