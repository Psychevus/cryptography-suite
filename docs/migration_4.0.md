# Migration Guide to Cryptography Suite 4.0.0

The following functions are deprecated and scheduled for removal in v4.0.0. Update
existing code to use the recommended replacements.

| Deprecated Function | Replacement |
| --- | --- |
| `derive_pbkdf2` | `kdf_pbkdf2` |
| `generate_rsa_keypair_and_save` | `KeyManager.generate_rsa_keypair_and_save` |
| `generate_ec_keypair_and_save` | `KeyManager.generate_ec_keypair_and_save` |
| `salsa20_encrypt` / `salsa20_decrypt` | `chacha20_encrypt` / `chacha20_decrypt` or `aead.chacha20_encrypt_aead` |
| `ascon.encrypt` / `ascon.decrypt` | `aead.chacha20_encrypt_aead` / `aead.chacha20_decrypt_aead` or `symmetric.aes_encrypt` / `symmetric.aes_decrypt` |
| `from_pem` for private keys | `load_encrypted_private_pem(pem, password)` |

All deprecated helpers emit `DeprecationWarning` when used. Remove any remaining
references before upgrading to v4.0.0.

## Private Key PEM Hardening

`to_pem(private_key)` no longer exports plaintext private keys. Use
`to_encrypted_private_pem(private_key, password)` for normal private-key PEM
export and `load_encrypted_private_pem(pem, password)` to load it. Public-key
PEM export remains available through `to_pem(public_key)` and
`to_public_pem(public_key)`.

Plaintext private-key export is intentionally noisy:
`to_unencrypted_private_pem_unsafe(private_key)` emits a warning and should be
limited to controlled testing or one-time migration. `pem_to_json(private_key)`
also requires a password unless the explicitly unsafe flag is provided.

`KeyManager.save_private_key` and `LocalKeyStore` now require encrypted writes by
default. Set `CRYPTOSUITE_STRICT_KEYS=error` in production-sensitive
environments to block legacy plaintext reads/writes, and migrate existing local
plaintext PEMs to encrypted PEM or HSM/KMS-backed storage.
