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

All deprecated helpers emit `DeprecationWarning` when used. Remove any remaining
references before upgrading to v4.0.0.
