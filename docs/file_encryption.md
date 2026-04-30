# File Encryption Format

`encrypt_file` and `encrypt_file_async` write AES-GCM encrypted files in the v2
streaming format:

```text
CSF! || version=2 || KDF id || salt length || nonce length || chunk size || salt || nonce || ciphertext || tag
```

The full header through `nonce` is passed to AES-GCM as additional
authenticated data. Decryption validates the magic, version, KDF id, salt
length, nonce length, chunk size, and minimum payload size before streaming any
plaintext.

Plaintext is written only to a temporary file in the requested output
directory. The requested output path is replaced atomically after the GCM tag
verifies. Authentication failure, malformed headers, truncation, or wrong
passwords leave any pre-existing output file untouched and remove only the
temporary file created by the current operation.

Legacy v1 versioned files and raw `salt || nonce || ciphertext || tag` files
are decrypt-only compatibility formats. Callers must pass
`allow_legacy_format=True`, or use `cryptography-suite file decrypt
--allow-legacy-format`, to decrypt those files.
