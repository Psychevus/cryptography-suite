Public API Inventory
====================

.. list-table:: Public API Inventory
   :header-rows: 1

   * - API
     - Summary
     - Status
   * - ``chacha20_encrypt``
     - Encrypt using ChaCha20-Poly1305 with an Argon2-derived key.
     - Core
   * - ``chacha20_decrypt``
     - Decrypt data encrypted with ChaCha20-Poly1305.
     - Core
   * - ``chacha20_encrypt_aead``
     - Encrypt ``plaintext`` using ChaCha20-Poly1305.
     - Core
   * - ``chacha20_decrypt_aead``
     - Decrypt data encrypted with :func:`chacha20_encrypt_aead`.
     - Core
   * - ``xchacha_encrypt``
     - Encrypt ``message`` using XChaCha20-Poly1305.
     - Core
   * - ``xchacha_decrypt``
     - Decrypt data encrypted with :func:`xchacha_encrypt`.
     - Core
   * - ``scrypt_encrypt``
     - 
     - Core
   * - ``scrypt_decrypt``
     - 
     - Core
   * - ``argon2_encrypt``
     - 
     - Core
   * - ``argon2_decrypt``
     - 
     - Core
   * - ``pbkdf2_encrypt``
     - 
     - Core
   * - ``pbkdf2_decrypt``
     - 
     - Core
   * - ``encrypt_file``
     - Encrypt a file using AES-GCM with a password-derived key.
     - Core
   * - ``decrypt_file``
     - Decrypt a file encrypted with AES-GCM using a password-derived key.
     - Core
   * - ``encrypt_file_async``
     - Asynchronously encrypt a file using AES-GCM with a password-derived key.
     - Core
   * - ``decrypt_file_async``
     - Asynchronously decrypt a file encrypted with AES-GCM using a password-derived key.
     - Core
   * - ``derive_key_scrypt``
     - Derive a cryptographic key using Scrypt KDF.
     - Core
   * - ``derive_key_pbkdf2``
     - Derive a key using PBKDF2 HMAC SHA-256.
     - Core
   * - ``derive_key_argon2``
     - Derive a key using Argon2id.
     - Core
   * - ``derive_hkdf``
     - Derive a key using HKDF-SHA256.
     - Core
   * - ``kdf_pbkdf2``
     - Derive a key using PBKDF2-HMAC-SHA256 with configurable iterations.
     - Core
   * - ``verify_derived_key_scrypt``
     - Verify a password against an expected key using Scrypt.
     - Core
   * - ``verify_derived_key_pbkdf2``
     - Verify a password against a previously derived PBKDF2 key.
     - Core
   * - ``generate_salt``
     - Generate a cryptographically secure random salt.
     - Core
   * - ``generate_rsa_keypair``
     - Generates an RSA private and public key pair.
     - Core
   * - ``generate_rsa_keypair_async``
     - Generate an RSA key pair in a background thread.
     - Core
   * - ``serialize_private_key``
     - Serializes a private key to PEM format, encrypted with a password.
     - Core
   * - ``serialize_public_key``
     - Serializes a public key to PEM format.
     - Core
   * - ``load_private_key``
     - Loads a private key (RSA, X25519, X448, or EC) from PEM data.
     - Core
   * - ``load_public_key``
     - Loads a public key (RSA, X25519, X448, or EC) from PEM data.
     - Core
   * - ``generate_x25519_keypair``
     - Generates an X25519 private and public key pair.
     - Core
   * - ``derive_x25519_shared_key``
     - Derives a shared key using X25519 key exchange.
     - Core
   * - ``generate_x448_keypair``
     - Generates an X448 private and public key pair.
     - Core
   * - ``derive_x448_shared_key``
     - Derives a shared key using X448 key exchange.
     - Core
   * - ``generate_ec_keypair``
     - Generates an Elliptic Curve key pair.
     - Core
   * - ``ec_encrypt``
     - Encrypt ``plaintext`` for ``public_key`` using ECIES.
     - Core
   * - ``ec_decrypt``
     - Decrypt ECIES ``ciphertext`` using ``private_key``.
     - Core
   * - ``hybrid_encrypt``
     - Encrypt ``message`` using hybrid RSA/ECIES + AES-GCM.
     - Core
   * - ``hybrid_decrypt``
     - Decrypt data produced by :func:`hybrid_encrypt`.
     - Core
   * - ``HybridEncryptor``
     - Object-oriented helper for hybrid encryption.
     - Core
   * - ``generate_ed25519_keypair``
     - Generates an Ed25519 private and public key pair.
     - Core
   * - ``sign_message``
     - Sign ``message`` using Ed25519 and return Base64 by default.
     - Core
   * - ``verify_signature``
     - Verifies an Ed25519 signature.
     - Core
   * - ``serialize_ed25519_private_key``
     - Serializes an Ed25519 private key to PEM format with encryption.
     - Core
   * - ``serialize_ed25519_public_key``
     - Serializes an Ed25519 public key to PEM format.
     - Core
   * - ``load_ed25519_private_key``
     - Loads an Ed25519 private key from PEM data.
     - Core
   * - ``load_ed25519_public_key``
     - Loads an Ed25519 public key from PEM data.
     - Core
   * - ``generate_ecdsa_keypair``
     - Generates an ECDSA private and public key pair.
     - Core
   * - ``sign_message_ecdsa``
     - Sign a message using ECDSA and return Base64 by default.
     - Core
   * - ``verify_signature_ecdsa``
     - Verifies an ECDSA signature.
     - Core
   * - ``serialize_ecdsa_private_key``
     - Serializes an ECDSA private key to PEM format with encryption.
     - Core
   * - ``serialize_ecdsa_public_key``
     - Serializes an ECDSA public key to PEM format.
     - Core
   * - ``load_ecdsa_private_key``
     - Loads an ECDSA private key from PEM data.
     - Core
   * - ``load_ecdsa_public_key``
     - Loads an ECDSA public key from PEM data.
     - Core
   * - ``sha384_hash``
     - Generates a SHA-384 hash of the given data.
     - Core
   * - ``sha256_hash``
     - Generates a SHA-256 hash of the given data.
     - Core
   * - ``sha512_hash``
     - Generates a SHA-512 hash of the given data.
     - Core
   * - ``sha3_256_hash``
     - Generates a SHA3-256 hash of the given data.
     - Core
   * - ``sha3_512_hash``
     - Generates a SHA3-512 hash of the given data.
     - Core
   * - ``blake2b_hash``
     - Generates a BLAKE2b hash of the given data.
     - Core
   * - ``blake3_hash``
     - Generates a BLAKE3 hash of the given data.
     - Core
   * - ``generate_aes_key``
     - Generates a secure random AES key.
     - Core
   * - ``rotate_aes_key``
     - Generates a new AES key to replace the old one.
     - Core
   * - ``secure_save_key_to_file``
     - Saves key data to a specified file path with secure permissions.
     - Core
   * - ``load_private_key_from_file``
     - Loads a PEM-encoded private key from a file.
     - Core
   * - ``load_public_key_from_file``
     - Loads a PEM-encoded public key from a file.
     - Core
   * - ``key_exists``
     - Checks if a key file exists at the given filepath.
     - Core
   * - ``create_shares``
     - Splits a secret into shares using Shamir's Secret Sharing.
     - Core
   * - ``reconstruct_secret``
     - Reconstructs the secret from shares using Lagrange interpolation.
     - Core
   * - ``SPAKE2Client``
     - Client-side implementation of the SPAKE2 protocol.
     - Core
   * - ``SPAKE2Server``
     - Server-side implementation of the SPAKE2 protocol.
     - Core
   * - ``generate_totp``
     - Generates a TOTP code based on a shared secret.
     - Core
   * - ``verify_totp``
     - Verifies a TOTP code within the allowed time window.
     - Core
   * - ``generate_hotp``
     - Generates an HOTP code based on a shared secret and counter.
     - Core
   * - ``verify_hotp``
     - Verifies an HOTP code within the allowed counter window.
     - Core
   * - ``base62_encode``
     - Encodes byte data into Base62 format.
     - Core
   * - ``base62_decode``
     - Decodes a Base62-encoded string into bytes.
     - Core
   * - ``secure_zero``
     - Overwrite ``data`` with zeros in-place using ``memset_s`` if available.
     - Core
   * - ``constant_time_compare``
     - Return ``True`` if ``val1`` equals ``val2`` using a timing-safe check.
     - Core
   * - ``generate_secure_random_string``
     - Generates a secure random string using Base62 encoding.
     - Core
   * - ``KeyVault``
     - Context manager for sensitive key storage.
     - Core
   * - ``to_pem``
     - Return a PEM-formatted string for a key.
     - Core
   * - ``from_pem``
     - Load a key object from a PEM-formatted string.
     - Core
   * - ``pem_to_json``
     - Serialize a key to a JSON object containing a PEM string.
     - Core
   * - ``encode_encrypted_message``
     - Convert a hybrid or Signal encrypted message into a Base64 string.
     - Core
   * - ``decode_encrypted_message``
     - Parse a Base64 string produced by :func:`encode_encrypted_message`.
     - Core
   * - ``KeyManager``
     - Utility class for handling private key storage and rotation.
     - Core
   * - ``generate_csr``
     - Generate a Certificate Signing Request (CSR).
     - Core
   * - ``self_sign_certificate``
     - Generate a self-signed X.509 certificate.
     - Core
   * - ``load_certificate``
     - Load a PEM encoded certificate.
     - Core
   * - ``audit_log``
     - Decorator to log cryptographic operations.
     - Core
   * - ``set_audit_logger``
     - Configure the audit logger.
     - Core
   * - ``CryptographySuiteError``
     - Base exception for the cryptography suite.
     - Core
   * - ``EncryptionError``
     - Raised when encryption fails or invalid parameters are provided.
     - Core
   * - ``DecryptionError``
     - Raised when decryption fails or invalid data is provided.
     - Core
   * - ``KeyDerivationError``
     - Raised when a key derivation operation fails.
     - Core
   * - ``SignatureVerificationError``
     - Raised when signature verification fails.
     - Core
   * - ``MissingDependencyError``
     - Raised when an optional dependency is missing.
     - Core
   * - ``ProtocolError``
     - Raised when a protocol implementation encounters an error.
     - Core
   * - ``available_backends``
     - 
     - Core
   * - ``use_backend``
     - Select the backend to use.
     - Core
   * - ``select_backend``
     - Register and select a backend.
     - Core
   * - ``PQCRYPTO_AVAILABLE``
     - bool(x) -> bool
     - Experimental
   * - ``SPHINCS_AVAILABLE``
     - bool(x) -> bool
     - Experimental
   * - ``dilithium_sign``
     - Sign a message using Dilithium level 2.
     - Experimental
   * - ``dilithium_verify``
     - Verify a Dilithium signature using level 2.
     - Experimental
   * - ``generate_dilithium_keypair``
     - Generate a Dilithium key pair using level 2 parameters.
     - Experimental
   * - ``generate_kyber_keypair``
     - Generate a Kyber key pair for the given ``level``.
     - Experimental
   * - ``generate_sphincs_keypair``
     - Generate a SPHINCS+ key pair using a 128-bit security level.
     - Experimental
   * - ``kyber_decrypt``
     - Decrypt data encrypted by :func:`kyber_encrypt`.
     - Experimental
   * - ``kyber_encrypt``
     - Encrypt ``plaintext`` using Kyber and AES-GCM.
     - Experimental
   * - ``sphincs_sign``
     - Sign ``message`` with SPHINCS+ returning Base64 by default.
     - Experimental
   * - ``sphincs_verify``
     - Verify a SPHINCS+ signature.
     - Experimental
   * - ``SIGNAL_AVAILABLE``
     - bool(x) -> bool
     - Experimental
   * - ``SignalSender``
     - Sender that initiates a Signal session.
     - Experimental
   * - ``SignalReceiver``
     - Receiver that responds to a Signal session.
     - Experimental
   * - ``initialize_signal_session``
     - Convenience function to create two parties with a shared session.
     - Experimental
   * - ``x3dh_initiator``
     - Perform the initiator side of the X3DH key agreement.
     - Experimental
   * - ``x3dh_responder``
     - Perform the responder side of the X3DH key agreement.
     - Experimental
   * - ``FHE_AVAILABLE``
     - bool(x) -> bool
     - Experimental
   * - ``fhe_keygen``
     - 
     - Experimental
   * - ``fhe_encrypt``
     - 
     - Experimental
   * - ``fhe_decrypt``
     - 
     - Experimental
   * - ``fhe_add``
     - 
     - Experimental
   * - ``fhe_multiply``
     -
     - Experimental
   * - ``fhe_serialize_context``
     -
     - Experimental
   * - ``fhe_load_context``
     -
     - Experimental
   * - ``BULLETPROOF_AVAILABLE``
     - bool(x) -> bool
     - Experimental
   * - ``bulletproof``
     - Bulletproof range proof utilities using pybulletproofs.
     - Experimental
   * - ``ZKSNARK_AVAILABLE``
     - bool(x) -> bool
     - Experimental
   * - ``zksnark``
     - ZK-SNARK utilities using PySNARK.
     - Experimental
   * - ``HandshakeFlowWidget``
     - Animated visualization of a handshake protocol.
     - Experimental
   * - ``KeyGraphWidget``
     - Display key relationships as a graph.
     - Experimental
   * - ``SessionTimelineWidget``
     - Visualize message and key events over time.
     - Experimental
   * - ``generate_bls_keypair``
     - Generate a BLS12-381 key pair.
     - Legacy
   * - ``bls_sign``
     - Sign a message using the BLS signature scheme.
     - Legacy
   * - ``bls_verify``
     - Verify a BLS signature.
     - Legacy
   * - ``bls_aggregate``
     - Aggregate multiple BLS signatures into one.
     - Legacy
   * - ``bls_aggregate_verify``
     - Verify an aggregated BLS signature against multiple messages.
     - Legacy
   * - ``generate_ed448_keypair``
     - Generates an Ed448 private and public key pair.
     - Legacy
   * - ``sign_message_ed448``
     - Sign a message using Ed448 and return Base64 by default.
     - Legacy
   * - ``verify_signature_ed448``
     - Verifies an Ed448 signature.
     - Legacy
   * - ``blake3_hash_v2``
     - Another BLAKE3 hash helper used for testing.
     - Legacy
