Security Considerations
=======================

.. warning::
   The following notes highlight important aspects for using ``cryptography-suite`` safely.

- Insecure primitives like ``salsa20_encrypt`` and ``chacha20_stream_encrypt`` provide
  no authentication and are for educational purposes only.
- Enabling ``VERBOSE_MODE`` prints derived keys and nonces to stdout. Do **not** enable
  this in production environments.
- When serializing private keys with :func:`cryptography_suite.serialize_private_key`
  or using :class:`cryptography_suite.protocols.key_management.KeyManager`, always
  supply a password so the key material is encrypted.
