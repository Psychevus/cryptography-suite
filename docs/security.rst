Security Considerations
=======================

.. warning::
   The following notes highlight important aspects for using ``cryptography-suite`` safely.

- ``chacha20_stream_encrypt`` provides no authentication and is for educational
  purposes only. The deprecated ``salsa20_encrypt`` will be removed in v4.0.0.
- Enabling ``VERBOSE_MODE`` prints derived keys and nonces to stdout. Do **not** enable
  this in production environments.
- When serializing private keys with :func:`cryptography_suite.serialize_private_key`
  or using :class:`cryptography_suite.protocols.key_management.KeyManager`, always
  supply a password so the key material is encrypted.
