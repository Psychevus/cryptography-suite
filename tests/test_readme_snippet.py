"""Doctest for README asymmetric encryption snippet.

Example from the documentation::

    >>> from cryptography_suite.asymmetric import (
    ...     generate_rsa_keypair, rsa_encrypt, rsa_decrypt
    ... )
    >>> priv, pub = generate_rsa_keypair()
    >>> ct = rsa_encrypt(b"data", pub)
    >>> rsa_decrypt(ct, priv)
    b'data'
"""

import doctest


def test_readme_snippet_doctest():
    """Execute README code block to ensure it remains valid."""
    result = doctest.testmod()
    assert result.failed == 0
