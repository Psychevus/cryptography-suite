"""Doctest for README asymmetric encryption snippet.

Example from the documentation::

    >>> from cryptography_suite.asymmetric import generate_rsa_keypair
    >>> from cryptography_suite.pipeline import RSAEncrypt, RSADecrypt
    >>> priv, pub = generate_rsa_keypair()
    >>> ct = RSAEncrypt(public_key=pub).run(b"data")
    >>> RSADecrypt(private_key=priv).run(ct)
    b'data'
"""

import doctest


def test_readme_snippet_doctest():
    """Execute README code block to ensure it remains valid."""
    result = doctest.testmod()
    assert result.failed == 0
