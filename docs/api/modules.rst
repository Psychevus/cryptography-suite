API Reference
=============

.. automodule:: cryptography_suite
    :members:
    :undoc-members:
    :show-inheritance:

Selecting a backend
-------------------

.. doctest::

    >>> from cryptography_suite.crypto_backends import use_backend
    >>> use_backend("pyca")
    >>> use_backend("sodium")  # doctest: +SKIP
    >>> use_backend("rust")    # doctest: +SKIP
