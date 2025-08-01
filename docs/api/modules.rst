API Reference
=============

Core API
--------

.. automodule:: cryptography_suite
    :members:
    :undoc-members:
    :show-inheritance:

Experimental API
----------------

.. automodule:: cryptography_suite.experimental
    :members:
    :undoc-members:
    :show-inheritance:

Legacy API
----------

.. automodule:: cryptography_suite.legacy
    :members:
    :undoc-members:
    :show-inheritance:

Selecting a backend
-------------------

.. doctest::

    >>> from cryptography_suite.crypto_backends import use_backend
    >>> with use_backend("pyca"):
    ...     pass
    >>> with use_backend("sodium"):  # doctest: +SKIP
    ...     pass
    >>> with use_backend("rust"):  # doctest: +SKIP
    ...     pass
