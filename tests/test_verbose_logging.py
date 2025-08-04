import importlib
import logging
import pytest
import os


def test_verbose_requires_debug(monkeypatch):
    monkeypatch.setenv("CRYPTOSUITE_VERBOSE_MODE", "1")
    import cryptography_suite.debug as debug
    import cryptography_suite.symmetric.aes as aes
    importlib.reload(debug)
    importlib.reload(aes)

    logger = logging.getLogger("cryptography_suite.symmetric.aes")
    logger.setLevel(logging.INFO)

    with pytest.raises(RuntimeError):
        aes.aes_encrypt("secret", "pw", kdf="scrypt")

    # reset modules
    monkeypatch.setenv("CRYPTOSUITE_VERBOSE_MODE", "0")
    importlib.reload(debug)
    importlib.reload(aes)


def test_ciphertext_logged_not_plain(monkeypatch, caplog):
    monkeypatch.setenv("CRYPTOSUITE_VERBOSE_MODE", "1")
    import cryptography_suite.debug as debug
    import cryptography_suite.symmetric.aes as aes
    importlib.reload(debug)
    importlib.reload(aes)

    logger = logging.getLogger("cryptography_suite.symmetric.aes")
    logger.setLevel(logging.DEBUG)

    plaintext = "sensitive data"
    with caplog.at_level(logging.DEBUG, logger="cryptography_suite.symmetric.aes"):
        aes.aes_encrypt(plaintext, "pw", kdf="scrypt")

    assert "ciphertext=" in caplog.text
    assert plaintext not in caplog.text

    # reset modules
    monkeypatch.setenv("CRYPTOSUITE_VERBOSE_MODE", "0")
    importlib.reload(debug)
    importlib.reload(aes)
