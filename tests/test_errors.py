import pytest

from cryptography_suite.errors import (
    CryptographySuiteError,
    DecryptionError,
    EncryptionError,
    KeyDerivationError,
    MissingDependencyError,
    ProtocolError,
    SignatureVerificationError,
)


def test_hierarchy():
    for exc in [
        EncryptionError,
        DecryptionError,
        KeyDerivationError,
        SignatureVerificationError,
        MissingDependencyError,
        ProtocolError,
    ]:
        assert issubclass(exc, CryptographySuiteError)


def test_exceptions_raise():
    with pytest.raises(EncryptionError):
        raise EncryptionError("encrypt")
    with pytest.raises(DecryptionError):
        raise DecryptionError("decrypt")
    with pytest.raises(KeyDerivationError):
        raise KeyDerivationError("kdf")
    with pytest.raises(SignatureVerificationError):
        raise SignatureVerificationError("sig")
    with pytest.raises(MissingDependencyError):
        raise MissingDependencyError("dep")
    with pytest.raises(ProtocolError):
        raise ProtocolError("proto")
