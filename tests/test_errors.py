import pytest

from cryptography_suite.core.errors import ErrorCode
from cryptography_suite.errors import (
    CryptographySuiteError,
    DecryptionError,
    EncryptionError,
    KeyDerivationError,
    MissingDependencyError,
    ProtocolError,
    SecurityError,
    SignatureVerificationError,
    StrictKeyPolicyError,
    UnsupportedAlgorithm,
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


def test_error_codes_are_stable_and_specific():
    assert EncryptionError("encrypt").code == ErrorCode.ENCRYPTION_FAILED
    assert DecryptionError("decrypt").code == ErrorCode.DECRYPTION_FAILED
    assert KeyDerivationError("kdf").code == ErrorCode.KEY_DERIVATION_FAILED
    assert SignatureVerificationError("sig").code == ErrorCode.SIGNATURE_VERIFICATION_FAILED
    assert MissingDependencyError("dep").code == ErrorCode.MISSING_DEPENDENCY
    assert UnsupportedAlgorithm("algo").code == ErrorCode.UNSUPPORTED_ALGORITHM
    assert SecurityError("sec").code == ErrorCode.SECURITY_POLICY_VIOLATION
    assert StrictKeyPolicyError("strict").code == ErrorCode.STRICT_KEY_POLICY
    assert ProtocolError("proto").code == ErrorCode.PROTOCOL_ERROR
