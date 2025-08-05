import pytest

from crypto_suite.utils.zeroize import secure_zero


def test_secure_zero_overwrites_buffer():
    data = bytearray(b"secret")
    secure_zero(data)
    assert data == b"\x00" * len(data)


def test_secure_zero_type_error():
    with pytest.raises(TypeError):
        secure_zero(b"not bytearray")

