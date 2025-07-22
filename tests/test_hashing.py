import hashlib
import pytest
from blake3 import blake3

from cryptography_suite.hashing import (
    sha256_hash,
    sha384_hash,
    sha512_hash,
    sha3_256_hash,
    sha3_512_hash,
    blake2b_hash,
    blake3_hash,
    blake3_hash_v2,
)


# Mapping of hashing functions to reference implementations from hashlib/blake3
REF_HASHES = {
    sha256_hash: lambda s: hashlib.sha256(s).hexdigest(),
    sha384_hash: lambda s: hashlib.sha384(s).hexdigest(),
    sha512_hash: lambda s: hashlib.sha512(s).hexdigest(),
    sha3_256_hash: lambda s: hashlib.sha3_256(s).hexdigest(),
    sha3_512_hash: lambda s: hashlib.sha3_512(s).hexdigest(),
    blake2b_hash: lambda s: hashlib.blake2b(s, digest_size=64).hexdigest(),
    blake3_hash: lambda s: blake3(s).hexdigest(),
    blake3_hash_v2: lambda s: blake3(s).hexdigest(),
}


@pytest.mark.parametrize("func,expected", [
    (sha256_hash, 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9'),
    (sha384_hash, 'fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3e417cb71ce646efd0819dd8c088de1bd'),
    (sha512_hash, '309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f'),
    (sha3_256_hash, '644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938'),
    (sha3_512_hash, '840006653e9ac9e95117a15c915caab81662918e925de9e004f774ff82d7079a40d4d27b1b372657c61d46d470304c88c788b3a4527ad074d1dccbee5dbaa99a'),
    (blake2b_hash, '021ced8799296ceca557832ab941a50b4a11f83478cf141f51f933f653ab9fbcc05a037cddbed06e309bf334942c4e58cdf1a46e237911ccd7fcf9787cbc7fd0'),
    (blake3_hash, 'd74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24'),
    (blake3_hash_v2, 'd74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24'),
])
def test_known_vectors(func, expected):
    """Verify each hash function against a known digest for 'hello world'."""
    assert func("hello world") == expected


@pytest.mark.parametrize("func", list(REF_HASHES))
def test_various_inputs(func):
    """Hashing empty, unicode and long strings should match reference libs."""
    for text in ("", "こんにちは", "a" * 10000):
        expected = REF_HASHES[func](text.encode())
        assert func(text) == expected


@pytest.mark.parametrize("func", list(REF_HASHES))
@pytest.mark.parametrize("invalid", [123, None, b"bytes"])
def test_invalid_types_raise(func, invalid):
    """Non-string inputs should raise AttributeError when .encode is missing."""
    with pytest.raises(AttributeError):
        func(invalid)  # type: ignore[arg-type]
