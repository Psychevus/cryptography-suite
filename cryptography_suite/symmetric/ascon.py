"""Ascon-128a authenticated encryption based on the NIST specification."""

from __future__ import annotations

from typing import List
import hmac
from ..errors import EncryptionError, DecryptionError
from ..utils import deprecated


def _to_bytes(data: List[int]) -> bytes:
    return bytes(bytearray(data))


def _zero_bytes(n: int) -> bytes:
    return b"\x00" * n


def _bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _int_to_bytes(value: int, n: int) -> bytes:
    return value.to_bytes(n, "big")


def _bytes_to_state(b: bytes) -> List[int]:
    return [_bytes_to_int(b[i : i + 8]) for i in range(0, 40, 8)]


def _rotr(val: int, r: int) -> int:
    return ((val >> r) | ((val & ((1 << r) - 1)) << (64 - r))) & ((1 << 64) - 1)


def _ascon_permutation(S: List[int], rounds: int) -> None:
    assert rounds <= 12
    for r in range(12 - rounds, 12):
        S[2] ^= 0xF0 - 0x10 * r + r
        S[0] ^= S[4]
        S[4] ^= S[3]
        S[2] ^= S[1]
        T = [((~S[i]) & S[(i + 1) % 5]) & 0xFFFFFFFFFFFFFFFF for i in range(5)]
        for i in range(5):
            S[i] ^= T[(i + 1) % 5]
        S[1] ^= S[0]
        S[0] ^= S[4]
        S[3] ^= S[2]
        S[2] ^= 0xFFFFFFFFFFFFFFFF
        S[0] ^= _rotr(S[0], 19) ^ _rotr(S[0], 28)
        S[1] ^= _rotr(S[1], 61) ^ _rotr(S[1], 39)
        S[2] ^= _rotr(S[2], 1) ^ _rotr(S[2], 6)
        S[3] ^= _rotr(S[3], 10) ^ _rotr(S[3], 17)
        S[4] ^= _rotr(S[4], 7) ^ _rotr(S[4], 41)


def _initialize(key: bytes, nonce: bytes) -> List[int]:
    if len(key) != 16 or len(nonce) != 16:
        raise EncryptionError("Key and nonce must be 16 bytes each.")
    iv = _to_bytes([128, 16 * 8, 12, 8]) + _zero_bytes(4)
    state_bytes = iv + key + nonce
    S = _bytes_to_state(state_bytes)
    _ascon_permutation(S, 12)
    zero_key = _bytes_to_state(_zero_bytes(24) + key)
    for i in range(5):
        S[i] ^= zero_key[i]
    return S


def _process_ad(S: List[int], ad: bytes) -> None:
    rate = 16
    if ad:
        pad_len = rate - (len(ad) % rate) - 1
        padded = ad + b"\x80" + _zero_bytes(pad_len)
        for i in range(0, len(padded), rate):
            S[0] ^= _bytes_to_int(padded[i : i + 8])
            S[1] ^= _bytes_to_int(padded[i + 8 : i + 16])
            _ascon_permutation(S, 8)
    S[4] ^= 1


def _process_plaintext(S: List[int], plaintext: bytes) -> bytes:
    rate = 16
    last_len = len(plaintext) % rate
    padded = plaintext + b"\x80" + _zero_bytes(rate - last_len - 1)
    ciphertext = b""
    for i in range(0, len(padded) - rate, rate):
        S[0] ^= _bytes_to_int(padded[i : i + 8])
        S[1] ^= _bytes_to_int(padded[i + 8 : i + 16])
        ciphertext += _int_to_bytes(S[0], 8) + _int_to_bytes(S[1], 8)
        _ascon_permutation(S, 8)
    i = len(padded) - rate
    S[0] ^= _bytes_to_int(padded[i : i + 8])
    S[1] ^= _bytes_to_int(padded[i + 8 : i + 16])
    ciphertext += (
        _int_to_bytes(S[0], 8)[: min(8, last_len)]
        + _int_to_bytes(S[1], 8)[: max(0, last_len - 8)]
    )
    return ciphertext


def _process_ciphertext(S: List[int], ciphertext: bytes) -> bytes:
    rate = 16
    last_len = len(ciphertext) % rate
    padded = ciphertext + _zero_bytes(rate - last_len)
    plaintext = b""
    for i in range(0, len(padded) - rate, rate):
        c0 = _bytes_to_int(padded[i : i + 8])
        c1 = _bytes_to_int(padded[i + 8 : i + 16])
        plaintext += _int_to_bytes(S[0] ^ c0, 8) + _int_to_bytes(S[1] ^ c1, 8)
        S[0], S[1] = c0, c1
        _ascon_permutation(S, 8)
    i = len(padded) - rate
    c0 = _bytes_to_int(padded[i : i + 8])
    c1 = _bytes_to_int(padded[i + 8 : i + 16])
    plaintext += (
        _int_to_bytes(S[0] ^ c0, 8) + _int_to_bytes(S[1] ^ c1, 8)
    )[:last_len]
    if last_len < 8:
        mask = (1 << (64 - last_len * 8)) - 1
        S[0] = c0 ^ (S[0] & mask) ^ (0x80 << ((8 - last_len - 1) * 8))
    else:
        mask = (1 << (64 - (last_len - 8) * 8)) - 1
        S[0] = c0
        S[1] = c1 ^ (S[1] & mask) ^ (0x80 << ((8 - (last_len - 8) - 1) * 8))
    return plaintext


def _finalize(S: List[int], key: bytes) -> bytes:
    S[2] ^= _bytes_to_int(key[0:8])
    S[3] ^= _bytes_to_int(key[8:16])
    _ascon_permutation(S, 12)
    S[3] ^= _bytes_to_int(key[0:8])
    S[4] ^= _bytes_to_int(key[8:16])
    return _int_to_bytes(S[3], 8) + _int_to_bytes(S[4], 8)


@deprecated("Ascon is experimental and not recommended for production.")
def encrypt(key: bytes, nonce: bytes, associated_data: bytes, plaintext: bytes) -> bytes:
    """Encrypt and authenticate using Ascon-128a."""
    S = _initialize(key, nonce)
    _process_ad(S, associated_data)
    ciphertext = _process_plaintext(S, plaintext)
    tag = _finalize(S, key)
    return ciphertext + tag


@deprecated("Ascon is experimental and not recommended for production.")
def decrypt(key: bytes, nonce: bytes, associated_data: bytes, ciphertext: bytes) -> bytes:
    """Decrypt and verify using Ascon-128a."""
    if len(ciphertext) < 16:
        raise DecryptionError("Ciphertext too short.")
    S = _initialize(key, nonce)
    _process_ad(S, associated_data)
    plaintext = _process_ciphertext(S, ciphertext[:-16])
    tag = _finalize(S, key)
    if not hmac.compare_digest(tag, ciphertext[-16:]):
        raise DecryptionError("Invalid authentication tag.")
    return plaintext


__all__ = ["encrypt", "decrypt"]
