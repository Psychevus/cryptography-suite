import pytest

from crypto_suite.handshake import (
    HandshakeHello,
    HandshakeContext,
    HandshakeError,
    Alert,
    negotiate_kem,
)


def test_mismatched_lists_abort():
    client = HandshakeHello(["Kyber512"])
    server = HandshakeHello(["Dilithium3"])
    with pytest.raises(HandshakeError) as exc:
        negotiate_kem(client, server)
    assert exc.value.alert is Alert.NoCommonKEM


def test_intersection_picks_strongest():
    client = HandshakeHello(["X25519", "Kyber512", "Dilithium3"])
    server = HandshakeHello(["Dilithium3", "Kyber512", "X25519"])
    chosen = negotiate_kem(client, server)
    assert chosen == "Dilithium3"
    ctx = HandshakeContext()
    ctx.add_hello(client)
    ctx.add_hello(server)
    mac = ctx.finished_mac(b"secret", chosen)
    assert isinstance(mac, bytes)
