import pytest

from crypto_suite.handshake import (
    HandshakeHello,
    HandshakeSelected,
    HandshakeContext,
    HandshakeError,
    Alert,
    negotiate_kem,
)


def test_intersection_picks_strongest():
    client = HandshakeHello()
    server = HandshakeHello(["X25519", "Kyber512", "Dilithium3"])
    assert client.supported_kem == ["Dilithium3", "Kyber512", "X25519"]
    chosen = negotiate_kem(client, server)
    assert chosen == "Dilithium3"
    ctx = HandshakeContext()
    ctx.add_hello(client)
    ctx.add_hello(server)
    ctx.add_selected(HandshakeSelected(chosen))
    mac = ctx.finished_mac(b"secret")
    assert isinstance(mac, bytes)


def test_mismatched_lists_abort():
    client = HandshakeHello(["Kyber512"])
    server = HandshakeHello(["Dilithium3"])
    with pytest.raises(HandshakeError) as exc:
        negotiate_kem(client, server)
    assert exc.value.alert is Alert.NoCommonKEM


def test_transcript_mac_detects_tampered_kem():
    client = HandshakeHello()
    server = HandshakeHello(["Dilithium3", "Kyber512"])
    chosen = negotiate_kem(client, server)

    ctx_ok = HandshakeContext()
    ctx_ok.add_hello(client)
    ctx_ok.add_hello(server)
    ctx_ok.add_selected(HandshakeSelected(chosen))
    mac_ok = ctx_ok.finished_mac(b"secret")

    tampered = "Kyber512"
    ctx_bad = HandshakeContext()
    ctx_bad.add_hello(client)
    ctx_bad.add_hello(server)
    ctx_bad.add_selected(HandshakeSelected(tampered))
    mac_bad = ctx_bad.finished_mac(b"secret")

    assert mac_ok != mac_bad
