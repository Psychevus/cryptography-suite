import importlib
import hashlib

import pytest
from blake3 import blake3

import cryptography_suite.cli as cli


def reload_cli():
    importlib.reload(cli)
    return cli


def test_main_keygen_rsa(monkeypatch, capsys):
    cli = reload_cli()
    called = {}

    class KM:
        def generate_rsa_keypair_and_save(self, priv, pub, pwd):
            called["args"] = (priv, pub, pwd)

    monkeypatch.setattr(cli, "KeyManager", lambda: KM())
    cli.main(
        [
            "keygen",
            "rsa",
            "--private",
            "priv.pem",
            "--public",
            "pub.pem",
            "--password",
            "pw",
        ]
    )
    assert called["args"] == ("priv.pem", "pub.pem", "pw")
    assert "RSA keys saved" in capsys.readouterr().out


def test_main_hash(tmp_path, capsys):
    cli = reload_cli()
    file = tmp_path / "f.txt"
    file.write_text("hello")
    cli.main(["hash", str(file), "--algorithm", "blake3"])
    out = capsys.readouterr().out.strip()
    assert out == blake3(b"hello").hexdigest()


@pytest.mark.parametrize(
    ("algorithm", "expected"),
    [
        ("sha3-256", lambda payload: hashlib.sha3_256(payload).hexdigest()),
        ("sha3-512", lambda payload: hashlib.sha3_512(payload).hexdigest()),
        ("blake2b", lambda payload: hashlib.blake2b(payload).hexdigest()),
        ("blake3", lambda payload: blake3(payload).hexdigest()),
    ],
)
def test_main_hash_binary_input(tmp_path, capsys, algorithm, expected):
    cli = reload_cli()
    payload = b"\x00\x01\xffhello\x00world\x10"
    file = tmp_path / "binary.dat"
    file.write_bytes(payload)

    cli.main(["hash", str(file), "--algorithm", algorithm])
    out = capsys.readouterr().out.strip()

    assert out == expected(payload)


def test_main_otp(monkeypatch, capsys):
    cli = reload_cli()
    monkeypatch.setattr(cli, "generate_totp", lambda *a, **k: "123")
    cli.main(["otp", "--secret", "abcd"])
    assert capsys.readouterr().out.strip() == "123"
