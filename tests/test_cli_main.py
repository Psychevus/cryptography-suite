import hashlib
import importlib
import io
from types import ModuleType

import pytest
from blake3 import blake3

import cryptography_suite.cli as cli


def reload_cli() -> ModuleType:
    importlib.reload(cli)
    return cli


def test_main_keygen_rsa(monkeypatch, capsys):
    cli = reload_cli()
    called = {}

    class KM:
        def generate_rsa_keypair_and_save(self, priv, pub, pwd):
            called["args"] = (priv, pub, pwd)

    monkeypatch.setattr(cli, "KeyManager", lambda: KM())
    monkeypatch.setattr("sys.stdin", io.StringIO("pw\n"))
    cli.main(
        [
            "keygen",
            "rsa",
            "--private",
            "priv.pem",
            "--public",
            "pub.pem",
            "--password-stdin",
        ]
    )
    assert called["args"] == ("priv.pem", "pub.pem", "pw")
    assert "RSA keys saved" in capsys.readouterr().out


def test_keygen_pqc_does_not_print_private_key(monkeypatch, capsys):
    cli = reload_cli()
    monkeypatch.setattr(cli, "PQCRYPTO_AVAILABLE", True)
    monkeypatch.setattr(cli, "generate_kyber_keypair", lambda: (b"public", b"private"))

    cli.keygen_cli(["kyber"])

    captured = capsys.readouterr()
    assert "key material was not printed" in captured.out
    assert "7075626c6963" not in captured.out
    assert "70726976617465" not in captured.out
    assert captured.err == ""


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


def test_main_hash_json_output(tmp_path, capsys):
    cli = reload_cli()
    file = tmp_path / "f.txt"
    file.write_text("hello")
    cli.main(["--output-format", "json", "hash", str(file), "--algorithm", "blake3"])
    out = capsys.readouterr().out.strip()
    assert '"algorithm": "blake3"' in out
    assert '"digest"' in out


def test_main_json_alias_deprecation(tmp_path, capsys):
    cli = reload_cli()
    file = tmp_path / "f.txt"
    file.write_text("hello")
    cli.main(["--json", "hash", str(file), "--algorithm", "blake3"])
    out_lines = [line for line in capsys.readouterr().out.splitlines() if line.strip()]
    assert "deprecated" in out_lines[0].lower()
    assert '"digest"' in out_lines[-1]
