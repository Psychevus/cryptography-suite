import importlib
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
    from cryptography_suite.hashing import blake3_hash

    assert out == blake3_hash("hello")


def test_main_otp(monkeypatch, capsys):
    cli = reload_cli()
    monkeypatch.setattr(cli, "generate_totp", lambda *a, **k: "123")
    cli.main(["otp", "--secret", "abcd"])
    assert capsys.readouterr().out.strip() == "123"
