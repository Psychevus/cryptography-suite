import importlib
import types
import sys
import pytest
from cryptography_suite.errors import MissingDependencyError


def get_cli(monkeypatch):
    import cryptography_suite.zk.bulletproof as bp_mod
    monkeypatch.setitem(sys.modules, "cryptography_suite.bulletproof", bp_mod)
    import cryptography_suite.cli as cli
    importlib.reload(cli)
    return cli


def test_bulletproof_cli_prints_valid(monkeypatch, capsys):
    cli = get_cli(monkeypatch)
    monkeypatch.setattr(cli, "bp_setup", lambda: None)
    monkeypatch.setattr(cli, "bp_prove", lambda v: (b"p", b"c", b"n"))
    monkeypatch.setattr(cli, "bp_verify", lambda p, c: True)
    cli.bulletproof_cli(["10"])
    out = capsys.readouterr().out
    assert "Proof valid: True" in out


def test_zksnark_cli(monkeypatch, capsys):
    cli = get_cli(monkeypatch)
    stub = types.SimpleNamespace(
        setup=lambda: None,
        prove=lambda b: ("abc", "proof"),
        verify=lambda h, p: True,
        ZKSNARK_AVAILABLE=True,
    )
    monkeypatch.setattr(cli, "ZKSNARK_AVAILABLE", True, raising=False)
    monkeypatch.setattr(cli, "zksnark", stub, raising=False)
    cli.zksnark_cli(["hello"])
    out = capsys.readouterr().out
    assert "Hash: abc" in out
    assert "Proof valid: True" in out


def test_zksnark_cli_runtime_error(monkeypatch):
    cli = get_cli(monkeypatch)
    monkeypatch.setattr(cli, "ZKSNARK_AVAILABLE", False, raising=False)
    with pytest.raises(MissingDependencyError):
        cli.zksnark_cli(["data"])
