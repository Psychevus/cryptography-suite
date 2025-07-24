"""Optional CLI integration tests covering additional code paths."""

import importlib
import types
import sys
import pytest
from cryptography_suite.errors import MissingDependencyError


def get_cli(monkeypatch):
    """Reload CLI with optional bulletproof module available."""
    import cryptography_suite.zk.bulletproof as bp_mod
    monkeypatch.setitem(sys.modules, "cryptography_suite.bulletproof", bp_mod)
    import cryptography_suite.cli as cli
    importlib.reload(cli)
    monkeypatch.setattr(cli, "BULLETPROOF_AVAILABLE", True, raising=False)
    return cli


def test_bulletproof_cli_prints_valid(monkeypatch, capsys):
    """Valid input should print proof success."""
    cli = get_cli(monkeypatch)
    monkeypatch.setattr(cli, "bp_setup", lambda: None)
    monkeypatch.setattr(cli, "bp_prove", lambda _v: (b"p", b"c", b"n"))
    monkeypatch.setattr(cli, "bp_verify", lambda _p, _c: True)
    cli.bulletproof_cli(["10"])
    out = capsys.readouterr().out
    assert "Proof valid: True" in out


def test_zksnark_cli(monkeypatch, capsys):
    """ZK-SNARK invocation outputs hash and validity result."""
    cli = get_cli(monkeypatch)
    stub = types.SimpleNamespace(
        setup=lambda: None,
        prove=lambda _b: ("abc", "proof"),
        verify=lambda _h, _p: True,
        ZKSNARK_AVAILABLE=True,
    )
    monkeypatch.setattr(cli, "ZKSNARK_AVAILABLE", True, raising=False)
    monkeypatch.setattr(cli, "zksnark", stub, raising=False)
    cli.zksnark_cli(["hello"])
    out = capsys.readouterr().out
    assert "Hash: abc" in out
    assert "Proof valid: True" in out


def test_zksnark_cli_runtime_error(monkeypatch):
    """Missing PySNARK should raise error when called explicitly."""
    cli = get_cli(monkeypatch)
    monkeypatch.setattr(cli, "ZKSNARK_AVAILABLE", False, raising=False)
    with pytest.raises(MissingDependencyError):
        cli.zksnark_cli(["data"])
