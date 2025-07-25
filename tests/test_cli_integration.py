"""Integration tests for CLI helpers using system argv manipulation."""

import importlib
import sys
import types

import pytest
from cryptography_suite.errors import MissingDependencyError

import cryptography_suite.cli as cli


def reload_cli(monkeypatch):
    """Reload :mod:`cryptography_suite.cli` while keeping monkeypatched stubs."""
    importlib.reload(cli)
    monkeypatch.setattr(cli, "BULLETPROOF_AVAILABLE", True, raising=False)
    return cli


def test_bulletproof_cli_sysargv_success(monkeypatch, capsys):
    """CLI prints success message with valid integer value."""
    cli = reload_cli(monkeypatch)
    monkeypatch.setattr(cli, "bp_setup", lambda: None)
    monkeypatch.setattr(cli, "bp_prove", lambda _v: (b"p", b"c", b"n"))
    monkeypatch.setattr(cli, "bp_verify", lambda _p, _c: True)
    monkeypatch.setattr(sys, "argv", ["prog", "7"])
    cli.bulletproof_cli()
    out = capsys.readouterr().out
    assert "Proof valid: True" in out


def test_bulletproof_cli_sysargv_invalid(monkeypatch):
    """Invalid argument should exit with code 2."""
    cli = reload_cli(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["prog", "bad"])
    with pytest.raises(SystemExit) as exc:
        cli.bulletproof_cli()
    assert exc.value.code == 2


def test_zksnark_cli_sysargv_success(monkeypatch, capsys):
    """ZK-SNARK CLI prints proof result when dependency is available."""
    cli = reload_cli(monkeypatch)
    stub = types.SimpleNamespace(
        setup=lambda: None,
        prove=lambda _b: ("deadbeef", "proof"),
        verify=lambda _h, _p: True,
    )
    monkeypatch.setattr(cli, "ZKSNARK_AVAILABLE", True, raising=False)
    monkeypatch.setattr(cli, "zksnark", stub, raising=False)
    monkeypatch.setattr(sys, "argv", ["prog", "hello"])
    cli.zksnark_cli()
    out = capsys.readouterr().out
    assert "Hash: deadbeef" in out
    assert "Proof valid: True" in out


def test_zksnark_cli_sysargv_unavailable(monkeypatch):
    """Missing PySNARK should raise ``MissingDependencyError``."""
    cli = reload_cli(monkeypatch)
    monkeypatch.setattr(cli, "ZKSNARK_AVAILABLE", False, raising=False)
    monkeypatch.setattr(sys, "argv", ["prog", "hi"])
    with pytest.raises(MissingDependencyError):
        cli.zksnark_cli()
