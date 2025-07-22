import importlib
import sys
import types

import pytest

import cryptography_suite.cli as cli


def reload_cli(monkeypatch):
    """Reload cli module with stubs preserved."""
    importlib.reload(cli)
    return cli


def test_bulletproof_cli_sysargv_success(monkeypatch, capsys):
    cli = reload_cli(monkeypatch)
    monkeypatch.setattr(cli, "bp_setup", lambda: None)
    monkeypatch.setattr(cli, "bp_prove", lambda v: (b"p", b"c", b"n"))
    monkeypatch.setattr(cli, "bp_verify", lambda p, c: True)
    monkeypatch.setattr(sys, "argv", ["prog", "7"])
    cli.bulletproof_cli()
    out = capsys.readouterr().out
    assert "Proof valid: True" in out


def test_bulletproof_cli_sysargv_invalid(monkeypatch):
    cli = reload_cli(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["prog", "bad"])
    with pytest.raises(SystemExit) as exc:
        cli.bulletproof_cli()
    assert exc.value.code == 2


def test_zksnark_cli_sysargv_success(monkeypatch, capsys):
    cli = reload_cli(monkeypatch)
    stub = types.SimpleNamespace(
        setup=lambda: None,
        prove=lambda b: ("deadbeef", "proof"),
        verify=lambda h, p: True,
    )
    monkeypatch.setattr(cli, "ZKSNARK_AVAILABLE", True, raising=False)
    monkeypatch.setattr(cli, "zksnark", stub, raising=False)
    monkeypatch.setattr(sys, "argv", ["prog", "hello"])
    cli.zksnark_cli()
    out = capsys.readouterr().out
    assert "Hash: deadbeef" in out
    assert "Proof valid: True" in out


def test_zksnark_cli_sysargv_unavailable(monkeypatch):
    cli = reload_cli(monkeypatch)
    monkeypatch.setattr(cli, "ZKSNARK_AVAILABLE", False, raising=False)
    monkeypatch.setattr(sys, "argv", ["prog", "hi"])
    with pytest.raises(RuntimeError):
        cli.zksnark_cli()
