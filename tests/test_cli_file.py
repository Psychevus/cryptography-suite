"""Unit tests for :mod:`cryptography_suite.cli.file_cli` entrypoint.

These tests cover both successful encryption/decryption flows and
error handling edge cases for invalid arguments or underlying failures.
"""

import importlib
import pytest

import cryptography_suite.cli as cli
import cryptography_suite.symmetric as symmetric


def reload_cli():
    """Reload ``cryptography_suite.cli`` to reset global state."""
    importlib.reload(cli)
    return cli


def test_file_cli_encrypt(monkeypatch, capsys):
    """Encrypts a file and verifies CLI arguments are parsed correctly."""
    cli = reload_cli()
    called: dict[str, tuple[str, str, str]] = {}

    def stub(inp: str, outp: str, pwd: str) -> None:
        called['args'] = (inp, outp, pwd)

    monkeypatch.setattr(symmetric, 'encrypt_file', stub)
    cli.file_cli(['encrypt', '--in', 'plain.txt', '--out', 'enc.bin', '--password', 'pw'])
    assert called['args'] == ('plain.txt', 'enc.bin', 'pw')
    out = capsys.readouterr().out
    assert 'Encrypted file written to enc.bin' in out


def test_file_cli_decrypt(monkeypatch, capsys):
    """Decrypts a file via CLI and checks output message."""
    cli = reload_cli()
    called: dict[str, tuple[str, str, str]] = {}

    def stub_dec(inp: str, outp: str, pwd: str) -> None:
        called['args'] = (inp, outp, pwd)

    monkeypatch.setattr(symmetric, 'decrypt_file', stub_dec)
    cli.file_cli(['decrypt', '--in', 'enc.bin', '--out', 'plain.txt', '--password', 'pw'])
    assert called['args'] == ('enc.bin', 'plain.txt', 'pw')
    out = capsys.readouterr().out
    assert 'Decrypted file written to plain.txt' in out


def test_file_cli_error(monkeypatch, capsys):
    """Displays a friendly error message when encryption fails."""
    cli = reload_cli()

    def bad(*_args):
        raise IOError('bad')

    monkeypatch.setattr(symmetric, 'encrypt_file', bad)
    cli.file_cli(['encrypt', '--in', 'a', '--out', 'b', '--password', 'pw'])
    out = capsys.readouterr().out
    assert 'Error:' in out


def test_file_cli_invalid(monkeypatch):
    """Invalid argument combinations should trigger a SystemExit."""
    cli = reload_cli()
    with pytest.raises(SystemExit):
        cli.file_cli(['encrypt'])
