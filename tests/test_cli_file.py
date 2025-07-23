import importlib
import pytest

import cryptography_suite.cli as cli
import cryptography_suite.symmetric as symmetric


def reload_cli():
    importlib.reload(cli)
    return cli


def test_file_cli_encrypt(monkeypatch, capsys):
    cli = reload_cli()
    called = {}

    def stub(inp, outp, pwd):
        called['args'] = (inp, outp, pwd)

    monkeypatch.setattr(symmetric, 'encrypt_file', stub)
    cli.file_cli(['encrypt', '--in', 'plain.txt', '--out', 'enc.bin', '--password', 'pw'])
    assert called['args'] == ('plain.txt', 'enc.bin', 'pw')
    out = capsys.readouterr().out
    assert 'Encrypted file written to enc.bin' in out


def test_file_cli_decrypt(monkeypatch, capsys):
    cli = reload_cli()
    called = {}

    def stub_dec(inp, outp, pwd):
        called['args'] = (inp, outp, pwd)

    monkeypatch.setattr(symmetric, 'decrypt_file', stub_dec)
    cli.file_cli(['decrypt', '--in', 'enc.bin', '--out', 'plain.txt', '--password', 'pw'])
    assert called['args'] == ('enc.bin', 'plain.txt', 'pw')
    out = capsys.readouterr().out
    assert 'Decrypted file written to plain.txt' in out


def test_file_cli_error(monkeypatch, capsys):
    cli = reload_cli()

    def bad(*args, **kwargs):
        raise IOError('bad')

    monkeypatch.setattr(symmetric, 'encrypt_file', bad)
    cli.file_cli(['encrypt', '--in', 'a', '--out', 'b', '--password', 'pw'])
    out = capsys.readouterr().out
    assert 'Error:' in out


def test_file_cli_invalid(monkeypatch):
    cli = reload_cli()
    with pytest.raises(SystemExit):
        cli.file_cli(['encrypt'])

