import importlib
import pytest
import cryptography_suite.cli as cli


def reload_cli():
    importlib.reload(cli)
    return cli


def test_cli_help_outputs(capsys):
    c = reload_cli()
    with pytest.raises(SystemExit):
        c.main(["--help"])
    top = capsys.readouterr().out
    assert "file" in top
    assert "export" in top

    with pytest.raises(SystemExit):
        c.main(["file", "--help"])
    file_help = capsys.readouterr().out
    assert "encrypt" in file_help and "decrypt" in file_help

    with pytest.raises(SystemExit):
        c.main(["encrypt", "--help"])
    enc_help = capsys.readouterr().out
    assert "file encrypt" in enc_help
