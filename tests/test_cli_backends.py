def test_backends_cli_list(capsys):
    from cryptography_suite.cli import backends_cli

    backends_cli(["list"])
    out = capsys.readouterr().out
    assert "pyca" in out
