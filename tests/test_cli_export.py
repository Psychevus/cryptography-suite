import importlib
from pathlib import Path
import cryptography_suite.cli as cli


def reload_cli():
    importlib.reload(cli)
    return cli


def test_main_export(tmp_path, capsys):
    c = reload_cli()
    pfile = tmp_path / "p.yaml"
    pfile.write_text("- A\n- B\n")
    c.main(["export", str(pfile), "--format", "proverif", "--track", "secret1"])
    out = capsys.readouterr().out
    assert "A" in out
    assert "B" in out
    assert "secret1" in out
