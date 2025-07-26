import importlib
import cryptography_suite.cli as cli


def reload_cli():
    importlib.reload(cli)
    return cli


def test_gen_cli_fastapi(tmp_path):
    c = reload_cli()
    pipeline = tmp_path / "pipe.yaml"
    pipeline.write_text("- StepA\n- StepB\n")
    out_dir = tmp_path / "gen"
    c.gen_cli([
        "--target", "fastapi",
        "--pipeline", str(pipeline),
        "--output", str(out_dir),
    ])
    assert (out_dir / "app.py").exists()
    assert (out_dir / "README.md").exists()

