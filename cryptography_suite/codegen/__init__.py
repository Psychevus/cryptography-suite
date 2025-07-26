"""Code generation utilities for cryptosuite."""
from __future__ import annotations

from importlib import resources
from pathlib import Path
from typing import Iterable

import yaml
from jinja2 import Environment, FileSystemLoader


def generate(target: str, pipeline_file: str, out_dir: str | None = None) -> Path:
    """Generate an application skeleton for the given target."""
    out_path = Path(out_dir or f"generated_{target}")
    out_path.mkdir(parents=True, exist_ok=True)

    with open(pipeline_file, "r", encoding="utf-8") as fh:
        steps: Iterable[str] = yaml.safe_load(fh) or []

    # Load templates
    with resources.path(__name__, "templates") as tpl_dir:
        env = Environment(loader=FileSystemLoader(str(tpl_dir)))
        if target == "fastapi":
            template = env.get_template("fastapi/app.py.j2")
            fname = "app.py"
        elif target == "flask":
            template = env.get_template("flask/app.py.j2")
            fname = "app.py"
        elif target == "node":
            template = env.get_template("node/app.ts.j2")
            fname = "app.ts"
        else:
            raise ValueError(f"Unknown target {target}")

        rendered = template.render(steps=list(steps))
        (out_path / fname).write_text(rendered, encoding="utf-8")

        readme_tpl = env.get_template("README.md.j2")
        (out_path / "README.md").write_text(readme_tpl.render(), encoding="utf-8")

    return out_path
