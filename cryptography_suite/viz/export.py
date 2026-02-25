"""Utilities for exporting widgets."""

from __future__ import annotations

from importlib.util import find_spec
from pathlib import Path
from typing import Any

_HAS_WIDGETS = find_spec("ipywidgets") is not None

if _HAS_WIDGETS:
    from ipywidgets import Widget
    from ipywidgets.embed import embed_minimal_html
else:
    Widget = Any


def export_widget_html(widget: Widget, path: str | Path) -> None:
    """Export a widget to a standalone HTML file."""
    output_path = Path(path)
    if _HAS_WIDGETS:
        embed_minimal_html(str(output_path), views=[widget], title="Widget Export")
        return

    output_path.write_text(
        "<html><body><h1>Widget Export</h1>"
        "<p>ipywidgets is not installed.</p></body></html>",
        encoding="utf-8",
    )


__all__ = ["export_widget_html"]
