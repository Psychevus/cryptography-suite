"""Utilities for exporting widgets."""

from __future__ import annotations

from importlib.util import find_spec
from pathlib import Path
from typing import Any

from ..errors import MissingDependencyError

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

    raise MissingDependencyError(
        "Widget export requires ipywidgets. "
        "Install cryptography-suite[viz] to use this feature."
    )


__all__ = ["export_widget_html"]
