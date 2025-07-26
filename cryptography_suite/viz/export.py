"""Utilities for exporting widgets."""

from __future__ import annotations

from pathlib import Path

from ipywidgets import Widget
from ipywidgets.embed import embed_minimal_html


def export_widget_html(widget: Widget, path: str | Path) -> None:
    """Export an ``ipywidgets`` widget to a standalone HTML file."""
    embed_minimal_html(str(path), views=[widget], title="Widget Export")


__all__ = ["export_widget_html"]
