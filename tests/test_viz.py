from importlib.util import find_spec

import pytest

from cryptography_suite.viz import HandshakeFlowWidget, export_widget_html

pytestmark = pytest.mark.skipif(
    find_spec("ipywidgets") is None or find_spec("networkx") is None,
    reason="visualization dependencies not installed; install cryptography-suite[viz]",
)


def test_widget_instantiation(tmp_path):
    widget = HandshakeFlowWidget(["a", "b"])
    export_widget_html(widget, tmp_path / "out.html")
    assert (tmp_path / "out.html").exists()
