from cryptography_suite.viz import HandshakeFlowWidget, export_widget_html


def test_widget_instantiation(tmp_path):
    widget = HandshakeFlowWidget(["a", "b"])
    export_widget_html(widget, tmp_path / "out.html")
    assert (tmp_path / "out.html").exists()
