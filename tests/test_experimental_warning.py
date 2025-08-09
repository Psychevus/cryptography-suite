import importlib
import warnings


def test_experimental_warning_once(capsys):
    warnings.simplefilter("always")
    with warnings.catch_warnings(record=True) as w:
        import suite.experimental  # noqa: F401
        err = capsys.readouterr().err
        assert "EXPERIMENTAL" in err
        assert any("suite.experimental" in str(item.message) for item in w)

    with warnings.catch_warnings(record=True) as w:
        importlib.reload(suite.experimental)
        err = capsys.readouterr().err
        assert err == ""
        assert w == []
