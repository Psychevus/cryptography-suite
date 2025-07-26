from cryptography_suite.keystores import load_plugins, list_keystores, get_keystore
from cryptography_suite.cli import keystore_cli
from cryptography_suite.audit import InMemoryAuditLogger, set_audit_logger


def test_keystore_loader():
    load_plugins()
    assert "local" in list_keystores()
    cls = get_keystore("local")
    ks = cls()
    assert ks.test_connection()


def test_keystore_cli_list(capsys):
    load_plugins()
    keystore_cli(["list"])
    out = capsys.readouterr().out
    assert "local" in out


def test_mock_hsm_audit():
    load_plugins()
    log = InMemoryAuditLogger()
    set_audit_logger(log)
    ks = get_keystore("mock_hsm")()
    ks.sign("test", b"data")
    set_audit_logger(None)
    assert log.logs[0]["operation"] == "sign"
