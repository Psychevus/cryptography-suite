# mypy: disable-error-code=no-untyped-call
import argparse
import importlib
import io
import logging

import pytest

import cryptography_suite.cli as cli
import cryptography_suite.debug as debug
from cryptography_suite.audit import InMemoryAuditLogger, audit_log, set_audit_logger
from cryptography_suite.core.logging import log_event
from cryptography_suite.pipeline import Pipeline


class Transform:
    def run(self, data: str) -> str:
        assert data == "PIPELINE_PLAINTEXT_MARKER"
        return "PIPELINE_INTERMEDIATE_MARKER"

    def to_proverif(self) -> str:
        return "transform"

    def to_tamarin(self) -> str:
        return "transform"


def _reload_verbose_modules(monkeypatch):
    monkeypatch.setenv("CRYPTOSUITE_VERBOSE_MODE", "1")
    import cryptography_suite.symmetric.aes as aes
    import cryptography_suite.symmetric.chacha as chacha

    importlib.reload(debug)
    importlib.reload(aes)
    importlib.reload(chacha)
    logging.getLogger("cryptography-suite").setLevel(logging.DEBUG)
    return aes, chacha


def test_verbose_print_redacts_sensitive_marker(monkeypatch, caplog):
    monkeypatch.setenv("CRYPTOSUITE_VERBOSE_MODE", "1")
    importlib.reload(debug)
    logging.getLogger("cryptography-suite").setLevel(logging.DEBUG)

    with caplog.at_level(logging.DEBUG, logger="cryptography-suite"):
        debug.verbose_print("password=VERBOSE_PASSWORD_MARKER")

    assert "VERBOSE_PASSWORD_MARKER" not in caplog.text
    assert debug.REDACTED_VALUE in caplog.text


def test_aes_verbose_does_not_log_password_key_nonce_or_ciphertext(monkeypatch, caplog):
    aes, _ = _reload_verbose_modules(monkeypatch)
    key_marker = b"KDF_MARKER_SECRET_VALUE_12345678"
    monkeypatch.setattr(aes, "select_kdf", lambda *_args, **_kwargs: key_marker)

    with caplog.at_level(logging.DEBUG, logger="cryptography-suite"):
        aes.aes_encrypt("AES_PLAINTEXT_MARKER", "AES_PASSWORD_MARKER", kdf="scrypt")

    assert "Mode: AES-GCM" in caplog.text
    for marker in (
        "AES_PLAINTEXT_MARKER",
        "AES_PASSWORD_MARKER",
        "KDF_MARKER_SECRET_VALUE",
        "Derived key",
        "Nonce:",
        "ciphertext=",
    ):
        assert marker not in caplog.text


def test_chacha_verbose_does_not_log_password_key_nonce_or_ciphertext(
    monkeypatch, caplog
):
    _, chacha = _reload_verbose_modules(monkeypatch)
    key_marker = b"KDF_MARKER_SECRET_VALUE_12345678"
    monkeypatch.setattr(
        chacha, "derive_key_argon2", lambda *_args, **_kwargs: key_marker
    )

    with caplog.at_level(logging.DEBUG, logger="cryptography-suite"):
        chacha.chacha20_encrypt("CHACHA_PLAINTEXT_MARKER", "CHACHA_PASSWORD_MARKER")

    assert "Mode: ChaCha20-Poly1305" in caplog.text
    for marker in (
        "CHACHA_PLAINTEXT_MARKER",
        "CHACHA_PASSWORD_MARKER",
        "KDF_MARKER_SECRET_VALUE",
        "Derived key",
        "Nonce:",
        "ciphertext=",
    ):
        assert marker not in caplog.text


def test_pipeline_dry_run_does_not_print_intermediate_values(capsys):
    result = (Pipeline() >> Transform()).dry_run("PIPELINE_PLAINTEXT_MARKER")

    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert result == "PIPELINE_INTERMEDIATE_MARKER"
    assert "Transform: executed" in combined
    assert "PIPELINE_PLAINTEXT_MARKER" not in combined
    assert "PIPELINE_INTERMEDIATE_MARKER" not in combined


def test_file_cli_password_stdin_does_not_echo(monkeypatch, capsys, tmp_path):
    called = {}

    def encrypt_stub(inp: str, outp: str, pwd: str, *, kdf: str = "argon2") -> None:
        called["password"] = pwd

    import cryptography_suite.symmetric as symmetric

    monkeypatch.setattr(symmetric, "encrypt_file", encrypt_stub)
    monkeypatch.setattr("sys.stdin", io.StringIO("CLI_PASSWORD_MARKER\n"))

    cli.file_cli(
        [
            "encrypt",
            "--in",
            "plain.txt",
            "--out",
            str(tmp_path / "enc.bin"),
            "--password-stdin",
        ]
    )

    captured = capsys.readouterr()
    assert called["password"] == "CLI_PASSWORD_MARKER"
    assert "CLI_PASSWORD_MARKER" not in captured.out + captured.err


def test_pq_keygen_does_not_print_key_material(monkeypatch, capsys):
    monkeypatch.setattr(cli, "PQCRYPTO_AVAILABLE", True)
    monkeypatch.setattr(cli, "SPHINCS_AVAILABLE", False)
    monkeypatch.setattr(
        cli,
        "generate_kyber_keypair",
        lambda: (b"PQ_PUBLIC_MARKER", b"PQ_PRIVATE_MARKER"),
    )

    cli.keygen_cli(["kyber"])

    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert "PQ_PUBLIC_MARKER" not in combined
    assert "PQ_PRIVATE_MARKER" not in combined
    assert "not printed" in combined


def test_log_event_redacts_sensitive_fields(caplog):
    logger = logging.getLogger("cryptography_suite.tests.redaction")

    with caplog.at_level(logging.INFO, logger=logger.name):
        log_event(
            logger,
            "redaction_test",
            argv=["cmd", "--password", "LOG_PASSWORD_MARKER"],
            password="LOG_PASSWORD_MARKER",
            stderr="LOG_STDERR_MARKER",
        )

    assert "LOG_PASSWORD_MARKER" not in caplog.text
    assert "LOG_STDERR_MARKER" not in caplog.text
    assert debug.REDACTED_VALUE in caplog.text


def test_audit_log_does_not_record_function_arguments():
    logger = InMemoryAuditLogger()
    set_audit_logger(logger)

    @audit_log
    def operation(password: str) -> str:
        return password

    try:
        assert operation("AUDIT_PASSWORD_MARKER") == "AUDIT_PASSWORD_MARKER"
        assert "AUDIT_PASSWORD_MARKER" not in str(logger.logs)
    finally:
        set_audit_logger(None)


def test_cli_errors_redact_sensitive_messages(capsys):
    cli._handle_cli_error(ValueError("password=CLI_ERROR_MARKER"))

    captured = capsys.readouterr()
    assert "CLI_ERROR_MARKER" not in captured.out + captured.err
    assert debug.REDACTED_VALUE in captured.out


def test_password_sources_are_mutually_exclusive(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("one\n"))

    with pytest.raises(ValueError, match="only one password input source"):
        cli._resolve_password(
            argparse.Namespace(
                password_stdin=True,
                password_env="CRYPTOSUITE_TEST_PASSWORD",
                password_file=None,
                password_fd=None,
            ),
            "File password",
        )
