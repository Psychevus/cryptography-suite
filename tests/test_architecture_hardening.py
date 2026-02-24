import importlib
import logging

import pytest


def test_settings_validation_invalid_env(monkeypatch):
    monkeypatch.setenv("CRYPTOSUITE_ENV", "invalid")
    module = importlib.import_module("cryptography_suite.core.settings")
    module.load_settings.cache_clear()
    with pytest.raises(Exception):
        module.load_settings()


def test_settings_normalizes_strict_keys(monkeypatch):
    monkeypatch.setenv("CRYPTOSUITE_STRICT_KEYS", "true")
    module = importlib.import_module("cryptography_suite.core.settings")
    module.load_settings.cache_clear()
    settings = module.load_settings()
    assert settings.strict_keys_mode == "error"


def test_structured_logger_adds_correlation_id(caplog):
    from cryptography_suite.core.logging import (
        configure_structured_logging,
        get_structured_logger,
    )

    configure_structured_logging(logging.INFO)
    logger = get_structured_logger("cryptography_suite.test")
    with caplog.at_level(logging.INFO):
        logger.info("hello")
    assert any("hello" in rec.message for rec in caplog.records)


def test_register_module_is_idempotent_for_same_class():
    from cryptography_suite.pipeline import CryptoModule, register_module

    class SameName(CryptoModule[str, str]):
        def run(self, data: str) -> str:
            return data

        def to_proverif(self) -> str:
            return "ok"

        def to_tamarin(self) -> str:
            return "ok"

    assert register_module(SameName) is SameName
    assert register_module(SameName) is SameName
