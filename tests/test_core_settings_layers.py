import concurrent.futures
import importlib
import os
import subprocess
import sys

import pytest
from hypothesis import given
from hypothesis import strategies as st

from cryptography_suite.core.errors import ErrorCode, SuiteError
from cryptography_suite.core.settings import (
    RuntimeEnvironment,
    _normalize_strict_keys_mode,
    _parse_environment,
    load_settings,
)


@pytest.mark.unit
def test_normalize_strict_keys_mode_happy_paths():
    assert _normalize_strict_keys_mode("warn") == "warn"
    assert _normalize_strict_keys_mode("ERROR") == "error"
    assert _normalize_strict_keys_mode(" true ") == "error"
    assert _normalize_strict_keys_mode("0") == "false"


@pytest.mark.unit
@given(st.sampled_from(["warn", "error", "true", "false", "1", "0"]))
def test_normalize_strict_keys_mode_property_valid_inputs(raw):
    normalized = _normalize_strict_keys_mode(raw)
    assert normalized in {"warn", "error", "false"}


@pytest.mark.unit
def test_normalize_strict_keys_mode_invalid_value():
    with pytest.raises(SuiteError) as exc_info:
        _normalize_strict_keys_mode("definitely-not-valid")

    assert exc_info.value.code == ErrorCode.CONFIGURATION_ERROR
    assert exc_info.value.details["CRYPTOSUITE_STRICT_KEYS"] == "definitely-not-valid"


@pytest.mark.unit
def test_parse_environment_happy_and_edge_cases():
    assert _parse_environment("DEV") is RuntimeEnvironment.DEV
    assert _parse_environment(" test ") is RuntimeEnvironment.TEST
    assert _parse_environment("prod") is RuntimeEnvironment.PROD


@pytest.mark.negative
def test_parse_environment_invalid_raises_typed_error():
    with pytest.raises(SuiteError) as exc_info:
        _parse_environment("staging")

    assert exc_info.value.code == ErrorCode.CONFIGURATION_ERROR
    assert exc_info.value.details["CRYPTOSUITE_ENV"] == "staging"


@pytest.mark.integration
def test_load_settings_reads_environment(monkeypatch):
    load_settings.cache_clear()
    monkeypatch.setenv("CRYPTOSUITE_ENV", "test")
    monkeypatch.setenv("CRYPTOSUITE_STRICT_KEYS", "1")
    monkeypatch.setenv("CRYPTOSUITE_LOG_LEVEL", "debug")

    settings = load_settings()
    assert settings.environment is RuntimeEnvironment.TEST
    assert settings.strict_keys_mode == "error"
    assert settings.log_level == "DEBUG"


@pytest.mark.integration
def test_load_settings_is_cached_and_thread_safe(monkeypatch):
    load_settings.cache_clear()
    monkeypatch.setenv("CRYPTOSUITE_ENV", "dev")

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        values = list(pool.map(lambda _: load_settings(), range(20)))

    first = values[0]
    assert all(v is first for v in values)


@pytest.mark.contract
def test_settings_contract_in_subprocess_environment_boundary(tmp_path):
    script = tmp_path / "contract_settings.py"
    script.write_text(
        "from cryptography_suite.core.settings import load_settings\n"
        "load_settings.cache_clear()\n"
        "print(load_settings().environment.value)\n",
        encoding="utf-8",
    )

    env = {
        **os.environ,
        "CRYPTOSUITE_ENV": "prod",
        "PYTHONPATH": os.getcwd(),
    }
    result = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )

    assert result.returncode == 0
    assert result.stdout.strip() == "prod"


@pytest.mark.integration
def test_config_facade_reloads_from_core_settings(monkeypatch):
    monkeypatch.setenv("CRYPTOSUITE_ENV", "test")
    monkeypatch.setenv("CRYPTOSUITE_STRICT_KEYS", "warn")
    monkeypatch.setenv("CRYPTOSUITE_LOG_LEVEL", "warning")

    import cryptography_suite.core.settings as settings_mod

    settings_mod.load_settings.cache_clear()
    import cryptography_suite.config as config

    importlib.reload(config)

    assert config.RUNTIME_ENV is RuntimeEnvironment.TEST
    assert config.STRICT_KEYS == "warn"
    assert config.LOG_LEVEL == "WARNING"
