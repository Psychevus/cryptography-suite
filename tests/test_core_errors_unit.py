import pytest

from cryptography_suite.core.errors import ErrorCode, SuiteError


@pytest.mark.unit
def test_suite_error_string_representation_is_backward_compatible():
    err = SuiteError(message="bad config", code=ErrorCode.CONFIGURATION_ERROR)
    assert str(err) == "bad config"


@pytest.mark.unit
def test_suite_error_format_with_code_includes_stable_error_code():
    err = SuiteError(message="bad config", code=ErrorCode.CONFIGURATION_ERROR)
    assert err.format_with_code() == "[ErrorCode.CONFIGURATION_ERROR] bad config"
