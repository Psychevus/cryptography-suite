from __future__ import annotations

from io import BytesIO

import pytest

from cryptography_suite import EncryptionContext, KeyRef, Policy, Protector


class ProviderSpy:
    provider_id = "example.provider"

    def __init__(self) -> None:
        self.calls: list[str] = []

    def wrap_data_key(self, *args: object, **kwargs: object) -> object:
        self.calls.append("wrap_data_key")
        raise AssertionError("provider must not be called in Phase 3")

    def unwrap_data_key(self, *args: object, **kwargs: object) -> object:
        self.calls.append("unwrap_data_key")
        raise AssertionError("provider must not be called in Phase 3")

    def describe_key(self, *args: object, **kwargs: object) -> object:
        self.calls.append("describe_key")
        raise AssertionError("provider must not be called in Phase 3")

    def health_check(self, *args: object, **kwargs: object) -> object:
        self.calls.append("health_check")
        raise AssertionError("provider must not be called in Phase 3")


class SinkSpy:
    max_write_size = 1024

    def __init__(self) -> None:
        self.events: list[str] = []

    def write(self, chunk: bytes) -> None:
        self.events.append(f"write:{len(chunk)}")

    def commit(self) -> None:
        self.events.append("commit")

    def abort(self) -> None:
        self.events.append("abort")


def test_every_operational_method_fails_closed_without_side_effects() -> None:
    provider = ProviderSpy()
    sink = SinkSpy()
    protector = Protector(
        provider=provider,
        policy=Policy("phase3-test"),
        primary_key=KeyRef("example.provider", "key", "1"),
    )
    plaintext = b"do-not-leak-plaintext"
    context = EncryptionContext({"purpose": "do-not-leak-context"})

    calls = [
        lambda: protector.seal(plaintext, context=context),
        lambda: protector.open(b"envelope", context=context),
        lambda: protector.inspect(b"envelope"),
        lambda: protector.rewrap(
            b"envelope",
            destination_key=KeyRef("example.provider", "destination", "1"),
        ),
        lambda: protector.seal_stream(
            BytesIO(plaintext),
            sink,
            context=context,
        ),
        lambda: protector.open_stream(
            BytesIO(b"envelope"),
            sink,
            context=context,
        ),
    ]

    for call in calls:
        with pytest.raises(NotImplementedError) as captured:
            call()
        message = str(captured.value)
        assert "not implemented in Phase 3" in message
        assert "do-not-leak-plaintext" not in message
        assert "do-not-leak-context" not in message

    assert provider.calls == []
    assert sink.events == []


def test_no_fake_provider_is_shipped() -> None:
    with pytest.raises(ModuleNotFoundError):
        __import__("cryptography_suite.providers.fake")
