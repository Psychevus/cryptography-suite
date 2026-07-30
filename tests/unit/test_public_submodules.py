from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

import cryptography_suite as suite
from cryptography_suite import audit, envelope, legacy, lifecycle, providers, streaming
from cryptography_suite.legacy import LegacyAdapter, LegacyFormat
from cryptography_suite.lifecycle import KeyRecord, KeyState
from cryptography_suite.providers import KeyRef

EXPECTED_SUBMODULE_EXPORTS = {
    "audit": ["AuditEvent", "AuditSink"],
    "envelope": ["AuthenticationStatus", "Envelope", "EnvelopeMetadata"],
    "legacy": ["LegacyAdapter", "LegacyFormat"],
    "lifecycle": ["KeyRecord", "KeyState"],
    "providers": [
        "KeyCapability",
        "KeyDescription",
        "KeyProvider",
        "KeyRef",
        "ProviderHealth",
        "ProviderHealthStatus",
        "ProviderKeyState",
        "ProviderRequest",
        "ReadOnlySecret",
        "SecretBuffer",
        "WrappedKey",
    ],
    "streaming": ["SinkState", "TransactionalSink"],
}


class LegacyDeclaration:
    @property
    def format(self) -> LegacyFormat:
        return LegacyFormat.CSF_V2


def test_all_public_submodule_exports_are_exact() -> None:
    actual = {
        "audit": audit.__all__,
        "envelope": envelope.__all__,
        "legacy": legacy.__all__,
        "lifecycle": lifecycle.__all__,
        "providers": providers.__all__,
        "streaming": streaming.__all__,
    }
    assert actual == EXPECTED_SUBMODULE_EXPORTS
    assert "LegacyFormat" not in suite.__all__
    assert "KeyRecord" not in suite.__all__


def test_atomic_filesystem_sink_remains_private() -> None:
    for module in (suite, streaming):
        assert not hasattr(module, "AtomicFileSink")
        assert not hasattr(module, "AtomicSinkOptions")
        assert not hasattr(module, "AtomicSinkState")
        assert not hasattr(module, "CommitOutcome")


def test_legacy_namespace_is_declaration_only() -> None:
    assert {member.name: member.value for member in LegacyFormat} == {
        "CSF_V2": "csf-v2",
        "CSF_V1": "csf-v1",
        "RAW_AES": "raw-aes",
        "PORTABLE_AES_V3": "password-aes-v3",
        "LOCAL_KEYSTORE": "local-keystore",
        "PEM_DER": "pem-der",
    }
    assert isinstance(LegacyDeclaration(), LegacyAdapter)
    assert set(vars(legacy)) >= {
        "LegacyAdapter",
        "LegacyFormat",
        "__all__",
    }
    assert all(
        name not in vars(legacy)
        for name in ("detect", "migrate", "open", "parse", "seal")
    )


def test_lifecycle_states_and_key_record_invariants_are_exact() -> None:
    assert {member.name: member.value for member in KeyState} == {
        "PENDING": "PENDING",
        "PRIMARY": "PRIMARY",
        "DECRYPT_ONLY": "DECRYPT_ONLY",
        "DISABLED": "DISABLED",
        "DESTROYED": "DESTROYED",
    }
    record = KeyRecord(
        logical_key_id="logical-key",
        key=KeyRef("example.provider", "key", "1"),
        state=KeyState.PRIMARY,
        generation=0,
    )
    assert record.key.version == "1"
    frozen_field = "generation"
    with pytest.raises(FrozenInstanceError):
        setattr(record, frozen_field, 1)
    with pytest.raises(ValueError, match="immutable key version"):
        KeyRecord(
            logical_key_id="logical-key",
            key=KeyRef("example.provider", "alias"),
            state=KeyState.PENDING,
            generation=0,
        )
    with pytest.raises(ValueError, match="non-negative"):
        KeyRecord(
            logical_key_id="logical-key",
            key=KeyRef("example.provider", "key", "1"),
            state=KeyState.PENDING,
            generation=-1,
        )
