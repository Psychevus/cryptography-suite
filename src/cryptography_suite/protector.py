"""Declaration-only v4 orchestration facade."""

from __future__ import annotations

from collections.abc import Callable
from typing import BinaryIO, NoReturn

from .audit import AuditSink
from .context import EncryptionContext
from .envelope import Envelope, EnvelopeMetadata
from .policy import Policy
from .providers import KeyProvider, KeyRef
from .streaming import TransactionalSink


def _operation_not_implemented() -> NoReturn:
    raise NotImplementedError(
        "v4 cryptographic operations are not implemented in Phase 3"
    )


class Protector:
    """The stable v4 orchestration object, intentionally non-operational."""

    def __init__(
        self,
        *,
        provider: KeyProvider,
        policy: Policy,
        primary_key: KeyRef,
        audit_sink: AuditSink | None = None,
    ) -> None:
        self._provider = provider
        self._policy = policy
        self._primary_key = primary_key
        self._audit_sink = audit_sink

    def seal(
        self,
        plaintext: bytes,
        *,
        context: EncryptionContext,
    ) -> Envelope:
        del plaintext, context
        _operation_not_implemented()

    def open(
        self,
        envelope: Envelope | bytes,
        *,
        context: EncryptionContext,
    ) -> bytes:
        del envelope, context
        _operation_not_implemented()

    def inspect(self, envelope: Envelope | bytes) -> EnvelopeMetadata:
        del envelope
        _operation_not_implemented()

    def rewrap(
        self,
        envelope: Envelope | bytes,
        *,
        destination_key: KeyRef,
    ) -> Envelope:
        del envelope, destination_key
        _operation_not_implemented()

    def seal_stream(
        self,
        source: BinaryIO,
        destination: TransactionalSink,
        *,
        context: EncryptionContext,
        cancel: Callable[[], bool] | None = None,
    ) -> EnvelopeMetadata:
        del source, destination, context, cancel
        _operation_not_implemented()

    def open_stream(
        self,
        source: BinaryIO,
        destination: TransactionalSink,
        *,
        context: EncryptionContext,
        cancel: Callable[[], bool] | None = None,
    ) -> EnvelopeMetadata:
        del source, destination, context, cancel
        _operation_not_implemented()


__all__ = ["Protector"]
