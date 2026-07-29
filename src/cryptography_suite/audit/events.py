"""Secret-free audit event and sink declarations."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType
from typing import Protocol, runtime_checkable

from ..errors import ErrorCode, JSONScalar


def _empty_attributes() -> Mapping[str, JSONScalar]:
    return MappingProxyType({})


@dataclass(frozen=True)
class AuditEvent:
    schema_version: str
    event_id: str
    occurred_at: datetime
    operation_id: str
    event_type: str
    outcome: str
    policy_id: str
    error_code: ErrorCode | None = None
    attributes: Mapping[str, JSONScalar] = field(default_factory=_empty_attributes)

    def __post_init__(self) -> None:
        if self.schema_version != "cs-audit/1":
            raise ValueError("unsupported audit schema")
        object.__setattr__(
            self,
            "attributes",
            MappingProxyType(dict(self.attributes)),
        )


@runtime_checkable
class AuditSink(Protocol):
    def emit(self, event: AuditEvent) -> None: ...


__all__ = ["AuditEvent", "AuditSink"]
