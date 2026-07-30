"""Non-operational immutable policy declaration."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import NoReturn


def _policy_not_implemented() -> NoReturn:
    raise NotImplementedError(
        "v4 policy construction and evaluation are not implemented in Phase 3"
    )


@dataclass(frozen=True)
class Policy:
    """An identified policy value without an evaluator.

    The caller may carry an already assigned nonsecret policy identifier.
    Canonical policy serialization, identifier derivation, composition, and
    authorization are deferred.
    """

    policy_id: str
    profile: str = "custom"

    def __post_init__(self) -> None:
        if not isinstance(self.policy_id, str) or not self.policy_id:
            raise ValueError("policy_id must be a non-empty string")
        if not isinstance(self.profile, str) or not self.profile:
            raise ValueError("profile must be a non-empty string")

    @classmethod
    def enterprise(cls, *, approved_providers: Iterable[str]) -> Policy:
        del approved_providers
        _policy_not_implemented()

    @classmethod
    def development(cls) -> Policy:
        _policy_not_implemented()

    @classmethod
    def migration(cls, *, deadline: datetime) -> Policy:
        del deadline
        _policy_not_implemented()

    def restrict(self, overlay: Policy) -> Policy:
        del overlay
        _policy_not_implemented()


__all__ = ["Policy"]
