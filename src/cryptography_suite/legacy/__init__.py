"""Explicit, non-operational legacy migration namespace."""

from __future__ import annotations

from enum import Enum
from typing import Protocol, runtime_checkable


class LegacyFormat(str, Enum):
    CSF_V2 = "csf-v2"
    CSF_V1 = "csf-v1"
    RAW_AES = "raw-aes"
    PASSWORD_AES_V3 = "password-aes-v3"
    LOCAL_KEYSTORE = "local-keystore"
    PEM_DER = "pem-der"


@runtime_checkable
class LegacyAdapter(Protocol):
    @property
    def format(self) -> LegacyFormat: ...


__all__ = ["LegacyAdapter", "LegacyFormat"]
