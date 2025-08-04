import os

STRICT_KEYS = os.getenv("CRYPTOSUITE_STRICT_KEYS", "warn").lower()
if STRICT_KEYS not in {"warn", "1", "true", "error", "0", "false"}:
    raise ValueError("Invalid STRICT_KEYS value")
if STRICT_KEYS in {"1", "true"}:
    STRICT_KEYS = "error"
elif STRICT_KEYS in {"0", "false"}:
    STRICT_KEYS = "false"
