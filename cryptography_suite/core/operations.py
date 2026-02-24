"""Operational hardening helpers for retries, subprocesses, metrics, and cancellation."""

from __future__ import annotations

import random
import signal
import subprocess
import threading
import time
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Callable, Iterator, Sequence, TypeVar

from .logging import get_structured_logger, log_event

T = TypeVar("T")


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 4
    base_delay_s: float = 0.2
    max_delay_s: float = 3.0
    jitter_s: float = 0.1
    max_retry_budget_s: float = 30.0


class MetricsCollector:
    """Minimal in-memory metrics hooks for counters and timers."""

    def __init__(self) -> None:
        self._counters: Counter[str] = Counter()
        self._timers_s: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def increment(self, name: str, amount: int = 1) -> None:
        with self._lock:
            self._counters[name] += amount

    def observe(self, name: str, duration_s: float) -> None:
        with self._lock:
            self._timers_s.setdefault(name, []).append(duration_s)

    @contextmanager
    def timed(self, name: str) -> Iterator[None]:
        start = time.monotonic()
        try:
            yield
        finally:
            self.observe(name, time.monotonic() - start)

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            timer_stats = {
                name: {
                    "count": len(vals),
                    "total_s": round(sum(vals), 6),
                    "avg_s": round(sum(vals) / len(vals), 6),
                }
                for name, vals in self._timers_s.items()
                if vals
            }
            return {"counters": dict(self._counters), "timers": timer_stats}


METRICS = MetricsCollector()
_CANCELLED = threading.Event()


def install_signal_handlers(logger_name: str = "cryptography_suite.ops") -> None:
    logger = get_structured_logger(logger_name)

    def _handler(signum: int, _frame: object) -> None:
        _CANCELLED.set()
        METRICS.increment("signal.received")
        log_event(logger, "shutdown_requested", signal=signum)

    signal.signal(signal.SIGINT, _handler)
    signal.signal(signal.SIGTERM, _handler)


def raise_if_cancelled() -> None:
    if _CANCELLED.is_set():
        raise RuntimeError("Operation cancelled by signal")


def retry_with_backoff(
    operation: Callable[[], T],
    *,
    policy: RetryPolicy,
    logger_name: str,
    operation_name: str,
) -> T:
    logger = get_structured_logger(logger_name)
    start = time.monotonic()
    attempts = 0
    while True:
        raise_if_cancelled()
        attempts += 1
        try:
            with METRICS.timed(f"{operation_name}.duration"):
                result = operation()
            METRICS.increment(f"{operation_name}.success")
            if attempts > 1:
                log_event(logger, "retry_recovered", operation=operation_name, attempts=attempts)
            return result
        except Exception as exc:
            METRICS.increment(f"{operation_name}.error")
            if attempts >= policy.max_attempts or (time.monotonic() - start) >= policy.max_retry_budget_s:
                log_event(
                    logger,
                    "retry_exhausted",
                    operation=operation_name,
                    attempts=attempts,
                    error=str(exc),
                )
                raise RuntimeError(
                    f"{operation_name} failed after {attempts} attempts: {exc}"
                ) from exc
            exp = min(policy.base_delay_s * (2 ** (attempts - 1)), policy.max_delay_s)
            sleep_for = exp + random.uniform(0.0, policy.jitter_s)
            log_event(
                logger,
                "retrying",
                operation=operation_name,
                attempts=attempts,
                sleep_s=round(sleep_for, 3),
                error=str(exc),
            )
            time.sleep(sleep_for)


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


def run_command(
    cmd: Sequence[str],
    *,
    timeout_s: float = 30.0,
    logger_name: str = "cryptography_suite.ops",
    operation_name: str = "subprocess",
) -> CommandResult:
    if not cmd or any(not token for token in cmd):
        raise ValueError("Command must contain non-empty tokens")
    if timeout_s <= 0:
        raise ValueError("timeout_s must be positive")

    logger = get_structured_logger(logger_name)
    log_event(logger, "subprocess_start", operation=operation_name, argv=list(cmd), timeout_s=timeout_s)
    with METRICS.timed(f"{operation_name}.duration"):
        proc = subprocess.run(
            list(cmd),
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
    METRICS.increment(f"{operation_name}.invocations")
    if proc.returncode != 0:
        METRICS.increment(f"{operation_name}.failure")
        log_event(
            logger,
            "subprocess_failed",
            operation=operation_name,
            returncode=proc.returncode,
            stderr=proc.stderr.strip(),
        )
        raise RuntimeError(
            f"{operation_name} failed with exit code {proc.returncode}: {proc.stderr.strip()}"
        )
    METRICS.increment(f"{operation_name}.success")
    log_event(logger, "subprocess_success", operation=operation_name)
    return CommandResult(returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)
