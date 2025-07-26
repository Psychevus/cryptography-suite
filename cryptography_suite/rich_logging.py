"""Rich-based logging utilities."""

from __future__ import annotations

import logging
from logging import Logger

from rich.logging import RichHandler
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn


def get_rich_logger(
    name: str = "cryptography-suite", level: int = logging.INFO
) -> Logger:
    """Return a configured Rich logger."""
    logger = logging.getLogger(name)
    if not any(isinstance(h, RichHandler) for h in logger.handlers):
        handler = RichHandler(rich_tracebacks=True, show_path=False)
        logger.addHandler(handler)
        logger.setLevel(level)
    return logger


class PipelineProgress:
    """Context manager to display pipeline progress."""

    def __init__(self, total: int) -> None:
        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
        )
        self._task = self._progress.add_task("pipeline", total=total)

    def __enter__(self) -> "PipelineProgress":
        self._progress.start()
        return self

    def step(self) -> None:
        self._progress.advance(self._task)

    def __exit__(self, exc_type, exc, tb) -> None:
        self._progress.stop()


__all__ = ["get_rich_logger", "PipelineProgress"]
