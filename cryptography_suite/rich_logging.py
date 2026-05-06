"""Rich-based logging utilities."""

from __future__ import annotations

import logging
from logging import Logger
from typing import Any

from .core.logging import configure_structured_logging
from .errors import MissingDependencyError


def _load_rich_logging() -> type[Any]:
    try:
        from rich.logging import RichHandler
    except Exception as exc:  # pragma: no cover - dependency missing
        raise MissingDependencyError(
            "Rich logging requires rich. "
            "Install cryptography-suite[cli] to use this feature."
        ) from exc
    return RichHandler


def _load_rich_progress() -> tuple[type[Any], type[Any], type[Any], type[Any]]:
    try:
        from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
    except Exception as exc:  # pragma: no cover - dependency missing
        raise MissingDependencyError(
            "Rich progress output requires rich. "
            "Install cryptography-suite[cli] to use this feature."
        ) from exc
    return BarColumn, Progress, SpinnerColumn, TextColumn


def get_rich_logger(
    name: str = "cryptography-suite", level: int = logging.INFO
) -> Logger:
    """Return a configured Rich logger."""
    rich_handler_cls = _load_rich_logging()
    configure_structured_logging(level)
    logger = logging.getLogger(name)
    if not any(isinstance(h, rich_handler_cls) for h in logger.handlers):
        handler = rich_handler_cls(rich_tracebacks=True, show_path=False)
        logger.addHandler(handler)
        logger.setLevel(level)
    return logger


class PipelineProgress:
    """Context manager to display pipeline progress."""

    def __init__(self, total: int) -> None:
        bar_column, progress_cls, spinner_column, text_column = _load_rich_progress()
        self._progress = progress_cls(
            spinner_column(),
            text_column("[progress.description]{task.description}"),
            bar_column(),
        )
        self._task = self._progress.add_task("pipeline", total=total)

    def __enter__(self) -> PipelineProgress:
        self._progress.start()
        return self

    def step(self) -> None:
        self._progress.advance(self._task)

    def __exit__(self, exc_type, exc, tb) -> None:
        self._progress.stop()


__all__ = ["get_rich_logger", "PipelineProgress"]
