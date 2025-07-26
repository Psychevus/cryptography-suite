from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Generic, Protocol, TypeVar, Callable, Iterable, Any
import json

Input = TypeVar("Input")
Output = TypeVar("Output")


class CryptoModule(Protocol[Input, Output]):
    """Protocol for pipeline modules."""

    def run(self, data: Input) -> Output:
        """Run the module on the provided data."""
        ...


@dataclass
class Pipeline(Generic[Input, Output]):
    """Composable cryptographic pipeline."""

    modules: list[CryptoModule[Any, Any]] | None = None

    def __post_init__(self) -> None:
        if self.modules is None:
            self.modules = []

    # operator overloads -------------------------------------------------
    def __rshift__(self, other: CryptoModule[Any, Any] | "Pipeline") -> "Pipeline":
        new_modules: list[CryptoModule[Any, Any]] = list(self.modules)
        if isinstance(other, Pipeline):
            new_modules.extend(other.modules)
        else:
            new_modules.append(other)
        return Pipeline(new_modules)

    # execution -----------------------------------------------------------
    def run(self, data: Any) -> Any:
        result = data
        for mod in self.modules:
            result = mod.run(result)
        return result

    # introspection -------------------------------------------------------
    def describe(self) -> list[dict[str, Any]]:
        desc: list[dict[str, Any]] = []
        for mod in self.modules:
            info = {
                "module": mod.__class__.__name__,
            }
            if hasattr(mod, "__dict__"):
                info["params"] = {
                    k: v for k, v in vars(mod).items() if not k.startswith("_")
                }
            desc.append(info)
        return desc

    def to_json(self) -> str:
        return json.dumps(self.describe())

    @classmethod
    def from_config(cls, config: Iterable[Callable[[], CryptoModule]]) -> "Pipeline":
        modules = [factory() for factory in config]
        return cls(list(modules))

    def dry_run(self, data: Any) -> Any:
        result = data
        for mod in self.modules:
            print(f"{mod.__class__.__name__}: {result!r}")
            result = mod.run(result)
        return result


class PipelineVisualizer:
    """Simple ASCII pipeline visualizer."""

    def __init__(self, pipeline: Pipeline) -> None:
        self.pipeline = pipeline

    def render_ascii(self) -> str:
        parts = [mod.__class__.__name__ for mod in self.pipeline.modules]
        return " -> ".join(parts)

