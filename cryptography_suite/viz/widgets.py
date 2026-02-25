from __future__ import annotations

from collections.abc import Iterable

try:
    import networkx as nx
    from IPython.display import display
    from ipywidgets import HTML, Output, VBox
    from networkx.readwrite import json_graph

    _HAS_VIZ_DEPS = True
except Exception:  # pragma: no cover - optional visualization dependencies
    _HAS_VIZ_DEPS = False

    class HTML:  # type: ignore[no-redef]
        def __init__(self, value: str = "") -> None:
            self.value = value

    class Output:  # type: ignore[no-redef]
        def clear_output(self) -> None:
            return None

        def __enter__(self) -> Output:
            return self

        def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
            return None

    class VBox:  # type: ignore[no-redef]
        def __init__(self, children: list[object] | None = None) -> None:
            self.children = children or []

    class _FallbackDiGraph:
        def __init__(self) -> None:
            self._edges: list[tuple[str, str]] = []

        def add_edges_from(self, edges: Iterable[tuple[str, str]]) -> None:
            self._edges.extend(edges)

        @property
        def nodes(self) -> list[str]:
            nodes: set[str] = set()
            for src, dst in self._edges:
                nodes.add(src)
                nodes.add(dst)
            return sorted(nodes)

    class _FallbackNX:
        DiGraph = _FallbackDiGraph

    class _FallbackJSONGraph:
        @staticmethod
        def tree_data(graph: _FallbackDiGraph, root: str) -> dict[str, object]:
            return {"root": root, "nodes": graph.nodes, "edges": graph._edges}

    nx = _FallbackNX()
    json_graph = _FallbackJSONGraph()

    def display(_obj: object) -> None:
        return None


class HandshakeFlowWidget(VBox):
    """Animated visualization of a handshake protocol."""

    def __init__(self, steps: Iterable[str]):
        self._steps = list(steps)
        self._index = 0
        self.output = HTML()
        super().__init__([self.output])
        self._render()

    def _render(self) -> None:
        shown = "<br>".join(self._steps[: self._index + 1])
        self.output.value = shown

    def next_step(self) -> None:
        if self._index < len(self._steps) - 1:
            self._index += 1
            self._render()


class KeyGraphWidget(VBox):
    """Display key relationships as a graph."""

    def __init__(self, edges: Iterable[tuple[str, str]] = ()):  # simple graph
        super().__init__()
        self._edges = list(edges)
        self.output = Output()
        self.children = [self.output]
        self._render()

    def _render(self) -> None:
        graph = nx.DiGraph()
        graph.add_edges_from(self._edges)
        data = (
            json_graph.tree_data(graph, root=list(graph.nodes)[0])
            if graph.nodes
            else {}
        )

        with self.output:
            self.output.clear_output()
            display(data)

    def add_edge(self, src: str, dst: str) -> None:
        self._edges.append((src, dst))
        self._render()


class SessionTimelineWidget(VBox):
    """Visualize message and key events over time."""

    def __init__(self, events: Iterable[str] = ()):  # simple timeline
        self._events = list(events)
        self.output = HTML("<br>".join(self._events))
        super().__init__([self.output])

    def add_event(self, event: str) -> None:
        self._events.append(event)
        self.output.value = "<br>".join(self._events)


__all__ = [
    "HandshakeFlowWidget",
    "KeyGraphWidget",
    "SessionTimelineWidget",
]
