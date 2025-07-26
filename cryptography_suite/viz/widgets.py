from __future__ import annotations

from typing import Iterable

from ipywidgets import VBox, HTML, Output
from IPython.display import display
import networkx as nx
from networkx.readwrite import json_graph


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
        self._graph = nx.DiGraph()
        self._graph.add_edges_from(edges)
        self.output = Output()
        self.children = [self.output]
        self._render()

    def _render(self) -> None:
        data = (
            json_graph.tree_data(self._graph, root=list(self._graph.nodes)[0])
            if self._graph.nodes
            else {}
        )
        with self.output:
            self.output.clear_output()
            display(data)

    def add_edge(self, src: str, dst: str) -> None:
        self._graph.add_edge(src, dst)
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
