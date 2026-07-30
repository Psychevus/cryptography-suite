from __future__ import annotations

import multiprocessing
import os
from pathlib import Path
from queue import Empty

from cryptography_suite.streaming.atomic import AtomicFileSink, AtomicSinkError


def _concurrent_writer(
    root: str,
    payload: bytes,
    ready: multiprocessing.synchronize.Event,
    start: multiprocessing.synchronize.Event,
    results: multiprocessing.queues.Queue,
) -> None:
    try:
        sink = AtomicFileSink(
            output_root=root,
            relative_destination="winner.bin",
        )
        sink.write(payload)
        ready.set()
        if not start.wait(20):
            sink.abort()
            results.put(("timeout", ""))
            return
        sink.commit()
        results.put(("committed", payload.decode("ascii")))
    except AtomicSinkError as error:
        sink.abort()
        results.put(("failed", error.code.value))


def test_two_process_no_overwrite_race_has_exactly_one_winner(
    tmp_path: Path,
) -> None:
    context = multiprocessing.get_context("spawn" if os.name == "nt" else "fork")
    ready_one = context.Event()
    ready_two = context.Event()
    start = context.Event()
    results = context.Queue()
    processes = [
        context.Process(  # type: ignore[attr-defined]
            target=_concurrent_writer,
            args=(str(tmp_path.absolute()), payload, ready, start, results),
        )
        for payload, ready in ((b"one", ready_one), (b"two", ready_two))
    ]
    for process in processes:
        process.start()
    assert ready_one.wait(20)
    assert ready_two.wait(20)
    start.set()
    for process in processes:
        process.join(30)
        assert process.exitcode == 0

    observed: list[tuple[str, str]] = []
    for _ in processes:
        try:
            observed.append(results.get(timeout=5))
        except Empty as error:
            raise AssertionError("concurrent writer result missing") from error

    committed = [value for status, value in observed if status == "committed"]
    failed = [value for status, value in observed if status == "failed"]
    assert len(committed) == 1
    assert failed == ["OUTPUT_EXISTS"]
    assert (tmp_path / "winner.bin").read_bytes() == committed[0].encode("ascii")
    assert [path.name for path in tmp_path.iterdir()] == ["winner.bin"]
