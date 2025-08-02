import hashlib
import importlib.util
import sys
from pathlib import Path

MODULE_PATH = (
    Path(__file__).resolve().parent.parent
    / "src"
    / "cryptography_suite"
    / "cli"
    / "migrate_keys.py"
)
spec = importlib.util.spec_from_file_location(
    "cryptography_suite.cli.migrate_keys", MODULE_PATH
)
migrate_keys = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = migrate_keys
assert spec.loader is not None
spec.loader.exec_module(migrate_keys)

AuditLogger = migrate_keys.AuditLogger
InMemoryBackend = migrate_keys.InMemoryBackend
migrate_batch = migrate_keys.migrate_batch
migrate_wizard = migrate_keys.migrate_wizard


def read_log(path: Path):
    """Read log and validate hash chain, returning lines."""
    text = path.read_text().strip().splitlines()
    prev = "0" * 64
    for line in text:
        entry, digest = line.rsplit("|", 1)
        assert hashlib.sha256((prev + entry).encode()).hexdigest() == digest
        prev = digest
    return text


def test_wizard_interactive(tmp_path, monkeypatch):
    src = InMemoryBackend.with_sample_keys("file")
    dst = InMemoryBackend("vault")
    log = tmp_path / "audit.log"
    logger = AuditLogger(log)
    responses = iter(["n", "all"])
    monkeypatch.setattr(migrate_keys.Prompt, "ask", lambda *a, **k: next(responses))

    migrate_wizard(src, dst, logger)

    assert set(dst._keys) == {"ecc", "ed"}
    lines = read_log(log)
    assert [line.split("|")[1] for line in lines] == ["skip", "migrate", "migrate"]
    assert {p.name for p in tmp_path.iterdir()} == {"audit.log"}


def test_batch_dry_run(tmp_path):
    src = InMemoryBackend.with_sample_keys("file")
    dst = InMemoryBackend("hsm")
    log = tmp_path / "audit.log"
    logger = AuditLogger(log)

    migrate_batch(src, dst, logger, dry_run=True)

    assert dst._keys == {}
    lines = read_log(log)
    assert len(lines) == 3
    assert all("dry-run" in line for line in lines)
    assert {p.name for p in tmp_path.iterdir()} == {"audit.log"}


def test_batch_error_handling(tmp_path, monkeypatch):
    src = InMemoryBackend.with_sample_keys("file")
    dst = InMemoryBackend("vault")
    log = tmp_path / "audit.log"
    logger = AuditLogger(log)

    def fail_first(info):
        raise ValueError("boom")

    monkeypatch.setattr(dst, "store_key", fail_first)

    migrate_batch(src, dst, logger, ignore_errors=False)

    lines = read_log(log)
    actions = [line.split("|")[1] for line in lines]
    assert actions == ["error", "skip", "skip"]
    assert dst._keys == {}

    # now test ignore_errors
    src2 = InMemoryBackend.with_sample_keys("file")
    dst2 = InMemoryBackend("vault")
    log2 = tmp_path / "audit2.log"
    logger2 = AuditLogger(log2)

    orig = dst2.store_key
    calls = {"count": 0}

    def flaky(info):
        calls["count"] += 1
        if calls["count"] == 1:
            raise ValueError("boom")
        orig(info)

    monkeypatch.setattr(dst2, "store_key", flaky)
    migrate_batch(src2, dst2, logger2, ignore_errors=True)

    lines2 = read_log(log2)
    actions2 = [line.split("|")[1] for line in lines2]
    assert actions2[0] == "error"
    assert actions2.count("migrate") == 2
    assert set(dst2._keys) == {"ecc", "ed"}
    assert {p.name for p in tmp_path.iterdir()} == {"audit.log", "audit2.log"}
