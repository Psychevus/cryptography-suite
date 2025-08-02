import base64
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519

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


def read_log(path: Path, public_key: bytes):
    """Read log, validate chain and signatures, returning lines."""

    text = path.read_text().strip().splitlines()
    prev = "0" * 64
    pub = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
    for line in text:
        parts = line.rsplit("|", 2)
        entry = parts[0]
        digest, sig_b64 = parts[1], parts[2]
        assert hashlib.sha256((prev + entry).encode()).hexdigest() == digest
        pub.verify(base64.b64decode(sig_b64), digest.encode())
        prev = digest
    return text


def test_wizard_interactive(tmp_path, monkeypatch, capsys):
    src = InMemoryBackend.with_sample_keys("file")
    dst = InMemoryBackend("vault")
    log = tmp_path / "audit.log"
    logger = AuditLogger(log)
    responses = iter(["n", "all"])
    monkeypatch.setattr(migrate_keys.Prompt, "ask", lambda *a, **k: next(responses))

    migrate_wizard(src, dst, logger)
    out = capsys.readouterr().out
    assert "hybrid" in out  # PQ hybrid warning shown

    assert set(dst._keys) == {"ecc", "ed", "kyber", "dilithium"}
    lines = read_log(log, logger.public_key_bytes)
    assert [line.split("|")[1] for line in lines] == [
        "skip",
        "migrate",
        "migrate",
        "migrate",
        "migrate",
    ]
    kyber_line = next(l for l in lines if "kyber" in l)
    assert "Kyber/3:file->vault" in kyber_line
    assert {p.name for p in tmp_path.iterdir()} == {"audit.log"}


def test_batch_dry_run(tmp_path):
    src = InMemoryBackend.with_sample_keys("file")
    dst = InMemoryBackend("hsm")
    log = tmp_path / "audit.log"
    logger = AuditLogger(log)

    migrate_batch(src, dst, logger, dry_run=True)

    assert dst._keys == {}
    lines = read_log(log, logger.public_key_bytes)
    assert len(lines) == 5
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

    lines = read_log(log, logger.public_key_bytes)
    actions = [line.split("|")[1] for line in lines]
    assert actions == ["error", "skip", "skip", "skip", "skip"]
    assert "boom" not in "".join(lines)
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

    lines2 = read_log(log2, logger2.public_key_bytes)
    actions2 = [line.split("|")[1] for line in lines2]
    assert actions2[0] == "error"
    assert actions2.count("migrate") == 4
    assert set(dst2._keys) == {"ecc", "ed", "kyber", "dilithium"}
    assert {p.name for p in tmp_path.iterdir()} == {"audit.log", "audit2.log"}


def test_forensics_report(tmp_path):
    src = InMemoryBackend.with_sample_keys("file")
    dst = InMemoryBackend("vault")
    log = tmp_path / "audit.log"
    logger = AuditLogger(log)

    migrate_batch(src, dst, logger, dry_run=True)
    report = tmp_path / "report.json"
    logger.export_report(report)

    data = json.loads(report.read_text())
    pub = ed25519.Ed25519PublicKey.from_public_bytes(
        base64.b64decode(data["public_key"])
    )
    pub.verify(base64.b64decode(data["signature"]), data["final_digest"].encode())
    assert len(data["entries"]) == 5


def test_webhook_integration(tmp_path, monkeypatch):
    src = InMemoryBackend.with_sample_keys("file")
    dst = InMemoryBackend("vault")
    log = tmp_path / "audit.log"
    calls: list[dict] = []

    class DummyResp:
        status_code = 200

    def fake_post(url, json, timeout=5):
        calls.append(json)
        return DummyResp()

    monkeypatch.setattr(migrate_keys.requests, "post", fake_post)
    logger = AuditLogger(log, webhook="https://example")
    migrate_batch(src, dst, logger, dry_run=True)
    assert len(calls) == 5
    assert all("signature" in c for c in calls)
