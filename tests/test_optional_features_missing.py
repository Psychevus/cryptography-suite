import builtins
import importlib
import sys
from collections.abc import Iterator
from contextlib import contextmanager

import pytest

from cryptography_suite.errors import MissingDependencyError


@contextmanager
def _blocked_imports(*roots: str) -> Iterator[None]:
    original_import = builtins.__import__
    removed = {}
    for name in list(sys.modules):
        if any(name == root or name.startswith(f"{root}.") for root in roots):
            removed[name] = sys.modules.pop(name)

    def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name.split(".", 1)[0] in roots:
            raise ModuleNotFoundError(f"No module named {name!r}", name=name)
        return original_import(name, globals, locals, fromlist, level)

    builtins.__import__ = guarded_import
    try:
        yield
    finally:
        builtins.__import__ = original_import
        for name, module in removed.items():
            sys.modules.setdefault(name, module)


def test_homomorphic_requires_pyfhel(monkeypatch):
    monkeypatch.setenv("CRYPTOSUITE_ALLOW_EXPERIMENTAL", "1")
    monkeypatch.setitem(sys.modules, "Pyfhel", None)
    for module_name in (
        "cryptography_suite.homomorphic",
        "cryptography_suite.experimental.fhe",
        "cryptography_suite.experimental",
    ):
        sys.modules.pop(module_name, None)
    h = importlib.import_module("cryptography_suite.experimental.fhe")
    with pytest.raises(MissingDependencyError, match=r"cryptography-suite\[fhe\]"):
        h.fhe_keygen()


def test_blake3_hashing_requires_hashing_extra():
    import cryptography_suite.hashing as hashing

    with _blocked_imports("blake3"):
        importlib.reload(hashing)
        with pytest.raises(
            MissingDependencyError,
            match=r"cryptography-suite\[hashing-extra\]",
        ):
            hashing.blake3_hash("message")
    importlib.reload(hashing)


def test_bls_requires_bls_extra():
    import cryptography_suite.asymmetric.bls as bls

    with _blocked_imports("py_ecc"):
        importlib.reload(bls)
        with pytest.raises(MissingDependencyError, match=r"cryptography-suite\[bls\]"):
            bls.generate_bls_keypair()
    importlib.reload(bls)


def test_spake2_requires_pake_extra():
    import cryptography_suite.protocols.pake as pake

    with _blocked_imports("spake2"):
        importlib.reload(pake)
        with pytest.raises(MissingDependencyError, match=r"cryptography-suite\[pake\]"):
            pake.SPAKE2Client("password")
    importlib.reload(pake)


def test_codegen_requires_codegen_extra(tmp_path):
    import cryptography_suite.codegen as codegen

    pipeline = tmp_path / "pipeline.yaml"
    pipeline.write_text("[]\n", encoding="utf-8")
    with _blocked_imports("jinja2"):
        importlib.reload(codegen)
        with pytest.raises(
            MissingDependencyError,
            match=r"cryptography-suite\[codegen\]",
        ):
            codegen.generate("fastapi", str(pipeline), str(tmp_path / "out"))
    importlib.reload(codegen)


def test_rich_logging_requires_cli_extra():
    import cryptography_suite.rich_logging as rich_logging

    with _blocked_imports("rich"):
        importlib.reload(rich_logging)
        with pytest.raises(MissingDependencyError, match=r"cryptography-suite\[cli\]"):
            rich_logging.get_rich_logger()
    importlib.reload(rich_logging)


def test_aws_kms_requires_kms_extra():
    import cryptography_suite.keystores.aws_kms as aws_kms

    with _blocked_imports("boto3"):
        importlib.reload(aws_kms)
        with pytest.raises(MissingDependencyError, match=r"cryptography-suite\[kms\]"):
            aws_kms.AWSKMSKeyStore()
    importlib.reload(aws_kms)


def test_pkcs11_requires_hsm_extra():
    import cryptography_suite.keystores.pkcs11 as pkcs11_module

    with _blocked_imports("pkcs11"):
        importlib.reload(pkcs11_module)
        with pytest.raises(MissingDependencyError, match=r"cryptography-suite\[hsm\]"):
            pkcs11_module.PKCS11KeyStore()
    importlib.reload(pkcs11_module)


def test_visualization_requires_viz_extra():
    import cryptography_suite.viz.widgets as widgets

    with _blocked_imports("ipywidgets", "networkx"):
        importlib.reload(widgets)
        with pytest.raises(MissingDependencyError, match=r"cryptography-suite\[viz\]"):
            widgets.HandshakeFlowWidget(["start"])
    importlib.reload(widgets)


def test_cli_blake3_missing_message(tmp_path, capsys):
    import cryptography_suite.cli as cli

    payload = tmp_path / "payload.txt"
    payload.write_text("hello", encoding="utf-8")
    with _blocked_imports("blake3"):
        importlib.reload(cli)
        with pytest.raises(SystemExit):
            cli.main(["hash", str(payload), "--algorithm", "blake3"])
    importlib.reload(cli)

    assert "Install cryptography-suite[hashing-extra]" in capsys.readouterr().out


def test_cli_export_yaml_missing_message(tmp_path, capsys):
    import cryptography_suite.cli as cli

    pipeline = tmp_path / "pipeline.yaml"
    pipeline.write_text("[]\n", encoding="utf-8")
    with _blocked_imports("yaml"):
        importlib.reload(cli)
        with pytest.raises(SystemExit):
            cli.main(["export", str(pipeline)])
    importlib.reload(cli)

    assert "Install cryptography-suite[cli]" in capsys.readouterr().out


def test_bulletproof_requires_dependency(monkeypatch):
    from cryptography_suite.zk import bulletproof as bp

    monkeypatch.setattr(bp, "BULLETPROOF_AVAILABLE", False)
    with pytest.raises(MissingDependencyError):
        bp.prove(1)


def test_zksnark_requires_dependency(monkeypatch):
    from cryptography_suite.zk import zksnark as zk

    monkeypatch.setattr(zk, "ZKSNARK_AVAILABLE", False)
    with pytest.raises(MissingDependencyError):
        zk.setup()
