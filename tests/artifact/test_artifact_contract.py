from __future__ import annotations

import email.parser
import tarfile
import zipfile
from pathlib import Path

from conftest import BuiltArtifacts

RUNTIME_FILES = {
    "cryptography_suite/__init__.py",
    "cryptography_suite/audit/__init__.py",
    "cryptography_suite/audit/events.py",
    "cryptography_suite/context.py",
    "cryptography_suite/envelope/__init__.py",
    "cryptography_suite/envelope/models.py",
    "cryptography_suite/errors.py",
    "cryptography_suite/legacy/__init__.py",
    "cryptography_suite/lifecycle/__init__.py",
    "cryptography_suite/lifecycle/models.py",
    "cryptography_suite/policy.py",
    "cryptography_suite/protector.py",
    "cryptography_suite/providers/__init__.py",
    "cryptography_suite/providers/base.py",
    "cryptography_suite/providers/models.py",
    "cryptography_suite/py.typed",
    "cryptography_suite/streaming/__init__.py",
    "cryptography_suite/streaming/sinks.py",
}

PROHIBITED_PARTS = {
    "/aead",
    "/asymmetric",
    "/cli",
    "/codegen",
    "/crypto_backends",
    "/experimental",
    "/fake",
    "/fhe",
    "/handshake",
    "/homomorphic",
    "/hybrid",
    "/keystore",
    "/labs",
    "/mock",
    "/nonce",
    "/otp",
    "/pipeline",
    "/pkcs11",
    "/pqc",
    "/protocols",
    "/symmetric",
    "/templates",
    "/viz",
    "/x509",
    "/zk",
    "crypto_suite/",
    "src/suite/",
    "tests/",
}


def _wheel_names(wheel: Path) -> set[str]:
    with zipfile.ZipFile(wheel) as archive:
        return set(archive.namelist())


def test_wheel_runtime_is_exact_allowlist(built_artifacts: BuiltArtifacts) -> None:
    names = _wheel_names(built_artifacts.wheel)
    runtime = {name for name in names if name.startswith("cryptography_suite/")}

    assert runtime == RUNTIME_FILES
    assert all(
        prohibited not in name.lower()
        for name in names
        for prohibited in PROHIBITED_PARTS
    )


def test_wheel_metadata_has_no_entry_points(
    built_artifacts: BuiltArtifacts,
) -> None:
    with zipfile.ZipFile(built_artifacts.wheel) as archive:
        names = archive.namelist()
        assert not any(name.endswith("entry_points.txt") for name in names)
        metadata_name = next(
            name for name in names if name.endswith(".dist-info/METADATA")
        )
        metadata = email.parser.Parser().parsestr(
            archive.read(metadata_name).decode("utf-8")
        )

    assert metadata["Name"] == "cryptography-suite"
    assert metadata["Version"] == "3.0.0"
    assert metadata["Requires-Python"] == ">=3.10"


def test_sdist_has_only_explicit_source_boundary(
    built_artifacts: BuiltArtifacts,
) -> None:
    with tarfile.open(built_artifacts.sdist) as archive:
        files = {
            name.split("/", 1)[1]
            for member in archive.getmembers()
            if member.isfile()
            for name in [member.name]
        }

    allowed_roots = {
        "LICENSE",
        "MANIFEST.in",
        "PKG-INFO",
        "README.md",
        "pyproject.toml",
        "setup.cfg",
        "setup.py",
    }
    unexpected = {
        name
        for name in files
        if name not in allowed_roots
        and not name.startswith("src/cryptography_suite/")
        and not name.startswith("src/cryptography_suite.egg-info/")
    }
    assert unexpected == set()
    assert {
        name.removeprefix("src/")
        for name in files
        if name.startswith("src/cryptography_suite/")
    } == RUNTIME_FILES
    assert all(
        prohibited not in name.lower()
        for name in files
        for prohibited in PROHIBITED_PARTS
    )
