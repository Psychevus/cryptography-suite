from __future__ import annotations

import configparser
import email.parser
import tarfile
import zipfile
from pathlib import Path

import tomllib
from conftest import REPO_ROOT, BuiltArtifacts

RUNTIME_FILES = {
    "cryptography_suite/__init__.py",
    "cryptography_suite/_internal/__init__.py",
    "cryptography_suite/_internal/filesystem.py",
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
    "cryptography_suite/streaming/atomic.py",
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

EXPECTED_EXTRAS = {"dev", "docs"}
REMOVED_EXTRAS = {
    "async",
    "aws",
    "bls",
    "cli",
    "codegen",
    "fhe",
    "hashing-extra",
    "hsm",
    "kms",
    "legacy",
    "network",
    "pake",
    "pqc",
    "viz",
    "zk",
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


def test_package_discovery_and_data_are_exact_allowlists() -> None:
    data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    setuptools = data["tool"]["setuptools"]

    assert setuptools["package-dir"] == {"": "src"}
    assert setuptools["include-package-data"] is False
    assert setuptools["packages"]["find"] == {
        "where": ["src"],
        "include": ["cryptography_suite*"],
        "namespaces": False,
    }
    assert setuptools["package-data"] == {"cryptography_suite": ["py.typed"]}
    assert "scripts" not in data["project"]
    assert "entry-points" not in data["project"]


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
    assert set(metadata.get_all("Provides-Extra", [])) == EXPECTED_EXTRAS
    assert set(metadata.get_all("Provides-Extra", [])).isdisjoint(REMOVED_EXTRAS)

    payload = metadata.get_payload()
    assert isinstance(payload, str)
    description = payload.lower()
    assert "declaration-only v4 development skeleton" in description
    assert "no operational encryption or decryption" in description
    for obsolete_advertisement in (
        "cryptography_suite.cli",
        "cryptography_suite.experimental",
        "cryptography_suite.keystores",
        "cryptography_suite.pipeline",
        "cryptography-suite file",
        "cryptosuite-fuzz",
        "aws kms",
        "homomorphic encryption",
        "pkcs#11",
        "post-quantum",
        "zero-knowledge",
    ):
        assert obsolete_advertisement not in description


def test_only_pyproject_defines_active_mypy_configuration() -> None:
    setup = configparser.ConfigParser()
    setup.read(REPO_ROOT / "setup.cfg", encoding="utf-8")
    assert setup.sections() == ["build_ext"]

    data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert data["tool"]["mypy"]["python_version"] == "3.10"
    assert "cryptography_suite._mypy_crypto_checker" not in (
        REPO_ROOT / "setup.cfg"
    ).read_text(encoding="utf-8")


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
