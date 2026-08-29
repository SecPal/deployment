#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Contract tests for the one active disposable PostgreSQL fixture."""

from __future__ import annotations

import ast
import importlib.util
import os
from pathlib import Path
import re
import runpy
import stat
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if os.fspath(SCRIPTS) not in sys.path:
    sys.path.insert(0, os.fspath(SCRIPTS))

import integration_runtime_contract as runtime_contract  # noqa: E402


CURRENT_SOURCE_ROOTS = (
    Path(".github/workflows"),
    Path("config"),
    Path("containers"),
    Path("schemas"),
    Path("scripts"),
)
CURRENT_FIXTURE_DOCUMENTS = (Path("docs/quadlet-integration.md"),)
MAX_CURRENT_FILES = 512
MAX_CURRENT_FILE_BYTES = 1_000_000
MAX_CURRENT_TOTAL_BYTES = 8_000_000
LEGACY_IDENTITY_PATTERNS = (
    re.compile(r"\bpostgres(?:ql)?[\t _-]*(?:major|version)[\t :=\"'-]*(?:16|17)(?:\.[0-9]+)?\b", re.IGNORECASE),
    re.compile(r"\bpostgres(?:ql)?[\t _-]+(?:16|17)(?:\.[0-9]+)?\b", re.IGNORECASE),
    re.compile(r"\bpg[ _-]?(?:16|17)(?:\.[0-9]+)?\b", re.IGNORECASE),
    re.compile(r"\bpostgresql(?:-client|-server)?-(?:16|17)\b", re.IGNORECASE),
    re.compile(r"\bPG_(?:MAJOR|VERSION)\s*[:=]\s*[\"']?(?:16|17)(?:\.[0-9]+)?\b", re.IGNORECASE),
    re.compile(r"/usr/lib/postgresql/(?:16|17)\b", re.IGNORECASE),
    re.compile(
        r"(?<![A-Za-z0-9])(?:[A-Za-z0-9._-]+(?::[0-9]+)?/)*"
        r"(?:postgres|postgresql|postgresql-server):(?:16|17)"
        r"(?:[.-][A-Za-z0-9._-]+)?\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"docker-library/postgres[^\r\n]{0,160}(?:[:/])(?:16|17)(?:/|\b)",
        re.IGNORECASE,
    ),
)
POSTGRES_IMAGE_PATTERN = re.compile(
    r"docker\.io/library/postgres@sha256:[0-9a-f]{64}"
)
def load_renderer():
    path = SCRIPTS / "render-integration-quadlets.py"
    spec = importlib.util.spec_from_file_location("integration_renderer", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load integration renderer")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _contains_legacy_identity(value: str) -> bool:
    return any(pattern.search(value) for pattern in LEGACY_IDENTITY_PATTERNS)


def _module_authority_strings(content: str, path: Path) -> list[tuple[int, str]]:
    tree = ast.parse(content, filename=os.fspath(path))
    strings = []
    for statement in tree.body:
        if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
            continue
        value = statement.value
        if value is None:
            continue
        strings.extend(
            (node.lineno, node.value)
            for node in ast.walk(value)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        )
    return strings


def _regular_files_beneath(directory: Path) -> list[Path]:
    """Discover regular files without following or skipping symlink entries."""
    try:
        mode = directory.lstat().st_mode
    except OSError as error:
        raise AssertionError(
            f"unable to inspect current PostgreSQL authority root: {directory}"
        ) from error
    if stat.S_ISLNK(mode):
        raise AssertionError(f"current PostgreSQL authority is a symlink: {directory}")
    if not stat.S_ISDIR(mode):
        raise AssertionError(
            f"current PostgreSQL authority root is not a directory: {directory}"
        )

    files = []
    try:
        with os.scandir(directory) as scanned:
            entries = sorted(scanned, key=lambda entry: entry.name)
    except OSError as error:
        raise AssertionError(
            f"unable to scan current PostgreSQL authority root: {directory}"
        ) from error
    for entry in entries:
        path = Path(entry.path)
        if entry.is_symlink():
            raise AssertionError(f"current PostgreSQL authority is a symlink: {path}")
        if entry.is_dir(follow_symlinks=False):
            if entry.name != "__pycache__":
                files.extend(_regular_files_beneath(path))
        elif entry.is_file(follow_symlinks=False):
            files.append(path)
        else:
            raise AssertionError(
                f"unsupported current PostgreSQL authority entry: {path}"
            )
    return files


def _is_regular_current_file(path: Path) -> bool:
    """Classify an explicitly named current authority without following links."""
    if not (path.exists() or path.is_symlink()):
        return False
    try:
        mode = path.lstat().st_mode
    except OSError as error:
        raise AssertionError(
            f"unable to inspect current PostgreSQL authority: {path}"
        ) from error
    if stat.S_ISLNK(mode):
        raise AssertionError(f"current PostgreSQL authority is a symlink: {path}")
    if not stat.S_ISREG(mode):
        raise AssertionError(f"current PostgreSQL authority is not a regular file: {path}")
    return True


def _current_authority_values(root: Path) -> list[tuple[Path, int, str]]:
    """Discover bounded current source and module-scope test authority values."""
    candidates: set[tuple[Path, bool]] = set()
    for relative_root in CURRENT_SOURCE_ROOTS:
        source_root = root / relative_root
        if source_root.exists() or source_root.is_symlink():
            candidates.update(
                (path, False)
                for path in _regular_files_beneath(source_root)
            )
    candidates.update(
        (root / relative, False)
        for relative in CURRENT_FIXTURE_DOCUMENTS
        if _is_regular_current_file(root / relative)
    )
    test_root = root / "tests"
    if test_root.exists() or test_root.is_symlink():
        candidates.update(
            (path, True)
            for path in _regular_files_beneath(test_root)
            if path.name != "postgres-fixture-contract.py" and path.suffix == ".py"
        )

    if len(candidates) > MAX_CURRENT_FILES:
        raise AssertionError("current PostgreSQL authority discovery exceeded its file bound")

    values = []
    total_bytes = 0
    for path, module_authority_only in sorted(candidates, key=lambda item: os.fspath(item[0])):
        size = path.stat().st_size
        if size > MAX_CURRENT_FILE_BYTES:
            raise AssertionError(f"current PostgreSQL authority exceeded its file bound: {path}")
        total_bytes += size
        if total_bytes > MAX_CURRENT_TOTAL_BYTES:
            raise AssertionError("current PostgreSQL authority discovery exceeded its byte bound")
        content = path.read_text(encoding="utf-8")
        current_values = (
            _module_authority_strings(content, path)
            if module_authority_only
            else list(enumerate(content.splitlines(), start=1))
        )
        values.extend((path, line, value) for line, value in current_values)
    return values


def find_current_legacy_identities(root: Path) -> list[str]:
    """Report explicit PG16/17 identities in discovered current authorities."""
    return [
        f"{path.relative_to(root).as_posix()}:{line}"
        for path, line, value in _current_authority_values(root)
        if _contains_legacy_identity(value)
    ]


def load_integration():
    path = SCRIPTS / "quadlet-integration.py"
    spec = importlib.util.spec_from_file_location("quadlet_integration", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load integration runner")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class PostgreSQLFixtureContractTests(unittest.TestCase):
    def test_canonical_fixture_is_immutable_postgresql_18(self) -> None:
        fixture = runtime_contract.POSTGRES_FIXTURE

        self.assertEqual(fixture.major, 18)
        self.assertRegex(fixture.version, r"^18\.[1-9][0-9]*$")
        self.assertRegex(
            fixture.image,
            r"^docker\.io/library/postgres@sha256:[0-9a-f]{64}$",
        )
        self.assertRegex(fixture.source, r":18/bookworm$")
        self.assertEqual(fixture.data_directory, "/var/lib/postgresql/18/docker")
        self.assertEqual(fixture.volume_target, "/var/lib/postgresql")

    def test_current_surfaces_share_the_canonical_immutable_image(self) -> None:
        fixture = runtime_contract.POSTGRES_FIXTURE
        references: set[str] = set()

        for _, _, value in _current_authority_values(ROOT):
            references.update(POSTGRES_IMAGE_PATTERN.findall(value))

        self.assertEqual(references, {fixture.image})

    def test_discovered_current_surfaces_have_no_pre_18_identity(self) -> None:
        self.assertEqual(find_current_legacy_identities(ROOT), [])

    def test_current_surfaces_reject_ordinary_pre_18_identity_forms(self) -> None:
        cases = {
            "pg16": ("scripts/quadlet-integration.py", "DATABASE_BASELINE=PG16\n"),
            "pg17": ("scripts/render-integration-quadlets.py", "database: PG17\n"),
            "client-package": (
                "scripts/ci-cloud/collect-workload-evidence.py",
                "DATABASE_CLIENT=postgresql-client-16\n",
            ),
            "tagged-image-outside-old-tuple": (
                "config/quadlet/current-postgres.container",
                "[Container]\nImage=postgres:16\n",
            ),
            "alternate-registry": (
                ".github/workflows/current-database.yml",
                "image: registry.example/secpal/postgresql-server:17\n",
            ),
            "active-file-outside-old-tuple": (
                "scripts/current-database-baseline.sh",
                "DATABASE_BASELINE=PG17\n",
            ),
        }
        for name, (relative, content) in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
                self.assertTrue(find_current_legacy_identities(root), relative)

    def test_current_source_discovery_rejects_all_symlink_classes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            regular_target = root / "regular-target"
            regular_target.write_text("DATABASE_BASELINE=PG17\n", encoding="utf-8")
            broken_target = root / "missing-target"
            directory_target = root / "directory-target"
            directory_target.mkdir()
            (directory_target / "current-database.conf").write_text(
                "DATABASE_BASELINE=PG17\n", encoding="utf-8"
            )

            cases = {
                "regular-symlink": regular_target,
                "broken-symlink": broken_target,
                "directory-symlink": directory_target,
            }
            for name, target in cases.items():
                with self.subTest(name=name):
                    link = root / "scripts" / name
                    link.parent.mkdir(parents=True, exist_ok=True)
                    link.symlink_to(
                        target, target_is_directory=name == "directory-symlink"
                    )
                    with self.assertRaises(AssertionError):
                        find_current_legacy_identities(root)
                    link.unlink()

    def test_guard_preserves_nonlegacy_and_noncurrent_material(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            controls = {
                "scripts/current-database.sh": (
                    "DATABASE=postgresql\nDATABASE_MAJOR=18\n"
                    "DATABASE_PACKAGE=postgresql-client-18\nPORT=1617\n"
                ),
                "config/quadlet/current-postgres.container": (
                    "[Container]\nImage=postgres:18\nEnvironment=DB_HOST=postgres\n"
                ),
                "docs/quadlet-integration.md": (
                    "PostgreSQL 18.6 uses /var/lib/postgresql/18/docker.\n"
                ),
                "tests/current-database-authority.py": (
                    'CURRENT_PACKAGE = "postgresql-client-18"\n'
                    "def test_rejects_legacy_data():\n"
                    '    rejected = ("PG16", "PG17", "postgres:16")\n'
                ),
                "tests/fixtures/immutable-history/postgres-16.txt": (
                    "immutable historical PostgreSQL 16 evidence\n"
                ),
                "docs/architecture/historical-postgres.md": (
                    "immutable historical PostgreSQL 17 evidence\n"
                ),
            }
            for relative, content in controls.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")

            self.assertEqual(find_current_legacy_identities(root), [])
        retirement = ROOT / "tests/production-postgres-retirement.py"
        self.assertIn("postgres:16", retirement.read_text(encoding="utf-8"))

    def test_renderer_consumes_the_canonical_pg18_layout(self) -> None:
        fixture = runtime_contract.POSTGRES_FIXTURE
        renderer = load_renderer()
        with tempfile.TemporaryDirectory() as directory:
            units = renderer.build_units(
                "contract01", 18443, Path(directory)
            )

        initializer = units["secpal-int-contract01-secrets-init.container"]
        postgres = units["secpal-int-contract01-postgres.container"]
        self.assertIn(
            f"Environment=SECPAL_POSTGRES_DATA_DIR={fixture.data_directory}",
            initializer,
        )
        self.assertIn(
            f"Volume=secpal-int-contract01-postgres.volume:{fixture.volume_target}",
            initializer,
        )
        self.assertIn(f"Image={fixture.image}", postgres)
        self.assertIn(
            f"Volume=secpal-int-contract01-postgres.volume:{fixture.volume_target}",
            postgres,
        )

    def test_cloud_observation_boundary_agrees_with_fixture_layout(self) -> None:
        fixture = runtime_contract.POSTGRES_FIXTURE
        collector = runpy.run_path(
            os.fspath(SCRIPTS / "ci-cloud" / "collect-workload-evidence.py")
        )
        contracts = collector["ROLE_CONTRACTS"]

        self.assertIn(
            ("postgres", fixture.volume_target, True),
            contracts["secrets-init"].volumes,
        )
        self.assertIn(
            ("postgres", fixture.volume_target, True),
            contracts["postgres"].volumes,
        )

    def test_runtime_mount_admission_agrees_with_fixture_layout(self) -> None:
        fixture = runtime_contract.POSTGRES_FIXTURE
        integration = load_integration()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lifecycle = integration.IntegrationLifecycle(
                root=ROOT,
                instance="contract01",
                port=18443,
                fixture_root=root / "fixture",
                output=root / "output.json",
            )

        for role in ("secrets-init", "postgres"):
            with self.subTest(role=role):
                self.assertIn(
                    fixture.volume_target,
                    lifecycle._expected_mounts(role),
                )

    def test_executable_version_admission_rejects_pre_18(self) -> None:
        integration = load_integration()
        integration.validate_postgres_version_line(
            "postgres (PostgreSQL) 18.6 (Debian 18.6-1.pgdg12+2)"
        )
        for major in (16, 17, 19):
            with self.subTest(major=major), self.assertRaises(
                integration.IntegrationError
            ):
                integration.validate_postgres_version_line(
                    f"postgres (PostgreSQL) {major}.9"
                )


if __name__ == "__main__":
    unittest.main()
