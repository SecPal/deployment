#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Contract tests for the one active disposable PostgreSQL fixture."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if os.fspath(SCRIPTS) not in sys.path:
    sys.path.insert(0, os.fspath(SCRIPTS))

import integration_runtime_contract as runtime_contract  # noqa: E402


ACTIVE_FIXTURE_PATHS = (
    ROOT / ".github" / "workflows" / "local-integration.yml",
    ROOT / "docs" / "quadlet-integration.md",
    ROOT / "scripts" / "ci-cloud" / "collect-workload-evidence.py",
    ROOT / "scripts" / "integration_runtime_contract.py",
    ROOT / "scripts" / "quadlet-integration.py",
    ROOT / "scripts" / "render-integration-quadlets.py",
    ROOT / "tests" / "ci-cloud-workload-evidence.py",
    ROOT / "tests" / "quadlet-integration-contract.py",
    ROOT / "tests" / "quadlet-integration-lifecycle.py",
)
PRE_18_PATTERN = re.compile(
    r"(?:postgres(?:ql)?(?:[_ ./@:-]*(?:major|version|image))?[_ ./@:=\"'-]*"
    r"|PG_(?:MAJOR|VERSION)[=: ]+|/usr/lib/postgresql/)(?:16|17)(?:\D|$)",
    re.IGNORECASE,
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


def find_current_legacy_identities(root: Path) -> list[Path]:
    """Model the current path-tuple guard against an isolated repository tree."""
    findings = []
    for canonical in ACTIVE_FIXTURE_PATHS:
        path = root / canonical.relative_to(ROOT)
        if path.is_file() and PRE_18_PATTERN.search(path.read_text(encoding="utf-8")):
            findings.append(path.relative_to(root))
    return findings


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

    def test_active_fixture_paths_have_no_independent_or_pre_18_identity(self) -> None:
        fixture = runtime_contract.POSTGRES_FIXTURE
        references: set[str] = set()

        for path in ACTIVE_FIXTURE_PATHS:
            content = path.read_text(encoding="utf-8")
            self.assertIsNone(PRE_18_PATTERN.search(content), path)
            references.update(POSTGRES_IMAGE_PATTERN.findall(content))

        self.assertEqual(references, {fixture.image})

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
