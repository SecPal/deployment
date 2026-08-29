#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Contract tests for retirement of the D.2 PostgreSQL product container."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
RENDERER_PATH = ROOT / "scripts" / "render-production-quadlets.py"
CONTRACT_PATH = ROOT / "config" / "production" / "state-contract.json"
QUADLET_ROOT = ROOT / "config" / "production" / "quadlet"
CURRENT_ACCEPTANCE_PATHS = (
    ROOT / ".github" / "workflows" / "local-integration.yml",
    ROOT / "scripts" / "preflight.sh",
    ROOT / "tests" / "production-state-contract.py",
    ROOT / "tests" / "production-state-native-lifecycle.sh",
    ROOT / "tests" / "repository-contract.sh",
)
RETIRED_IDENTITIES = (
    "secpal-postgres-init.container",
    "secpal-postgres.container",
    "secpal-postgres-init.service",
    "secpal-postgres.service",
    "ContainerName=secpal-postgres-init",
    "ContainerName=secpal-postgres",
    "production-postgres-entrypoint.sh",
)


def load_renderer():
    spec = importlib.util.spec_from_file_location("production_renderer", RENDERER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load production Quadlet renderer")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ProductionPostgresRetirementTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.renderer = load_renderer()
        cls.contract = cls.renderer.load_contract(CONTRACT_PATH)

    def test_renderer_cannot_emit_a_postgres_product_container(self) -> None:
        rendered = self.renderer.build_units(self.contract)
        combined = "\n".join(rendered.values())

        for identity in RETIRED_IDENTITIES:
            with self.subTest(identity=identity):
                self.assertNotIn(identity, rendered)
                self.assertNotIn(identity, combined)
        self.assertNotIn("Image=docker.io/library/postgres@", combined)
        self.assertNotIn("Label=org.secpal.role=postgres", combined)

    def test_checked_production_quadlets_have_no_postgres_units(self) -> None:
        checked = {
            path.name: path.read_text(encoding="utf-8")
            for path in QUADLET_ROOT.iterdir()
            if path.is_file()
        }
        combined = "\n".join(checked.values())

        for identity in RETIRED_IDENTITIES:
            with self.subTest(identity=identity):
                self.assertNotIn(identity, checked)
                self.assertNotIn(identity, combined)
        self.assertNotIn("Image=docker.io/library/postgres@", combined)
        self.assertNotIn("Label=org.secpal.role=postgres", combined)

    def test_current_acceptance_cannot_reactivate_the_retired_path(self) -> None:
        for path in CURRENT_ACCEPTANCE_PATHS:
            content = path.read_text(encoding="utf-8")
            for identity in RETIRED_IDENTITIES:
                with self.subTest(path=path.relative_to(ROOT), identity=identity):
                    self.assertNotIn(identity, content)
            with self.subTest(path=path.relative_to(ROOT), requirement="PG16"):
                self.assertNotRegex(content, r"PG_VERSION.{0,32}(?:=|==|\] = )['\" ]*16\b")

    def test_no_legacy_launcher_or_reactivation_switch_exists(self) -> None:
        self.assertFalse((ROOT / "scripts" / "production-postgres-entrypoint.sh").exists())
        renderer_source = RENDERER_PATH.read_text(encoding="utf-8")
        self.assertNotIn("POSTGRES_IMAGE", renderer_source)
        self.assertNotIn("docker.io/library/postgres", renderer_source)
        self.assertNotIn('role_spec("postgres")', renderer_source)
        self.assertNotIn('tmpfs_mounts("postgres")', renderer_source)
        for identity in RETIRED_IDENTITIES:
            with self.subTest(identity=identity):
                self.assertNotIn(identity, renderer_source)
        self.assertNotRegex(renderer_source, r"(?i)(legacy|compat|fallback).{0,80}postgres")


if __name__ == "__main__":
    unittest.main()
