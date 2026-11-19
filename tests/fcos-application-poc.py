#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT
"""Exercise the two disposable FCOS application bundle profiles."""

import json
from pathlib import Path
import runpy
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
renderer = runpy.run_path(str(ROOT / "scripts/render-fcos-application-poc.py"))
build = renderer["build"]
INSTANCE = "testpoc01"
PREFIX = f"secpal-int-{INSTANCE}"


class ApplicationPoC(unittest.TestCase):
    def test_database_diagnostic_contract_fails_closed(self):
        helper = (ROOT / "scripts/fcos-poc-db-roles.sh").read_text()
        declaration = json.loads(
            (ROOT / ".secpal/evidence-architecture.json").read_text()
        )
        validate = renderer["validate_database_diagnostics"]
        validate(helper, declaration)
        declaration["external_operations"] = [
            entry
            for entry in declaration["external_operations"]
            if entry["id"] != "fcos-db-roles.start-migration"
        ]
        with self.assertRaisesRegex(ValueError, "diagnostic coverage"):
            validate(helper, declaration)
        with self.assertRaisesRegex(
            ValueError, "maintained evidence architecture validator"
        ):
            renderer["admit_database_dispatch"](None)

    def test_failed_operation_reveals_only_its_stage(self):
        script = ROOT / "scripts/fcos-poc-db-roles.sh"
        result = subprocess.run(
            [
                "bash",
                "-c",
                'podman() { printf "%s\\n" diagnostic-redaction-witness >&2; return 23; }; '
                'export -f podman; bash "$1" prepare fixture01',
                "bash",
                str(script),
            ],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "fcos-db-roles.rootless-runtime: failed\n")

    def test_separate_database_mounts_and_explicit_owner_migration(self):
        units, _ = build(
            INSTANCE, "lab.example.invalid", "10.0.0.28", least_privilege=True
        )
        for role in ("php-fpm", "worker-general", "worker-hash-chain", "scheduler"):
            unit = units[f"{PREFIX}-{role}.container"]
            self.assertIn("subpath=runtime-database", unit)
            self.assertIn("subpath=api", unit)
            self.assertNotIn("migration-database", unit)
            self.assertNotIn(f"{PREFIX}-migrate.service", unit)
            self.assertNotIn(f"{PREFIX}-secrets.volume:/run/secpal/secrets", unit)
        postgres = units[f"{PREFIX}-postgres.container"]
        self.assertIn("POSTGRES_USER=secpal_fixture_admin", postgres)
        self.assertIn("subpath=postgresql", postgres)
        self.assertNotIn("subpath=migration-database", postgres)
        migrate = units[f"{PREFIX}-migrate.container"]
        self.assertIn("subpath=migration-database", migrate)
        self.assertNotIn("subpath=runtime-database", migrate)
        self.assertIn("Exec=/run/secpal/production-migrate.php", migrate)
        self.assertNotIn("[Install]", migrate)

    def test_stack_preserves_roles_state_and_explicit_oneshots(self):
        units, caddy = build(INSTANCE, "lab.example.invalid", "10.0.0.28", 18443)
        for role in (
            "postgres",
            "api",
            "php-fpm",
            "frontend",
            "scheduler",
            "worker-general",
            "worker-hash-chain",
            "gateway",
        ):
            self.assertIn("ReadOnly=true", units[f"{PREFIX}-{role}.container"])
        publications = [
            line
            for content in units.values()
            for line in content.splitlines()
            if line.startswith("PublishPort=")
        ]
        self.assertEqual(publications, ["PublishPort=10.0.0.28:18443:8443"])
        self.assertIn("https://app.lab.example.invalid:8443", caddy)
        self.assertIn("https://api.lab.example.invalid:8443", caddy)
        self.assertIn(
            "SESSION_DOMAIN=.lab.example.invalid", units[f"{PREFIX}-php-fpm.container"]
        )
        self.assertNotIn(
            f"{PREFIX}-migrate.service", units[f"{PREFIX}-php-fpm.container"]
        )
        self.assertNotIn("[Install]", units[f"{PREFIX}-migrate.container"])
        self.assertNotIn("[Install]", units[f"{PREFIX}-secrets-init.container"])
        self.assertIn("[Install]", units[f"{PREFIX}-gateway.container"])
        self.assertIn(
            f"{PREFIX}-postgres.volume", units[f"{PREFIX}-postgres.container"]
        )

    def test_restore_has_no_external_ingress_or_boot_activation(self):
        units, caddy = build(INSTANCE)
        self.assertIsNone(caddy)
        roles = {name.removeprefix(f"{PREFIX}-") for name in units}
        self.assertEqual(
            roles,
            {
                "api.container",
                "php-fpm.container",
                "postgres.container",
                "secrets-init.container",
                "application.network",
                "postgres.volume",
                "secrets.volume",
                "fpm-socket.volume",
                "private-storage.volume",
            },
        )
        self.assertIn("Internal=true", units[f"{PREFIX}-application.network"])
        self.assertIn(
            f"Network={PREFIX}-application.network", units[f"{PREFIX}-api.container"]
        )
        for content in units.values():
            self.assertNotIn("PublishPort=", content)
            self.assertNotIn("[Install]", content)

    def test_invalid_input_never_enters_unit_files(self):
        for host, address, port in (
            ("host\nExec=sh", "10.0.0.28", 18443),
            ("lab.example.invalid", "8.8.8.8", 18443),
            ("lab.example.invalid", "10.0.0.28", 443),
        ):
            with self.subTest(host=host, address=address, port=port), self.assertRaises(
                ValueError
            ):
                build(INSTANCE, host, address, port)

    def test_direct_oneshots_have_no_ci_wrapper_mount(self):
        for options in ((), ("lab.example.invalid", "10.0.0.28", 18443)):
            units, _ = build(INSTANCE, *options)
            for unit in units.values():
                self.assertNotIn("/run/secpal/quadlet-oneshot-entrypoint.sh", unit)
        units, _ = build(INSTANCE, "lab.example.invalid", "10.0.0.28", 18443)
        self.assertIn('Entrypoint=["php"]', units[f"{PREFIX}-migrate.container"])
        self.assertNotIn("--no-check-certificate", units[f"{PREFIX}-gateway.container"])


if __name__ == "__main__":
    unittest.main()
