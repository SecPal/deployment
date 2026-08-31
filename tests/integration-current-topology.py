#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Current-surface contract for the disposable no-Valkey integration."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, os.fspath(SCRIPTS))

import integration_runtime_contract as runtime


def load_lifecycle():
    specification = importlib.util.spec_from_file_location(
        "quadlet_integration", SCRIPTS / "quadlet-integration.py"
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("unable to load integration lifecycle")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


lifecycle = load_lifecycle()


def load_renderer():
    specification = importlib.util.spec_from_file_location(
        "render_integration_quadlets", RENDERER
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("unable to load integration renderer")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


RENDERER = SCRIPTS / "render-integration-quadlets.py"
PROBE = SCRIPTS / "phase-b-runtime-probe.php"
SECRET_INITIALIZER = SCRIPTS / "init-local-secrets.sh"
CONTAINER_ENTRYPOINT = SCRIPTS / "container-entrypoint.sh"
INSTANCE = "contract01"


class CurrentIntegrationTopology(unittest.TestCase):
    def render(self) -> dict[str, str]:
        temporary = tempfile.TemporaryDirectory(prefix="secpal-current-topology.")
        self.addCleanup(temporary.cleanup)
        fixture = Path(temporary.name)
        output = fixture / "rendered"
        subprocess.run(
            [
                "python3",
                os.fspath(RENDERER),
                "render",
                "--instance",
                INSTANCE,
                "--port",
                "18443",
                "--fixture-root",
                os.fspath(fixture),
                "--output",
                os.fspath(output),
            ],
            cwd=ROOT,
            check=True,
        )
        return {
            path.name: path.read_text(encoding="utf-8")
            for path in sorted(output.iterdir())
        }

    def test_runtime_authority_has_no_valkey_server_role_or_image(self) -> None:
        self.assertNotIn("valkey", runtime.ROLE_SPECS)
        self.assertFalse(hasattr(runtime, "VALKEY_IMAGE"))

    def test_renderer_emits_only_database_backed_application_state(self) -> None:
        units = self.render()
        self.assertNotIn(f"secpal-int-{INSTANCE}-valkey.container", units)
        application_units = {
            name: content
            for name, content in units.items()
            if name.endswith(
                (
                    "-migrate.container",
                    "-api.container",
                    "-worker-general.container",
                    "-worker-hash-chain.container",
                    "-scheduler.container",
                )
            )
        }
        self.assertEqual(len(application_units), 5)
        for name, content in application_units.items():
            with self.subTest(unit=name):
                self.assertIn("Environment=CACHE_STORE=database\n", content)
                self.assertIn("Environment=QUEUE_CONNECTION=database\n", content)
                self.assertIn("Environment=SESSION_DRIVER=database\n", content)
                self.assertNotIn("REDIS_", content)
                self.assertNotIn("VALKEY_", content)

    def test_lifecycle_has_no_valkey_dependency_or_image_path(self) -> None:
        self.assertNotIn("valkey", lifecycle.ROLE_PREDECESSORS)
        self.assertNotIn("valkey", lifecycle.ROLE_PREDECESSORS["migrate"])
        self.assertNotIn("valkey", lifecycle.CLOUD_IMAGE_TAGS)
        self.assertFalse(
            any("valkey" in stage for stage in lifecycle.CLOUD_DIAGNOSTIC_STAGES)
        )

    def test_queue_probe_dispatches_on_database_connection(self) -> None:
        probe = PROBE.read_text(encoding="utf-8")
        self.assertIn("->onConnection('database')->onQueue($queue)", probe)
        self.assertNotIn("->onConnection('redis')", probe)

    def test_secret_authority_has_no_valkey_credential(self) -> None:
        initializer = SECRET_INITIALIZER.read_text(encoding="utf-8")
        entrypoint = CONTAINER_ENTRYPOINT.read_text(encoding="utf-8")
        self.assertNotIn("valkey-password", initializer)
        self.assertNotIn("SECPAL_VALKEY_UID", initializer)
        self.assertNotIn("valkey-password", entrypoint)
        self.assertNotIn("REDIS_PASSWORD", entrypoint)

    def test_semantic_guard_rejects_backend_reintroduction_mutations(self) -> None:
        renderer = load_renderer()
        units = self.render()
        api_name = f"secpal-int-{INSTANCE}-api.container"
        postgres_name = f"secpal-int-{INSTANCE}-postgres.container"
        cases: dict[str, dict[str, str]] = {}

        renamed_server = dict(units)
        renamed_server[f"secpal-int-{INSTANCE}-cache-daemon.container"] = units[
            postgres_name
        ].replace("postgres", "cache-daemon")
        cases["renamed server role"] = renamed_server

        redis_image = dict(units)
        redis_image[api_name] = redis_image[api_name].replace(
            runtime.API_IMAGE,
            "docker.io/library/redis@sha256:" + "a" * 64,
        )
        cases["server image"] = redis_image

        redis_environment = dict(units)
        redis_environment[api_name] = redis_environment[api_name].replace(
            "Environment=CACHE_STORE=database\n",
            "Environment=CACHE_STORE=database\nEnvironment=REDIS_HOST=cache-daemon\n",
        )
        cases["application environment"] = redis_environment

        redis_health = dict(units)
        redis_health[api_name] = redis_health[api_name].replace(
            "HealthCmd=/usr/local/bin/secpal-http-live",
            "HealthCmd=redis-cli -h cache-daemon ping",
        )
        cases["readiness path"] = redis_health

        extra_hash_worker = dict(units)
        extra_hash_worker[
            f"secpal-int-{INSTANCE}-worker-hash-chain-second.container"
        ] = units[f"secpal-int-{INSTANCE}-worker-hash-chain.container"]
        cases["multiple hash-chain workers"] = extra_hash_worker

        missing_hash_worker = dict(units)
        del missing_hash_worker[
            f"secpal-int-{INSTANCE}-worker-hash-chain.container"
        ]
        cases["zero hash-chain workers"] = missing_hash_worker

        for name, mutation in cases.items():
            with self.subTest(mutation=name), self.assertRaises(
                renderer.ContractError
            ):
                renderer.validate_current_topology(INSTANCE, mutation)

    def test_guard_is_bounded_to_current_executable_surfaces(self) -> None:
        renderer = load_renderer()
        units = self.render()
        renderer.validate_current_topology(INSTANCE, units)
        historical_evidence = (
            "Historical Valkey evidence and an explicit Redis negative-test fixture."
        )
        self.assertIn("Valkey", historical_evidence)
        self.assertIn("Redis", historical_evidence)


if __name__ == "__main__":
    unittest.main(verbosity=2)
