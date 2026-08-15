#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Static contract for the active rootless Podman/Quadlet integration."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, os.fspath(ROOT / "scripts"))

from integration_runtime_contract import (
    API_DIGEST,
    API_IMAGE,
    FRONTEND_DIGEST,
    POSTGRES_IMAGE,
    VALKEY_IMAGE,
    podman_version_supported as quadlet_generator_version_supported,
)


RENDERER = ROOT / "scripts" / "render-integration-quadlets.py"
GATEWAY_CONFIG = ROOT / "config" / "quadlet" / "Caddyfile"
ONESHOT_WRAPPER = ROOT / "scripts" / "quadlet-oneshot-entrypoint.sh"
HARNESS = ROOT / "scripts" / "quadlet-integration.py"
WORKFLOW = ROOT / ".github" / "workflows" / "local-integration.yml"
TARGET_CONFORMANCE = ROOT / "scripts" / "ci-cloud" / "target-conformance.sh"
INSTANCE = "contract01"
PORT = "18443"
GATEWAY_DIGEST = "sha256:" + "a" * 64
EXPECTED_FILES = {
    f"secpal-int-{INSTANCE}-api.container",
    f"secpal-int-{INSTANCE}-application.network",
    f"secpal-int-{INSTANCE}-edge.network",
    f"secpal-int-{INSTANCE}-frontend.container",
    f"secpal-int-{INSTANCE}-gateway.container",
    f"secpal-int-{INSTANCE}-migrate.container",
    f"secpal-int-{INSTANCE}-postgres.container",
    f"secpal-int-{INSTANCE}-postgres.volume",
    f"secpal-int-{INSTANCE}-private-storage.volume",
    f"secpal-int-{INSTANCE}-scheduler.container",
    f"secpal-int-{INSTANCE}-secrets-init.container",
    f"secpal-int-{INSTANCE}-secrets.volume",
    f"secpal-int-{INSTANCE}-worker-general.container",
    f"secpal-int-{INSTANCE}-worker-hash-chain.container",
    f"secpal-int-{INSTANCE}-valkey.container",
    f"secpal-int-{INSTANCE}.target",
}

PRODUCT_ROLES = {
    "api",
    "frontend",
    "migrate",
    "scheduler",
    "secrets-init",
    "worker-general",
    "worker-hash-chain",
}


class QuadletContract(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="secpal-quadlet-test.")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fixture_root = self.root / "fixture"
        self.fixture_root.mkdir(mode=0o700)
        self.output = self.fixture_root / "rendered"

    def run_renderer(self, *extra: str, check: bool = False) -> subprocess.CompletedProcess[str]:
        command = [
            "python3",
            os.fspath(RENDERER),
            "render",
            "--instance",
            INSTANCE,
            "--port",
            PORT,
            "--fixture-root",
            os.fspath(self.fixture_root),
            "--output",
            os.fspath(self.output),
            *extra,
        ]
        return subprocess.run(command, cwd=ROOT, check=check, text=True, capture_output=True)

    def render(self) -> dict[str, str]:
        result = self.run_renderer(check=True)
        self.assertEqual(result.stdout, "")
        return {
            path.name: path.read_text(encoding="utf-8")
            for path in sorted(self.output.iterdir())
        }

    def validate(self, directory: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "python3",
                os.fspath(RENDERER),
                "validate",
                "--instance",
                INSTANCE,
                "--port",
                PORT,
                "--fixture-root",
                os.fspath(self.fixture_root),
                "--input",
                os.fspath(directory),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )

    def render_cloud(self) -> dict[str, str]:
        result = self.run_renderer(
            "--cloud-gateway-digest", GATEWAY_DIGEST, check=True
        )
        self.assertEqual(result.stdout, "")
        return {
            path.name: path.read_text(encoding="utf-8")
            for path in sorted(self.output.iterdir())
        }

    def test_cloud_renderer_uses_only_closed_local_digest_identities(self) -> None:
        units = self.render_cloud()
        api_reference = f"localhost/secpal-ci-api@{API_DIGEST}"
        frontend_reference = f"localhost/secpal-ci-frontend@{FRONTEND_DIGEST}"
        postgres_digest = POSTGRES_IMAGE.rsplit("@", 1)[1]
        valkey_digest = VALKEY_IMAGE.rsplit("@", 1)[1]
        expected = {
            "api": api_reference,
            "migrate": api_reference,
            "secrets-init": api_reference,
            "worker-general": api_reference,
            "worker-hash-chain": api_reference,
            "scheduler": api_reference,
            "frontend": frontend_reference,
            "postgres": f"localhost/secpal-ci-postgres@{postgres_digest}",
            "valkey": f"localhost/secpal-ci-valkey@{valkey_digest}",
            "gateway": (
                f"localhost/secpal-ci-gateway-{INSTANCE}@{GATEWAY_DIGEST}"
            ),
        }
        for role, image in expected.items():
            with self.subTest(role=role):
                unit = units[f"secpal-int-{INSTANCE}-{role}.container"]
                self.assertIn(f"Image={image}\n", unit)
                repository, separator, digest = image.partition("@")
                self.assertEqual(separator, "@")
                self.assertNotIn(":", repository)
                self.assertRegex(
                    repository, r"^localhost/secpal-ci-[a-z0-9-]+$"
                )
                self.assertRegex(digest, r"^sha256:[0-9a-f]{64}$")
        api = units[f"secpal-int-{INSTANCE}-api.container"]
        self.assertIn(
            "HealthCmd=CMD /usr/local/bin/secpal-http-live\n", api
        )
        secrets_init = units[f"secpal-int-{INSTANCE}-secrets-init.container"]
        self.assertIn(
            'Entrypoint=["/bin/bash","/run/secpal/init-local-secrets.sh"]\n',
            secrets_init,
        )
        self.assertNotIn("Exec=", secrets_init)
        migrate = units[f"secpal-int-{INSTANCE}-migrate.container"]
        self.assertIn(
            'Entrypoint=["/bin/bash","/run/secpal/container-entrypoint.sh"]\n',
            migrate,
        )
        self.assertIn("Exec=php artisan migrate --force\n", migrate)
        for role in ("secrets-init", "migrate"):
            with self.subTest(retained_oneshot=role):
                unit = units[f"secpal-int-{INSTANCE}-{role}.container"]
                self.assertIn("PodmanArgs=--rm=false\n", unit)
                self.assertIn("quadlet-oneshot-entrypoint.sh", unit)

    def test_cloud_renderer_rejects_non_digest_gateway_identity(self) -> None:
        for value in (
            "latest",
            "sha256:" + "a" * 63,
            "sha256:" + "A" * 64,
            "sha256:" + "a" * 64 + "\nPodmanArgs=--privileged",
        ):
            with self.subTest(value=value):
                result = self.run_renderer(
                    "--cloud-gateway-digest", value, check=False
                )
                self.assertNotEqual(result.returncode, 0)

    def test_cloud_target_phases_delegate_only_to_the_fixed_harness_modes(self) -> None:
        target = TARGET_CONFORMANCE.read_text(encoding="utf-8")
        self.assertIn(
            "python3 scripts/quadlet-integration.py --cloud-phase prepare",
            target,
        )
        self.assertIn(
            "python3 scripts/quadlet-integration.py --cloud-phase cleanup",
            target,
        )
        self.assertIn(
            "SECPAL_TARGET_DIAGNOSTIC_V1:host-contract",
            target,
        )
        self.assertIn(
            "SECPAL_TARGET_DIAGNOSTIC_V1:workload-target-entrypoint",
            target,
        )
        self.assertIn(
            "SECPAL_TARGET_DIAGNOSTIC_V1:workload-cleanup",
            target,
        )
        self.assertNotIn(
            "this target does not implement the fixed D.1a lifecycle phase",
            target,
        )

    def test_complete_native_unit_set_and_security_contract(self) -> None:
        self.assertIn('"catatonit",', HARNESS.read_text(encoding="utf-8"))
        self.assertIn('"du",', HARNESS.read_text(encoding="utf-8"))
        self.assertIn('"--force-rm=true",', HARNESS.read_text(encoding="utf-8"))
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("podman crun catatonit netavark", workflow)
        self.assertIn("command -v catatonit", workflow)
        self.assertIn("for failure_case in migration dependency health", workflow)
        self.assertIn("--instance parallel01", workflow)
        self.assertIn("--instance parallel02", workflow)
        self.assertIn("Prove handled SIGTERM cleanup", workflow)
        self.assertIn('test "$signal_status" -eq 143', workflow)
        self.assertIn("signal_deadline=$((SECONDS + 600))", workflow)
        self.assertNotIn("for _attempt in {1..600}", workflow)
        self.assertIn("runner: ubuntu-26.04", workflow)
        self.assertIn("runner: ubuntu-26.04-arm", workflow)
        self.assertIn("gh_arch: amd64", workflow)
        self.assertIn("gh_arch: arm64", workflow)
        self.assertIn("GH_LINUX_ARCH: ${{ matrix.gh_arch }}", workflow)
        self.assertIn(
            "sleep 1",
            ONESHOT_WRAPPER.read_text(encoding="utf-8"),
        )
        self.assertIn(
            "auto_https disable_redirects",
            GATEWAY_CONFIG.read_text(encoding="utf-8"),
        )
        units = self.render()
        self.assertEqual(set(units), EXPECTED_FILES)
        combined = "\n".join(units.values())

        self.assertNotIn("docker compose", combined.lower())
        self.assertNotIn("docker-compose", combined.lower())
        self.assertNotIn("podman compose", combined.lower())
        self.assertNotIn("podman-compose", combined.lower())
        self.assertNotIn("GlobalArgs=", combined)
        self.assertNotIn("AutoUpdate=", combined)
        self.assertNotIn("Network=host", combined)
        self.assertNotIn("SecurityLabelDisable=true", combined)
        self.assertNotIn("EnvironmentHost=true", combined)
        self.assertNotRegex(combined, r"(?i)(podman|docker)\.sock|tcp://")

        containers = {name: text for name, text in units.items() if name.endswith(".container")}
        for argument in (
            "--http-proxy=false",
            "--pid=private",
            "--ipc=private",
            "--uts=private",
        ):
            with self.subTest(podman_argument=argument):
                self.assertEqual(
                    combined.count(f"PodmanArgs={argument}"),
                    len(containers),
                )
        self.assertEqual(combined.count("PodmanArgs="), len(containers) * 4)
        for name, text in containers.items():
            with self.subTest(name=name):
                self.assertIn(f"PartOf=secpal-int-{INSTANCE}.target", text)
                self.assertIn("Label=org.secpal.integration.instance=contract01", text)
                self.assertIn("NoNewPrivileges=true", text)
                self.assertIn("DropCapability=all", text)
                self.assertIn("ReadOnly=true", text)
                self.assertIn("PidsLimit=512", text)
                self.assertNotIn("Privileged=true", text)
                self.assertIn("Pull=never", text)

        for name, text in units.items():
            if name.endswith((".network", ".volume")):
                with self.subTest(name=name):
                    self.assertIn(f"PartOf=secpal-int-{INSTANCE}.target", text)

        for role in PRODUCT_ROLES:
            text = units[f"secpal-int-{INSTANCE}-{role}.container"]
            self.assertIn("Pull=never", text)

        self.assertEqual(
            combined.count(
                "Image=ghcr.io/secpal/api@sha256:5a095b27105691139b161ac0578ceae86e68b6821afadf7cb455fb86c8009c0e"
            ),
            6,
        )
        self.assertEqual(
            combined.count(
                "Image=ghcr.io/secpal/frontend@sha256:cdccded2eade53d9300aafff3a2663a779d3d158cfa74f1e9c182e5786285077"
            ),
            1,
        )
        expected_users = {
            "api": "10001",
            "frontend": "101",
            "gateway": "10003",
            "migrate": "10001",
            "postgres": "999",
            "scheduler": "10001",
            "secrets-init": "0",
            "valkey": "10002",
            "worker-general": "10001",
            "worker-hash-chain": "10001",
        }
        for role, uid in expected_users.items():
            self.assertIn(f"User={uid}\n", units[f"secpal-int-{INSTANCE}-{role}.container"])

        gateway = units[f"secpal-int-{INSTANCE}-gateway.container"]
        self.assertEqual(gateway.count("PublishPort="), 1)
        self.assertIn(f"PublishPort=127.0.0.1:{PORT}:8443", gateway)
        self.assertIn("AddHost=app.secpal.example.invalid:127.0.0.1", gateway)
        for name, text in containers.items():
            if name != f"secpal-int-{INSTANCE}-gateway.container":
                self.assertNotIn("PublishPort=", text)

    def test_playwright_output_is_scoped_to_the_integration_instance(self) -> None:
        observed = []
        for instance in ("parallel01", "parallel02"):
            environment = dict(os.environ)
            environment.update(
                {
                    "APP_ORIGIN": "https://app.secpal.example.invalid:18443",
                    "API_ORIGIN": "https://api.secpal.example.invalid:18443",
                    "SECPAL_INTEGRATION_INSTANCE": instance,
                }
            )
            result = subprocess.run(
                [
                    "node",
                    "-e",
                    "const config=require('./playwright.integration.config.js');"
                    "process.stdout.write(JSON.stringify(config.outputDir));",
                ],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=True,
            )
            output = Path(json.loads(result.stdout))
            self.assertTrue(output.is_absolute())
            self.assertEqual(
                output,
                ROOT / "test-results" / f"secpal-int-{instance}",
            )
            observed.append(output)
        self.assertNotEqual(*observed)

        historical_environment = dict(os.environ)
        historical_environment.update(
            {
                "APP_ORIGIN": "https://app.secpal.example.invalid:18443",
                "API_ORIGIN": "https://api.secpal.example.invalid:18443",
            }
        )
        historical_environment.pop("SECPAL_INTEGRATION_INSTANCE", None)
        result = subprocess.run(
            [
                "node",
                "-e",
                "const config=require('./playwright.integration.config.js');"
                "process.stdout.write(JSON.stringify(config.outputDir));",
            ],
            cwd=ROOT,
            env=historical_environment,
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertEqual(
            Path(json.loads(result.stdout)),
            ROOT / "test-results" / "secpal-int-phasebcompose",
        )

    def test_roles_networks_dependencies_and_singletons_are_exact(self) -> None:
        units = self.render()
        combined = "\n".join(units.values())
        application = f"secpal-int-{INSTANCE}-application.network"
        edge = f"secpal-int-{INSTANCE}-edge.network"

        for network in (application, edge):
            self.assertIn("Internal=true", units[network])

        for role in ("postgres", "valkey", "migrate", "worker-general", "worker-hash-chain", "scheduler"):
            self.assertIn(f"Network={application}", units[f"secpal-int-{INSTANCE}-{role}.container"])
            self.assertNotIn(f"Network={edge}", units[f"secpal-int-{INSTANCE}-{role}.container"])
        self.assertIn(f"Network={application}", units[f"secpal-int-{INSTANCE}-api.container"])
        self.assertIn(f"Network={edge}", units[f"secpal-int-{INSTANCE}-api.container"])
        self.assertIn(f"Network={edge}", units[f"secpal-int-{INSTANCE}-frontend.container"])
        self.assertNotIn(f"Network={application}", units[f"secpal-int-{INSTANCE}-frontend.container"])

        self.assertEqual(
            sum("--queue=activity-hash-chain" in text for text in units.values()),
            1,
        )
        self.assertEqual(sum("schedule:work" in text for text in units.values()), 1)
        self.assertEqual(sum("artisan migrate --force" in text for text in units.values()), 1)
        expected_processes = {
            "api": "frankenphp run --config /etc/frankenphp/Caddyfile",
            "worker-general": (
                "php artisan queue:work --queue=merkle,opentimestamp,default "
                "--sleep=1 --tries=3 --timeout=90"
            ),
            "worker-hash-chain": (
                "php artisan queue:work --queue=activity-hash-chain "
                "--sleep=1 --tries=3 --timeout=90"
            ),
            "scheduler": "php artisan schedule:work",
        }
        for role, command in expected_processes.items():
            with self.subTest(execution_role=role):
                text = units[f"secpal-int-{INSTANCE}-{role}.container"]
                self.assertIn(
                    'Entrypoint=["/bin/bash","/run/secpal/container-entrypoint.sh"]',
                    text,
                )
                self.assertIn(f"Exec={command}", text)
        self.assertIn("Type=oneshot", units[f"secpal-int-{INSTANCE}-migrate.container"])
        self.assertIn("Notify=healthy", units[f"secpal-int-{INSTANCE}-postgres.container"])
        self.assertIn(
            "Mount=type=tmpfs,destination=/run/postgresql,",
            units[f"secpal-int-{INSTANCE}-postgres.container"],
        )
        self.assertNotIn(
            "destination=/var/run/postgresql,",
            units[f"secpal-int-{INSTANCE}-postgres.container"],
        )
        self.assertIn("Notify=healthy", units[f"secpal-int-{INSTANCE}-valkey.container"])
        self.assertIn(
            "HealthCmd=VALKEYCLI_AUTH=$(cat /run/secpal-secrets/valkey-password) valkey-cli ping | grep -qx PONG",
            units[f"secpal-int-{INSTANCE}-valkey.container"],
        )
        self.assertIn(
            "HealthCmd=curl --fail --silent --show-error --max-time 3 http://127.0.0.1:8080/health/live",
            units[f"secpal-int-{INSTANCE}-frontend.container"],
        )
        self.assertIn(
            "HealthCmd=wget --no-check-certificate -q -T 3 -O /dev/null https://app.secpal.example.invalid:8443/health/live",
            units[f"secpal-int-{INSTANCE}-gateway.container"],
        )
        for role in ("secrets-init", "migrate"):
            oneshot = units[f"secpal-int-{INSTANCE}-{role}.container"]
            self.assertIn("quadlet-oneshot-entrypoint.sh", oneshot)
            self.assertIn("Mount=type=tmpfs,destination=/tmp", oneshot)
        self.assertNotRegex(combined, r"(?:Tmpfs|type=tmpfs).*\b(?:uid|gid)=")
        for line in combined.splitlines():
            if line.startswith("Mount=type=tmpfs"):
                self.assertIn("U=true", line)
        for role in ("postgres", "valkey", "api", "frontend", "gateway"):
            text = units[f"secpal-int-{INSTANCE}-{role}.container"]
            self.assertIn(
                "HealthOnFailure=kill",
                text,
            )
            unit_section, service_section = text.split("[Container]", 1)
            self.assertIn("StartLimitIntervalSec=60", unit_section)
            self.assertIn("StartLimitBurst=3", unit_section)
            self.assertNotIn("StartLimitIntervalSec=", service_section)
            self.assertNotIn("StartLimitBurst=", service_section)

        migrate = units[f"secpal-int-{INSTANCE}-migrate.container"]
        self.assertIn(
            "Exec=/bin/bash /run/secpal/container-entrypoint.sh "
            "php artisan migrate --force",
            migrate,
        )
        self.assertIn(
            f"Requires=secpal-int-{INSTANCE}-postgres.service secpal-int-{INSTANCE}-valkey.service",
            migrate,
        )
        for role in ("api", "worker-general", "worker-hash-chain", "scheduler"):
            self.assertIn(
                f"Requires=secpal-int-{INSTANCE}-migrate.service",
                units[f"secpal-int-{INSTANCE}-{role}.container"],
            )
        gateway = units[f"secpal-int-{INSTANCE}-gateway.container"]
        self.assertIn(
            f"Requires=secpal-int-{INSTANCE}-api.service secpal-int-{INSTANCE}-frontend.service",
            gateway,
        )
        target = units[f"secpal-int-{INSTANCE}.target"]
        for role in ("gateway", "worker-general", "worker-hash-chain", "scheduler"):
            self.assertIn(f"secpal-int-{INSTANCE}-{role}.service", target)

    def test_renderer_accepts_only_bounded_runtime_values(self) -> None:
        for bad_instance in (
            "UPPER",
            "short",
            "../escape",
            "a" * 25,
            "socket.sock",
            "parallel-01",
        ):
            result = subprocess.run(
                [
                    "python3",
                    os.fspath(RENDERER),
                    "render",
                    "--instance",
                    bad_instance,
                    "--port",
                    PORT,
                    "--fixture-root",
                    os.fspath(self.fixture_root),
                    "--output",
                    os.fspath(self.output),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(result.returncode, 0, bad_instance)
        for bad_port in ("", "80", "65536", "8443\nPodmanArgs=--privileged"):
            result = subprocess.run(
                [
                    "python3",
                    os.fspath(RENDERER),
                    "render",
                    "--instance",
                    INSTANCE,
                    "--port",
                    bad_port,
                    "--fixture-root",
                    os.fspath(self.fixture_root),
                    "--output",
                    os.fspath(self.output),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(result.returncode, 0, repr(bad_port))

        result = self.run_renderer("--image", "example.invalid/image:latest")
        self.assertNotEqual(result.returncode, 0)
        result = self.run_renderer("--failure-case", "arbitrary")
        self.assertNotEqual(result.returncode, 0)

        unsafe_root = self.root / "fixture with spaces"
        unsafe_root.mkdir(mode=0o700)
        unsafe_output = unsafe_root / "rendered"
        result = subprocess.run(
            [
                "python3",
                os.fspath(RENDERER),
                "render",
                "--instance",
                INSTANCE,
                "--port",
                PORT,
                "--fixture-root",
                os.fspath(unsafe_root),
                "--output",
                os.fspath(unsafe_output),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("safe ASCII path", result.stderr)

        escaped = subprocess.run(
            [
                "python3",
                os.fspath(RENDERER),
                "render",
                "--instance",
                INSTANCE,
                "--port",
                PORT,
                "--fixture-root",
                os.fspath(self.fixture_root),
                "--output",
                os.fspath(self.fixture_root / ".." / "escaped"),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(escaped.returncode, 0)

    def test_failure_profiles_have_one_fixed_reviewed_delta_each(self) -> None:
        normal = self.render()
        expected = {
            "migration": (f"secpal-int-{INSTANCE}-migrate.container", "Exec=/bin/false"),
            "dependency": (f"secpal-int-{INSTANCE}-postgres.container", "Exec=/bin/false"),
            "health": (f"secpal-int-{INSTANCE}-gateway.container", "HealthCmd=/bin/false"),
        }
        for failure_case, (changed_name, marker) in expected.items():
            with self.subTest(failure_case=failure_case):
                output = self.fixture_root / f"rendered-{failure_case}"
                result = subprocess.run(
                    [
                        "python3",
                        os.fspath(RENDERER),
                        "render",
                        "--instance",
                        INSTANCE,
                        "--port",
                        PORT,
                        "--fixture-root",
                        os.fspath(self.fixture_root),
                        "--failure-case",
                        failure_case,
                        "--output",
                        os.fspath(output),
                    ],
                    cwd=ROOT,
                    text=True,
                    capture_output=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                fault = {
                    path.name: path.read_text(encoding="utf-8")
                    for path in sorted(output.iterdir())
                }
                self.assertEqual(
                    {name for name in normal if normal[name] != fault[name]},
                    {changed_name},
                )
                self.assertIn(marker, fault[changed_name])
                if failure_case == "health":
                    self.assertIn("HealthOnFailure=kill", fault[changed_name])
                    self.assertIn("HealthStartPeriod=5s", fault[changed_name])
                    self.assertIn("TimeoutStartSec=180", fault[changed_name])

    def test_validation_rejects_policy_mutations_and_incomplete_output(self) -> None:
        self.render()
        mutations = {
            "host-network": ("Network=host\n", f"secpal-int-{INSTANCE}-api.container"),
            "auto-update": ("AutoUpdate=registry\n", f"secpal-int-{INSTANCE}-api.container"),
            "mutable-image": ("Image=ghcr.io/secpal/api:main\n", f"secpal-int-{INSTANCE}-api.container"),
            "socket": ("Volume=/run/podman/podman.sock:/run/podman/podman.sock\n", f"secpal-int-{INSTANCE}-api.container"),
            "privilege": ("AddCapability=all\n", f"secpal-int-{INSTANCE}-api.container"),
            "unsafe-mount": ("Volume=/:/host\n", f"secpal-int-{INSTANCE}-api.container"),
            "duplicate-migration": ("Exec=php artisan migrate --force\n", f"secpal-int-{INSTANCE}-api.container"),
            "duplicate-singleton": ("Exec=php artisan schedule:work\n", f"secpal-int-{INSTANCE}-worker-general.container"),
        }
        for label, (injection, filename) in mutations.items():
            with self.subTest(label=label):
                candidate = self.root / label
                shutil.copytree(self.output, candidate)
                with (candidate / filename).open("a", encoding="utf-8") as stream:
                    stream.write(injection)
                self.assertNotEqual(self.validate(candidate).returncode, 0)

        incomplete = self.root / "incomplete"
        shutil.copytree(self.output, incomplete)
        (incomplete / f"secpal-int-{INSTANCE}-scheduler.container").unlink()
        self.assertNotEqual(self.validate(incomplete).returncode, 0)

        writable = self.root / "writable"
        shutil.copytree(self.output, writable)
        (writable / f"secpal-int-{INSTANCE}-api.container").chmod(0o664)
        self.assertNotEqual(self.validate(writable).returncode, 0)

        linked = self.root / "linked"
        shutil.copytree(self.output, linked)
        linked_api = linked / f"secpal-int-{INSTANCE}-api.container"
        linked_api.unlink()
        linked_api.symlink_to(self.output / linked_api.name)
        self.assertNotEqual(self.validate(linked).returncode, 0)

    def test_installed_quadlet_generator_translates_every_native_resource(self) -> None:
        generator = Path("/usr/libexec/podman/quadlet")
        if not generator.is_file():
            self.skipTest("Podman Quadlet generator is not installed")
        podman = shutil.which("podman")
        if podman is None:
            self.skipTest("Podman client is not installed")
        version_result = subprocess.run(
            [podman, "version", "--format", "{{.Client.Version}}"],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        version = version_result.stdout.strip()
        if (
            version_result.returncode != 0
            or not quadlet_generator_version_supported(version)
        ):
            observed = version or "unknown"
            self.skipTest(
                f"installed Quadlet generator belongs to unsupported Podman {observed}"
            )
        units = self.render()
        environment = dict(os.environ)
        environment["QUADLET_UNIT_DIRS"] = os.fspath(self.output)
        result = subprocess.run(
            [os.fspath(generator), "-user", "-dryrun"],
            cwd=ROOT,
            env=environment,
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        generated = result.stdout + result.stderr
        for name in EXPECTED_FILES:
            if name.endswith(".target"):
                continue
            service = name.removesuffix(".container").removesuffix(".network").removesuffix(".volume")
            if name.endswith(".network"):
                service += "-network"
            elif name.endswith(".volume"):
                service += "-volume"
            self.assertIn(f"---{service}.service---", generated, name)
        for role in ("postgres", "valkey", "api", "frontend", "gateway"):
            marker = f"---secpal-int-{INSTANCE}-{role}.service---"
            translated_service = generated.split(marker, 1)[1].split("\n---", 1)[0]
            with self.subTest(health_service=role):
                self.assertIn("Type=notify", translated_service)
                self.assertIn("NotifyAccess=all", translated_service)
                self.assertIn("--sdnotify=healthy", translated_service)
                self.assertIn("--health-on-failure kill", translated_service)
        self.assertNotIn("--pull always", generated)
        self.assertNotIn("--network host", generated)
        self.assertNotIn("podman.sock", generated)
        container_starts = [
            line
            for line in generated.splitlines()
            if line.startswith("ExecStart=/usr/bin/podman run ")
        ]
        self.assertEqual(len(container_starts), 10)
        for argument in (
            "--http-proxy=false",
            "--pid=private",
            "--ipc=private",
            "--uts=private",
        ):
            with self.subTest(translated_argument=argument):
                self.assertTrue(
                    all(f" {argument} " in line for line in container_starts)
                )
        for option in (
            " --init ",
            " --log-driver journald ",
            " --pids-limit 512 ",
            " --stop-timeout 30 ",
        ):
            with self.subTest(translated_option=option.strip()):
                self.assertTrue(all(option in line for line in container_starts))

        scheduler = generated.split(
            f"---secpal-int-{INSTANCE}-scheduler.service---", 1
        )[1].split("\n---", 1)[0]
        self.assertIn(
            '--entrypoint "[\\"/bin/bash\\",'
            '\\"/run/secpal/container-entrypoint.sh\\"]"',
            scheduler,
        )
        self.assertIn(
            f"{API_IMAGE} php artisan schedule:work",
            scheduler,
        )
        self.assertEqual(len(units), len(EXPECTED_FILES))

        analyzer = shutil.which("systemd-analyze")
        if analyzer is None:
            self.skipTest("systemd-analyze is not installed")
        generated_root = self.root / "generated"
        early_root = self.root / "early"
        late_root = self.root / "late"
        for directory in (generated_root, early_root, late_root):
            directory.mkdir()
        translated = subprocess.run(
            [
                os.fspath(generator),
                "-user",
                os.fspath(generated_root),
                os.fspath(early_root),
                os.fspath(late_root),
            ],
            cwd=ROOT,
            env=environment,
            text=True,
            capture_output=True,
        )
        self.assertEqual(translated.returncode, 0, translated.stderr)
        shutil.copyfile(
            self.output / f"secpal-int-{INSTANCE}.target",
            generated_root / f"secpal-int-{INSTANCE}.target",
        )
        generated_files = sorted(generated_root.glob("*.service"))
        generated_files.append(generated_root / f"secpal-int-{INSTANCE}.target")
        verified = subprocess.run(
            [analyzer, "verify", *(os.fspath(path) for path in generated_files)],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        self.assertEqual(verified.returncode, 0, verified.stderr)

    def test_cloud_generator_retains_completed_oneshot_evidence(self) -> None:
        generator = Path(
            "/usr/lib/systemd/user-generators/podman-user-generator"
        )
        if not generator.is_file():
            self.skipTest("native Podman user generator is not installed")
        self.render_cloud()
        environment = dict(os.environ)
        environment["QUADLET_UNIT_DIRS"] = os.fspath(self.output)
        result = subprocess.run(
            [os.fspath(generator), "-user", "-dryrun"],
            cwd=ROOT,
            env=environment,
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        generated = result.stdout + result.stderr
        starts = {
            role: next(
                line
                for line in generated.splitlines()
                if line.startswith("ExecStart=/usr/bin/podman run ")
                and f"--name secpal-int-{INSTANCE}-{role} " in line
            )
            for role in ("secrets-init", "migrate")
        }
        for role, command in starts.items():
            with self.subTest(role=role):
                self.assertLess(
                    command.index(" --rm "), command.index(" --rm=false ")
                )
                self.assertNotIn(
                    '--entrypoint "[\\"/bin/sh\\",\\"/run/secpal/'
                    'quadlet-oneshot-entrypoint.sh\\"]"',
                    command,
                )
        self.assertIn(
            '--entrypoint "[\\"/bin/bash\\",\\"/run/secpal/'
            'init-local-secrets.sh\\"]"',
            starts["secrets-init"],
        )
        self.assertIn(
            '--entrypoint "[\\"/bin/bash\\",\\"/run/secpal/'
            'container-entrypoint.sh\\"]"',
            starts["migrate"],
        )
        self.assertTrue(
            starts["migrate"].endswith(" php artisan migrate --force")
        )
        api_start = next(
            line
            for line in generated.splitlines()
            if line.startswith("ExecStart=/usr/bin/podman run ")
            and f"--name secpal-int-{INSTANCE}-api " in line
        )
        health_command = re.search(
            r' --health-cmd "([^"]+)" ', api_start
        )
        self.assertIsNotNone(health_command)
        self.assertIn(
            health_command.group(1),
            (
                "CMD /usr/local/bin/secpal-http-live",
                r"CMD\x20/usr/local/bin/secpal-http-live",
            ),
        )

    def test_quadlet_generator_version_gate_matches_runtime_contract(self) -> None:
        self.assertFalse(quadlet_generator_version_supported("4.9.3"))
        self.assertFalse(quadlet_generator_version_supported("5.4.2-rc1"))
        self.assertFalse(quadlet_generator_version_supported("5.4.2~rc1"))
        self.assertFalse(quadlet_generator_version_supported("05.4.2"))
        self.assertTrue(quadlet_generator_version_supported("5.4.2"))
        self.assertTrue(quadlet_generator_version_supported("5.4.2+ds1-1+b1"))
        self.assertTrue(quadlet_generator_version_supported("5.7.0"))
        self.assertFalse(quadlet_generator_version_supported("6.0.0"))
        self.assertFalse(quadlet_generator_version_supported("not-a-version"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
