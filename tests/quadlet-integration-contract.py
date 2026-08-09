#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Static contract for the active rootless Podman/Quadlet integration."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RENDERER = ROOT / "scripts" / "render-integration-quadlets.py"
GATEWAY_CONFIG = ROOT / "config" / "quadlet" / "Caddyfile"
ONESHOT_WRAPPER = ROOT / "scripts" / "quadlet-oneshot-entrypoint.sh"
HARNESS = ROOT / "scripts" / "quadlet-integration.py"
WORKFLOW = ROOT / ".github" / "workflows" / "local-integration.yml"
INSTANCE = "contract01"
PORT = "18443"
MINIMUM_PODMAN_VERSION = (5, 4, 2)
MAXIMUM_PODMAN_VERSION = (6, 0, 0)


def quadlet_generator_version_supported(value: str) -> bool:
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:[-+].*)?", value)
    if match is None:
        return False
    version = tuple(int(part) for part in match.groups())
    return MINIMUM_PODMAN_VERSION <= version < MAXIMUM_PODMAN_VERSION


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
        self.assertNotIn("PodmanArgs=", combined)
        self.assertNotIn("GlobalArgs=", combined)
        self.assertNotIn("AutoUpdate=", combined)
        self.assertNotIn("Network=host", combined)
        self.assertNotIn("SecurityLabelDisable=true", combined)
        self.assertNotIn("EnvironmentHost=true", combined)
        self.assertNotRegex(combined, r"(?i)(podman|docker)\.sock|tcp://")

        containers = {name: text for name, text in units.items() if name.endswith(".container")}
        for name, text in containers.items():
            with self.subTest(name=name):
                self.assertIn(f"PartOf=secpal-int-{INSTANCE}.target", text)
                self.assertIn("Label=org.secpal.integration.instance=contract01", text)
                self.assertIn("NoNewPrivileges=true", text)
                self.assertIn("DropCapability=all", text)
                self.assertIn("ReadOnly=true", text)
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

    def test_roles_networks_dependencies_and_singletons_are_exact(self) -> None:
        units = self.render()
        combined = "\n".join(units.values())
        application = f"secpal-int-{INSTANCE}-application.network"
        edge = f"secpal-int-{INSTANCE}-edge.network"

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
        for bad_instance in ("UPPER", "short", "../escape", "a" * 25, "socket.sock"):
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
        self.assertNotIn("--pull always", generated)
        self.assertNotIn("--network host", generated)
        self.assertNotIn("podman.sock", generated)
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

    def test_quadlet_generator_version_gate_matches_runtime_contract(self) -> None:
        self.assertFalse(quadlet_generator_version_supported("4.9.3"))
        self.assertTrue(quadlet_generator_version_supported("5.4.2"))
        self.assertTrue(quadlet_generator_version_supported("5.7.0"))
        self.assertFalse(quadlet_generator_version_supported("6.0.0"))
        self.assertFalse(quadlet_generator_version_supported("not-a-version"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
