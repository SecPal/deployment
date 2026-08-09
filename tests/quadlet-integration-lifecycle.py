#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Lifecycle contract for the rootless Podman/Quadlet integration harness."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


sys.dont_write_bytecode = True


ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "scripts" / "quadlet-integration.py"


def load_harness():
    spec = importlib.util.spec_from_file_location("quadlet_integration", HARNESS)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load integration harness")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class RecordingLifecycle:
    def __init__(self, module, fail_at: str | None = None):
        self.module = module
        self.fail_at = fail_at
        self.events: list[str] = []
        self.cleanup_calls = 0

    def _phase(self, name: str) -> None:
        self.events.append(name)
        if self.fail_at == name:
            raise self.module.IntegrationError(f"fixture failed at {name}")

    def validate_repository_and_runtime(self) -> None:
        self._phase("admission")

    def retrieve_verify_and_stage_images(self) -> None:
        self._phase("verify-stage")

    def render_validate_and_install_units(self) -> None:
        self._phase("quadlets")

    def start_target(self) -> None:
        self._phase("start")

    def prove_runtime(self) -> None:
        self._phase("prove")

    def collect_resource_evidence(self) -> None:
        self._phase("observe")

    def cleanup(self) -> None:
        self.cleanup_calls += 1
        self.events.append("cleanup")


class CleanupFailureLifecycle(RecordingLifecycle):
    def cleanup(self) -> None:
        super().cleanup()
        raise self.module.IntegrationError("cleanup verification failed")


class RecordingExpectedFailureLifecycle(RecordingLifecycle):
    def start_expected_failure(self) -> None:
        self._phase("failure-start")

    def prove_expected_failure(self) -> None:
        self._phase("failure-prove")


class TerminatingRunner:
    def __init__(self):
        self.termination_requests = 0

    def terminate_active(self) -> None:
        self.termination_requests += 1


class SignalDuringStartLifecycle(RecordingLifecycle):
    def __init__(self, module):
        super().__init__(module)
        self.runner = TerminatingRunner()
        self.signal_number = None
        self.cleanup_active = False

    def start_target(self) -> None:
        self.events.append("start")
        self.module.handle_signal(self, signal.SIGTERM)


class FakeRunner:
    def __init__(self):
        self.commands: list[tuple[str, ...]] = []

    def run(self, command, **_kwargs):
        argv = tuple(command)
        self.commands.append(argv)
        if len(argv) >= 4 and argv[:3] == ("podman", "container", "inspect"):
            name = argv[3]
            role = name.removeprefix("secpal-int-contract01-")
            payload = [
                {
                    "Config": {
                        "Labels": {
                            "org.secpal.integration": "true",
                            "org.secpal.integration.instance": "contract01",
                            "org.secpal.role": role,
                        }
                    }
                }
            ]
            return subprocess.CompletedProcess(argv, 0, json.dumps(payload), "")
        if len(argv) >= 4 and argv[:3] in {
            ("podman", "network", "inspect"),
            ("podman", "volume", "inspect"),
        }:
            payload = [
                {
                    "Labels": {
                        "org.secpal.integration": "true",
                        "org.secpal.integration.instance": "contract01",
                    }
                }
            ]
            return subprocess.CompletedProcess(argv, 0, json.dumps(payload), "")
        if len(argv) >= 4 and argv[:3] == ("podman", "image", "inspect"):
            payload = [
                {
                    "Labels": {
                        "org.secpal.integration": "true",
                        "org.secpal.integration.instance": "contract01",
                    }
                }
            ]
            return subprocess.CompletedProcess(argv, 0, json.dumps(payload), "")
        return subprocess.CompletedProcess(argv, 0, "", "")


class MissingRuntimeRunner:
    def __init__(self):
        self.calls = 0

    def run(self, _command, **_kwargs):
        self.calls += 1
        raise OSError("runtime command is unavailable")


class CollidingResourceRunner:
    """Expose one same-named container that is not owned by the fixture."""

    def __init__(self, container: str):
        self.container = container
        self.commands: list[tuple[str, ...]] = []

    def run(self, command, **kwargs):
        argv = tuple(command)
        self.commands.append(argv)
        stdout = ""
        returncode = 1
        if argv == ("podman", "container", "exists", self.container):
            returncode = 0
        elif argv == ("podman", "container", "inspect", self.container):
            returncode = 0
            stdout = json.dumps(
                [
                    {
                        "Config": {
                            "Labels": {
                                "org.secpal.integration": "false",
                                "org.secpal.integration.instance": "someone-else",
                            }
                        }
                    }
                ]
            )
        return subprocess.CompletedProcess(argv, returncode, stdout, "")


class QuadletLifecycleContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_harness()

    def valid_info(self) -> dict:
        return {
            "version": {"Version": "5.4.2"},
            "host": {
                "serviceIsRemote": False,
                "networkBackend": "netavark",
                "rootlessNetworkCmd": "pasta",
                "ociRuntime": {"name": "crun"},
                "security": {
                    "rootless": True,
                    "apparmorEnabled": True,
                    "seccompEnabled": True,
                },
            },
        }

    def test_runtime_admission_accepts_only_the_d1_runtime(self) -> None:
        self.module.validate_runtime_info(self.valid_info(), uid=1000, environment={})
        mutations = {
            "rootful": ("host.security.rootless", False),
            "remote": ("host.serviceIsRemote", True),
            "wrong-runtime": ("host.ociRuntime.name", "runc"),
            "wrong-network": ("host.networkBackend", "cni"),
            "wrong-transport": ("host.rootlessNetworkCmd", "slirp4netns"),
            "too-old": ("version.Version", "5.4.1"),
            "future-major": ("version.Version", "6.0.0"),
            "no-seccomp": ("host.security.seccompEnabled", False),
        }
        for label, (path, value) in mutations.items():
            with self.subTest(label=label):
                info = json.loads(json.dumps(self.valid_info()))
                target = info
                parts = path.split(".")
                for part in parts[:-1]:
                    target = target[part]
                target[parts[-1]] = value
                with self.assertRaises(self.module.IntegrationError):
                    self.module.validate_runtime_info(info, uid=1000, environment={})

        for name in (
            "CONTAINER_HOST",
            "CONTAINER_CONNECTION",
            "DOCKER_HOST",
            "CONTAINERS_CONF",
            "CONTAINERS_REGISTRIES_CONF",
            "CONTAINERS_REGISTRIES_CONF_DIR",
            "CONTAINERS_STORAGE_CONF",
            "CONTAINERS_POLICY",
        ):
            with self.subTest(environment=name), self.assertRaises(self.module.IntegrationError):
                self.module.validate_runtime_info(
                    self.valid_info(), uid=1000, environment={name: "tcp://example.invalid:1234"}
                )

        with self.assertRaises(self.module.IntegrationError):
            self.module.validate_runtime_info(self.valid_info(), uid=0, environment={})

    def test_registry_rewrite_mirror_fallback_and_insecure_ghcr_fail_closed(self) -> None:
        self.module.validate_registry_documents([{"unqualified-search-registries": ["docker.io"]}])
        for entry in (
            {"prefix": "ghcr.io", "location": "mirror.example.invalid"},
            {"prefix": "ghcr.io/secpal", "mirror": [{"location": "mirror.example.invalid"}]},
            {"prefix": "ghcr.io", "insecure": True},
            {"prefix": "*.io", "location": "fallback.example.invalid"},
            {"prefix": "docker.io", "location": "cache.example.invalid"},
            {"prefix": "docker.io/library", "mirror": [{"location": "mirror.example.invalid"}]},
        ):
            with self.subTest(entry=entry), self.assertRaises(self.module.IntegrationError):
                self.module.validate_registry_documents([{"registry": [entry]}])

    def test_effective_container_security_rejects_expansion(self) -> None:
        valid = {
            "HostConfig": {
                "Privileged": False,
                "ReadonlyRootfs": True,
                "NetworkMode": "secpal-int-contract01-edge",
                "CapAdd": [],
                "CapDrop": ["CAP_ALL"],
                "SecurityOpt": ["no-new-privileges"],
                "Binds": [],
                "Tmpfs": {"/tmp": "rw,noexec,nosuid,nodev,size=16m"},
            },
            "Mounts": [
                {
                    "Type": "volume",
                    "Name": "secpal-int-contract01-private-storage",
                    "Destination": "/app/storage/app/private",
                    "RW": True,
                }
            ],
            "AppArmorProfile": "containers-default-1.0.0",
            "EffectiveCaps": [],
            "BoundingCaps": [],
        }
        self.module.validate_container_security(
            valid,
            apparmor_available=True,
            expected_mounts={
                "/app/storage/app/private": (
                    "volume",
                    "secpal-int-contract01-private-storage",
                    True,
                )
            },
            expected_tmpfs={"/tmp"},
        )
        for label, path, value in (
            ("privileged", ("HostConfig", "Privileged"), True),
            ("writable-root", ("HostConfig", "ReadonlyRootfs"), False),
            ("host-network", ("HostConfig", "NetworkMode"), "host"),
            ("socket", ("HostConfig", "Binds"), ["/run/podman/podman.sock:/run/podman/podman.sock"]),
            ("capability", ("HostConfig", "CapAdd"), ["CAP_SYS_ADMIN"]),
            ("seccomp-unconfined", ("HostConfig", "SecurityOpt"), ["no-new-privileges", "seccomp=unconfined"]),
            ("unconfined", ("AppArmorProfile",), "unconfined"),
        ):
            with self.subTest(label=label):
                candidate = json.loads(json.dumps(valid))
                if len(path) == 1:
                    candidate[path[0]] = value
                else:
                    candidate[path[0]][path[1]] = value
                with self.assertRaises(self.module.IntegrationError):
                    self.module.validate_container_security(
                        candidate,
                        apparmor_available=True,
                        expected_mounts={
                            "/app/storage/app/private": (
                                "volume",
                                "secpal-int-contract01-private-storage",
                                True,
                            )
                        },
                        expected_tmpfs={"/tmp"},
                    )

        for label, mutation in (
            (
                "automatic-host-mount",
                lambda candidate: candidate["Mounts"].append(
                    {
                        "Type": "bind",
                        "Source": "/",
                        "Destination": "/host",
                        "RW": True,
                    }
                ),
            ),
            (
                "missing-reviewed-mount",
                lambda candidate: candidate.__setitem__("Mounts", []),
            ),
            (
                "writable-reviewed-secret",
                lambda candidate: candidate["Mounts"][0].__setitem__("RW", False),
            ),
            (
                "automatic-tmpfs",
                lambda candidate: candidate["HostConfig"]["Tmpfs"].__setitem__(
                    "/unexpected", "rw"
                ),
            ),
        ):
            with self.subTest(label=label):
                candidate = json.loads(json.dumps(valid))
                mutation(candidate)
                with self.assertRaises(self.module.IntegrationError):
                    self.module.validate_container_security(
                        candidate,
                        apparmor_available=True,
                        expected_mounts={
                            "/app/storage/app/private": (
                                "volume",
                                "secpal-int-contract01-private-storage",
                                True,
                            )
                        },
                        expected_tmpfs={"/tmp"},
                    )

        candidate = json.loads(json.dumps(valid))
        candidate["HostConfig"]["Tmpfs"]["/unexpected"] = "rw"
        with self.assertRaisesRegex(
            self.module.IntegrationError,
            r"expected \['/tmp'\].*observed \['/tmp', '/unexpected'\]",
        ):
            self.module.validate_container_security(
                candidate,
                apparmor_available=True,
                expected_mounts={
                    "/app/storage/app/private": (
                        "volume",
                        "secpal-int-contract01-private-storage",
                        True,
                    )
                },
                expected_tmpfs={"/tmp"},
            )

    def test_user_writable_runtime_configuration_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            containers = home / ".config" / "containers"
            containers.mkdir(parents=True)
            self.module.validate_user_container_configuration(home)
            for relative in (
                "containers.conf",
                "mounts.conf",
                "policy.json",
                "storage.conf",
                "containers.conf.d/override.conf",
            ):
                with self.subTest(relative=relative):
                    path = containers / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("unsafe\n", encoding="utf-8")
                    with self.assertRaises(self.module.IntegrationError):
                        self.module.validate_user_container_configuration(home)
                    path.unlink()

    def test_oneshot_state_requires_one_successful_retained_systemd_invocation(self) -> None:
        valid = "\n".join(
            (
                "ActiveState=active",
                "SubState=exited",
                "Result=success",
                "ExecMainStatus=0",
                "NRestarts=0",
                "InvocationID=0123456789abcdef0123456789abcdef",
                "ExecMainStartTimestampMonotonic=1234567",
            )
        )
        self.assertEqual(
            self.module.validate_oneshot_state(valid),
            ("0123456789abcdef0123456789abcdef", "1234567"),
        )
        for mutation in (
            "ActiveState=failed",
            "SubState=dead",
            "Result=exit-code",
            "ExecMainStatus=1",
            "NRestarts=1",
            "InvocationID=",
            "ExecMainStartTimestampMonotonic=0",
        ):
            key = mutation.split("=", 1)[0]
            candidate = "\n".join(
                mutation if line.startswith(f"{key}=") else line
                for line in valid.splitlines()
            )
            with self.subTest(mutation=mutation), self.assertRaises(
                self.module.IntegrationError
            ):
                self.module.validate_oneshot_state(candidate)

    def test_lifecycle_order_and_every_failure_path_cleanup(self) -> None:
        expected = ["admission", "verify-stage", "quadlets", "start", "prove", "observe", "cleanup"]
        successful = RecordingLifecycle(self.module)
        self.module.execute_lifecycle(successful)
        self.assertEqual(successful.events, expected)
        self.assertEqual(successful.cleanup_calls, 1)

        for phase in expected[:-1]:
            with self.subTest(phase=phase):
                failing = RecordingLifecycle(self.module, fail_at=phase)
                with self.assertRaises(self.module.IntegrationError):
                    self.module.execute_lifecycle(failing)
                self.assertEqual(failing.cleanup_calls, 1)
                self.assertEqual(failing.events[-1], "cleanup")
                self.assertNotIn("observe", failing.events if phase != "observe" else [])

    def test_image_verification_failure_cannot_reach_quadlet_or_product_execution(self) -> None:
        failing = RecordingLifecycle(self.module, fail_at="verify-stage")
        with self.assertRaises(self.module.IntegrationError):
            self.module.execute_lifecycle(failing)
        self.assertEqual(failing.events, ["admission", "verify-stage", "cleanup"])

    def test_cleanup_failure_reports_the_original_lifecycle_failure(self) -> None:
        failing = CleanupFailureLifecycle(self.module, fail_at="start")
        with self.assertRaises(self.module.IntegrationError) as raised:
            self.module.execute_lifecycle(failing)
        self.assertIn("fixture failed at start", str(raised.exception))
        self.assertIn("cleanup verification failed", str(raised.exception))

    def test_signal_cleanup_returns_conventional_status(self) -> None:
        lifecycle = SignalDuringStartLifecycle(self.module)
        with mock.patch.object(self.module.signal, "signal") as set_handler:
            with self.assertRaises(self.module.IntegrationInterrupted) as raised:
                self.module.execute_lifecycle(lifecycle)
        self.assertEqual(raised.exception.signal_number, signal.SIGTERM)
        self.assertEqual(lifecycle.signal_number, signal.SIGTERM)
        self.assertEqual(lifecycle.runner.termination_requests, 1)
        self.assertEqual(lifecycle.cleanup_calls, 1)
        self.assertEqual(
            set_handler.call_args_list,
            [
                mock.call(signal.SIGHUP, signal.SIG_IGN),
                mock.call(signal.SIGINT, signal.SIG_IGN),
                mock.call(signal.SIGTERM, signal.SIG_IGN),
            ],
        )

    def test_expected_real_failure_lifecycle_still_cleans_every_phase(self) -> None:
        expected = [
            "admission",
            "verify-stage",
            "quadlets",
            "failure-start",
            "failure-prove",
            "cleanup",
        ]
        lifecycle = RecordingExpectedFailureLifecycle(self.module)
        self.module.execute_expected_failure_lifecycle(lifecycle)
        self.assertEqual(lifecycle.events, expected)
        for phase in expected[:-1]:
            with self.subTest(phase=phase):
                failing = RecordingExpectedFailureLifecycle(self.module, fail_at=phase)
                with self.assertRaises(self.module.IntegrationError):
                    self.module.execute_expected_failure_lifecycle(failing)
                self.assertEqual(failing.cleanup_calls, 1)

    def test_cleanup_targets_only_deterministic_run_resources(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            active_root = Path(directory)
            runner = FakeRunner()
            resources = self.module.Resources.for_instance(
                "contract01", uid=1000, active_root=active_root
            )
            self.module.cleanup_resources(runner, resources)
            flattened = "\n".join(" ".join(command) for command in runner.commands)
            self.assertIn("systemctl --user stop secpal-int-contract01.target", flattened)
            for role in self.module.CONTAINER_ROLES:
                self.assertIn(f"secpal-int-contract01-{role}", flattened)
            for name in ("application", "edge"):
                self.assertIn(f"podman network rm secpal-int-contract01-{name}", flattened)
            for name in ("secrets", "private-storage", "postgres"):
                self.assertIn(f"podman volume rm secpal-int-contract01-{name}", flattened)
            self.assertIn("localhost/secpal-integration-gateway-contract01:2.10.2", flattened)
            self.assertNotIn("prune", flattened)
            self.assertNotIn("unrelated", flattened)
            self.assertNotRegex(flattened, r"podman (rm|network rm|volume rm) .*--all")
            self.assertNotIn(("systemctl", "--user", "reset-failed"), runner.commands)
            reset_commands = [
                command for command in runner.commands if "reset-failed" in command
            ]
            self.assertTrue(reset_commands)
            self.assertTrue(
                all(
                    all(argument.startswith("secpal-int-contract01") for argument in command[3:])
                    for command in reset_commands
                )
            )

    def test_cleanup_refuses_same_named_resources_without_ownership_labels(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            resources = self.module.Resources.for_instance(
                "contract01", uid=1000, active_root=Path(directory)
            )
            collision = "secpal-int-contract01-api"
            runner = CollidingResourceRunner(collision)
            with self.assertRaises(self.module.IntegrationError):
                self.module.cleanup_resources(runner, resources)
            self.assertNotIn(("podman", "rm", "--force", collision), runner.commands)
            self.assertFalse(
                any(command[:3] == ("systemctl", "--user", "stop") for command in runner.commands)
            )

    def test_cleanup_recovers_unlabelled_resource_with_trusted_active_unit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            resources = self.module.Resources.for_instance(
                "contract01", uid=1000, active_root=Path(directory)
            )
            collision = "secpal-int-contract01-api"
            runner = CollidingResourceRunner(collision)
            with mock.patch.object(self.module, "_owned_unit_file", return_value=True):
                self.module.cleanup_resources(runner, resources)
            self.assertIn(("podman", "rm", "--force", collision), runner.commands)

    def test_cleanup_does_not_mask_an_early_runtime_admission_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture_root = Path(directory) / "fixture"
            fixture_root.mkdir(mode=0o700)
            runner = MissingRuntimeRunner()
            lifecycle = self.module.IntegrationLifecycle(
                root=ROOT,
                instance="admission01",
                port=18443,
                fixture_root=fixture_root,
                output=fixture_root / "quadlets",
                runner=runner,
            )
            lifecycle.cleanup()
            self.assertFalse(fixture_root.exists())
            self.assertEqual(runner.calls, 0)

    def test_parallel_instances_have_disjoint_units_and_resources(self) -> None:
        first = self.module.Resources.for_instance(
            "parallel01", uid=1000, active_root=Path("/etc/containers/systemd/users/1000")
        )
        second = self.module.Resources.for_instance(
            "parallel02", uid=1000, active_root=Path("/etc/containers/systemd/users/1000")
        )
        self.assertTrue(set(first.containers).isdisjoint(second.containers))
        self.assertTrue(set(first.networks).isdisjoint(second.networks))
        self.assertTrue(set(first.volumes).isdisjoint(second.volumes))
        self.assertTrue(set(first.unit_files).isdisjoint(second.unit_files))
        self.assertNotEqual(first.target, second.target)

    def test_active_runtime_uses_the_reviewed_phase_b_probe_namespace(self) -> None:
        self.assertEqual(
            self.module.runtime_probe_contract("contract01"),
            {
                "cache_key": "phase-b-cache-contract01",
                "cache_value": "phase-b-cache-value-contract01",
                "worker-general": ("phase-b-queue-general-contract01", "default"),
                "worker-hash-chain": (
                    "phase-b-queue-hash-chain-contract01",
                    "activity-hash-chain",
                ),
            },
        )

    def test_failure_profiles_check_only_actual_dependency_descendants(self) -> None:
        common = ("api", "worker-general", "worker-hash-chain", "scheduler", "gateway")
        self.assertEqual(self.module.failure_blocked_roles("migration"), common)
        self.assertEqual(
            self.module.failure_blocked_roles("dependency"),
            ("migrate", *common),
        )

    def test_systemd_resource_evidence_is_bounded_to_numeric_observations(self) -> None:
        self.assertEqual(
            self.module.parse_systemd_resource_properties(
                "MemoryCurrent=1234\nMemoryPeak=5678\nCPUUsageNSec=9012\n"
            ),
            {"CPUUsageNSec": 9012, "MemoryCurrent": 1234, "MemoryPeak": 5678},
        )
        self.assertEqual(
            self.module.parse_systemd_resource_properties(
                "MemoryCurrent=[not set]\nMemoryPeak=infinity\nCPUUsageNSec=0\n"
            ),
            {"CPUUsageNSec": 0},
        )

    def test_effective_network_contract_includes_both_one_shots(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lifecycle = self.module.IntegrationLifecycle(
                root=ROOT,
                instance="contract01",
                port=18443,
                fixture_root=Path(directory),
                output=Path(directory) / "quadlets",
                runner=FakeRunner(),
            )
            self.assertEqual(lifecycle._expected_networks("secrets-init"), {"none"})
            self.assertEqual(
                lifecycle._expected_networks("migrate"),
                {"secpal-int-contract01-application"},
            )

    def test_application_restart_does_not_replan_the_fail_closed_dependency_graph(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runner = FakeRunner()
            lifecycle = self.module.IntegrationLifecycle(
                root=ROOT,
                instance="contract01",
                port=18443,
                fixture_root=Path(directory),
                output=Path(directory) / "quadlets",
                runner=runner,
            )
            lifecycle.restart_application()
            self.assertIn(
                (
                    "systemctl",
                    "--user",
                    "restart",
                    "--job-mode=ignore-dependencies",
                    "secpal-int-contract01-api.service",
                ),
                runner.commands,
            )

    def test_invalid_quadlet_output_removes_the_new_fixture_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "new-fixture"
            result = subprocess.run(
                [
                    "python3",
                    os.fspath(HARNESS),
                    "--fixture-root",
                    os.fspath(fixture),
                    "--quadlet-output",
                    os.fspath(Path(directory) / "outside"),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(fixture.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
