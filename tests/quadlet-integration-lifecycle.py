#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Lifecycle contract for the rootless Podman/Quadlet integration harness."""

from __future__ import annotations

import importlib.util
import io
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


class PortRetryLifecycle(RecordingLifecycle):
    def __init__(self, module, collisions: int, port: int | None = None):
        super().__init__(module)
        self.port = port
        self.collisions = collisions
        self.port_attempts: list[int] = []
        self.retry_cleanups = 0

    def select_port(self, port: int) -> None:
        self.port = port
        self.port_attempts.append(port)

    def start_target(self) -> None:
        self._phase("start")
        if self.collisions:
            self.collisions -= 1
            raise self.module.PortCollisionError("loopback port is already allocated")

    def prepare_port_retry(self) -> None:
        self.retry_cleanups += 1
        self.events.append("retry-cleanup")


class ExpectedFailurePortRetryLifecycle(PortRetryLifecycle):
    def start_expected_failure(self) -> None:
        self._phase("failure-start")
        if self.collisions:
            self.collisions -= 1
            raise self.module.PortCollisionError("loopback port is already allocated")

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
        elif argv == ("systemctl", "--user", "daemon-reload"):
            returncode = 0
        return subprocess.CompletedProcess(argv, returncode, stdout, "")


class ResourceStateRunner:
    def __init__(self, states: dict[tuple[str, ...], int]):
        self.states = states
        self.commands: list[tuple[str, ...]] = []

    def run(self, command, **_kwargs):
        argv = tuple(command)
        self.commands.append(argv)
        default = 3 if argv[:3] == ("systemctl", "--user", "is-active") else 1
        return subprocess.CompletedProcess(argv, self.states.get(argv, default), "", "")


class ResourceNamesRunner:
    def __init__(self, names: dict[tuple[str, ...], str]):
        self.names = names

    def run(self, command, **_kwargs):
        argv = tuple(command)
        return subprocess.CompletedProcess(argv, 0, self.names.get(argv, ""), "")


class FinalLivenessRunner:
    def run(self, command, **_kwargs):
        argv = tuple(command)
        if argv[:3] == ("systemctl", "--user", "is-active"):
            role = argv[3].removeprefix("secpal-int-contract01-").removesuffix(
                ".service"
            )
            if role == "scheduler":
                return subprocess.CompletedProcess(argv, 3, "inactive\n", "")
            return subprocess.CompletedProcess(argv, 0, "active\n", "")
        if argv[:3] == ("podman", "container", "inspect"):
            return subprocess.CompletedProcess(
                argv,
                0,
                json.dumps([{"State": {"Running": True}}]),
                "",
            )
        return subprocess.CompletedProcess(argv, 0, "", "")


class QuadletLifecycleContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_harness()

    def failure_lifecycle(self, directory: str, failure_case: str):
        fixture = Path(directory)
        return self.module.IntegrationLifecycle(
            root=ROOT,
            instance="contract01",
            port=18443,
            fixture_root=fixture,
            output=fixture / "quadlets",
            failure_case=failure_case,
            runner=FakeRunner(),
        )

    def valid_info(self) -> dict:
        return {
            "version": {"Version": "5.4.2"},
            "host": {
                "idMappings": {
                    "uidmap": [
                        {"container_id": 0, "host_id": 1000, "size": 1},
                        {"container_id": 1, "host_id": 100000, "size": 65536},
                    ],
                    "gidmap": [
                        {"container_id": 0, "host_id": 1000, "size": 1},
                        {"container_id": 1, "host_id": 100000, "size": 65536},
                    ],
                },
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
            "store": {
                "graphRoot": "/srv/podman-storage",
                "runRoot": "/run/user/1000/containers",
            },
        }

    def test_runtime_admission_accepts_only_the_d1_runtime(self) -> None:
        self.assertEqual(
            self.module.validate_runtime_info(self.valid_info(), uid=1000, environment={}),
            (Path("/srv/podman-storage"), Path("/run/user/1000/containers")),
        )
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
            "CONTAINERS_CONF_OVERRIDE",
            "CONTAINERS_CONF_MODULES",
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

    def test_runtime_admission_requires_every_configured_container_identity_mapping(self) -> None:
        for mapping_name in ("uidmap", "gidmap"):
            with self.subTest(mapping=mapping_name):
                info = self.valid_info()
                info["host"]["idMappings"][mapping_name] = [
                    {"container_id": 0, "host_id": 1000, "size": 1}
                ]
                with self.assertRaisesRegex(
                    self.module.IntegrationError,
                    f"usable subordinate {mapping_name.removesuffix('map')} mapping",
                ):
                    self.module.validate_runtime_info(info, uid=1000, environment={})

    def test_required_command_output_parsers_fail_closed(self) -> None:
        self.assertEqual(
            self.module.required_first_line("gh version 2.97.0\n", "GitHub CLI"),
            "gh version 2.97.0",
        )
        with self.assertRaises(self.module.IntegrationError):
            self.module.required_first_line("", "GitHub CLI")

        for line in (
            "gh version 2.97.0",
            "gh version 2.97.0 (2026-07-31)",
        ):
            with self.subTest(accepted=line):
                self.module.validate_gh_version_line(line)
        for line in (
            "gh version 2.97.01",
            "gh version 2.97.0-rc.1",
            "gh version 2.97.0foo",
            "gh version 2.97",
        ):
            with self.subTest(rejected=line), self.assertRaises(
                self.module.IntegrationError
            ):
                self.module.validate_gh_version_line(line)

        playwright_probe = self.module.playwright_admission_command()
        self.assertEqual(playwright_probe[:2], ("node", "-e"))
        self.assertIn("chromium.executablePath()", playwright_probe[2])
        self.assertIn("fs.accessSync", playwright_probe[2])
        self.assertIn("fs.constants.X_OK", playwright_probe[2])

        self.assertEqual(
            self.module.parse_json_mapping('{"version":{"Version":"5.4.2"}}', "Podman info"),
            {"version": {"Version": "5.4.2"}},
        )
        self.assertEqual(
            self.module.parse_json_objects('[{"URI":"unix:///run/user/1000/podman.sock"}]', "connections"),
            [{"URI": "unix:///run/user/1000/podman.sock"}],
        )
        for payload in ("", "{", "null", "[]"):
            with self.subTest(mapping=payload), self.assertRaises(
                self.module.IntegrationError
            ):
                self.module.parse_json_mapping(payload, "Podman info")
        for payload in ("", "{", "null", "{}", '["unexpected"]'):
            with self.subTest(objects=payload), self.assertRaises(
                self.module.IntegrationError
            ):
                self.module.parse_json_objects(payload, "connections")

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

        for document in (
            {"credential-helpers": ["secretservice"]},
            {"credential-helpers": ["containers-auth.json", "pass"]},
            {"additional-layer-store-auth-helper": "/usr/local/bin/helper"},
        ):
            with self.subTest(document=document), self.assertRaises(
                self.module.IntegrationError
            ):
                self.module.validate_registry_documents([document])

    def test_malformed_system_registry_configuration_is_reported_safely(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            malformed = Path(directory) / "registries.conf"
            malformed.write_text("=\n", encoding="utf-8")
            with self.assertRaisesRegex(
                self.module.IntegrationError,
                "system registry configuration could not be parsed safely",
            ):
                self.module.load_registry_document(malformed)

    def test_registry_configuration_directories_require_trusted_ancestry(self) -> None:
        path = Path("/etc/containers/registries.conf.d")
        trusted = mock.Mock(
            st_uid=0,
            st_gid=0,
            st_mode=self.module.stat.S_IFDIR | 0o755,
        )
        with mock.patch.object(Path, "lstat", autospec=True, return_value=trusted):
            self.module.validate_trusted_directory(path, "system registry configuration")

        unsafe = Path("/etc/containers")
        for label, mode, uid, gid in (
            ("symlink", self.module.stat.S_IFLNK | 0o777, 0, 0),
            ("user-owned", self.module.stat.S_IFDIR | 0o755, 1000, 0),
            ("group-writable", self.module.stat.S_IFDIR | 0o775, 0, 0),
        ):
            with self.subTest(label=label):
                def metadata_for(target, mode=mode, uid=uid, gid=gid):
                    if target == unsafe:
                        return mock.Mock(st_uid=uid, st_gid=gid, st_mode=mode)
                    return trusted

                with mock.patch.object(
                    Path, "lstat", autospec=True, side_effect=metadata_for
                ), self.assertRaisesRegex(
                    self.module.IntegrationError,
                    "system registry configuration directory",
                ):
                    self.module.validate_trusted_directory(
                        path, "system registry configuration"
                    )

    def test_quadlet_generator_admission_requires_a_usable_binary(self) -> None:
        with self.assertRaisesRegex(
            self.module.IntegrationError, "native Quadlet user generator"
        ):
            self.module.validate_quadlet_generator(
                Path("/secpal-missing-quadlet-generator")
            )

    def test_quadlet_search_path_policy_requires_trusted_ancestry(self) -> None:
        policy = Path("/etc/environment.d/90-secpal-quadlet.conf")
        expected = "QUADLET_UNIT_DIRS=/etc/containers/systemd/users/1000\n"
        directory_metadata = mock.Mock(
            st_uid=0,
            st_gid=0,
            st_mode=self.module.stat.S_IFDIR | 0o755,
        )
        file_metadata = mock.Mock(
            st_uid=0,
            st_gid=0,
            st_mode=self.module.stat.S_IFREG | 0o644,
        )

        def metadata_for(target):
            return file_metadata if target == policy else directory_metadata

        with mock.patch.object(
            Path, "lstat", autospec=True, side_effect=metadata_for
        ), mock.patch.object(Path, "read_text", autospec=True, return_value=expected):
            self.module.validate_quadlet_search_path_policy(policy, expected)

        unsafe = Path("/etc/environment.d")

        def unsafe_metadata_for(target):
            if target == unsafe:
                return mock.Mock(
                    st_uid=0,
                    st_gid=0,
                    st_mode=self.module.stat.S_IFLNK | 0o777,
                )
            return metadata_for(target)

        with mock.patch.object(
            Path, "lstat", autospec=True, side_effect=unsafe_metadata_for
        ), self.assertRaisesRegex(
            self.module.IntegrationError, "root-owned Quadlet search-path policy"
        ):
            self.module.validate_quadlet_search_path_policy(policy, expected)

    def test_admission_checks_the_generator_before_registry_or_image_work(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            lifecycle = self.module.IntegrationLifecycle(
                root=ROOT,
                instance="contract01",
                port=18443,
                fixture_root=fixture,
                output=fixture / "quadlets",
                runner=FakeRunner(),
            )

            def captured(argv, **_kwargs):
                if tuple(argv) == ("gh", "version"):
                    return "gh version 2.97.0\n"
                if tuple(argv) == ("podman", "info", "--format", "json"):
                    return json.dumps(self.valid_info())
                self.fail(f"unexpected captured command: {argv}")

            with mock.patch.object(
                self.module.shutil, "which", return_value="/usr/bin/true"
            ), mock.patch.object(lifecycle, "captured", side_effect=captured), mock.patch.object(
                self.module,
                "validate_quadlet_generator",
                side_effect=self.module.IntegrationError("native Quadlet user generator is unavailable"),
            ) as generator, mock.patch.object(
                lifecycle, "_validate_registry_files"
            ) as registry, self.assertRaisesRegex(
                self.module.IntegrationError, "native Quadlet user generator"
            ):
                lifecycle.validate_repository_and_runtime()

            generator.assert_called_once_with(self.module.QUADLET_USER_GENERATOR)
            registry.assert_not_called()

    def test_api_origin_rejects_the_frontend_spa_shell(self) -> None:
        self.module.validate_api_origin_root('{"status":"not found"}')
        with self.assertRaisesRegex(
            self.module.IntegrationError, "API origin returned the frontend SPA shell"
        ):
            self.module.validate_api_origin_root("<!doctype html><html></html>")

    def test_external_behavior_rejects_the_spa_shell_from_the_api_origin(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            lifecycle = self.module.IntegrationLifecycle(
                root=ROOT,
                instance="contract01",
                port=18443,
                fixture_root=fixture,
                output=fixture / "quadlets",
                runner=FakeRunner(),
            )

            def curl(origin, path, *extra, check=True):
                result = {
                    ("api", "/health/live"): (0, '{"status":"alive"}'),
                    ("app", "/health/live"): (0, "alive\n"),
                    ("api", "/"): (0, "<!doctype html><html></html>"),
                }.get((origin, path))
                if result is None:
                    self.fail(f"unexpected external probe: {origin} {path} {extra} {check}")
                return subprocess.CompletedProcess((), result[0], result[1], "")

            with mock.patch.object(lifecycle, "curl", side_effect=curl), self.assertRaisesRegex(
                self.module.IntegrationError, "API origin returned the frontend SPA shell"
            ):
                lifecycle._validate_external_behavior()

    def test_anonymous_pull_environment_isolates_all_fallback_authentication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            auth_root = fixture / "auth-root"
            auth_root.mkdir(mode=0o700)
            auth_file = auth_root / "auth.json"
            auth_file.write_text("{}\n", encoding="utf-8")
            lifecycle = self.module.IntegrationLifecycle(
                root=ROOT,
                instance="contract01",
                port=18443,
                fixture_root=fixture,
                output=fixture / "quadlets",
                runner=FakeRunner(),
            )
            inherited = {
                "HOME": "/home/caller",
                "XDG_CONFIG_HOME": "/home/caller/config",
                "XDG_DATA_HOME": "/srv/podman-data",
                "DOCKER_CONFIG": "/home/caller/docker",
                "REGISTRY_AUTH_FILE": "/home/caller/auth.json",
                "CONTAINERS_CONF_OVERRIDE": "/home/caller/override.conf",
                "CONTAINERS_CONF_MODULES": "unreviewed-module",
            }
            with mock.patch.dict(self.module.os.environ, inherited, clear=True):
                environment = lifecycle.anonymous_environment(
                    auth_file,
                    credential_root=auth_root,
                )
            self.assertEqual(environment["REGISTRY_AUTH_FILE"], os.fspath(auth_file))
            self.assertEqual(environment["HOME"], os.fspath(auth_root / "home"))
            self.assertEqual(
                environment["XDG_CONFIG_HOME"], os.fspath(auth_root / "xdg-config")
            )
            self.assertEqual(
                environment["DOCKER_CONFIG"], os.fspath(auth_root / "docker-config")
            )
            self.assertEqual(environment["XDG_DATA_HOME"], "/srv/podman-data")
            self.assertNotIn("CONTAINERS_CONF_OVERRIDE", environment)
            self.assertNotIn("CONTAINERS_CONF_MODULES", environment)
            for name in ("home", "xdg-config", "docker-config", "certs"):
                path = auth_root / name
                self.assertTrue(path.is_dir())
                self.assertEqual(path.stat().st_mode & 0o777, 0o700)

    def test_anonymous_pull_pins_the_admitted_rootless_storage_and_empty_certificates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            runner = FakeRunner()
            lifecycle = self.module.IntegrationLifecycle(
                root=ROOT,
                instance="contract01",
                port=18443,
                fixture_root=fixture,
                output=fixture / "quadlets",
                runner=runner,
            )
            lifecycle.graph_root = Path("/srv/podman-storage")
            lifecycle.run_root = Path("/run/user/1000/containers")
            lifecycle.anonymous_pull("api", "ghcr.io/secpal/api@sha256:abc")
            pull = next(command for command in runner.commands if "pull" in command)
            self.assertEqual(
                pull[:6],
                (
                    "podman",
                    "--root",
                    "/srv/podman-storage",
                    "--runroot",
                    "/run/user/1000/containers",
                    "pull",
                ),
            )
            self.assertIn("--authfile", pull)
            self.assertIn("--cert-dir", pull)

    def test_anonymous_pull_credential_cleanup_errors_are_controlled(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            lifecycle = self.module.IntegrationLifecycle(
                root=ROOT,
                instance="contract01",
                port=18443,
                fixture_root=fixture,
                output=fixture / "quadlets",
                runner=FakeRunner(),
            )
            lifecycle.graph_root = Path("/srv/podman-storage")
            lifecycle.run_root = Path("/run/user/1000/containers")
            with mock.patch.object(
                self.module.shutil,
                "rmtree",
                side_effect=PermissionError("credentials are not removable"),
            ), self.assertRaisesRegex(
                self.module.IntegrationError,
                "credential isolation could not be removed",
            ):
                lifecycle.anonymous_pull("api", "ghcr.io/secpal/api@sha256:abc")

    def test_tmpfs_validation_accepts_podman_54_and_57_rw_forms(self) -> None:
        expected = self.module.TmpfsSpec(
            size=16 * 1024 * 1024, mode=0o700, noexec=True
        )
        for podman_version, options in (
            (
                "5.4",
                "size=16m,mode=0700,uid=10001,gid=10001,nosuid,nodev,"
                "noexec,rw,rprivate,tmpcopyup",
            ),
            (
                "5.7",
                "size=16m,mode=0700,uid=10001,gid=10001,nosuid,nodev,"
                "noexec,rprivate,tmpcopyup",
            ),
        ):
            with self.subTest(podman_version=podman_version):
                self.module.validate_tmpfs_options(
                    options, expected, (10001, 10001)
                )

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
                "Tmpfs": {
                    "/tmp": "size=16m,mode=0700,uid=10001,gid=10001,nosuid,nodev,noexec,rw,rprivate,tmpcopyup"
                },
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
            expected_tmpfs={
                "/tmp": self.module.TmpfsSpec(size=16 * 1024 * 1024, mode=0o700)
            },
            expected_tmpfs_identity=(10001, 10001),
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
                        expected_tmpfs={
                            "/tmp": self.module.TmpfsSpec(
                                size=16 * 1024 * 1024, mode=0o700
                            )
                        },
                        expected_tmpfs_identity=(10001, 10001),
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
                        expected_tmpfs={
                            "/tmp": self.module.TmpfsSpec(
                                size=16 * 1024 * 1024, mode=0o700
                            )
                        },
                        expected_tmpfs_identity=(10001, 10001),
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
                expected_tmpfs={
                    "/tmp": self.module.TmpfsSpec(
                        size=16 * 1024 * 1024, mode=0o700
                    )
                },
                expected_tmpfs_identity=(10001, 10001),
            )

        for label, options in (
            ("size", "rw,noexec,nosuid,nodev,size=8m,mode=0700,uid=10001,gid=10001,rprivate,tmpcopyup"),
            ("mode", "rw,noexec,nosuid,nodev,size=16m,mode=0755,uid=10001,gid=10001,rprivate,tmpcopyup"),
            ("nosuid", "rw,noexec,nodev,size=16m,mode=0700,uid=10001,gid=10001,rprivate,tmpcopyup"),
            ("nodev", "rw,noexec,nosuid,size=16m,mode=0700,uid=10001,gid=10001,rprivate,tmpcopyup"),
            ("noexec", "rw,nosuid,nodev,size=16m,mode=0700,uid=10001,gid=10001,rprivate,tmpcopyup"),
            ("read-only", "ro,noexec,nosuid,nodev,size=16m,mode=0700,uid=10001,gid=10001,rprivate,tmpcopyup"),
            ("uid", "rw,noexec,nosuid,nodev,size=16m,mode=0700,uid=10002,gid=10001,rprivate,tmpcopyup"),
            ("gid", "rw,noexec,nosuid,nodev,size=16m,mode=0700,uid=10001,gid=10002,rprivate,tmpcopyup"),
            ("unresolved-ownership", "rw,noexec,nosuid,nodev,size=16m,mode=0700,U,rprivate,tmpcopyup"),
        ):
            with self.subTest(tmpfs_option=label):
                candidate = json.loads(json.dumps(valid))
                candidate["HostConfig"]["Tmpfs"]["/tmp"] = options
                with self.assertRaisesRegex(
                    self.module.IntegrationError, "tmpfs options"
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
                        expected_tmpfs={
                            "/tmp": self.module.TmpfsSpec(
                                size=16 * 1024 * 1024, mode=0o700
                            )
                        },
                        expected_tmpfs_identity=(10001, 10001),
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
                "registries.conf.d",
                "containers.conf.d/override.conf",
            ):
                with self.subTest(relative=relative):
                    path = containers / relative
                    if relative.endswith(".d"):
                        path.mkdir(parents=True, exist_ok=True)
                    else:
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_text("unsafe\n", encoding="utf-8")
                    with self.assertRaises(self.module.IntegrationError):
                        self.module.validate_user_container_configuration(home)
                    if path.is_dir():
                        path.rmdir()
                    else:
                        path.unlink()

            alternate = home / "alternate-config"
            alternate_containers = alternate / "containers"
            alternate_containers.mkdir(parents=True)
            (alternate_containers / "containers.conf").write_text(
                "unsafe\n", encoding="utf-8"
            )
            with self.assertRaises(self.module.IntegrationError):
                self.module.validate_user_container_configuration(
                    home,
                    {"XDG_CONFIG_HOME": os.fspath(alternate)},
                )

    def test_active_quadlet_inputs_require_trusted_recursive_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            active_root = Path(directory)
            drop_in = active_root / "unrelated.container.d"
            drop_in.mkdir()
            override = drop_in / "10-unrelated.conf"
            override.write_text("[Service]\n", encoding="utf-8")

            def metadata_for(target, override_metadata=None):
                if target == override and override_metadata is not None:
                    return override_metadata
                mode = (
                    self.module.stat.S_IFDIR | 0o755
                    if target == drop_in
                    else self.module.stat.S_IFREG | 0o644
                )
                return mock.Mock(st_uid=0, st_gid=0, st_mode=mode)

            with mock.patch.object(
                Path, "lstat", autospec=True, side_effect=metadata_for
            ):
                self.module.validate_active_quadlet_inputs(active_root)

            invalid_metadata = (
                (
                    "user-owned",
                    mock.Mock(
                        st_uid=1000,
                        st_gid=0,
                        st_mode=self.module.stat.S_IFREG | 0o644,
                    ),
                ),
                (
                    "group-writable",
                    mock.Mock(
                        st_uid=0,
                        st_gid=0,
                        st_mode=self.module.stat.S_IFREG | 0o664,
                    ),
                ),
                (
                    "symlink",
                    mock.Mock(
                        st_uid=0,
                        st_gid=0,
                        st_mode=self.module.stat.S_IFLNK | 0o777,
                    ),
                ),
                (
                    "special",
                    mock.Mock(
                        st_uid=0,
                        st_gid=0,
                        st_mode=self.module.stat.S_IFIFO | 0o600,
                    ),
                ),
            )
            for label, metadata in invalid_metadata:
                with self.subTest(label=label), mock.patch.object(
                    Path,
                    "lstat",
                    autospec=True,
                    side_effect=lambda target, value=metadata: metadata_for(
                        target, value
                    ),
                ), self.assertRaises(self.module.IntegrationError):
                    self.module.validate_active_quadlet_inputs(active_root)

    def test_active_quadlet_root_rejects_a_symlinked_ancestor(self) -> None:
        active_root = Path("/etc/containers/systemd/users/1000")
        trusted = mock.Mock(
            st_uid=0,
            st_gid=0,
            st_mode=self.module.stat.S_IFDIR | 0o755,
        )
        symlinked_ancestor = Path("/etc/containers")

        def lstat_for(target):
            if target == symlinked_ancestor:
                return mock.Mock(
                    st_uid=0,
                    st_gid=0,
                    st_mode=self.module.stat.S_IFLNK | 0o777,
                )
            return trusted

        with mock.patch.object(
            Path, "lstat", autospec=True, side_effect=lstat_for
        ), self.assertRaisesRegex(self.module.IntegrationError, "active Quadlet root"):
            self.module.validate_active_root(active_root)

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

    def test_oneshot_inspection_waits_for_the_effective_running_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lifecycle = self.failure_lifecycle(directory, "migration")
            created = subprocess.CompletedProcess(
                (),
                0,
                json.dumps([{"State": {"Running": False, "Status": "created"}}]),
                "",
            )
            activating = subprocess.CompletedProcess(
                (), 0, "ActiveState=activating\nResult=success\n", ""
            )
            running_details = {"State": {"Running": True, "Status": "running"}}
            running = subprocess.CompletedProcess(
                (), 0, json.dumps([running_details]), ""
            )
            with mock.patch.object(
                lifecycle, "command", side_effect=(created, activating, running)
            ), mock.patch.object(self.module.time, "sleep"):
                observed = lifecycle._wait_for_oneshot_container("migrate")

            self.assertEqual(observed, running_details)

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

    def test_automatic_port_collisions_retry_only_the_fixture_attempt(self) -> None:
        lifecycle = PortRetryLifecycle(self.module, collisions=2)
        allocated = iter((18445, 18446, 18447))

        self.module.execute_lifecycle(lifecycle, port_allocator=lambda: next(allocated))

        self.assertEqual(lifecycle.port_attempts, [18445, 18446, 18447])
        self.assertEqual(lifecycle.retry_cleanups, 2)
        self.assertEqual(lifecycle.events.count("admission"), 1)
        self.assertEqual(lifecycle.events.count("verify-stage"), 1)
        self.assertEqual(lifecycle.events.count("quadlets"), 3)
        self.assertEqual(lifecycle.events.count("start"), 3)
        self.assertEqual(lifecycle.cleanup_calls, 1)

    def test_expected_health_failure_retries_verified_automatic_port_collisions(self) -> None:
        lifecycle = ExpectedFailurePortRetryLifecycle(self.module, collisions=2)
        allocated = iter((18445, 18446, 18447))

        self.module.execute_expected_failure_lifecycle(
            lifecycle, port_allocator=lambda: next(allocated)
        )

        self.assertEqual(lifecycle.port_attempts, [18445, 18446, 18447])
        self.assertEqual(lifecycle.retry_cleanups, 2)
        self.assertEqual(lifecycle.events.count("admission"), 1)
        self.assertEqual(lifecycle.events.count("verify-stage"), 1)
        self.assertEqual(lifecycle.events.count("quadlets"), 3)
        self.assertEqual(lifecycle.events.count("failure-start"), 3)
        self.assertEqual(lifecycle.events.count("failure-prove"), 1)
        self.assertEqual(lifecycle.cleanup_calls, 1)

    def test_only_verified_gateway_bind_errors_are_retryable(self) -> None:
        for message in (
            "Error: rootlessport listen tcp 127.0.0.1:18443: bind: address already in use",
            "failed to bind host port 127.0.0.1:18443",
            "port is already allocated",
            "Bind for 127.0.0.1:18443 failed",
        ):
            with self.subTest(message=message):
                self.assertTrue(self.module.is_port_collision_log(message))
        for message in (
            "migration failed",
            "permission denied while opening port configuration",
            "gateway health check failed",
            "",
        ):
            with self.subTest(message=message):
                self.assertFalse(self.module.is_port_collision_log(message))

    def test_gateway_collision_evidence_is_bound_to_the_current_systemd_invocation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            lifecycle = self.module.IntegrationLifecycle(
                root=ROOT,
                instance="contract01",
                port=18443,
                fixture_root=fixture,
                output=fixture / "quadlets",
                runner=FakeRunner(),
            )
            invocation = "b" * 32
            with mock.patch.object(
                lifecycle,
                "command",
                side_effect=(
                    subprocess.CompletedProcess((), 0, invocation + "\n", ""),
                    subprocess.CompletedProcess(
                        (), 0, "bind: address already in use\n", ""
                    ),
                ),
            ) as command:
                self.assertTrue(lifecycle._gateway_port_collision())

            journal_command = command.call_args_list[1].args[0]
            self.assertIn(f"_SYSTEMD_INVOCATION_ID={invocation}", journal_command)

            with mock.patch.object(
                lifecycle,
                "command",
                return_value=subprocess.CompletedProcess((), 0, "not-an-id\n", ""),
            ) as command:
                self.assertFalse(lifecycle._gateway_port_collision())
                command.assert_called_once()

    def test_health_failure_wait_retries_only_a_verified_gateway_collision(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lifecycle = self.failure_lifecycle(directory, "health")
            absent = subprocess.CompletedProcess((), 125, "", "not found")
            failed = subprocess.CompletedProcess(
                (), 0, "ActiveState=failed\nResult=exit-code\n", ""
            )
            with mock.patch.object(
                lifecycle, "command", side_effect=(absent, failed)
            ), mock.patch.object(
                lifecycle, "_gateway_port_collision", return_value=True
            ), self.assertRaises(self.module.PortCollisionError):
                lifecycle._wait_for_injected_health_failure()

            with mock.patch.object(
                lifecycle, "command", side_effect=(absent, failed)
            ), mock.patch.object(
                lifecycle, "_gateway_port_collision", return_value=False
            ), self.assertRaisesRegex(
                self.module.IntegrationError,
                "before the injected health check",
            ):
                lifecycle._wait_for_injected_health_failure()

    def test_health_failure_wait_polls_without_an_unbounded_podman_wait(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lifecycle = self.failure_lifecycle(directory, "health")
            starting_details = {
                "Config": {"Healthcheck": {"Test": ["CMD-SHELL", "/bin/false"]}},
                "State": {
                    "Running": True,
                    "Status": "running",
                    "Health": {"Status": "starting", "FailingStreak": 0, "Log": []},
                },
            }
            unhealthy_details = json.loads(json.dumps(starting_details))
            unhealthy_details["State"]["Health"] = {
                "Status": "unhealthy",
                "FailingStreak": 1,
                "Log": [{"ExitCode": 1, "Output": ""}],
            }
            with mock.patch.object(
                lifecycle,
                "command",
                side_effect=(
                    subprocess.CompletedProcess(
                        (), 0, json.dumps([starting_details]), ""
                    ),
                    subprocess.CompletedProcess(
                        (), 0, "ActiveState=active\nResult=success\n", ""
                    ),
                    subprocess.CompletedProcess(
                        (), 0, json.dumps([unhealthy_details]), ""
                    ),
                ),
            ) as command, mock.patch.object(
                lifecycle, "_validate_effective_container"
            ), mock.patch.object(self.module.time, "sleep"):
                lifecycle._wait_for_injected_health_failure()

            self.assertTrue(lifecycle.injected_health_failure_observed)
            self.assertFalse(
                any(
                    call.args[0][:2] == ["podman", "wait"]
                    for call in command.call_args_list
                )
            )

    def test_health_failure_inspection_waits_until_the_container_is_running(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lifecycle = self.failure_lifecycle(directory, "health")
            created = subprocess.CompletedProcess(
                (),
                0,
                json.dumps([{"State": {"Running": False, "Status": "created"}}]),
                "",
            )
            activating = subprocess.CompletedProcess(
                (), 0, "ActiveState=activating\nResult=success\n", ""
            )
            running_details = {
                "Config": {
                    "Healthcheck": {"Test": ["CMD-SHELL", "/bin/false"]}
                },
                "State": {
                    "Running": True,
                    "Status": "running",
                    "Health": {
                        "Status": "starting",
                        "FailingStreak": 0,
                        "Log": [],
                    },
                },
            }
            running = subprocess.CompletedProcess(
                (), 0, json.dumps([running_details]), ""
            )
            unhealthy_details = json.loads(json.dumps(running_details))
            unhealthy_details["State"]["Health"] = {
                "Status": "unhealthy",
                "FailingStreak": 1,
                "Log": [{"ExitCode": 1, "Output": ""}],
            }
            active = subprocess.CompletedProcess(
                (), 0, "ActiveState=active\nResult=success\n", ""
            )
            unhealthy = subprocess.CompletedProcess(
                (), 0, json.dumps([unhealthy_details]), ""
            )
            with mock.patch.object(
                lifecycle,
                "command",
                side_effect=(created, activating, running, active, unhealthy),
            ), mock.patch.object(
                lifecycle, "_validate_effective_container"
            ) as validate, mock.patch.object(self.module.time, "sleep"):
                lifecycle._wait_for_injected_health_failure()

            self.assertEqual(
                validate.call_args_list,
                [
                    mock.call("gateway", running_details),
                    mock.call("gateway", unhealthy_details),
                ],
            )

    def test_port_retry_preserves_data_roles_and_completed_migration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            output = fixture / "quadlets"
            output.mkdir()
            (output / "attempt.unit").write_text("attempt\n", encoding="utf-8")
            runner = FakeRunner()
            lifecycle = self.module.IntegrationLifecycle(
                root=ROOT,
                instance="contract01",
                port=18443,
                fixture_root=fixture,
                output=output,
                runner=runner,
            )
            lifecycle.inspected_oneshots = {"secrets-init", "migrate"}
            invocation = ("a" * 32, "1234")
            with mock.patch.object(
                lifecycle, "oneshot_invocation", return_value=invocation
            ):
                lifecycle.prepare_port_retry()

            removed = {
                command[-1]
                for command in runner.commands
                if command[:3] == ("podman", "rm", "--force")
            }
            self.assertEqual(
                removed,
                {
                    "secpal-int-contract01-api",
                    "secpal-int-contract01-worker-general",
                    "secpal-int-contract01-worker-hash-chain",
                    "secpal-int-contract01-scheduler",
                    "secpal-int-contract01-frontend",
                    "secpal-int-contract01-gateway",
                },
            )
            self.assertNotIn("secpal-int-contract01-migrate", removed)
            self.assertNotIn("secpal-int-contract01-postgres", removed)
            self.assertNotIn("secpal-int-contract01-valkey", removed)
            self.assertEqual(lifecycle.migration_invocation, invocation)
            self.assertIsNone(lifecycle.port)
            self.assertFalse(output.exists())

    def test_explicit_port_collision_never_retries(self) -> None:
        lifecycle = PortRetryLifecycle(self.module, collisions=1, port=18443)

        with self.assertRaises(self.module.PortCollisionError):
            self.module.execute_lifecycle(lifecycle, port_allocator=lambda: 18444)

        self.assertEqual(lifecycle.port_attempts, [])
        self.assertEqual(lifecycle.retry_cleanups, 0)
        self.assertEqual(lifecycle.cleanup_calls, 1)

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

    def test_fixture_cleanup_errors_are_controlled(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "fixture"
            fixture.mkdir(mode=0o700)
            lifecycle = self.module.IntegrationLifecycle(
                root=ROOT,
                instance="contract01",
                port=18443,
                fixture_root=fixture,
                output=fixture / "quadlets",
                runner=FakeRunner(),
            )
            with mock.patch.object(
                self.module.shutil,
                "rmtree",
                side_effect=PermissionError("fixture is not removable"),
            ), self.assertRaisesRegex(
                self.module.IntegrationError,
                "fixture root could not be removed",
            ):
                lifecycle.cleanup()

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
            resource_services = (
                "secpal-int-contract01-application-network.service",
                "secpal-int-contract01-edge-network.service",
                "secpal-int-contract01-secrets-volume.service",
                "secpal-int-contract01-private-storage-volume.service",
                "secpal-int-contract01-postgres-volume.service",
            )
            self.assertTrue(
                any(
                    command[:3] == ("systemctl", "--user", "stop")
                    and set(command[3:]) == set(resource_services)
                    for command in runner.commands
                )
            )
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

    def test_cleanup_rejects_a_failed_systemd_daemon_reload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runner = FakeRunner()
            original_run = runner.run

            def fail_reload(command, **kwargs):
                result = original_run(command, **kwargs)
                if tuple(command) == ("systemctl", "--user", "daemon-reload"):
                    return subprocess.CompletedProcess(command, 1, "", "reload failed")
                return result

            runner.run = fail_reload
            resources = self.module.Resources.for_instance(
                "contract01", uid=1000, active_root=Path(directory)
            )
            with self.assertRaisesRegex(
                self.module.IntegrationError, "systemd user daemon reload failed"
            ):
                self.module.cleanup_resources(runner, resources)
            self.assertTrue(any("reset-failed" in command for command in runner.commands))

    def test_removed_systemd_units_must_be_unloaded(self) -> None:
        self.module.validate_removed_systemd_unit_state(
            "LoadState=not-found\nActiveState=inactive\n"
        )
        for properties in (
            "LoadState=loaded\nActiveState=inactive\n",
            "LoadState=not-found\nActiveState=active\n",
            "LoadState=not-found\n",
            "LoadState=not-found\nLoadState=loaded\nActiveState=inactive\n",
        ):
            with self.subTest(properties=properties), self.assertRaises(
                self.module.IntegrationError
            ):
                self.module.validate_removed_systemd_unit_state(properties)

    def test_effective_systemd_units_reject_override_fragments_and_dropins(self) -> None:
        fragment = "/run/user/1000/systemd/generator/secpal-int-contract01-api.service"
        self.module.validate_effective_systemd_unit(
            f"FragmentPath={fragment}\nDropInPaths=\n", Path(fragment)
        )
        for properties in (
            "FragmentPath=/home/user/.config/systemd/user/"
            "secpal-int-contract01-api.service\nDropInPaths=\n",
            f"FragmentPath={fragment}\nDropInPaths=/home/user/.config/systemd/user/"
            "secpal-int-contract01-api.service.d/override.conf\n",
            f"FragmentPath={fragment}\n",
        ):
            with self.subTest(properties=properties), self.assertRaises(
                self.module.IntegrationError
            ):
                self.module.validate_effective_systemd_unit(
                    properties, Path(fragment)
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

    def test_cleanup_refuses_to_treat_runtime_query_errors_as_absence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            resources = self.module.Resources.for_instance(
                "contract01", uid=1000, active_root=Path(directory)
            )
            runner = ResourceStateRunner(
                {
                    (
                        "podman",
                        "container",
                        "exists",
                        "secpal-int-contract01-secrets-init",
                    ): 125
                }
            )
            with self.assertRaisesRegex(
                self.module.IntegrationError,
                "unable to verify same-named container",
            ):
                self.module.cleanup_resources(runner, resources)

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

    def test_parallel_snapshots_exclude_every_owned_integration_instance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lifecycle = self.module.IntegrationLifecycle(
                root=ROOT,
                instance="parallel02",
                port=18444,
                fixture_root=Path(directory),
                output=Path(directory) / "quadlets",
                runner=ResourceNamesRunner(
                    {
                        ("podman", "ps", "--all", "--format", "{{.Names}}"): (
                            "secpal-int-parallel01-api\nunrelated-container\n"
                        ),
                        ("podman", "network", "ls", "--format", "{{.Name}}"): (
                            "secpal-int-parallel01-edge\nunrelated-network\n"
                        ),
                        ("podman", "volume", "ls", "--format", "{{.Name}}"): (
                            "secpal-int-parallel01-postgres\nunrelated-volume\n"
                        ),
                    }
                ),
            )
            lifecycle.snapshot_unrelated_resources()
            self.assertEqual(
                lifecycle.preexisting_resources,
                {
                    "containers": {"unrelated-container"},
                    "networks": {"unrelated-network"},
                    "volumes": {"unrelated-volume"},
                },
            )

    def test_cleanup_verifies_gateway_image_and_runtime_query_errors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lifecycle = self.module.IntegrationLifecycle(
                root=ROOT,
                instance="contract01",
                port=18443,
                fixture_root=Path(directory),
                output=Path(directory) / "quadlets",
                runner=ResourceStateRunner(
                    {
                        (
                            "podman",
                            "image",
                            "exists",
                            "localhost/secpal-integration-gateway-contract01:2.10.2",
                        ): 0,
                        (
                            "podman",
                            "container",
                            "exists",
                            "secpal-int-contract01-api",
                        ): 125,
                    }
                ),
            )
            errors = lifecycle._owned_resource_errors()
            self.assertIn("gateway image remained", "\n".join(errors))
            self.assertIn("unable to verify container", "\n".join(errors))
            self.assertIn("unable to verify generated service unload", "\n".join(errors))
            self.assertIn("unable to verify target unload", "\n".join(errors))

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
        with self.assertRaises(self.module.IntegrationError):
            self.module.runtime_probe_contract("parallel-01")

    def test_forbidden_user_unit_queries_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lifecycle = self.module.IntegrationLifecycle(
                root=ROOT,
                instance="contract01",
                port=18443,
                fixture_root=Path(directory),
                output=Path(directory) / "quadlets",
                runner=FakeRunner(),
            )
            query_error = subprocess.CompletedProcess(
                ("systemctl", "--user", "show"),
                125,
                "",
                "user manager unavailable",
            )
            with mock.patch.object(
                lifecycle,
                "command",
                return_value=query_error,
            ), self.assertRaisesRegex(
                self.module.IntegrationError,
                "unable to verify forbidden user unit",
            ):
                lifecycle._validate_disabled_user_unit("podman.socket")

            safe = subprocess.CompletedProcess(
                ("systemctl", "--user", "show"),
                0,
                "LoadState=loaded\nUnitFileState=disabled\nActiveState=inactive\n",
                "",
            )
            with mock.patch.object(lifecycle, "command", return_value=safe):
                lifecycle._validate_disabled_user_unit("podman.socket")

            for unsafe_output in (
                "LoadState=loaded\nUnitFileState=enabled\nActiveState=inactive\n",
                "LoadState=loaded\nUnitFileState=disabled\nActiveState=active\n",
            ):
                with self.subTest(output=unsafe_output):
                    unsafe = subprocess.CompletedProcess(
                        ("systemctl", "--user", "show"),
                        0,
                        unsafe_output,
                        "",
                    )
                    with mock.patch.object(
                        lifecycle,
                        "command",
                        return_value=unsafe,
                    ), self.assertRaisesRegex(
                        self.module.IntegrationError,
                        "forbidden user unit is enabled or active",
                    ):
                        lifecycle._validate_disabled_user_unit("podman.socket")

    def test_failure_profiles_check_only_actual_dependency_descendants(self) -> None:
        common = ("api", "worker-general", "worker-hash-chain", "scheduler", "gateway")
        self.assertEqual(self.module.failure_blocked_roles("migration"), common)
        self.assertEqual(
            self.module.failure_blocked_roles("dependency"),
            ("migrate", *common),
        )

    def test_failure_evidence_rejects_descendant_query_errors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lifecycle = self.module.IntegrationLifecycle(
                root=ROOT,
                instance="contract01",
                port=18443,
                fixture_root=Path(directory),
                output=Path(directory) / "quadlets",
                failure_case="migration",
                runner=FakeRunner(),
            )
            lifecycle.expected_failure_observed = True
            failed = "ActiveState=failed\nResult=exit-code\nExecMainStatus=1\n"
            target = "ActiveState=failed\n"
            query_error = subprocess.CompletedProcess(
                ("podman", "container", "exists"), 125, "", "runtime unavailable"
            )
            with mock.patch.object(
                lifecycle, "captured", side_effect=(failed, target)
            ), mock.patch.object(
                lifecycle, "command", return_value=query_error
            ), self.assertRaisesRegex(
                self.module.IntegrationError,
                "unable to verify blocked role absence",
            ):
                lifecycle.prove_expected_failure()

    def test_injected_health_failure_requires_podman_health_evidence(self) -> None:
        evidence = {
            "Config": {
                "Healthcheck": {"Test": ["CMD-SHELL", "/bin/false"]},
            },
            "State": {
                "Health": {
                    "Status": "unhealthy",
                    "FailingStreak": 1,
                    "Log": [{"ExitCode": 1, "Output": ""}],
                }
            },
        }
        self.assertTrue(self.module.has_injected_health_failure(evidence))

        pending = json.loads(json.dumps(evidence))
        pending["State"]["Health"] = {
            "Status": "starting",
            "FailingStreak": 0,
            "Log": [],
        }
        self.assertFalse(self.module.has_injected_health_failure(pending))
        pending["State"]["Health"] = {
            "Status": "",
            "FailingStreak": 0,
            "Log": None,
        }
        self.assertFalse(self.module.has_injected_health_failure(pending))

        mutations = (
            ("Config.Healthcheck.Test", ["CMD-SHELL", "wget example.invalid"]),
            ("State.Health.Status", "healthy"),
            ("State.Health.FailingStreak", 0),
            ("State.Health.Log", [{"ExitCode": 0, "Output": ""}]),
            ("State.Health.Log", []),
        )
        for path, value in mutations:
            with self.subTest(path=path, value=value):
                candidate = json.loads(json.dumps(evidence))
                target = candidate
                parts = path.split(".")
                for part in parts[:-1]:
                    target = target[part]
                target[parts[-1]] = value
                with self.assertRaises(self.module.IntegrationError):
                    self.module.has_injected_health_failure(candidate)

    def test_fixed_process_failures_reject_an_unrelated_service_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            for failure_case in ("migration", "dependency"):
                lifecycle = self.failure_lifecycle(directory, failure_case)
                lifecycle.expected_failure_observed = True
                failed = "ActiveState=failed\nResult=timeout\nExecMainStatus=143\n"
                with self.subTest(failure_case=failure_case), mock.patch.object(
                    lifecycle, "captured", return_value=failed
                ), self.assertRaisesRegex(
                    self.module.IntegrationError, "failure profile was not fail-closed"
                ):
                    lifecycle.prove_expected_failure()

    def test_health_failure_proof_requires_podman_evidence_and_the_kill_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lifecycle = self.failure_lifecycle(directory, "health")
            lifecycle.expected_failure_observed = True
            lifecycle.migration_invocation = ("a" * 32, "1234")
            failed = "ActiveState=failed\nResult=exit-code\nExecMainStatus=137\n"
            target = "ActiveState=failed\n"
            with mock.patch.object(
                lifecycle, "captured", side_effect=(failed, target)
            ), self.assertRaisesRegex(
                self.module.IntegrationError,
                "injected health check",
            ):
                lifecycle.prove_expected_failure()
            lifecycle.injected_health_failure_observed = True
            with mock.patch.object(
                lifecycle, "captured", side_effect=(failed, target)
            ):
                lifecycle.prove_expected_failure()

    def test_health_port_retry_cannot_hide_a_second_migration_invocation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lifecycle = self.failure_lifecycle(directory, "health")
            lifecycle.inspected_oneshots = {"secrets-init", "migrate"}
            lifecycle.migration_invocation = ("a" * 32, "1234")
            with mock.patch.object(
                lifecycle,
                "_wait_for_oneshot_success",
                return_value=("b" * 32, "5678"),
            ), mock.patch.object(
                lifecycle, "_wait_for_injected_health_failure"
            ) as wait_for_health, self.assertRaisesRegex(
                self.module.IntegrationError,
                "migration executed more than once",
            ):
                lifecycle.start_expected_failure()
            wait_for_health.assert_not_called()

    def test_final_liveness_rejects_an_inactive_scheduler(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lifecycle = self.module.IntegrationLifecycle(
                root=ROOT,
                instance="contract01",
                port=18443,
                fixture_root=Path(directory),
                output=Path(directory) / "quadlets",
                runner=FinalLivenessRunner(),
            )
            with self.assertRaisesRegex(
                self.module.IntegrationError, "scheduler is not systemd-active"
            ):
                lifecycle._validate_long_running_roles()

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
        self.assertEqual(self.module.parse_du_size("12345\t/path/to/volume\n"), 12345)
        self.assertIsNone(self.module.parse_du_size("permission denied\n"))

    def test_effective_network_contract_accepts_podman_none_inspection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lifecycle = self.module.IntegrationLifecycle(
                root=ROOT,
                instance="contract01",
                port=18443,
                fixture_root=Path(directory),
                output=Path(directory) / "quadlets",
                runner=FakeRunner(),
            )
            details = {
                "Config": {
                    "User": "0:0",
                    "Labels": {
                        "org.secpal.integration": "true",
                        "org.secpal.integration.instance": "contract01",
                        "org.secpal.role": "secrets-init",
                    },
                },
                "NetworkSettings": {"Networks": {"none": {}}},
            }
            with mock.patch.object(self.module, "validate_container_security"):
                lifecycle._validate_effective_container("secrets-init", details)
            self.assertEqual(
                lifecycle._expected_networks("migrate"),
                {"secpal-int-contract01-application"},
            )

    def test_frontend_dns_isolation_rejects_probe_errors(self) -> None:
        self.module.validate_dns_isolation_result(2, "postgres")
        with self.assertRaisesRegex(
            self.module.IntegrationError, "unexpectedly resolved data service"
        ):
            self.module.validate_dns_isolation_result(0, "postgres")
        for returncode in (1, 3, 125):
            with self.subTest(returncode=returncode), self.assertRaisesRegex(
                self.module.IntegrationError,
                "unable to verify frontend DNS isolation",
            ):
                self.module.validate_dns_isolation_result(returncode, "postgres")

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

    def test_invalid_output_fixture_rollback_errors_are_controlled(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root / "new-fixture"
            arguments = self.module.parse_arguments(
                [
                    "--fixture-root",
                    os.fspath(fixture),
                    "--quadlet-output",
                    os.fspath(root / "outside"),
                ]
            )
            stderr = io.StringIO()
            with mock.patch.object(
                self.module,
                "parse_arguments",
                return_value=arguments,
            ), mock.patch.object(
                self.module.shutil,
                "rmtree",
                side_effect=PermissionError("fixture is not removable"),
            ), mock.patch.object(
                self.module.sys,
                "stderr",
                stderr,
            ):
                self.assertEqual(self.module.main(), 1)
            self.assertIn("unable to remove invalid fixture root", stderr.getvalue())

    def test_unsafe_fixture_path_is_rejected_before_runtime_admission(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "new fixture"
            result = subprocess.run(
                [
                    "python3",
                    os.fspath(HARNESS),
                    "--fixture-root",
                    os.fspath(fixture),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("safe ASCII path", result.stderr)
            self.assertFalse(fixture.exists())

    def test_generated_fixture_rejects_an_unsafe_temporary_base_before_admission(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temporary_base = Path(directory) / "unsafe temporary base"
            temporary_base.mkdir()
            environment = dict(os.environ)
            environment["TMPDIR"] = os.fspath(temporary_base)
            result = subprocess.run(
                ["python3", os.fspath(HARNESS)],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("new safe ASCII path", result.stderr)
            self.assertNotIn("Traceback", result.stderr)
            self.assertEqual(list(temporary_base.iterdir()), [])

    def test_explicit_empty_instance_and_port_zero_are_not_defaulted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for label, arguments, message in (
                ("empty-instance", ("--instance", ""), "invalid integration instance"),
                ("zero-port", ("--port", "0"), "port must be from 1024"),
            ):
                with self.subTest(label=label):
                    fixture = root / label
                    result = subprocess.run(
                        [
                            "python3",
                            os.fspath(HARNESS),
                            *arguments,
                            "--fixture-root",
                            os.fspath(fixture),
                            "--quadlet-output",
                            os.fspath(root / "outside"),
                        ],
                        cwd=ROOT,
                        text=True,
                        capture_output=True,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(message, result.stderr)
                    self.assertNotIn("Traceback", result.stderr)
                    self.assertFalse(fixture.exists())

    def test_fixture_creation_errors_are_controlled(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "missing-parent" / "fixture"
            result = subprocess.run(
                [
                    "python3",
                    os.fspath(HARNESS),
                    "--fixture-root",
                    os.fspath(fixture),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unable to create private fixture root", result.stderr)
            self.assertNotIn("Traceback", result.stderr)
            self.assertFalse(fixture.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
