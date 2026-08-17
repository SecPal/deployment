#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Regression tests for the bounded root-owned Quadlet fixture bridge."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts" / "ci-cloud" / "quadlet-fixture-installer.py"
CLIENT = ROOT / "scripts" / "ci-cloud" / "quadlet-fixture-client.py"
TRUSTED_SERVICE_SECTION = (
    b"\n[Service]\n"
    b"Environment=CONTAINERS_CONF=/dev/null\n"
    b"Environment=CONTAINERS_CONF_OVERRIDE=/dev/null\n"
    b"Environment=CONTAINERS_CONF_MODULES=\n"
    b"Environment=PODMAN_USERNS=\n"
)


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class QuadletFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.installer = load(INSTALLER, "quadlet_fixture_installer")
        cls.client = load(CLIENT, "quadlet_fixture_client")

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="secpal-quadlet-fixture-test-"
        )
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.layout = self.installer.Layout(
            staging_root=root / "staging",
            quadlet_root=root / "quadlets",
            systemd_root=root / "systemd",
            state_root=root / "state",
            operator_uid=os.getuid(),
            operator_gid=os.getgid(),
            trusted_uid=os.getuid(),
            trusted_gid=os.getgid(),
        )
        for path in (
            self.layout.staging_root,
        ):
            path.mkdir(mode=0o700)
        for path in (
            self.layout.quadlet_root,
            self.layout.systemd_root,
            self.layout.state_root,
        ):
            path.mkdir(mode=0o755)
            path.chmod(0o755)

    def source_units(self, instance: str) -> Path:
        source = Path(self.temporary.name) / f"source-{instance}"
        source.mkdir(mode=0o700)
        for name in self.installer.expected_unit_names(instance):
            (source / name).write_text(
                f"# fixture {instance}\n[Unit]\nDescription={name}\n",
                encoding="utf-8",
            )
            (source / name).chmod(0o600)
        return source

    def stage(self, operation: str, instance: str, source: Path | None = None) -> str:
        return self.client.stage_request(
            operation,
            instance,
            source,
            self.client.Layout(staging_root=self.layout.staging_root),
        )

    def test_closed_unit_name_set(self) -> None:
        names = self.installer.expected_unit_names("a1b2c3d4")
        self.assertEqual(16, len(names))
        self.assertIn("secpal-int-a1b2c3d4-api.container", names)
        self.assertIn("secpal-int-a1b2c3d4-application.network", names)
        self.assertIn("secpal-int-a1b2c3d4-postgres.volume", names)
        self.assertIn("secpal-int-a1b2c3d4.target", names)
        with self.assertRaises(ValueError):
            self.installer.expected_unit_names("../../escape")

    def test_install_snapshots_only_the_complete_closed_set(self) -> None:
        instance = "a1b2c3d4"
        source = self.source_units(instance)
        request_id = self.stage("install", instance, source)
        stopped: list[str] = []

        self.assertTrue(
            self.installer.handle_request(
                "install", self.layout, stopped.append
            )
        )
        self.assertEqual([self.installer.INSTALL_PATH_UNIT], stopped)
        result = json.loads(self.layout.result_path("install").read_text())
        self.assertEqual(
            {
                "instance": instance,
                "operation": "install",
                "request_id": request_id,
                "reason": "none",
                "result": "installed",
                "schema_version": 1,
            },
            result,
        )
        self.assertTrue(self.layout.ready_path("install").exists())
        for name in self.installer.expected_unit_names(instance):
            destination = self.layout.destination(name)
            self.assertTrue(destination.is_file())
            self.assertFalse(destination.is_symlink())
            self.assertEqual(0o644, destination.stat().st_mode & 0o777)
            expected = (source / name).read_bytes()
            if not name.endswith(".target"):
                expected += TRUSTED_SERVICE_SECTION
            self.assertEqual(expected, destination.read_bytes())
        active = json.loads(self.layout.active_state.read_text())
        self.assertEqual("active", active["state"])
        self.assertEqual(
            sorted(self.installer.expected_unit_names(instance)),
            sorted(active["files"]),
        )
        for name, record in active["files"].items():
            content = self.layout.destination(name).read_bytes()
            self.assertEqual(len(content), record["size"])
            self.assertEqual(
                hashlib.sha256(content).hexdigest(), record["sha256"]
            )

    def test_trusted_pins_follow_target_authored_service_values(self) -> None:
        instance = "a1b2c3d4"
        source = self.source_units(instance)
        target = source / f"secpal-int-{instance}-api.container"
        with target.open("ab") as stream:
            stream.write(
                b"\n[Service]\n"
                b"Environment=CONTAINERS_CONF_OVERRIDE=/tmp/target.conf\n"
            )
        self.stage("install", instance, source)

        self.assertTrue(
            self.installer.handle_request("install", self.layout, lambda _: None)
        )

        installed = self.layout.destination(target.name).read_bytes()
        self.assertTrue(installed.endswith(TRUSTED_SERVICE_SECTION))
        self.assertLess(
            installed.index(b"CONTAINERS_CONF_OVERRIDE=/tmp/target.conf"),
            installed.rindex(b"CONTAINERS_CONF_OVERRIDE=/dev/null"),
        )

    def test_trusted_pin_expansion_respects_the_unit_size_limit(self) -> None:
        instance = "a1b2c3d4"
        source = self.source_units(instance)
        target = source / f"secpal-int-{instance}-api.container"
        target.write_bytes(b"x" * (self.installer.MAX_UNIT_BYTES - 1) + b"\n")
        self.stage("install", instance, source)

        self.assertFalse(
            self.installer.handle_request("install", self.layout, lambda _: None)
        )
        result = json.loads(self.layout.result_path("install").read_text())
        self.assertEqual("size-limit", result["reason"])
        self.assertFalse(self.layout.active_state.exists())
        self.assertFalse(any(self.layout.quadlet_root.iterdir()))

    def test_cleanup_requires_and_removes_only_recorded_snapshot(self) -> None:
        instance = "a1b2c3d4"
        self.stage("install", instance, self.source_units(instance))
        self.assertTrue(self.installer.handle_request("install", self.layout, lambda _: None))
        unrelated = self.layout.systemd_root / "unrelated.service"
        unrelated.write_text("keep\n", encoding="utf-8")

        request_id = self.stage("remove", instance)
        stopped: list[str] = []
        self.assertTrue(
            self.installer.handle_request("remove", self.layout, stopped.append)
        )
        self.assertEqual([self.installer.REMOVE_PATH_UNIT], stopped)
        self.assertFalse(self.layout.active_state.exists())
        self.assertTrue(unrelated.exists())
        self.assertFalse(
            any(
                self.layout.destination(name).exists()
                for name in self.installer.expected_unit_names(instance)
            )
        )
        result = json.loads(self.layout.result_path("remove").read_text())
        self.assertEqual(request_id, result["request_id"])
        self.assertEqual("removed", result["result"])
        self.assertEqual("none", result["reason"])

    def test_rejects_symlink_unknown_missing_and_oversized_inputs(self) -> None:
        instance = "a1b2c3d4"
        mutations = ("symlink", "unknown", "missing", "oversized")
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                source_path = Path(self.temporary.name) / f"source-{instance}"
                if source_path.exists():
                    __import__("shutil").rmtree(source_path)
                source = self.source_units(instance)
                self.stage("install", instance, source)
                staged = self.layout.request_path("install") / "units"
                first = staged / self.installer.expected_unit_names(instance)[0]
                if mutation == "symlink":
                    first.unlink()
                    first.symlink_to("/etc/passwd")
                elif mutation == "unknown":
                    (staged / "arbitrary.service").write_text("bad\n", encoding="utf-8")
                    (staged / "arbitrary.service").chmod(0o600)
                elif mutation == "missing":
                    first.unlink()
                else:
                    first.write_bytes(b"x" * (self.installer.MAX_UNIT_BYTES + 1))
                stopped: list[str] = []
                self.assertFalse(
                    self.installer.handle_request(
                        "install", self.layout, stopped.append
                    )
                )
                self.assertEqual([self.installer.INSTALL_PATH_UNIT], stopped)
                self.assertFalse(self.layout.active_state.exists())
                self.assertFalse(any(self.layout.quadlet_root.iterdir()))
                self.assertEqual(
                    "rejected",
                    json.loads(self.layout.result_path("install").read_text())["result"],
                )
                self.assertNotEqual(
                    "none",
                    json.loads(self.layout.result_path("install").read_text())["reason"],
                )
                self.client.clear_request(
                    "install", self.client.Layout(self.layout.staging_root)
                )
                self.layout.result_path("install").unlink()

    def test_cleanup_refuses_changed_or_unrecorded_destinations(self) -> None:
        instance = "a1b2c3d4"
        self.stage("install", instance, self.source_units(instance))
        self.assertTrue(self.installer.handle_request("install", self.layout, lambda _: None))
        changed = self.layout.destination(
            "secpal-int-a1b2c3d4-api.container"
        )
        changed.write_text("changed\n", encoding="utf-8")
        self.stage("remove", instance)

        self.assertFalse(
            self.installer.handle_request("remove", self.layout, lambda _: None)
        )
        self.assertTrue(changed.exists())
        self.assertTrue(self.layout.active_state.exists())

    def test_cleanup_resumes_an_interrupted_removing_state(self) -> None:
        instance = "a1b2c3d4"
        self.stage("install", instance, self.source_units(instance))
        self.assertTrue(self.installer.handle_request("install", self.layout, lambda _: None))
        self.client.clear_request(
            "install", self.client.Layout(self.layout.staging_root)
        )
        state = json.loads(self.layout.active_state.read_text(encoding="utf-8"))
        state["state"] = "removing"
        self.layout.active_state.chmod(0o600)
        self.layout.active_state.write_bytes(self.installer.canonical_json(state))
        self.layout.active_state.chmod(0o400)
        first = self.layout.destination(
            self.installer.expected_unit_names(instance)[0]
        )
        first.unlink()
        self.stage("remove", instance)

        self.assertTrue(
            self.installer.handle_request("remove", self.layout, lambda _: None)
        )
        self.assertFalse(self.layout.active_state.exists())
        self.assertFalse(
            any(
                self.layout.destination(name).exists()
                for name in self.installer.expected_unit_names(instance)
            )
        )

    def test_cleanup_removes_interrupted_atomic_write_before_reinstall(self) -> None:
        instance = "a1b2c3d4"
        source = self.source_units(instance)
        self.stage("install", instance, source)
        self.assertTrue(
            self.installer.handle_request("install", self.layout, lambda _: None)
        )
        self.client.clear_request(
            "install", self.client.Layout(self.layout.staging_root)
        )
        state = json.loads(self.layout.active_state.read_text(encoding="utf-8"))
        state["state"] = "installing"
        self.layout.active_state.chmod(0o600)
        self.layout.active_state.write_bytes(self.installer.canonical_json(state))
        self.layout.active_state.chmod(0o400)
        first = self.layout.destination(
            self.installer.expected_unit_names(instance)[0]
        )
        orphan = first.parent / f".{first.name}.{'0' * 32}"
        orphan.write_bytes(b"partial")
        orphan.chmod(0o600)
        target = self.layout.destination(f"secpal-int-{instance}.target")
        unrelated = target.parent / f".{target.name}.backup"
        unrelated.write_bytes(b"unrelated\n")
        unrelated.chmod(0o600)

        self.stage("remove", instance)
        self.assertTrue(
            self.installer.handle_request("remove", self.layout, lambda _: None)
        )
        self.assertFalse(orphan.exists())
        self.assertTrue(unrelated.exists())

        self.client.clear_request(
            "remove", self.client.Layout(self.layout.staging_root)
        )
        self.stage("install", instance, source)
        self.assertTrue(
            self.installer.handle_request("install", self.layout, lambda _: None)
        )

    def test_atomic_write_keeps_temporary_file_private_until_complete(self) -> None:
        destination = self.layout.state_root / "public-result.json"
        observed_modes: list[int] = []
        original_write = os.write

        def observe_mode(descriptor: int, content: bytes) -> int:
            observed_modes.append(stat.S_IMODE(os.fstat(descriptor).st_mode))
            return original_write(descriptor, content)

        with mock.patch.object(os, "write", side_effect=observe_mode):
            self.installer.atomic_bytes(destination, b"published\n", 0o444)

        self.assertEqual([0o600], observed_modes)
        self.assertEqual(0o444, stat.S_IMODE(destination.stat().st_mode))

    def test_cleanup_publishes_removing_state_before_the_first_unlink(self) -> None:
        instance = "a1b2c3d4"
        names = self.installer.expected_unit_names(instance)
        self.stage("install", instance, self.source_units(instance))
        self.assertTrue(self.installer.handle_request("install", self.layout, lambda _: None))
        self.client.clear_request(
            "install", self.client.Layout(self.layout.staging_root)
        )
        self.stage("remove", instance)
        original_unlink = Path.unlink
        interrupted = False

        def interrupt_first_fixture_unlink(path: Path, *args, **kwargs):
            nonlocal interrupted
            if not interrupted and path.name in names:
                interrupted = True
                raise OSError("simulated cleanup interruption")
            return original_unlink(path, *args, **kwargs)

        stopped: list[str] = []
        with mock.patch.object(Path, "unlink", new=interrupt_first_fixture_unlink):
            self.assertFalse(
                self.installer.handle_request("remove", self.layout, stopped.append)
            )
        state = json.loads(self.layout.active_state.read_text(encoding="utf-8"))
        self.assertEqual("removing", state["state"])
        result = json.loads(self.layout.result_path("remove").read_text())
        self.assertEqual("retrying", result["result"])
        self.assertEqual("internal-error", result["reason"])
        self.assertEqual([], stopped)

        self.client.clear_request(
            "remove", self.client.Layout(self.layout.staging_root)
        )
        self.layout.result_path("remove").unlink()
        self.stage("remove", instance)
        self.assertTrue(
            self.installer.handle_request("remove", self.layout, stopped.append)
        )
        self.assertEqual([self.installer.REMOVE_PATH_UNIT], stopped)
        self.assertFalse(self.layout.active_state.exists())

    def test_one_shared_lock_rejects_a_concurrent_operation(self) -> None:
        instance = "a1b2c3d4"
        self.stage("install", instance, self.source_units(instance))
        with self.installer.operation_lock(self.layout):
            self.assertFalse(
                self.installer.handle_request("install", self.layout, lambda _: None)
            )
        result = json.loads(self.layout.result_path("install").read_text())
        self.assertEqual("rejected", result["result"])
        self.assertEqual("operation-busy", result["reason"])

    def test_manifest_rejects_boolean_schema_and_duplicate_keys(self) -> None:
        instance = "a1b2c3d4"
        mutations = {
            "boolean-schema": (
                '{"instance":"a1b2c3d4","operation":"install",'
                '"request_id":"REQUEST_ID","schema_version":true}\n'
            ),
            "duplicate-key": (
                '{"instance":"a1b2c3d4","operation":"remove",'
                '"operation":"install","request_id":"REQUEST_ID",'
                '"schema_version":1}\n'
            ),
            "invalid-instance": (
                '{"instance":"../../escape","operation":"install",'
                '"request_id":"REQUEST_ID","schema_version":1}\n'
            ),
        }
        for label, replacement in mutations.items():
            with self.subTest(label=label):
                source = Path(self.temporary.name) / f"source-{instance}"
                if source.exists():
                    shutil.rmtree(source)
                self.stage("install", instance, self.source_units(instance))
                request = self.layout.request_path("install")
                manifest = json.loads((request / "manifest.json").read_text())
                (request / "manifest.json").write_text(
                    replacement.replace("REQUEST_ID", manifest["request_id"]),
                    encoding="utf-8",
                )
                (request / "manifest.json").chmod(0o600)
                self.assertFalse(
                    self.installer.handle_request(
                        "install", self.layout, lambda _: None
                    )
                )
                result = json.loads(self.layout.result_path("install").read_text())
                self.assertEqual("manifest-invalid", result["reason"])
                self.client.clear_request(
                    "install", self.client.Layout(self.layout.staging_root)
                )
                self.layout.result_path("install").unlink()

    def test_trusted_file_type_is_rejected_before_content_is_read(self) -> None:
        target = Path(self.temporary.name) / "target"
        target.write_text("reviewed\n", encoding="utf-8")
        symlink = self.layout.systemd_root / "collision.service"
        symlink.symlink_to(target)
        fifo = self.layout.systemd_root / "collision.fifo"
        os.mkfifo(fifo, mode=0o644)
        record = self.installer.file_record(b"reviewed\n")
        with mock.patch.object(
            os, "read", side_effect=AssertionError("unsafe content read")
        ):
            self.assertFalse(
                self.installer.trusted_file_matches(
                    symlink, record, self.layout
                )
            )
            self.assertFalse(
                self.installer.trusted_file_matches(fifo, record, self.layout)
            )

    def test_untrusted_fifo_is_rejected_without_blocking_or_reading(self) -> None:
        fifo = self.layout.staging_root / "request.fifo"
        os.mkfifo(fifo, mode=0o600)
        with mock.patch.object(
            os, "read", side_effect=AssertionError("unsafe content read")
        ):
            with self.assertRaises(self.installer.RequestError):
                self.installer.bounded_regular_file(fifo, self.layout, 512)

    def test_root_never_unlinks_a_replaced_request_path(self) -> None:
        instance = "a1b2c3d4"
        self.stage("install", instance, self.source_units(instance))
        request = self.layout.request_path("install")
        displaced = self.layout.staging_root / "displaced-install-request"
        unrelated = Path(self.temporary.name) / "unrelated-root-directory"
        unrelated.mkdir(mode=0o755)
        unrelated_ready = unrelated / "ready"
        unrelated_ready.write_text("must survive\n", encoding="utf-8")

        def replace_request_path(_: str) -> None:
            request.rename(displaced)
            request.symlink_to(unrelated, target_is_directory=True)

        self.assertFalse(
            self.installer.handle_request(
                "install", self.layout, replace_request_path
            )
        )
        self.assertTrue(unrelated_ready.exists())
        self.assertTrue((displaced / "ready").exists())

    def test_client_publishes_fixed_request_without_arbitrary_paths(self) -> None:
        instance = "a1b2c3d4"
        source = self.source_units(instance)
        request_id = self.stage("install", instance, source)
        request = self.layout.request_path("install")
        self.assertEqual(
            {"manifest.json", "ready", "units"},
            {path.name for path in request.iterdir()},
        )
        manifest = json.loads((request / "manifest.json").read_text())
        self.assertEqual(
            {
                "instance": instance,
                "operation": "install",
                "request_id": request_id,
                "schema_version": 1,
            },
            manifest,
        )
        self.assertNotIn(str(source), (request / "manifest.json").read_text())

    def test_systemd_bridge_is_fixed_hardened_and_not_persistent(self) -> None:
        documents = self.installer.systemd_unit_documents(self.layout)
        self.assertEqual(
            {
                "secpal-ci-quadlet-install.path",
                "secpal-ci-quadlet-install.service",
                "secpal-ci-quadlet-remove.path",
                "secpal-ci-quadlet-remove.service",
            },
            set(documents),
        )
        for operation in ("install", "remove"):
            service = documents[f"secpal-ci-quadlet-{operation}.service"]
            path = documents[f"secpal-ci-quadlet-{operation}.path"]
            self.assertIn("Type=oneshot", service)
            self.assertIn("NoNewPrivileges=true", service)
            self.assertIn("PrivateNetwork=true", service)
            self.assertIn("ProtectSystem=strict", service)
            self.assertIn("ProtectHome=true", service)
            self.assertIn(str(self.layout.ready_path(operation)), path)
            self.assertIn("TriggerLimitIntervalSec=60s", path)
            self.assertIn("TriggerLimitBurst=3", path)
            self.assertNotIn(
                f"-{self.layout.request_path(operation)}", service
            )
            self.assertNotIn("WantedBy=", service)

    def test_systemd_bridge_documents_pass_native_verification(self) -> None:
        if shutil.which("systemd-analyze") is None:
            self.skipTest("systemd-analyze is unavailable")
        documents = self.installer.systemd_unit_documents(self.layout)
        unit_root = Path(self.temporary.name) / "system-units"
        unit_root.mkdir(mode=0o755)
        unit_paths: list[Path] = []
        for name, document in documents.items():
            unit_path = unit_root / name
            unit_path.write_text(
                document.replace(
                    "/usr/local/sbin/secpal-ci-quadlet-fixture-installer",
                    str(INSTALLER),
                ),
                encoding="utf-8",
            )
            unit_paths.append(unit_path)
        verified = subprocess.run(
            ["systemd-analyze", "verify", *(str(path) for path in unit_paths)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            0,
            verified.returncode,
            f"{verified.stdout}\n{verified.stderr}",
        )

    def test_setup_helpers_reject_symlinked_directories_and_unit_collisions(
        self,
    ) -> None:
        trusted = Path(self.temporary.name) / "trusted-directory"
        trusted.mkdir(mode=0o755)
        symlink = Path(self.temporary.name) / "trusted-symlink"
        symlink.symlink_to(trusted, target_is_directory=True)
        with self.assertRaises(self.installer.RequestError):
            self.installer.ensure_trusted_directory(symlink, self.layout)

        unit = trusted / "fixed.service"
        unit.write_text("unexpected\n", encoding="utf-8")
        unit.chmod(0o644)
        with self.assertRaises(self.installer.RequestError):
            self.installer.install_trusted_document(
                unit, b"reviewed\n", self.layout
            )
        self.assertEqual("unexpected\n", unit.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
