#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Behavioral contract for bounded Rocky target-qualification failures."""

from __future__ import annotations

import importlib.util
import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from unittest import mock
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
CLASSIFIER = ROOT / "scripts/ci-cloud/classify-rocky-target-qualification-failure.py"
SCHEMA = ROOT / "schemas/rocky-cloud-target-qualification-failure.schema.json"
WORKFLOW = ROOT / ".github/workflows/rocky-cloud-qualification.yml"
CONTROL = ROOT / "scripts/ci-cloud/rocky-control.py"
RUNNER = ROOT / "scripts/ci-cloud/run-rocky-target-qualification.sh"
TRACE = ROOT / "scripts/ci-cloud/rocky-target-qualification-trace.sh"
OBSERVER = ROOT / "scripts/ci-cloud/observe-rocky-quadlet-reload-adjacency.py"
RELOAD_RUNUSER = ROOT / "scripts/ci-cloud/rocky-reload-runuser.py"
RELOAD_SYSTEMCTL = ROOT / "scripts/ci-cloud/rocky-reload-systemctl.py"


class RetainedBytesIO(io.BytesIO):
    """Retain protocol output after production closes its admitted channel."""

    def close(self) -> None:
        pass


def load_classifier():
    specification = importlib.util.spec_from_file_location(
        "rocky_target_qualification_failure", CLASSIFIER
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("cannot load target qualification classifier")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def load_observer():
    specification = importlib.util.spec_from_file_location(
        "rocky_quadlet_reload_observer", OBSERVER
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("cannot load Quadlet reload adjacency observer")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def load_rocky_control():
    specification = importlib.util.spec_from_file_location(
        "rocky_control", CONTROL
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("cannot load Rocky control validator")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def load_script(path: Path, name: str):
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise RuntimeError(f"cannot load {path.name}")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


class RockyTargetQualificationDiagnosticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.classifier = load_classifier()
        cls.observer = load_observer()

    @staticmethod
    def reload_observation_fields() -> dict[str, object]:
        return {
            "manager_pid": 1087,
            "control_process_pid": 2048,
            "control_process_selinux_type": "unconfined_service_t",
            "manager_process_selinux_type": "unconfined_service_t",
            "systemd_nevra": "systemd-257-23.el10_2.2.rocky.0.1.x86_64",
            "run_systemd_statvfs_success": True,
            "run_systemd_free_bytes": 64 * 1024 * 1024,
            "run_systemd_reload_minimum_bytes": 16 * 1024 * 1024,
            "run_systemd_space_sufficient": True,
            "reload_request_logged": True,
            "reload_request_client_pid": 42,
            "reload_rate_limit_rejected": False,
            "reload_started": True,
            "reload_finished": True,
            "reload_internal_failure": "none",
            "reload_reply_send_failed": False,
            "reload_journal_observation_reason": "none",
            "reload_access_avc_observed": False,
            "reload_access_avc": None,
            "reload_access_avc_ambiguous": False,
        }

    def classify(
        self,
        output: str = "",
        trace: str = "",
        status: int = 1,
        *,
        target_bound: bool = True,
        marker: str | None = None,
    ) -> tuple[str, str]:
        return self.classifier.classify_failure(
            output.encode(),
            trace.encode(),
            status,
            target_bound=target_bound,
            trusted_marker=marker,
            line_rules=self.classifier.HISTORICAL_LINE_RULES,
        )

    def classify_current(self, trace: str) -> tuple[str, str]:
        return self.classifier.classify_failure(
            b"", trace.encode(), 1, target_bound=True,
            line_rules=self.classifier.LINE_RULES,
        )

    def observer_arguments(self, directory: str) -> types.SimpleNamespace:
        return types.SimpleNamespace(
            event=Path(directory) / "event",
            ack=Path(directory) / "ack",
            output=Path(directory) / "observation.json",
            target_sha=self.classifier.EXPECTED_TARGET_SHA,
            control_sha="c" * 40,
            run_id="12345",
            run_attempt="1",
            boot_id="12345678-1234-1234-1234-123456789abc",
            journal_baseline="2026-08-30 00:00:00.000000 UTC",
        )

    @staticmethod
    def reload_event(frame: int | str) -> bytes:
        return (
            b"SECPAL_QUADLET_RELOAD_CLIENT_V1:4242\n"
            + b"SECPAL_QUADLET_RELOAD_FAILURE_V3:1:31337:40960:"
            + b"20260830000000:s=abc;i=1;b=def;m=2;t=3;x=4:"
            + str(frame).encode("ascii")
            + b"\n"
        )

    def test_missing_nss_account_preserves_bounded_failure_ack(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            acknowledgement = RetainedBytesIO()
            with (
                mock.patch.object(
                    self.observer,
                    "admitted_fifo",
                    side_effect=[io.BytesIO(self.reload_event("237,242")), acknowledgement],
                ),
                mock.patch.object(
                    self.observer, "validate_client_identity", create=True
                ),
                mock.patch.object(
                    self.observer, "collect_observation", side_effect=KeyError("secpal-runtime")
                ),
            ):
                self.assertEqual(
                    1, self.observer.observe(self.observer_arguments(directory))
                )
            self.assertEqual(
                b"SECPAL_RELOAD_CLIENT_ADMITTED_V1\n"
                b"SECPAL_RELOAD_ADJACENCY_FAILED_V1\n",
                acknowledgement.getvalue(),
            )

    def test_historical_reload_frame_cannot_satisfy_current_observer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            acknowledgement = RetainedBytesIO()
            with (
                mock.patch.object(
                    self.observer,
                    "admitted_fifo",
                    side_effect=[io.BytesIO(self.reload_event(242)), acknowledgement],
                ),
                mock.patch.object(
                    self.observer, "validate_client_identity", create=True
                ),
                mock.patch.object(self.observer, "collect_observation", return_value={}),
                mock.patch.object(self.observer, "write_document"),
            ):
                self.assertEqual(
                    1, self.observer.observe(self.observer_arguments(directory))
                )
            self.assertEqual(
                b"SECPAL_RELOAD_CLIENT_ADMITTED_V1\n"
                b"SECPAL_RELOAD_ADJACENCY_FAILED_V1\n",
                acknowledgement.getvalue(),
            )

    def test_direct_user_record_transport_has_exact_trusted_helpers(self) -> None:
        self.assertTrue(RELOAD_RUNUSER.is_file())
        self.assertTrue(RELOAD_SYSTEMCTL.is_file())
        trace = TRACE.read_text(encoding="utf-8")
        runner = RELOAD_RUNUSER.read_text(encoding="utf-8")
        client = RELOAD_SYSTEMCTL.read_text(encoding="utf-8")
        self.assertIn("/opt/secpal-control/libexec/rocky-reload-runuser", trace)
        self.assertNotIn('export PATH="/opt/secpal-control/libexec:$PATH"', trace)
        self.assertIn("os.dup2(RECORD_FD, 1", runner)
        self.assertIn("os.dup2(ACK_FD, 0", runner)
        self.assertIn("/usr/local/libexec/secpal-control/rocky-reload-systemctl", runner)
        self.assertNotIn("os.environ", runner.split("RECORD_FD", 1)[0])
        self.assertIn('REAL_SYSTEMCTL = "/usr/bin/systemctl"', client)
        self.assertIn("os.execv(REAL_SYSTEMCTL", client)

    def test_runuser_proxy_maps_only_admitted_channels_and_uses_absolute_helper(
        self,
    ) -> None:
        proxy = load_script(RELOAD_RUNUSER, "rocky_reload_runuser")
        runtime = types.SimpleNamespace(pw_uid=994, pw_gid=994, pw_dir="/var/lib/secpal-runtime")
        expected = [
            "--user", "secpal-runtime", "--", "env",
            "-u", "CONTAINER_HOST", "-u", "CONTAINER_CONNECTION",
            "HOME=/var/lib/secpal-runtime",
            "XDG_RUNTIME_DIR=/run/user/994",
            "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/994/bus",
            "systemctl", "--user", "daemon-reload",
        ]
        fifo = types.SimpleNamespace(
            st_mode=stat.S_IFIFO | 0o600, st_uid=0, st_gid=0
        )
        execution = RuntimeError("exec")
        with (
            mock.patch.object(proxy.sys, "argv", [str(RELOAD_RUNUSER), *expected]),
            mock.patch.object(proxy.os, "geteuid", return_value=0),
            mock.patch.dict(proxy.os.environ, {"SECPAL_RELOAD_EXACT_CALL": "1"}),
            mock.patch.object(proxy.pwd, "getpwnam", return_value=runtime),
            mock.patch.object(proxy.os, "fstat", return_value=fifo),
            mock.patch.object(proxy.fcntl, "fcntl", return_value=os.O_RDWR),
            mock.patch.object(proxy.os, "dup2") as duplicate,
            mock.patch.object(proxy.os, "closerange") as close_range,
            mock.patch.object(proxy.os, "sysconf", return_value=64),
            mock.patch.object(proxy.os, "execv", side_effect=execution) as execute,
        ):
            with self.assertRaisesRegex(RuntimeError, "exec"):
                proxy.main()
        duplicate.assert_has_calls(
            [mock.call(proxy.ACK_FD, 0, inheritable=True),
             mock.call(proxy.RECORD_FD, 1, inheritable=True)]
        )
        close_range.assert_called_once_with(3, 64)
        executed = execute.call_args.args[1]
        self.assertEqual(proxy.REAL_RUNUSER, executed[0])
        self.assertEqual(proxy.TRUSTED_SYSTEMCTL, executed[-3])
        self.assertNotIn("systemctl", executed)

    def test_runtime_helper_keeps_pid_and_rejects_wrong_semantic_actor(self) -> None:
        client = load_script(RELOAD_SYSTEMCTL, "rocky_reload_systemctl")
        runtime = types.SimpleNamespace(pw_uid=994, pw_gid=994)
        execution = RuntimeError("exec")
        with (
            mock.patch.object(client.sys, "argv", [str(RELOAD_SYSTEMCTL), "--user", "daemon-reload"]),
            mock.patch.dict(client.os.environ, {"SECPAL_RELOAD_EXACT_CALL": "1"}),
            mock.patch.object(client.pwd, "getpwnam", return_value=runtime),
            mock.patch.object(client.os, "getresuid", return_value=(994, 994, 994)),
            mock.patch.object(client.os, "getresgid", return_value=(994, 994, 994)),
            mock.patch.object(client, "admitted_fifo"),
            mock.patch.object(client.os, "getpid", return_value=4242),
            mock.patch.object(client.os, "write", return_value=40) as write,
            mock.patch.object(client, "read_acknowledgement", return_value=client.ACK),
            mock.patch.object(client.os, "close"),
            mock.patch.object(client.os, "execv", side_effect=execution) as execute,
        ):
            record = b"SECPAL_QUADLET_RELOAD_CLIENT_V1:4242\n"
            write.return_value = len(record)
            with self.assertRaisesRegex(RuntimeError, "exec"):
                client.main()
            write.assert_called_once_with(1, record)
            execute.assert_called_once_with(
                client.REAL_SYSTEMCTL,
                [client.REAL_SYSTEMCTL, "--user", "daemon-reload"],
            )

        with (
            mock.patch.object(client.sys, "argv", [str(RELOAD_SYSTEMCTL), "--user", "daemon-reload"]),
            mock.patch.dict(client.os.environ, {"SECPAL_RELOAD_EXACT_CALL": "1"}),
            mock.patch.object(client.pwd, "getpwnam", return_value=runtime),
            mock.patch.object(client.os, "getresuid", return_value=(0, 0, 0)),
            mock.patch.object(client.os, "getresgid", return_value=(0, 0, 0)),
            mock.patch.object(client.os, "execv") as execute,
        ):
            self.assertEqual(126, client.main())
            execute.assert_not_called()

    def test_observer_rejects_forged_or_wrong_pid_actor(self) -> None:
        runtime = types.SimpleNamespace(pw_uid=994, pw_gid=994)
        wrong_actor = (
            b"Name:\tsystemctl\nUid:\t0\t0\t0\t0\n"
            b"Gid:\t0\t0\t0\t0\n"
        )
        with (
            mock.patch.object(self.observer.Path, "read_bytes", return_value=wrong_actor),
            mock.patch.object(self.observer.pwd, "getpwnam", return_value=runtime),
        ):
            with self.assertRaises(self.observer.ObservationError):
                self.observer.validate_client_identity(4242)

    def test_observer_distinguishes_malformed_identity_from_mismatch(self) -> None:
        runtime = types.SimpleNamespace(pw_uid=994, pw_gid=994)
        incomplete_identity = b"Name:\tsystemctl\nUid:\t994\t994\t994\t994\n"
        with (
            mock.patch.object(
                self.observer.Path, "read_bytes", return_value=incomplete_identity
            ),
            mock.patch.object(self.observer.pwd, "getpwnam", return_value=runtime),
        ):
            with self.assertRaisesRegex(
                self.observer.ObservationError,
                "daemon-reload client identity is malformed",
            ):
                self.observer.validate_client_identity(4242)
        with mock.patch.object(
            self.observer.Path, "read_bytes", side_effect=FileNotFoundError
        ):
            with self.assertRaises(self.observer.ObservationError):
                self.observer.validate_client_identity(4242)

    def test_current_target_line_map_is_private_relabel_only(self) -> None:
        cases = ((237, "qualify-quadlet-daemon-reload"), (238, "qualify-quadlet-start"),
                 (239, "qualify-quadlet-active-state"), (245, "qualify-workload-primary"),
                 (250, "qualify-seccomp"), (262, "qualify-selinux-storage"))
        for line, operation in cases:
            with self.subTest(line=line):
                self.assertEqual((operation, "command-failed"), self.classify_current(f"SECPAL_TARGET_ERR_V2:1:{line}"))
        for line in (250, 252, 253):
            self.assertNotEqual("qualify-selinux-storage-fcontext-add", self.classifier.operation_for_line(line))

    def run_traced_bash(
        self, script: str
    ) -> tuple[subprocess.CompletedProcess[bytes], str]:
        with tempfile.TemporaryDirectory() as directory:
            trace = Path(directory) / "trace"
            with trace.open("wb") as descriptor:
                result = subprocess.run(
                    ["bash", "-c", script],
                    check=False,
                    env={**os.environ, "BASH_ENV": str(TRACE)},
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    pass_fds=(descriptor.fileno(),),
                    close_fds=True,
                    preexec_fn=lambda: os.dup2(descriptor.fileno(), 3),
                )
            return result, trace.read_text(encoding="ascii")

    def test_real_bash_trace_retains_bounded_semantic_call_stack(self) -> None:
        cases = (
            ("set -eEuo pipefail\nfalse\n", (2,)),
            (
                "set -eEuo pipefail\nhelper() {\n  false\n}\nhelper\n",
                (3, 5),
            ),
            (
                "set -eEuo pipefail\ninner() {\n  false\n}\n"
                "outer() {\n  inner\n}\nouter\n",
                (3, 6, 8),
            ),
        )
        for script, required_lines in cases:
            with self.subTest(required_lines=required_lines):
                result, trace = self.run_traced_bash(script)
                self.assertEqual(1, result.returncode)
                match = self.classifier.TRACE_PATTERN.fullmatch(trace.strip())
                self.assertIsNotNone(match)
                self.assertEqual(1, int(match.group(1)))
                frames = tuple(int(value) for value in match.group(2).split(","))
                self.assertLessEqual(len(frames), self.classifier.MAX_TRACE_FRAMES)
                for line in required_lines:
                    self.assertIn(line, frames)

    def test_real_bash_helper_failures_classify_by_outer_semantic_call_site(self) -> None:
        definitions = {
            27: "read_os_release_value() {",
            28: "  false",
            29: "}",
            39: "run_as_service_account() {",
            40: "  false",
            41: "}",
            48: "rootless_podman() {",
            49: "  run_as_service_account",
            50: "}",
            52: "user_systemctl() {",
            53: "  false",
            54: "}",
        }
        cases = (
            (117, 'value="$(read_os_release_value)"', "qualify-host-identity"),
            (183, "rootless_podman", "qualify-rootless-runtime"),
            (242, "user_systemctl", "qualify-quadlet-daemon-reload"),
            (243, "user_systemctl", "qualify-quadlet-start"),
            (244, "user_systemctl", "qualify-quadlet-active-state"),
            (257, "rootless_podman", "qualify-workload-primary"),
            (269, "rootless_podman", "qualify-workload-secondary"),
            (271, "rootless_podman", "qualify-selinux-storage"),
        )
        for call_line, command, operation in cases:
            lines = ["set -eEuo pipefail"] + [""] * (call_line - 1)
            for line_number, source in definitions.items():
                lines[line_number - 1] = source
            lines[call_line - 1] = command
            with self.subTest(operation=operation):
                result, trace = self.run_traced_bash("\n".join(lines) + "\n")
                self.assertEqual(1, result.returncode)
                self.assertEqual(
                    (operation, "command-failed"),
                    self.classify(trace=trace),
                )

    def test_daemon_reload_event_captures_actual_input_before_exit_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            harness = root / "qualify-production-host.sh"
            target_input = root / "secpal-host-qualification-fixture.container"
            trace = root / "trace"
            fake_bin = root / "bin"
            fake_bin.mkdir()
            for name, body in {
                "journalctl": "printf '%s\\n' '-- cursor: s=abc;i=1;b=def;m=2;t=3;x=4'",
                "stat": "printf '%s\\n' '10 4096'",
                "date": "printf '%s\\n' '20260828235959'",
            }.items():
                executable = fake_bin / name
                executable.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
                executable.chmod(0o700)
            lines = ["set -euo pipefail"] + [""] * 236
            definitions = {
                52: "user_systemctl() {",
                53: "  false",
                54: "}",
                62: "cleanup() {",
                63: "  local exit_status=$?",
                64: '  rm -f -- "$FIXTURE_INPUT"',
                65: '  exit "$exit_status"',
                66: "}",
                204: "trap cleanup EXIT",
                216: 'printf "actual input\\n" >"$FIXTURE_INPUT"',
                237: "user_systemctl daemon-reload",
            }
            for line_number, source in definitions.items():
                lines[line_number - 1] = source
            harness.write_text("\n".join(lines) + "\n", encoding="utf-8")

            event_read, event_write = os.pipe()
            ack_read, ack_write = os.pipe()
            captured: dict[str, object] = {}

            def observe() -> None:
                with os.fdopen(event_read, "rb", closefd=True) as events:
                    event = events.readline(512)
                captured["event"] = event
                if event:
                    captured["present"] = target_input.is_file()
                    if target_input.is_file():
                        captured["sha256"] = hashlib.sha256(
                            target_input.read_bytes()
                        ).hexdigest()
                    os.write(ack_write, b"SECPAL_RELOAD_ADJACENCY_CAPTURED_V1\n")
                os.close(ack_write)

            observer = threading.Thread(target=observe)
            observer.start()
            with trace.open("wb") as descriptor:
                process = subprocess.Popen(
                    ["bash", harness],
                    env={
                        **os.environ,
                        "BASH_ENV": str(TRACE),
                        "FIXTURE_INPUT": str(target_input),
                        "PATH": f"{fake_bin}:{os.environ['PATH']}",
                    },
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    pass_fds=tuple(
                        {3, 4, 5, descriptor.fileno(), event_write, ack_read}
                    ),
                    close_fds=True,
                    preexec_fn=lambda: (
                        os.dup2(descriptor.fileno(), 3),
                        os.dup2(event_write, 4),
                        os.dup2(ack_read, 5),
                    ),
                )
                os.close(event_write)
                os.close(ack_read)
                self.assertEqual(1, process.wait(timeout=10))
            observer.join(timeout=10)
            self.assertFalse(observer.is_alive())
            self.assertRegex(
                captured.get("event", b"").decode("ascii"),
                r"^SECPAL_QUADLET_RELOAD_FAILURE_V3:1:[1-9][0-9]{0,9}:"
                r"40960:20260828235959:s=abc;i=1;b=def;m=2;t=3;x=4:"
                r"[0-9]+(?:,[0-9]+){0,7}\n$",
            )
            self.assertIs(True, captured.get("present"))
            self.assertEqual(
                hashlib.sha256(b"actual input\n").hexdigest(),
                captured.get("sha256"),
            )
            self.assertFalse(target_input.exists())

    def test_daemon_reload_adjacency_has_a_closed_fail_safe_decision_matrix(self) -> None:
        admitted_input = {
            "match_count": 1,
            "present": True,
            "regular_file": True,
            "not_symlink": True,
            "owner_uid": 0,
            "owner_gid": 0,
            "mode": "0644",
            "size": 320,
            "sha256": "a" * 64,
        }
        baseline = {
            "schema_version": 1,
            "target_sha": self.classifier.EXPECTED_TARGET_SHA,
            "trusted_control_sha": "c" * 40,
            "qualification_run_id": "12345",
            "qualification_run_attempt": "1",
            "boot_id": "12345678-1234-1234-1234-123456789abc",
            "failure_status": 1,
            "failure_event_sha256": "e" * 64,
            "captured_before_cleanup": True,
            "capture_monotonic_ns": 123456789,
            "manager_continuity_observed": True,
            "manager_active_after_reload_failure": True,
            "bus_available_after_reload_failure": True,
            "control_reachable_after_reload_failure": True,
            **self.reload_observation_fields(),
            "quadlet_input": admitted_input,
            "podman_generator_executed": True,
            "podman_generator_exit_status": 0,
            "podman_generator_accepted_actual_input": True,
            "generator_failures": [],
            "generator_failure_ambiguous": False,
            "generator_observation_reason": "none",
            "selinux_avc_observed": False,
            "selinux_avc": None,
            "selinux_avc_ambiguous": False,
        }
        mutations = (
            (
                "manager-continuity-lost",
                {"manager_active_after_reload_failure": False},
            ),
            (
                "target-input-invalid",
                {"quadlet_input": dict(admitted_input, present=False, match_count=0)},
            ),
            (
                "target-input-invalid",
                {
                    "quadlet_input": dict(
                        admitted_input, regular_file=False, not_symlink=False
                    )
                },
            ),
            (
                "target-input-invalid",
                {"quadlet_input": dict(admitted_input, owner_uid=994, mode="0600")},
            ),
            (
                "podman-generator-rejected",
                {
                    "podman_generator_exit_status": 1,
                    "podman_generator_accepted_actual_input": False,
                },
            ),
            (
                "other-generator-failed",
                {
                    "generator_failures": [
                        {"basename": "example-generator", "exit_status": 1}
                    ]
                },
            ),
            (
                "selinux-reload-denied",
                {
                    "selinux_avc_observed": True,
                    "selinux_avc": {
                        "source_type": "container_runtime_t",
                        "target_type": "etc_t",
                        "object_class": "file",
                        "denied_permission": "read",
                    },
                },
            ),
            ("reload-reply-transport-failed", {}),
            (
                "diagnostic-unavailable",
                {
                    "generator_failure_ambiguous": True,
                    "generator_observation_reason": "journal-timeout",
                },
            ),
        )
        expected = {
            "target_sha": self.classifier.EXPECTED_TARGET_SHA,
            "trusted_control_sha": "c" * 40,
            "qualification_run_id": "12345",
            "qualification_run_attempt": "1",
            "failure_status": 1,
        }
        for classification, mutation in mutations:
            observation = {**baseline, **mutation}
            with self.subTest(classification=classification):
                admitted = self.classifier.admit_daemon_reload_adjacency(
                    observation, expected, "timeout"
                )
                self.assertEqual(classification, admitted["classification"])

        malformed = (
            {**baseline, "extra": True},
            {**baseline, "captured_before_cleanup": False},
            {**baseline, "trusted_control_sha": "d" * 40},
            {**baseline, "manager_active_after_reload_failure": 1},
            {
                **baseline,
                "podman_generator_executed": False,
                "podman_generator_exit_status": 0,
            },
            {
                **baseline,
                "selinux_avc_observed": True,
                "selinux_avc": None,
            },
            {
                **baseline,
                "generator_failure_ambiguous": True,
                "generator_observation_reason": "none",
            },
            {
                **baseline,
                "generator_failure_ambiguous": False,
                "generator_observation_reason": "journal-timeout",
            },
        )
        for observation in malformed:
            with self.subTest(malformed=observation):
                self.assertEqual(
                    self.classifier.unavailable_daemon_reload_adjacency(),
                    self.classifier.admit_daemon_reload_adjacency(
                        observation, expected, "timeout"
                    ),
                )

    def test_reviewed_systemd_generator_message_normalizes_without_free_text(self) -> None:
        boot_id = "12345678-1234-1234-1234-123456789abc"
        entry = {
            "_UID": "994",
            "_BOOT_ID": boot_id.replace("-", ""),
            "CODE_FILE": "../src/shared/exec-util.c",
            "CODE_FUNC": "do_execute",
            "MESSAGE": "/usr/lib/systemd/user-generators/example-generator failed with exit status 7, ignoring.",
        }
        with mock.patch.object(
            self.observer,
            "admitted_generator",
            return_value=Path(
                "/usr/lib/systemd/user-generators/example-generator"
            ),
        ):
            failures, reason = self.observer.generator_failures(
                (json.dumps(entry) + "\n").encode(), 994, boot_id
            )
        self.assertEqual(
            [{"basename": "example-generator", "exit_status": 7}], failures
        )
        self.assertEqual("none", reason)

        malformed = dict(entry, MESSAGE="arbitrary localized generator output")
        failures, reason = self.observer.generator_failures(
            (json.dumps(malformed) + "\n").encode(), 994, boot_id
        )
        self.assertEqual([], failures)
        self.assertEqual("candidate-representation-invalid", reason)

    def test_generator_journal_is_narrowed_before_bounded_collection(self) -> None:
        boot_id = "12345678-1234-1234-1234-123456789abc"
        command = self.observer.generator_journal_command(994, boot_id, "@123")
        self.assertEqual(
            [
                "journalctl",
                "--no-pager",
                "--output=json",
                "--output-fields=_UID,_BOOT_ID,CODE_FUNC,CODE_FILE,MESSAGE",
                f"--boot={boot_id.replace('-', '')}",
                "--since=@123",
                "_UID=994",
                "CODE_FUNC=do_execute",
                "CODE_FILE=../src/shared/exec-util.c",
            ],
            command,
        )
        irrelevant = {
            "_UID": "994",
            "_BOOT_ID": boot_id.replace("-", ""),
            "CODE_FUNC": "unrelated",
            "CODE_FILE": "src/unrelated.c",
            "MESSAGE": "x" * 3_000,
        }
        self.assertNotEqual(
            f"CODE_FUNC={irrelevant['CODE_FUNC']}", command[-2]
        )
        broad_journal = ((json.dumps(irrelevant) + "\n") * 100).encode()
        self.assertGreater(
            len(broad_journal), self.observer.MAX_GENERATOR_JOURNAL_BYTES
        )
        self.assertNotIn(
            "CODE_FUNC=unrelated",
            command,
        )
        failures, reason = self.observer.generator_failures(b"", 994, boot_id)
        self.assertEqual([], failures)
        self.assertEqual("none", reason)

    def test_generator_candidate_failures_have_closed_reasons(self) -> None:
        boot_id = "12345678-1234-1234-1234-123456789abc"
        base = {
            "_UID": "994",
            "_BOOT_ID": boot_id.replace("-", ""),
            "CODE_FILE": "../src/shared/exec-util.c",
            "CODE_FUNC": "do_execute",
            "MESSAGE": "/usr/lib/systemd/user-generators/example-generator failed with exit status 7, ignoring.",
        }
        oversized = dict(base, MESSAGE="x" * 3_000)
        failures, reason = self.observer.generator_failures(
            (json.dumps(oversized) + "\n").encode(), 994, boot_id
        )
        self.assertEqual([], failures)
        self.assertEqual("candidate-representation-invalid", reason)

        with mock.patch.object(
            self.observer, "admitted_generator", return_value=None
        ):
            failures, reason = self.observer.generator_failures(
                (json.dumps(base) + "\n").encode(), 994, boot_id
            )
        self.assertEqual([], failures)
        self.assertEqual("candidate-generator-unadmitted", reason)

        payload = (json.dumps(base) + "\n").encode() * 4
        with mock.patch.object(
            self.observer,
            "admitted_generator",
            return_value=Path(
                "/usr/lib/systemd/user-generators/example-generator"
            ),
        ):
            failures, reason = self.observer.generator_failures(payload, 994, boot_id)
        self.assertEqual(
            [{"basename": "example-generator", "exit_status": 7}], failures
        )
        self.assertEqual("candidate-count-exceeded", reason)

    def test_generator_command_failures_have_closed_reasons(self) -> None:
        boot_id = "12345678-1234-1234-1234-123456789abc"
        cases = (
            (125, "command-failed", "journal-command-failed"),
            (124, "timeout", "journal-timeout"),
            (125, "output-bound-exceeded", "journal-output-bound-exceeded"),
            (1, None, "journal-command-failed"),
        )
        for status, command_reason, expected in cases:
            with self.subTest(expected=expected):
                failures, reason = self.observer.generator_observation(
                    status, b"", command_reason, 994, boot_id
                )
                self.assertEqual([], failures)
                self.assertEqual(expected, reason)

    def test_exact_rocky_reload_source_contract_is_closed(self) -> None:
        self.assertEqual(
            "systemd-257-23.el10_2.2.rocky.0.1.src.rpm",
            self.observer.ROCKY_SYSTEMD_SOURCE_RPM,
        )
        self.assertEqual(
            self.observer.ADMITTED_SYSTEMD_NEVRAS,
            self.classifier.ADMITTED_SYSTEMD_NEVRAS,
        )
        self.assertEqual(16 * 1024 * 1024, self.observer.RELOAD_SPACE_MINIMUM_BYTES)
        command = self.observer.reload_journal_command(
            1087,
            "12345678-1234-1234-1234-123456789abc",
            "@123",
        )
        self.assertIn("_PID=1087", command)
        self.assertIn("--after-cursor=@123", command)
        self.assertNotIn("--since=@123", command)
        self.assertIn("CODE_FUNC=log_caller", command)
        self.assertIn("CODE_FUNC=method_reload", command)
        self.assertIn("CODE_FUNC=invoke_main_loop", command)
        self.assertIn("CODE_FUNC=manager_reload", command)
        self.assertIn("CODE_FUNC=bus_send_pending_reload_message", command)
        self.assertIn(
            "--output-fields=_PID,_BOOT_ID,CODE_FUNC,CODE_FILE,MESSAGE", command
        )

    def test_reload_stage_markers_ignore_unrelated_records(self) -> None:
        boot_id = "12345678-1234-1234-1234-123456789abc"
        irrelevant = {
            "_PID": "1087",
            "_BOOT_ID": boot_id.replace("-", ""),
            "CODE_FILE": "../src/core/main.c",
            "CODE_FUNC": "unrelated",
            "MESSAGE": "Reloading...",
        }
        facts, reason = self.observer.reload_stage_markers(
            (json.dumps(irrelevant) + "\n").encode(), 1087, boot_id, 42
        )
        self.assertEqual("candidate-representation-invalid", reason)
        self.assertFalse(facts["reload_request_logged"])
        self.assertFalse(facts["reload_rate_limit_rejected"])
        self.assertFalse(facts["reload_started"])
        self.assertFalse(facts["reload_finished"])
        self.assertEqual("none", facts["reload_internal_failure"])
        self.assertFalse(facts["reload_reply_send_failed"])

    def test_reload_stage_markers_admit_exact_source_events(self) -> None:
        boot_id = "12345678-1234-1234-1234-123456789abc"
        entries = (
            ("../src/core/dbus-manager.c", "log_caller", "Reload requested from client PID 42 ('systemctl')..."),
            ("../src/core/main.c", "invoke_main_loop", "Reloading..."),
            ("../src/core/main.c", "invoke_main_loop", "Reloading finished in 12 ms."),
        )
        payload = b"".join(
            (json.dumps({
                "_PID": "1087",
                "_BOOT_ID": boot_id.replace("-", ""),
                "CODE_FILE": code_file,
                "CODE_FUNC": code_func,
                "MESSAGE": message,
            }) + "\n").encode()
            for code_file, code_func, message in entries
        )
        facts, reason = self.observer.reload_stage_markers(
            payload, 1087, boot_id, 42
        )
        self.assertEqual("none", reason)
        self.assertEqual(
            {
                "reload_request_logged": True,
                "reload_request_client_pid": 42,
                "reload_rate_limit_rejected": False,
                "reload_started": True,
                "reload_finished": True,
                "reload_internal_failure": "none",
                "reload_reply_send_failed": False,
            },
            facts,
        )

    def test_reload_stage_internal_failures_are_finite(self) -> None:
        boot_id = "12345678-1234-1234-1234-123456789abc"
        cases = (
            ("manager_reload", "Failed to create serialization file: No space left on device", "serialization-file-failed"),
            ("manager_reload", "Out of memory.", "resource-allocation-failed"),
            ("manager_serialize", "Failed to flush serialization: Input/output error", "serialization-failed"),
            ("manager_serialize", "Out of memory.", "resource-allocation-failed"),
            ("manager_reload", "Failed to seek to beginning of serialization: Invalid argument", "serialization-seek-failed"),
        )
        for code_func, message, expected in cases:
            entry = {
                "_PID": "1087",
                "_BOOT_ID": boot_id.replace("-", ""),
                "CODE_FILE": "../src/core/manager-serialize.c" if code_func == "manager_serialize" else "../src/core/manager.c",
                "CODE_FUNC": code_func,
                "MESSAGE": message,
            }
            with self.subTest(expected=expected):
                facts, reason = self.observer.reload_stage_markers(
                    (json.dumps(entry) + "\n").encode(), 1087, boot_id, 42
                )
                self.assertEqual("none", reason)
                self.assertEqual(expected, facts["reload_internal_failure"])

    def test_reload_stage_rejects_multiple_request_clients(self) -> None:
        boot_id = "12345678-1234-1234-1234-123456789abc"
        payload = b"".join(
            (
                json.dumps(
                    {
                        "_PID": "1087",
                        "_BOOT_ID": boot_id.replace("-", ""),
                        "CODE_FILE": "../src/core/dbus-manager.c",
                        "CODE_FUNC": "log_caller",
                        "MESSAGE": f"Reload requested from client PID {pid} ('systemctl')...",
                    }
                )
                + "\n"
            ).encode()
            for pid in (42, 43)
        )
        facts, reason = self.observer.reload_stage_markers(
            payload, 1087, boot_id, 42
        )
        self.assertEqual("multiple-causes", reason)
        self.assertIsNone(facts["reload_request_client_pid"])

    def test_reload_stage_rejects_a_request_from_another_client(self) -> None:
        boot_id = "12345678-1234-1234-1234-123456789abc"
        entry = {
            "_PID": "1087",
            "_BOOT_ID": boot_id.replace("-", ""),
            "CODE_FILE": "../src/core/dbus-manager.c",
            "CODE_FUNC": "log_caller",
            "MESSAGE": "Reload requested from client PID 43 ('systemctl')...",
        }
        facts, reason = self.observer.reload_stage_markers(
            (json.dumps(entry) + "\n").encode(), 1087, boot_id, 42
        )
        self.assertEqual("request-client-unbound", reason)
        self.assertEqual(43, facts["reload_request_client_pid"])

    def test_reload_stage_rejects_execution_after_rate_limit_rejection(self) -> None:
        boot_id = "12345678-1234-1234-1234-123456789abc"
        entries = (
            ("../src/core/dbus-manager.c", "log_caller", "Reload requested from client PID 42 ('systemctl')..."),
            ("../src/core/dbus-manager.c", "method_reload", "Reloading request rejected due to rate limit."),
            ("../src/core/main.c", "invoke_main_loop", "Reloading..."),
        )
        payload = b"".join(
            (json.dumps({
                "_PID": "1087",
                "_BOOT_ID": boot_id.replace("-", ""),
                "CODE_FILE": code_file,
                "CODE_FUNC": code_func,
                "MESSAGE": message,
            }) + "\n").encode()
            for code_file, code_func, message in entries
        )
        _, reason = self.observer.reload_stage_markers(
            payload, 1087, boot_id, 42
        )
        self.assertEqual("candidate-representation-invalid", reason)

    def test_reload_stage_rejects_completion_after_serialization_failure(self) -> None:
        boot_id = "12345678-1234-1234-1234-123456789abc"
        entries = (
            ("../src/core/dbus-manager.c", "log_caller", "Reload requested from client PID 42 ('systemctl')..."),
            ("../src/core/main.c", "invoke_main_loop", "Reloading..."),
            ("../src/core/manager.c", "manager_reload", "Failed to create serialization file: No space left on device"),
            ("../src/core/main.c", "invoke_main_loop", "Reloading finished in 12 ms."),
        )
        payload = b"".join(
            (json.dumps({
                "_PID": "1087",
                "_BOOT_ID": boot_id.replace("-", ""),
                "CODE_FILE": code_file,
                "CODE_FUNC": code_func,
                "MESSAGE": message,
            }) + "\n").encode()
            for code_file, code_func, message in entries
        )
        _, reason = self.observer.reload_stage_markers(
            payload, 1087, boot_id, 42
        )
        self.assertEqual("candidate-representation-invalid", reason)

    def test_reload_client_error_is_normalized_without_raw_output(self) -> None:
        cases = (
            (b"Reload daemon failed: Reload() request rejected due to rate limit.\n", "rate-limited"),
            (
                b"Reload daemon failed: Refusing to reload, not enough space available on /run/systemd. Currently, 1B are free, but a safety buffer of 16.0M is enforced.\n",
                "run-space-rejected",
            ),
            (b"Reload daemon failed: Interactive authentication required.\n", "interactive-auth-required"),
            (b"Reload daemon failed: SELinux policy denies access: Permission denied\n", "selinux-access-denied"),
            (b"Reload daemon failed: Access denied\n", "access-denied"),
            (b"Reload daemon failed: Connection timed out\n", "timeout"),
        )
        for payload, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(expected, self.classifier.reload_client_error(payload))
        self.assertEqual("unavailable", self.classifier.reload_client_error(b"unrelated\n"))

    def test_reload_stage_decision_matrix_is_finite(self) -> None:
        baseline = {
            "manager_continuity_observed": True,
            "manager_active": True,
            "bus_available": True,
            "control_reachable": True,
            "input_admitted": True,
            "generator_executed": True,
            "generator_accepted": True,
            "failures": [],
            "generator_ambiguous": False,
            "avc_observed": False,
            "avc_ambiguous": False,
            "run_space_observed": True,
            "run_space_sufficient": True,
            "client_error": "timeout",
            "reload_request_logged": True,
            "reload_rate_limit_rejected": False,
            "reload_started": True,
            "reload_finished": True,
            "reload_internal_failure": "none",
            "reload_reply_send_failed": False,
            "reload_journal_reason": "none",
            "reload_access_avc_observed": False,
            "reload_access_avc_ambiguous": False,
            "reload_selinux_contexts_admitted": True,
            "reload_access_avc_matches_contexts": True,
            "systemd_source_contract_admitted": True,
        }
        cases = (
            (
                "reload-run-space-rejected",
                {
                    "run_space_sufficient": False,
                    "client_error": "run-space-rejected",
                    "reload_request_logged": False,
                    "reload_started": False,
                    "reload_finished": False,
                },
            ),
            (
                "reload-selinux-access-denied",
                {
                    "reload_access_avc_observed": True,
                    "reload_request_logged": False,
                    "reload_started": False,
                    "reload_finished": False,
                },
            ),
            (
                "reload-authorization-denied",
                {
                    "client_error": "access-denied",
                    "reload_request_logged": False,
                    "reload_started": False,
                    "reload_finished": False,
                },
            ),
            (
                "reload-authorization-interactive-required",
                {
                    "client_error": "interactive-auth-required",
                    "reload_request_logged": False,
                    "reload_started": False,
                    "reload_finished": False,
                },
            ),
            (
                "reload-rate-limited",
                {
                    "client_error": "rate-limited",
                    "reload_rate_limit_rejected": True,
                    "reload_started": False,
                    "reload_finished": False,
                },
            ),
            (
                "reload-manager-serialization-failed",
                {
                    "reload_finished": False,
                    "reload_internal_failure": "serialization-file-failed",
                },
            ),
            ("reload-reply-transport-failed", {}),
        )
        for expected, mutation in cases:
            with self.subTest(expected=expected):
                classification, reason = self.classifier.daemon_reload_classification(
                    **{**baseline, **mutation}
                )
                self.assertEqual(expected, classification)
                self.assertEqual("none", reason)

        classification, reason = self.classifier.daemon_reload_classification(
            **{**baseline, "reload_journal_reason": "journal-timeout"}
        )
        self.assertEqual("diagnostic-unavailable", classification)
        self.assertEqual("reload-journal-timeout", reason)

        classification, reason = self.classifier.daemon_reload_classification(
            **{**baseline, "manager_continuity_observed": False}
        )
        self.assertEqual("diagnostic-unavailable", classification)
        self.assertEqual("manager-continuity-observation-unavailable", reason)

        classification, reason = self.classifier.daemon_reload_classification(
            **{
                **baseline,
                "run_space_sufficient": False,
                "client_error": "run-space-rejected",
                "reload_request_logged": False,
                "reload_started": False,
                "reload_finished": False,
                "reload_journal_reason": "journal-timeout",
            }
        )
        self.assertEqual("diagnostic-unavailable", classification)
        self.assertEqual("reload-journal-timeout", reason)

        classification, reason = self.classifier.daemon_reload_classification(
            **{
                **baseline,
                "reload_finished": False,
                "reload_internal_failure": "none",
            }
        )
        self.assertEqual("diagnostic-unavailable", classification)
        self.assertEqual("reload-completion-not-observed", reason)

        classification, reason = self.classifier.daemon_reload_classification(
            **{
                **baseline,
                "run_space_sufficient": False,
                "client_error": "access-denied",
                "reload_request_logged": False,
                "reload_started": False,
                "reload_finished": False,
            }
        )
        self.assertEqual("diagnostic-unavailable", classification)
        self.assertEqual("reload-stage-evidence-contradictory", reason)

        for client_error in ("access-denied", "interactive-auth-required"):
            with self.subTest(admitted_request_client_error=client_error):
                classification, reason = self.classifier.daemon_reload_classification(
                    **{**baseline, "client_error": client_error}
                )
                self.assertEqual("diagnostic-unavailable", classification)
                self.assertEqual("reload-stage-evidence-contradictory", reason)

        classification, reason = self.classifier.daemon_reload_classification(
            **{
                **baseline,
                "run_space_sufficient": False,
                "client_error": "run-space-rejected",
                "reload_request_logged": False,
            }
        )
        self.assertEqual("diagnostic-unavailable", classification)
        self.assertEqual("reload-stage-evidence-contradictory", reason)

        classification, reason = self.classifier.daemon_reload_classification(
            **{
                **baseline,
                "client_error": "selinux-access-denied",
            }
        )
        self.assertEqual("diagnostic-unavailable", classification)
        self.assertEqual("reload-stage-evidence-contradictory", reason)

        classification, reason = self.classifier.daemon_reload_classification(
            **{
                **baseline,
                "client_error": "rate-limited",
                "reload_request_logged": False,
                "reload_started": False,
                "reload_finished": False,
                "reload_access_avc_observed": True,
            }
        )
        self.assertEqual("diagnostic-unavailable", classification)
        self.assertEqual("reload-stage-evidence-contradictory", reason)

        classification, reason = self.classifier.daemon_reload_classification(
            **{
                **baseline,
                "client_error": "rate-limited",
                "reload_rate_limit_rejected": False,
            }
        )
        self.assertEqual("diagnostic-unavailable", classification)
        self.assertEqual("reload-stage-evidence-contradictory", reason)

        classification, reason = self.classifier.daemon_reload_classification(
            **{
                **baseline,
                "reload_internal_failure": "serialization-file-failed",
            }
        )
        self.assertEqual("diagnostic-unavailable", classification)
        self.assertEqual("reload-stage-evidence-contradictory", reason)

        classification, reason = self.classifier.daemon_reload_classification(
            **{
                **baseline,
                "client_error": "rate-limited",
                "reload_rate_limit_rejected": True,
            }
        )
        self.assertEqual("diagnostic-unavailable", classification)
        self.assertEqual("reload-stage-evidence-contradictory", reason)

        for client_error in ("access-denied", "interactive-auth-required"):
            with self.subTest(client_error=client_error):
                classification, reason = self.classifier.daemon_reload_classification(
                    **{
                        **baseline,
                        "client_error": client_error,
                        "reload_request_logged": False,
                    }
                )
                self.assertEqual("diagnostic-unavailable", classification)
                self.assertEqual("reload-stage-evidence-contradictory", reason)

        classification, reason = self.classifier.daemon_reload_classification(
            **{**baseline, "reload_selinux_contexts_admitted": False}
        )
        self.assertEqual("diagnostic-unavailable", classification)
        self.assertEqual("reload-selinux-context-observation-unavailable", reason)

        classification, reason = self.classifier.daemon_reload_classification(
            **{**baseline, "reload_access_avc_matches_contexts": False}
        )
        self.assertEqual("diagnostic-unavailable", classification)
        self.assertEqual("reload-selinux-observation-ambiguous", reason)

        classification, reason = self.classifier.daemon_reload_classification(
            **{**baseline, "systemd_source_contract_admitted": False}
        )
        self.assertEqual("diagnostic-unavailable", classification)
        self.assertEqual("systemd-source-contract-mismatch", reason)

    def test_reload_selinux_access_is_distinct_from_quadlet_avc(self) -> None:
        payload = b"""type=AVC msg=audit(1.2:3): avc:  denied  { reload } for  pid=7 scontext=system_u:system_r:unconfined_service_t:s0 tcontext=system_u:system_r:init_t:s0 tclass=system permissive=0
----
type=AVC msg=audit(1.3:4): avc:  denied  { read } for  pid=8 scontext=system_u:system_r:container_t:s0 tcontext=system_u:object_r:container_file_t:s0 tclass=file permissive=0
"""
        observed, avc, ambiguous = self.observer.reload_access_avc(payload, 7)
        self.assertTrue(observed)
        self.assertFalse(ambiguous)
        self.assertEqual(
            {
                "source_type": "unconfined_service_t",
                "target_type": "init_t",
                "object_class": "system",
                "denied_permission": "reload",
            },
            avc,
        )

        observed, avc, ambiguous = self.observer.reload_access_avc(payload, 9)
        self.assertFalse(observed)
        self.assertIsNone(avc)
        self.assertFalse(ambiguous)

        malformed = payload.replace(b"pid=7", b"pid=unknown")
        observed, avc, ambiguous = self.observer.reload_access_avc(malformed, 7)
        self.assertTrue(observed)
        self.assertIsNone(avc)
        self.assertTrue(ambiguous)

    def test_bounded_collector_distinguishes_io_failure_from_timeout(self) -> None:
        process = mock.Mock(pid=123)
        process.stdout.fileno.return_value = 9
        cases = (
            (OSError("journal read failed"), (125, b"", "command-failed")),
            (
                subprocess.TimeoutExpired(["journalctl"], 3),
                (124, b"", "timeout"),
            ),
        )
        for failure, expected in cases:
            with self.subTest(expected=expected), mock.patch.object(
                self.observer.subprocess, "Popen", return_value=process
            ), mock.patch.object(
                self.observer.os, "set_blocking"
            ), mock.patch.object(
                self.observer.select, "select", side_effect=failure
            ), mock.patch.object(
                self.observer, "terminate_group"
            ):
                result = self.observer.bounded_command_output(
                    ["journalctl"], timeout=3
                )
            self.assertEqual(expected, result)

    def test_manager_state_distinguishes_probe_failure_from_inactivity(self) -> None:
        cases = (
            ((125, b"", "command-failed"), (False, False, None)),
            ((0, b"ActiveState=inactive\nMainPID=0\n", None), (True, False, None)),
            ((0, b"ActiveState=active\nMainPID=1087\n", None), (True, True, 1087)),
        )
        for command_result, expected in cases:
            with self.subTest(expected=expected), mock.patch.object(
                self.observer,
                "bounded_command_output",
                return_value=command_result,
            ):
                self.assertEqual(expected, self.observer.manager_state(994))

    def test_observer_execution_failure_is_not_a_generator_rejection(self) -> None:
        with mock.patch.object(
            self.observer.subprocess,
            "Popen",
            side_effect=OSError("unavailable"),
        ), self.assertRaisesRegex(
            self.observer.ObservationError,
            "could not execute",
        ):
            self.observer.command_status(["fixed-diagnostic"])

        process = mock.Mock(pid=123)
        process.wait.side_effect = [
            self.observer.subprocess.TimeoutExpired(["fixed-diagnostic"], 3),
            self.observer.subprocess.TimeoutExpired(["fixed-diagnostic"], 2),
        ]
        with mock.patch.object(
            self.observer.subprocess,
            "Popen",
            return_value=process,
        ), mock.patch.object(
            self.observer.os,
            "killpg",
            side_effect=PermissionError("denied"),
        ), self.assertRaisesRegex(
            self.observer.ObservationError,
            "exceeded its timeout",
        ):
            self.observer.command_status(["fixed-diagnostic"])

    def test_trusted_packaged_generator_symlink_is_admitted(self) -> None:
        candidate = Path(
            "/usr/lib/systemd/user-generators/podman-system-generator"
        )
        resolved = Path("/usr/libexec/podman/quadlet")
        directory_metadata = mock.Mock(st_mode=0o040755, st_uid=0, st_gid=0)
        link_metadata = mock.Mock(st_mode=0o120777, st_uid=0, st_gid=0)
        executable_metadata = mock.Mock(st_mode=0o100755, st_uid=0, st_gid=0)

        def lstat(target: Path):
            return link_metadata if target == candidate else directory_metadata

        def resolve(target: Path, *, strict: bool):
            self.assertTrue(strict)
            return resolved if target == candidate else target

        with mock.patch.object(
            Path, "lstat", autospec=True, side_effect=lstat
        ), mock.patch.object(
            Path, "resolve", autospec=True, side_effect=resolve
        ), mock.patch.object(
            Path, "stat", autospec=True, return_value=executable_metadata
        ):
            self.assertEqual(
                candidate,
                self.observer.admitted_generator(candidate, podman=True),
            )

    def test_selinux_adjacency_emits_only_closed_correlated_fields(self) -> None:
        target_input = Path(
            "/etc/containers/systemd/users/994/"
            "secpal-host-qualification-Ab12Cd.container"
        )
        audit = (
            'type=AVC msg=audit(1.2:3): avc:  denied  { read } for '
            'comm="podman-system-g" '
            'scontext=system_u:system_r:container_runtime_t:s0 '
            'tcontext=system_u:object_r:etc_t:s0 tclass=file permissive=0\n'
        ).encode()
        observed, fields, ambiguous = self.observer.selinux_adjacency(
            audit, target_input, set()
        )
        self.assertTrue(observed)
        self.assertEqual(
            {
                "source_type": "container_runtime_t",
                "target_type": "etc_t",
                "object_class": "file",
                "denied_permission": "read",
            },
            fields,
        )
        self.assertFalse(ambiguous)

        unrelated = audit.replace(b'comm="podman-system-g"', b'comm="systemd"')
        observed, fields, ambiguous = self.observer.selinux_adjacency(
            unrelated, target_input, set()
        )
        self.assertFalse(observed)
        self.assertIsNone(fields)
        self.assertFalse(ambiguous)

    def test_exact_d892_quadlet_shape_has_one_bounded_deterministic_digest(self) -> None:
        unit_name = "secpal-host-qualification-Ab12Cd"
        image = (
            "docker.io/library/alpine@sha256:"
            "4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1"
        )
        payload = (
            "[Unit]\n"
            "Description=SecPal bounded Rocky host qualification fixture\n"
            "[Container]\n"
            f"Image={image}\n"
            f"ContainerName={unit_name}\n"
            "Pull=never\n"
            "User=65532:65532\n"
            "DropCapability=all\n"
            "Network=none\n"
            "Exec=sleep infinity\n"
            "PodmanArgs=--security-opt=no-new-privileges\n"
            "[Service]\n"
            "TimeoutStopSec=15\n"
        ).encode()
        self.assertLessEqual(len(payload), self.observer.MAX_INPUT_BYTES)
        self.assertEqual(
            "f79c269f607174feb6bbdc4d553f0881f536243f265e2d71c998ebfdcd769fff",
            hashlib.sha256(payload).hexdigest(),
        )
        self.assertNotIn(b"AutoUpdate=", payload)
        self.assertNotIn(b"Privileged=true", payload)

    def test_diagnostic_ack_failure_preserves_original_status_and_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            harness = root / "qualify-production-host.sh"
            target_input = root / "fixture.container"
            trace = root / "trace"
            lines = ["set -euo pipefail"] + [""] * 241
            for line_number, source in {
                52: "user_systemctl() {",
                53: "  return 7",
                54: "}",
                62: "cleanup() {",
                63: "  local exit_status=$?",
                64: '  rm -f -- "$FIXTURE_INPUT"',
                65: '  exit "$exit_status"',
                66: "}",
                204: "trap cleanup EXIT",
                216: 'printf "actual input\\n" >"$FIXTURE_INPUT"',
                242: "user_systemctl daemon-reload",
            }.items():
                lines[line_number - 1] = source
            harness.write_text("\n".join(lines) + "\n", encoding="utf-8")
            event_read, event_write = os.pipe()
            ack_read, ack_write = os.pipe()

            def fail_observation() -> None:
                with os.fdopen(event_read, "rb", closefd=True) as events:
                    events.readline(512)
                os.close(ack_write)

            observer = threading.Thread(target=fail_observation)
            observer.start()
            with trace.open("wb") as descriptor:
                process = subprocess.Popen(
                    ["bash", harness],
                    env={
                        **os.environ,
                        "BASH_ENV": str(TRACE),
                        "FIXTURE_INPUT": str(target_input),
                    },
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    pass_fds=tuple(
                        {3, 4, 5, descriptor.fileno(), event_write, ack_read}
                    ),
                    close_fds=True,
                    preexec_fn=lambda: (
                        os.dup2(descriptor.fileno(), 3),
                        os.dup2(event_write, 4),
                        os.dup2(ack_read, 5),
                    ),
                )
                os.close(event_write)
                os.close(ack_read)
                self.assertEqual(7, process.wait(timeout=10))
            observer.join(timeout=10)
            self.assertFalse(observer.is_alive())
            self.assertFalse(target_input.exists())
            records = trace.read_text(encoding="ascii").splitlines()
            self.assertEqual(1, len(records))
            self.assertRegex(records[0], r"^SECPAL_TARGET_ERR_V2:7:")

    def test_reachable_bash_control_constructs_preserve_closed_diagnostics(self) -> None:
        definitions = {
            39: "run_as_service_account() {",
            40: "  false",
            41: "}",
            48: "rootless_podman() {",
            49: "  run_as_service_account",
            50: "}",
        }
        for call_line, command, operation in (
            (183, 'value="$(rootless_podman)"', "qualify-rootless-runtime"),
            (271, "rootless_podman | cat", "qualify-selinux-storage"),
        ):
            lines = ["set -eEuo pipefail"] + [""] * (call_line - 1)
            for line_number, source in definitions.items():
                lines[line_number - 1] = source
            lines[call_line - 1] = command
            with self.subTest(operation=operation):
                result, trace = self.run_traced_bash("\n".join(lines) + "\n")
                self.assertEqual(1, result.returncode)
                self.assertEqual(
                    (operation, "command-failed"),
                    self.classify(trace=trace),
                )

        conditional = (
            "set -eEuo pipefail\nhelper() { false; }\n"
            "if ! helper; then\n"
            "  printf 'ERROR: service-account home is not usable by secpal-runtime\\n'\n"
            "  exit 1\n"
            "fi\n"
        )
        result, trace = self.run_traced_bash(conditional)
        self.assertEqual(1, result.returncode)
        self.assertEqual("", trace)
        self.assertEqual(
            ("qualify-service-account", "invariant-failed"),
            self.classify(result.stdout.decode("utf-8"), trace),
        )

    def test_every_reviewed_semantic_surface_has_an_exact_failure_identity(self) -> None:
        cases = (
            ("NOT RUN: Rocky Linux 10.2 native qualification requires ID=rocky", "", "qualify-host-identity", "invariant-failed"),
            ("ERROR: native qualification must run as an administrator on the disposable qualification host.", "", "qualify-administrator-execution", "invariant-failed"),
            ("ERROR: --image must be a fully qualified, pre-staged digest reference.", "", "qualify-fixture-reference", "invariant-failed"),
            ("ERROR: required service account does not exist: secpal-runtime", "", "qualify-service-account", "invariant-failed"),
            ("ERROR: SELinux is not Enforcing.", "", "qualify-selinux-host", "invariant-failed"),
            ("", "SECPAL_TARGET_ERR_V2:1:162", "qualify-package-prerequisites", "command-failed"),
            ("ERROR: unsupported native architecture: ppc64le", "", "qualify-native-architecture", "invariant-failed"),
            ("ERROR: unified cgroup v2 is not effective.", "", "qualify-cgroup", "invariant-failed"),
            ("ERROR: rootless Podman does not select crun.", "", "qualify-rootless-runtime", "invariant-failed"),
            ("ERROR: digest-only fixture image is not pre-staged for the service account.", "", "qualify-fixture-presence", "invariant-failed"),
            ("", "SECPAL_TARGET_ERR_V2:1:196", "qualify-fixture-setup", "command-failed"),
            ("ERROR: service account can write the administrator Quadlet directory.", "", "qualify-quadlet-authority", "invariant-failed"),
            ("", "SECPAL_TARGET_ERR_V2:1:242", "qualify-quadlet-daemon-reload", "command-failed"),
            ("", "SECPAL_TARGET_ERR_V2:1:243", "qualify-quadlet-start", "command-failed"),
            ("", "SECPAL_TARGET_ERR_V2:1:244", "qualify-quadlet-active-state", "command-failed"),
            ("", "SECPAL_TARGET_ERR_V2:1:249", "qualify-selinux-storage-directory-create", "command-failed"),
            ("", "SECPAL_TARGET_ERR_V2:1:250", "qualify-selinux-storage-fcontext-add", "command-failed"),
            ("", "SECPAL_TARGET_ERR_V2:1:252", "qualify-selinux-storage-restorecon", "command-failed"),
            ("", "SECPAL_TARGET_ERR_V2:1:253", "qualify-selinux-storage-matchpathcon", "command-failed"),
            ("ERROR: representative process or storage label is not container-confined.", "", "qualify-selinux-storage", "invariant-failed"),
            ("", "SECPAL_TARGET_ERR_V2:1:257", "qualify-workload-primary", "command-failed"),
            ("ERROR: representative rootless workload is not effectively seccomp-confined.", "", "qualify-seccomp", "invariant-failed"),
            ("", "SECPAL_TARGET_ERR_V2:1:269", "qualify-workload-secondary", "command-failed"),
            ("ERROR: representative SELinux MCS boundaries are not distinct and effective.", "", "qualify-mcs-relationship", "invariant-failed"),
            ("ERROR: cross-boundary read unexpectedly succeeded.", "", "qualify-cross-mcs-denial", "invariant-failed"),
            ("ERROR: cross-boundary failure lacks a matching SELinux AVC denial.", "", "qualify-avc-correlation", "invariant-failed"),
            ("ERROR: unable to restore SELinux dontaudit policy.", "", "qualify-selinux-policy-restoration", "command-failed"),
            ("ERROR: effective runtime facts contain a forbidden security fallback.", "", "qualify-runtime-fallback-absence", "invariant-failed"),
            ("", "", "qualify-fixture-cleanup", "cleanup-failed", "qualify-fixture-cleanup cleanup-failed"),
        )
        observed = set()
        for case in cases:
            with self.subTest(operation=case[2]):
                output, trace, operation, reason, *marker = case
                result = self.classify(
                    output,
                    trace,
                    marker=marker[0] if marker else None,
                )
                self.assertEqual((operation, reason), result)
                observed.add(operation)
        self.assertEqual(self.classifier.OPERATIONS - {"qualification-harness"}, observed)

    def test_unknown_ambiguous_and_unbound_failures_are_never_guessed(self) -> None:
        self.assertEqual(
            ("qualification-harness", "unclassified-target-failure"),
            self.classify("unexpected target failure"),
        )
        self.assertEqual(
            ("qualification-harness", "unclassified-target-failure"),
            self.classify(
                "ERROR: SELinux is not Enforcing.\n"
                "ERROR: unified cgroup v2 is not effective."
            ),
        )
        self.assertEqual(
            ("qualification-harness", "representation-invalid"),
            self.classify(target_bound=False),
        )
        self.assertEqual(
            ("qualification-harness", "unclassified-target-failure"),
            self.classify(trace="SECPAL_TARGET_ERR_V2:1:243,257"),
        )

    def test_timeout_and_malformed_representations_fail_closed(self) -> None:
        self.assertEqual(
            ("qualification-harness", "timeout"),
            self.classify(status=124),
        )
        self.assertEqual(
            ("qualification-harness", "representation-invalid"),
            self.classifier.classify_failure(
                b"\xff", b"", 1, target_bound=True, trusted_marker=None
            ),
        )

    def test_every_reviewed_message_and_call_site_has_a_closed_mapping(self) -> None:
        for prefix, operation, reason in self.classifier.EXPLICIT_RULES:
            with self.subTest(prefix=prefix):
                self.assertEqual((operation, reason), self.classify(prefix))
        for first, last, operation in self.classifier.HISTORICAL_LINE_RULES:
            with self.subTest(line=first):
                self.assertEqual(
                    (operation, "command-failed"),
                    self.classify(trace=f"SECPAL_TARGET_ERR_V2:1:{first}"),
                )
                self.assertLessEqual(first, last)

    def test_bash_env_trace_records_only_numeric_failure_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            harness = root / "harness.sh"
            trace = root / "trace"
            harness.write_text("set -euo pipefail\nfalse\n", encoding="utf-8")
            with trace.open("wb") as descriptor:
                result = subprocess.run(
                    ["bash", harness],
                    check=False,
                    env={**os.environ, "BASH_ENV": str(TRACE)},
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    pass_fds=(descriptor.fileno(),),
                    close_fds=True,
                    preexec_fn=lambda: os.dup2(descriptor.fileno(), 3),
                )
            self.assertEqual(1, result.returncode)
            self.assertRegex(
                trace.read_text(encoding="ascii"),
                r"^SECPAL_TARGET_ERR_V2:1:[0-9]+(?:,[0-9]+){0,7}\n$",
            )

    def test_helper_frames_resolve_only_through_reviewed_outer_call_sites(self) -> None:
        cases = (
            ("qualify-rootless-runtime", (40, 49, 183)),
            ("qualify-quadlet-daemon-reload", (53, 242)),
            ("qualify-quadlet-start", (53, 243)),
            ("qualify-quadlet-active-state", (53, 244)),
            ("qualify-workload-primary", (40, 49, 257)),
            ("qualify-workload-secondary", (40, 49, 269)),
            ("qualify-selinux-storage", (40, 49, 271)),
        )
        for operation, frames in cases:
            with self.subTest(operation=operation):
                trace = "SECPAL_TARGET_ERR_V2:1:" + ",".join(map(str, frames))
                self.assertEqual(
                    (operation, "command-failed"), self.classify(trace=trace)
                )
                for helper_line in frames[:-1]:
                    self.assertIsNone(self.classifier.operation_for_line(helper_line))

        self.assertEqual(
            ("qualify-service-account", "invariant-failed"),
            self.classify("ERROR: service-account home is not usable by secpal-runtime"),
        )
        explicit_conditionals = (
            (
                "ERROR: digest-only fixture image is not pre-staged",
                "qualify-fixture-presence",
            ),
            (
                "ERROR: cross-boundary read unexpectedly succeeded.",
                "qualify-cross-mcs-denial",
            ),
            (
                "ERROR: cross-boundary failure lacks a matching SELinux AVC denial.",
                "qualify-avc-correlation",
            ),
            (
                "ERROR: effective runtime facts contain a forbidden security fallback.",
                "qualify-runtime-fallback-absence",
            ),
        )
        for message, operation in explicit_conditionals:
            self.assertEqual(
                (operation, "invariant-failed"), self.classify(message)
            )

    def test_same_operation_frames_agree_but_different_operations_are_ambiguous(self) -> None:
        self.assertEqual(
            ("qualify-rootless-runtime", "command-failed"),
            self.classify(trace="SECPAL_TARGET_ERR_V2:1:40,49,183,187"),
        )
        self.assertEqual(
            ("qualification-harness", "unclassified-target-failure"),
            self.classify(trace="SECPAL_TARGET_ERR_V2:1:183,243"),
        )
        for line, operation in (
            (242, "qualify-quadlet-daemon-reload"),
            (243, "qualify-quadlet-start"),
            (244, "qualify-quadlet-active-state"),
        ):
            with self.subTest(operation=operation):
                self.assertEqual(
                    (operation, "command-failed"),
                    self.classify(
                        trace=f"SECPAL_TARGET_ERR_V2:1:{line},{line}"
                    ),
                )
        for frames in ("242,243", "243,244", "242,244"):
            with self.subTest(frames=frames):
                self.assertEqual(
                    ("qualification-harness", "unclassified-target-failure"),
                    self.classify(trace=f"SECPAL_TARGET_ERR_V2:1:{frames}"),
                )

    def test_selinux_storage_setup_lines_have_distinct_closed_operations(self) -> None:
        operations = (
            (249, "qualify-selinux-storage-directory-create"),
            (250, "qualify-selinux-storage-fcontext-add"),
            (252, "qualify-selinux-storage-restorecon"),
            (253, "qualify-selinux-storage-matchpathcon"),
        )
        for line, operation in operations:
            with self.subTest(line=line):
                self.assertEqual(
                    (operation, "command-failed"),
                    self.classify(trace=f"SECPAL_TARGET_ERR_V2:1:{line}"),
                )
        for index, first in enumerate(operations):
            for second in operations[index + 1 :]:
                with self.subTest(lines=(first[0], second[0])):
                    self.assertEqual(
                        ("qualification-harness", "unclassified-target-failure"),
                        self.classify(
                            trace=f"SECPAL_TARGET_ERR_V2:1:{first[0]},{second[0]}"
                        ),
                    )

    def test_semanage_fcontext_add_reasons_are_closed_and_path_free(self) -> None:
        roots = (
            "/var/tmp/secpal-host-qualification-a1B2c3",
            "/var/tmp/secpal-host-qualification-Z9y8X7",
        )
        cases = (
            ("SELinux policy is not managed or store cannot be accessed.", "semanage-store-access-failed"),
            ("Cannot read policy store.", "semanage-store-access-failed"),
            ("Could not establish semanage connection", "semanage-store-access-failed"),
            ("Could not test MLS enabled status", "semanage-store-access-failed"),
            ("Could not start semanage transaction", "semanage-transaction-begin-failed"),
            ("Could not create key for {expression}", "semanage-fcontext-key-create-failed"),
            ("Could not check if file context for {expression} is defined", "semanage-fcontext-existence-check-failed"),
            ("Could not create file context for {expression}", "semanage-fcontext-record-create-failed"),
            ("Could not create context for {expression}", "semanage-fcontext-context-create-failed"),
            ("Could not set type in file context for {expression}", "semanage-fcontext-type-set-failed"),
            ("Could not set file context for {expression}", "semanage-fcontext-context-attach-failed"),
            ("Could not add file context for {expression}", "semanage-fcontext-local-add-failed"),
            ("Could not commit semanage transaction", "semanage-transaction-commit-failed"),
        )
        for root in roots:
            expression = root + "(/.*)?"
            for shape, reason in cases:
                with self.subTest(root=root, reason=reason):
                    output = "ValueError: " + shape.format(expression=expression)
                    operation, actual_reason = self.classify(
                        output,
                        "SECPAL_TARGET_ERR_V2:1:250",
                    )
                    self.assertEqual("qualify-selinux-storage-fcontext-add", operation)
                    self.assertEqual(reason, actual_reason)
                    self.assertNotIn(root, actual_reason)
                    self.assertNotIn(expression, actual_reason)
                    self.assertEqual(
                        reason,
                        self.classify(output + "\n", "SECPAL_TARGET_ERR_V2:1:250")[1],
                    )

    def test_semanage_fcontext_add_equivalency_is_closed_and_path_free(self) -> None:
        expression = "/var/tmp/secpal-host-qualification-a1B2c3(/.*)?"
        output = (
            "ValueError: File spec " + expression
            + " conflicts with equivalency rule '/var/tmp /home'; Try adding '/home(/.*)?' instead"
        )
        self.assertEqual(
            ("qualify-selinux-storage-fcontext-add", "semanage-fcontext-equivalency-conflict"),
            self.classify(output, "SECPAL_TARGET_ERR_V2:1:250"),
        )

    def test_semanage_fcontext_add_rejects_near_matches_wrong_operations_and_unknowns(self) -> None:
        expression = "/var/tmp/secpal-host-qualification-a1B2c3(/.*)?"
        exact = "ValueError: Could not add file context for " + expression
        rejected = (
            "prefix " + exact,
            exact + " suffix",
            "ValueError: Could not add file context for /var/tmp/unrelated(/.*)?",
            "ValueError: arbitrary failure for " + expression,
            "RuntimeError: Could not add file context for " + expression,
        )
        for output in rejected:
            with self.subTest(output=output):
                self.assertEqual(
                    ("qualify-selinux-storage-fcontext-add", "command-failed"),
                    self.classify(output, "SECPAL_TARGET_ERR_V2:1:250"),
                )
        for line in (249, 252, 253):
            with self.subTest(line=line):
                self.assertEqual(
                    (self.classifier.operation_for_line(line, self.classifier.HISTORICAL_LINE_RULES), "command-failed"),
                    self.classify(exact, f"SECPAL_TARGET_ERR_V2:1:{line}"),
                )

    def test_explicit_message_and_stack_must_agree(self) -> None:
        self.assertEqual(
            ("qualify-selinux-host", "invariant-failed"),
            self.classify(
                "ERROR: SELinux is not Enforcing.",
                "SECPAL_TARGET_ERR_V2:1:153",
            ),
        )
        self.assertEqual(
            ("qualification-harness", "unclassified-target-failure"),
            self.classify(
                "ERROR: SELinux is not Enforcing.",
                "SECPAL_TARGET_ERR_V2:1:179",
            ),
        )

    def test_v2_trace_bounds_and_unknown_frames_fail_closed(self) -> None:
        self.assertEqual(
            ("qualification-harness", "unclassified-target-failure"),
            self.classify(trace="SECPAL_TARGET_ERR_V2:1:40,49,9999"),
        )
        malformed = (
            "SECPAL_TARGET_ERR_V1:183:1",
            "SECPAL_TARGET_ERR_V2:0:183",
            "SECPAL_TARGET_ERR_V2:2:183",
            "SECPAL_TARGET_ERR_V2:1:183,command",
            "SECPAL_TARGET_ERR_V2:1:" + ",".join(["183"] * 9),
        )
        for trace in malformed:
            with self.subTest(trace=trace):
                self.assertEqual(
                    ("qualification-harness", "representation-invalid"),
                    self.classify(trace=trace),
                )
        self.assertEqual(
            ("qualification-harness", "representation-invalid"),
            self.classify(
                "ERROR: SELinux is not Enforcing.",
                "SECPAL_TARGET_ERR_V1:153:1",
            ),
        )

    def test_failure_schema_is_closed_bounded_and_run_bound(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        self.assertEqual(
            self.classifier.OPERATIONS,
            set(schema["properties"]["operation"]["enum"]),
        )
        self.assertEqual(
            self.classifier.REASONS,
            set(schema["properties"]["reason"]["enum"]),
        )
        self.assertNotIn(
            "manager-reload-transaction-failed",
            schema["properties"]["daemon_reload_adjacency"]["properties"]
            ["classification"]["enum"],
        )
        document = {
            "schema_version": 1,
            "phase": "target-qualification",
            "target_sha": self.classifier.EXPECTED_TARGET_SHA,
            "trusted_control_sha": "c" * 40,
            "qualification_run_id": "12345",
            "qualification_run_attempt": "1",
            "harness_sha256": self.classifier.EXPECTED_HARNESS_SHA256,
            "operation": "qualify-seccomp",
            "reason": "invariant-failed",
            "exit_status": 1,
            "diagnostic_input_sha256": "b" * 64,
            "diagnostic_input_bytes": 100,
        }
        self.assertEqual([], list(validator.iter_errors(document)))
        for mutation in (
            dict(document, stdout="untrusted"),
            dict(document, operation="arbitrary-command"),
            dict(document, reason="some-error-text"),
            dict(document, qualification_run_id="0"),
            dict(document, diagnostic_input_bytes=135_425),
        ):
            self.assertTrue(list(validator.iter_errors(mutation)))
        historical_semanage_document = dict(
            document,
            target_sha=self.classifier.HISTORICAL_TARGET_SHA,
            harness_sha256=self.classifier.HISTORICAL_HARNESS_SHA256,
            operation="qualify-selinux-storage-fcontext-add",
            reason="semanage-fcontext-local-add-failed",
        )
        self.assertEqual([], list(validator.iter_errors(historical_semanage_document)))
        self.assertTrue(
            list(
                validator.iter_errors(
                    dict(
                        historical_semanage_document,
                        operation="qualify-selinux-storage-restorecon",
                    )
                )
            )
        )
        for mixed_authority in (
            dict(document, harness_sha256=self.classifier.HISTORICAL_HARNESS_SHA256),
            dict(historical_semanage_document, harness_sha256=self.classifier.EXPECTED_HARNESS_SHA256),
        ):
            with self.subTest(mixed_authority=mixed_authority):
                self.assertTrue(list(validator.iter_errors(mixed_authority)))
        self.assertTrue(
            list(
                validator.iter_errors(
                    dict(
                        document,
                        operation="qualify-selinux-storage-fcontext-add",
                        reason="semanage-fcontext-local-add-failed",
                    )
                )
            )
        )
        unbound = dict(
            document,
            harness_sha256="a" * 64,
            operation="qualification-harness",
            reason="representation-invalid",
        )
        self.assertEqual([], list(validator.iter_errors(unbound)))
        self.assertTrue(
            list(
                validator.iter_errors(
                    dict(unbound, operation="qualify-seccomp", reason="invariant-failed")
                )
            )
        )

        daemon_reload = dict(
            document,
            operation="qualify-quadlet-daemon-reload",
            reason="command-failed",
        )
        self.assertTrue(
            list(validator.iter_errors(daemon_reload)),
            "the exact daemon-reload failure must carry its pre-cleanup adjacency",
        )

    def test_trusted_validator_binds_the_exact_control_target_and_run(self) -> None:
        document = {
            "schema_version": 1,
            "phase": "target-qualification",
            "target_sha": self.classifier.EXPECTED_TARGET_SHA,
            "trusted_control_sha": "c" * 40,
            "qualification_run_id": "12345",
            "qualification_run_attempt": "1",
            "harness_sha256": self.classifier.EXPECTED_HARNESS_SHA256,
            "operation": "qualify-seccomp",
            "reason": "invariant-failed",
            "exit_status": 1,
            "diagnostic_input_sha256": "b" * 64,
            "diagnostic_input_bytes": 100,
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "failure.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            command = [
                CONTROL,
                "validate-target-qualification-failure",
                path,
                "--target-sha",
                self.classifier.EXPECTED_TARGET_SHA,
                "--control-sha",
                "c" * 40,
                "--run-id",
                "12345",
                "--run-attempt",
                "1",
            ]
            self.assertEqual(
                0,
                subprocess.run(command, check=False, capture_output=True).returncode,
            )
            command[-1] = "2"
            self.assertNotEqual(
                0,
                subprocess.run(command, check=False, capture_output=True).returncode,
            )
            document["harness_sha256"] = self.classifier.HISTORICAL_HARNESS_SHA256
            path.write_text(json.dumps(document), encoding="utf-8")
            command[-1] = "1"
            self.assertNotEqual(
                0,
                subprocess.run(command, check=False, capture_output=True).returncode,
            )

    def test_trusted_validator_recomputes_daemon_reload_classification(self) -> None:
        observation = {
            "schema_version": 1,
            "target_sha": self.classifier.EXPECTED_TARGET_SHA,
            "trusted_control_sha": "c" * 40,
            "qualification_run_id": "12345",
            "qualification_run_attempt": "1",
            "boot_id": "12345678-1234-1234-1234-123456789abc",
            "failure_status": 1,
            "failure_event_sha256": "e" * 64,
            "captured_before_cleanup": True,
            "capture_monotonic_ns": 123456789,
            "manager_continuity_observed": True,
            "manager_active_after_reload_failure": True,
            "bus_available_after_reload_failure": True,
            "control_reachable_after_reload_failure": True,
            **self.reload_observation_fields(),
            "quadlet_input": {
                "match_count": 1,
                "present": True,
                "regular_file": True,
                "not_symlink": True,
                "owner_uid": 0,
                "owner_gid": 0,
                "mode": "0644",
                "size": 320,
                "sha256": "a" * 64,
            },
            "podman_generator_executed": True,
            "podman_generator_exit_status": 0,
            "podman_generator_accepted_actual_input": True,
            "generator_failures": [],
            "generator_failure_ambiguous": False,
            "generator_observation_reason": "none",
            "selinux_avc_observed": False,
            "selinux_avc": None,
            "selinux_avc_ambiguous": False,
        }
        adjacency = self.classifier.admit_daemon_reload_adjacency(
            observation,
            {
                "target_sha": self.classifier.EXPECTED_TARGET_SHA,
                "trusted_control_sha": "c" * 40,
                "qualification_run_id": "12345",
                "qualification_run_attempt": "1",
                "failure_status": 1,
            },
            "timeout",
        )
        document = {
            "schema_version": 1,
            "phase": "target-qualification",
            "target_sha": self.classifier.EXPECTED_TARGET_SHA,
            "trusted_control_sha": "c" * 40,
            "qualification_run_id": "12345",
            "qualification_run_attempt": "1",
            "harness_sha256": self.classifier.EXPECTED_HARNESS_SHA256,
            "operation": "qualify-quadlet-daemon-reload",
            "reason": "command-failed",
            "exit_status": 1,
            "diagnostic_input_sha256": "b" * 64,
            "diagnostic_input_bytes": 100,
            "daemon_reload_adjacency": adjacency,
        }
        validator = Draft202012Validator(
            json.loads(SCHEMA.read_text(encoding="utf-8"))
        )
        self.assertEqual([], list(validator.iter_errors(document)))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "failure.json"
            command = [
                CONTROL,
                "validate-target-qualification-failure",
                path,
                "--target-sha",
                self.classifier.EXPECTED_TARGET_SHA,
                "--control-sha",
                "c" * 40,
                "--run-id",
                "12345",
                "--run-attempt",
                "1",
            ]
            path.write_text(json.dumps(document), encoding="utf-8")
            self.assertEqual(
                0, subprocess.run(command, check=False, capture_output=True).returncode
            )
            document["daemon_reload_adjacency"]["classification"] = (
                "target-input-invalid"
            )
            path.write_text(json.dumps(document), encoding="utf-8")
            self.assertNotEqual(
                0, subprocess.run(command, check=False, capture_output=True).returncode
            )

    def test_canonical_validator_accepts_the_bootstrap_installed_classifier_name(
        self,
    ) -> None:
        """The extensionless installed classifier is the guest representation."""
        observation = {
            "schema_version": 1,
            "target_sha": self.classifier.EXPECTED_TARGET_SHA,
            "trusted_control_sha": "c" * 40,
            "qualification_run_id": "12345",
            "qualification_run_attempt": "1",
            "boot_id": "12345678-1234-1234-1234-123456789abc",
            "failure_status": 1,
            "failure_event_sha256": "e" * 64,
            "captured_before_cleanup": True,
            "capture_monotonic_ns": 123456789,
            "manager_continuity_observed": True,
            "manager_active_after_reload_failure": True,
            "bus_available_after_reload_failure": True,
            "control_reachable_after_reload_failure": True,
            **self.reload_observation_fields(),
            "quadlet_input": {
                "match_count": 1,
                "present": True,
                "regular_file": True,
                "not_symlink": True,
                "owner_uid": 0,
                "owner_gid": 0,
                "mode": "0644",
                "size": 320,
                "sha256": "a" * 64,
            },
            "podman_generator_executed": True,
            "podman_generator_exit_status": 0,
            "podman_generator_accepted_actual_input": True,
            "generator_failures": [],
            "generator_failure_ambiguous": False,
            "generator_observation_reason": "none",
            "selinux_avc_observed": False,
            "selinux_avc": None,
            "selinux_avc_ambiguous": False,
        }
        adjacency = self.classifier.admit_daemon_reload_adjacency(
            observation,
            {
                "target_sha": self.classifier.EXPECTED_TARGET_SHA,
                "trusted_control_sha": "c" * 40,
                "qualification_run_id": "12345",
                "qualification_run_attempt": "1",
                "failure_status": 1,
            },
            "timeout",
        )
        document = {
            "schema_version": 1,
            "phase": "target-qualification",
            "target_sha": self.classifier.EXPECTED_TARGET_SHA,
            "trusted_control_sha": "c" * 40,
            "qualification_run_id": "12345",
            "qualification_run_attempt": "1",
            "harness_sha256": self.classifier.EXPECTED_HARNESS_SHA256,
            "operation": "qualify-quadlet-daemon-reload",
            "reason": "command-failed",
            "exit_status": 1,
            "diagnostic_input_sha256": "b" * 64,
            "diagnostic_input_bytes": 100,
            "daemon_reload_adjacency": adjacency,
        }
        control = load_rocky_control()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository_classifier = (
                root
                / "repository/scripts/ci-cloud"
                / "classify-rocky-target-qualification-failure.py"
            )
            repository_classifier.parent.mkdir(parents=True)
            classifier_bytes = CLASSIFIER.read_bytes()
            repository_classifier.write_bytes(classifier_bytes)
            installed_classifier = root / "secpal-classify-rocky-target-failure"
            installed_classifier.write_bytes(classifier_bytes)
            installed_classifier.chmod(0o700)
            document_path = root / "failure.json"
            document_path.write_text(json.dumps(document), encoding="utf-8")

            with mock.patch.object(control, "ROOT", root / "repository"):
                control.validate_target_qualification_failure(
                    document_path,
                    self.classifier.EXPECTED_TARGET_SHA,
                    "c" * 40,
                    "12345",
                    "1",
                )
                malformed = json.loads(json.dumps(document))
                malformed["daemon_reload_adjacency"]["classification"] = (
                    "target-input-invalid"
                )
                document_path.write_text(json.dumps(malformed), encoding="utf-8")
                with self.assertRaises(control.ControlError):
                    control.validate_target_qualification_failure(
                        document_path,
                        self.classifier.EXPECTED_TARGET_SHA,
                        "c" * 40,
                        "12345",
                        "1",
                    )
                document_path.write_text(json.dumps(document), encoding="utf-8")

            with (
                mock.patch.object(control, "ROOT", root / "missing-repository"),
                mock.patch.object(
                    control, "INSTALLED_TARGET_FAILURE_CLASSIFIER", installed_classifier
                ),
                mock.patch.object(control, "CLASSIFIER_TRUSTED_UID", os.getuid()),
                mock.patch.object(control, "CLASSIFIER_TRUSTED_GID", os.getgid()),
            ):
                control.validate_target_qualification_failure(
                    document_path,
                    self.classifier.EXPECTED_TARGET_SHA,
                    "c" * 40,
                    "12345",
                    "1",
                )

                malformed = json.loads(json.dumps(document))
                malformed["daemon_reload_adjacency"]["classification"] = (
                    "target-input-invalid"
                )
                document_path.write_text(json.dumps(malformed), encoding="utf-8")
                with self.assertRaises(control.ControlError):
                    control.validate_target_qualification_failure(
                        document_path,
                        self.classifier.EXPECTED_TARGET_SHA,
                        "c" * 40,
                        "12345",
                        "1",
                    )

                document["daemon_reload_adjacency"] = (
                    self.classifier.unavailable_daemon_reload_adjacency()
                )
                document_path.write_text(json.dumps(document), encoding="utf-8")
                control.validate_target_qualification_failure(
                    document_path,
                    self.classifier.EXPECTED_TARGET_SHA,
                    "c" * 40,
                    "12345",
                    "1",
                )

    def test_installed_classifier_loader_fails_closed_on_path_and_module_mutations(
        self,
    ) -> None:
        control = load_rocky_control()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            installed = root / "secpal-classify-rocky-target-failure"
            installed.write_bytes(CLASSIFIER.read_bytes())
            installed.chmod(0o700)

            def load(path: Path):
                with (
                    mock.patch.object(control, "ROOT", root / "missing-repository"),
                    mock.patch.object(control, "INSTALLED_TARGET_FAILURE_CLASSIFIER", path),
                    mock.patch.object(control, "CLASSIFIER_TRUSTED_UID", os.getuid()),
                    mock.patch.object(control, "CLASSIFIER_TRUSTED_GID", os.getgid()),
                ):
                    return control.load_target_failure_classifier()

            self.assertTrue(
                callable(
                    getattr(
                        load(installed),
                        "validate_admitted_daemon_reload_adjacency",
                    )
                )
            )
            self.assertFalse((root / "__pycache__").exists())

            substitute = root / "secpal_target_qualification_failure.py"
            substitute.write_text("raise RuntimeError('substituted')\n", encoding="utf-8")
            with mock.patch.object(sys, "path", [str(root), *sys.path]):
                self.assertEqual(str(installed), load(installed).__file__)

            for writable_mode in (0o720, 0o707):
                installed.chmod(writable_mode)
                with self.assertRaisesRegex(
                    control.ControlError, "representation is invalid"
                ):
                    load(installed)
            installed.chmod(0o700)

            with self.assertRaisesRegex(control.ControlError, "is unavailable"):
                load(root / "wrong-installed-classifier")

            syntax_error = root / "syntax-error"
            syntax_error.write_text("not valid python!", encoding="utf-8")
            syntax_error.chmod(0o700)
            with self.assertRaisesRegex(control.ControlError, "cannot be loaded"):
                load(syntax_error)

            missing_symbol = root / "missing-symbol"
            missing_symbol.write_text("value = 1\n", encoding="utf-8")
            missing_symbol.chmod(0o700)
            with self.assertRaisesRegex(control.ControlError, "cannot be loaded"):
                load(missing_symbol)

            non_callable_symbol = root / "non-callable-symbol"
            non_callable_symbol.write_text(
                "validate_admitted_daemon_reload_adjacency = object()\n",
                encoding="utf-8",
            )
            non_callable_symbol.chmod(0o700)
            with self.assertRaisesRegex(control.ControlError, "cannot be loaded"):
                load(non_callable_symbol)

            replacement = root / "replacement"
            replacement.write_bytes(CLASSIFIER.read_bytes())
            replacement.chmod(0o700)
            symlink = root / "symlink"
            symlink.symlink_to(replacement)
            with self.assertRaisesRegex(
                control.ControlError, "representation is invalid"
            ):
                load(symlink)

    def test_success_and_failure_transport_are_disjoint(self) -> None:
        workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
        steps = {
            step["name"]: step
            for step in workflow["jobs"]["qualify_target"]["steps"]
            if "name" in step
        }
        failure = steps["Retrieve and validate bounded target-qualification failure"]
        success = steps["Retrieve and validate target-owned qualification evidence"]
        self.assertIn("qualification_failure_expected == 'true'", failure["if"])
        self.assertEqual(
            "${{ steps.target_execution.outcome == 'success' }}", success["if"]
        )
        self.assertNotIn("qualification.json", failure["run"])
        self.assertNotIn("target-qualification-failure.json", success["run"])
        self.assertIn("head -c 4097", failure["run"])
        self.assertIn("-le 4096", failure["run"])

        runner = RUNNER.read_text(encoding="utf-8")
        direct_failure = runner.split('if [[ "$status" -ne 0 ]]; then', 1)[1].split(
            "fi", 1
        )[0]
        self.assertNotIn("--trusted-marker", direct_failure)
        self.assertIn(
            'rm -f -- "$source_failure" "$qualification_failure" '
            '"$qualification_trace" \\\n  "$qualification_marker" "$reload_adjacency"',
            runner,
        )
        self.assertIn(
            'exit 91\nfi\n\n# The target cannot pre-seed the trusted admission marker.',
            runner,
        )
        self.assertIn('rm -f -- "$qualification_marker"\nset +e\npython3 -', runner)
        self.assertIn("representation_option=(--representation-invalid)", runner)

    def test_trace_overflow_and_unsafe_inputs_fail_closed(self) -> None:
        self.assertEqual(
            ("qualification-harness", "representation-invalid"),
            self.classifier.classify_failure(
                b"",
                b"x" * (self.classifier.MAX_TRACE_BYTES + 1),
                1,
                target_bound=True,
                representation_invalid=True,
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            missing = root / "missing"
            with self.assertRaises(ValueError):
                self.classifier.bounded_bytes(missing, 1)
            target = root / "target"
            target.write_bytes(b"ok")
            link = root / "link"
            link.symlink_to(target)
            with self.assertRaises(ValueError):
                self.classifier.bounded_bytes(link, 2)
            with self.assertRaises(ValueError):
                self.classifier.bounded_bytes(target, 1)

    def test_trace_helper_is_inert_without_its_dedicated_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            harness = Path(directory) / "harness.sh"
            harness.write_text("set -euo pipefail\nfalse\n", encoding="utf-8")
            result = subprocess.run(
                ["bash", harness],
                check=False,
                env={**os.environ, "BASH_ENV": str(TRACE)},
                capture_output=True,
                text=True,
            )
            self.assertEqual(1, result.returncode)
            self.assertNotIn("Bad file descriptor", result.stderr)


if __name__ == "__main__":
    unittest.main()
