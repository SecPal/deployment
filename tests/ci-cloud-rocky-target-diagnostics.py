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
import re
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
START_RUNUSER = ROOT / "scripts/ci-cloud/rocky-start-runuser.py"
START_ENV = ROOT / "scripts/ci-cloud/rocky-start-env.py"
START_SYSTEMCTL = ROOT / "scripts/ci-cloud/rocky-start-systemctl.py"
ACTIVE_RUNUSER = ROOT / "scripts/ci-cloud/rocky-active-runuser.py"
ACTIVE_ENV = ROOT / "scripts/ci-cloud/rocky-active-env.py"
ACTIVE_SYSTEMCTL = ROOT / "scripts/ci-cloud/rocky-active-systemctl.py"
PRIMARY_RUNUSER = ROOT / "scripts/ci-cloud/rocky-primary-runuser.py"
PRIMARY_RUNTIME = ROOT / "scripts/ci-cloud/rocky-primary-runtime.py"


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

    @staticmethod
    def primary_podman_arguments(suffix: str = "Ab12Cd") -> list[str]:
        return [
            "run", "--detach", "--name",
            f"secpal-host-qualification-{suffix}-a",
            "--security-opt", "no-new-privileges", "--cap-drop", "all",
            "--user", "65532:65532", "--network", "pasta", "-v",
            f"/var/tmp/secpal-host-qualification-{suffix}/state-a:/state:Z",
            "docker.io/library/alpine@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1",
            "sleep", "infinity",
        ]

    @classmethod
    def primary_runuser_arguments(cls, runtime: object) -> list[str]:
        return [
            "--user", "secpal-runtime", "--", "env",
            "-u", "CONTAINER_HOST", "-u", "CONTAINER_CONNECTION",
            f"HOME={runtime.pw_dir}",
            f"XDG_RUNTIME_DIR=/run/user/{runtime.pw_uid}",
            f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{runtime.pw_uid}/bus",
            "podman", *cls.primary_podman_arguments(),
        ]

    def test_primary_router_admits_only_the_exact_immutable_request(self) -> None:
        router = load_script(PRIMARY_RUNUSER, "rocky_primary_router_contract")
        runtime = types.SimpleNamespace(pw_uid=1001, pw_dir="/var/lib/secpal-runtime")
        arguments = self.primary_runuser_arguments(runtime)
        self.assertEqual(
            self.primary_podman_arguments(), router.exact_primary(arguments, runtime)
        )
        for index in (0, 3, 8, 11, 12, 15, 25, 28):
            mutated = list(arguments)
            mutated[index] += "-mutated"
            with self.subTest(index=index):
                self.assertIsNone(router.exact_primary(mutated, runtime))
        self.assertIsNone(router.exact_primary(arguments + ["extra"], runtime))

    def test_primary_runtime_maps_podman_status_without_copying_output(self) -> None:
        runtime_helper = load_script(PRIMARY_RUNTIME, "rocky_primary_runtime_contract")
        runtime = types.SimpleNamespace(
            pw_uid=1001, pw_gid=1001, pw_dir="/var/lib/secpal-runtime"
        )
        arguments = self.primary_podman_arguments()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for status, stage in (
                (0, "success"),
                (125, "podman-internal-failed"),
                (126, "podman-oci-status-126"),
                (127, "podman-oci-status-127"),
                (42, "podman-request-failed"),
            ):
                executable = root / f"podman-{status}"
                executable.write_text(f"#!/bin/sh\nexit {status}\n", encoding="ascii")
                executable.chmod(0o755)
                with self.subTest(status=status), mock.patch.object(
                    runtime_helper.os, "getresuid", return_value=(1001,) * 3
                ), mock.patch.object(
                    runtime_helper.os, "getresgid", return_value=(1001,) * 3
                ):
                    self.assertEqual(
                        (status, stage, status),
                        runtime_helper.execute(
                            arguments, runtime=runtime, podman_path=executable
                        ),
                    )
            missing = root / "missing-podman"
            with mock.patch.object(
                runtime_helper.os, "getresuid", return_value=(1001,) * 3
            ), mock.patch.object(
                runtime_helper.os, "getresgid", return_value=(1001,) * 3
            ):
                self.assertEqual(
                    (127, "podman-exec-failed", None),
                    runtime_helper.execute(
                        arguments, runtime=runtime, podman_path=missing
                    ),
                )

    def test_primary_router_forwards_only_the_closed_control_environment(self) -> None:
        router = load_script(PRIMARY_RUNUSER, "rocky_primary_closed_environment")
        payload = (
            b'{"kind":"runtime","schema_version":1,"stage":"runtime-entered"}\n'
            b'{"kind":"runtime","podman_status":0,"schema_version":1,'
            b'"stage":"success"}\n'
        )
        with mock.patch.object(
            router.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 0, stdout=payload),
        ) as run:
            status, facts = router.execute_primary(self.primary_podman_arguments())
        self.assertEqual(0, status)
        self.assertEqual("success", facts["stage"])
        self.assertEqual(
            {
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin",
                "LC_ALL": "C",
            },
            run.call_args.kwargs["env"],
        )
        runtime_helper = load_script(
            PRIMARY_RUNTIME, "rocky_primary_runtime_closed_environment"
        )
        runtime = types.SimpleNamespace(
            pw_uid=1001, pw_gid=1001, pw_dir="/home/secpal-runtime"
        )
        with mock.patch.object(
            runtime_helper.os, "getresuid", return_value=(1001,) * 3
        ), mock.patch.object(
            runtime_helper.os, "getresgid", return_value=(1001,) * 3
        ):
            self.assertEqual(
                {
                    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin",
                    "LC_ALL": "C",
                    "HOME": "/home/secpal-runtime",
                    "XDG_RUNTIME_DIR": "/run/user/1001",
                    "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1001/bus",
                },
                runtime_helper.runtime_environment(runtime),
            )

    def test_primary_protocol_closes_runuser_env_and_podman_boundaries(self) -> None:
        router = load_script(PRIMARY_RUNUSER, "rocky_primary_protocol_contract")
        entered = {"kind": "runtime", "schema_version": 1, "stage": "runtime-entered"}
        cases = (
            (b"", 126, "runuser-invocation-failed", None),
            (
                entered,
                {"kind": "runtime", "podman_status": None,
                 "schema_version": 1, "stage": "env-preparation-failed"},
                126,
                "env-preparation-failed",
                None,
            ),
            (
                entered,
                {"kind": "runtime", "podman_status": None,
                 "schema_version": 1, "stage": "podman-exec-failed"},
                127,
                "podman-exec-failed",
                None,
            ),
        )
        empty_payload, empty_status, empty_stage, empty_podman = cases[0]
        empty = router.parse_protocol(empty_payload, empty_status)
        self.assertEqual((empty_stage, empty_podman), (
            empty["stage"], empty["podman_status"]
        ))
        for first, second, status, stage, podman_status in cases[1:]:
            payload = "\n".join(
                json.dumps(item, sort_keys=True, separators=(",", ":"))
                for item in (first, second)
            ).encode("ascii") + b"\n"
            with self.subTest(stage=stage):
                observed = router.parse_protocol(payload, status)
                self.assertEqual(stage, observed["stage"])
                self.assertEqual(podman_status, observed["podman_status"])
        self.assertEqual(
            "diagnostic-unavailable",
            router.parse_protocol(b"x" * (router.MAX_PROTOCOL_BYTES + 1), 126)[
                "stage"
            ],
        )

    def test_primary_observation_failure_never_replays_the_request(self) -> None:
        router = load_script(PRIMARY_RUNUSER, "rocky_primary_no_replay_contract")
        runtime = types.SimpleNamespace(pw_uid=1001, pw_dir="/runtime")
        arguments = self.primary_runuser_arguments(runtime)
        with mock.patch.object(router.sys, "argv", ["router", *arguments]), \
             mock.patch.object(router.pwd, "getpwnam", return_value=runtime), \
             mock.patch.object(router.os, "geteuid", return_value=0), \
             mock.patch.object(router, "admitted_observation_path", return_value=Path("/obs")), \
             mock.patch.object(
                 router,
                 "execute_primary",
                 return_value=(126, router.diagnostic("podman-oci-status-126", 126, 126)),
             ) as execute, mock.patch.object(
                 router, "write_observation", side_effect=OSError("full")
             ), mock.patch.object(router, "fallback") as fallback:
            self.assertEqual(126, router.main())
        execute.assert_called_once_with(self.primary_podman_arguments())
        fallback.assert_not_called()

    def test_primary_classifier_admits_only_status_consistent_facts(self) -> None:
        cases = (
            ("runuser-exec-failed", None, None, 126,
             "qualify-workload-primary-runuser", "exec-failed"),
            ("runuser-invocation-failed", 126, None, 126,
             "qualify-workload-primary-runuser", "invocation-failed"),
            ("env-preparation-failed", 126, None, 126,
             "qualify-workload-primary-env", "invariant-failed"),
            ("podman-exec-failed", 127, None, 127,
             "qualify-workload-primary-podman", "exec-failed"),
            ("podman-internal-failed", 125, 125, 125,
             "qualify-workload-primary-podman", "request-failed"),
            ("podman-oci-status-126", 126, 126, 126,
             "qualify-workload-primary-podman-oci", "invocation-failed"),
            ("podman-oci-status-127", 127, 127, 127,
             "qualify-workload-primary-podman-oci", "command-exec-failed"),
        )
        for stage, runuser_status, podman_status, status, operation, reason in cases:
            raw = {
                "schema_version": 1,
                "stage": stage,
                "runuser_status": runuser_status,
                "podman_status": podman_status,
            }
            with self.subTest(stage=stage):
                observed_operation, observed_reason, diagnostic = (
                    self.classifier.admit_primary_workload_observation(raw, status)
                )
                self.assertEqual(
                    (operation, reason), (observed_operation, observed_reason)
                )
                self.classifier.validate_admitted_primary_workload_diagnostic(
                    diagnostic, operation, reason, status
                )
                mutated = dict(raw, runuser_status=1)
                self.assertEqual(
                    ("qualify-workload-primary", "diagnostic-unavailable"),
                    self.classifier.admit_primary_workload_observation(
                        mutated, status
                    )[:2],
                )

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
        self.assertNotIn("SECPAL_RELOAD_EXACT_CALL", trace + runner + client)
        self.assertIn("os.execve(REAL_RUNUSER", runner)
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
            mock.patch.object(proxy.pwd, "getpwnam", return_value=runtime),
            mock.patch.object(proxy.os, "fstat", return_value=fifo),
            mock.patch.object(proxy.fcntl, "fcntl", return_value=os.O_RDWR),
            mock.patch.object(proxy.os, "dup2") as duplicate,
            mock.patch.object(proxy.os, "closerange") as close_range,
            mock.patch.object(proxy.os, "sysconf", return_value=64),
            mock.patch.object(proxy.os, "execve", side_effect=execution) as execute,
        ):
            with self.assertRaisesRegex(RuntimeError, "exec"):
                proxy.main()
        duplicate.assert_has_calls(
            [mock.call(proxy.ACK_FD, 0, inheritable=True),
             mock.call(proxy.RECORD_FD, 1, inheritable=True)]
        )
        close_range.assert_called_once_with(3, 64)
        executed = execute.call_args.args[1]
        self.assertEqual(
            {
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin",
                "LC_ALL": "C",
            },
            execute.call_args.args[2],
        )
        self.assertEqual(proxy.REAL_RUNUSER, executed[0])
        self.assertEqual(proxy.TRUSTED_SYSTEMCTL, executed[-3])
        self.assertNotIn("systemctl", executed)

    def test_runtime_helper_keeps_pid_and_rejects_wrong_semantic_actor(self) -> None:
        client = load_script(RELOAD_SYSTEMCTL, "rocky_reload_systemctl")
        runtime = types.SimpleNamespace(pw_uid=994, pw_gid=994)
        execution = RuntimeError("exec")
        with (
            mock.patch.object(client.sys, "argv", [str(RELOAD_SYSTEMCTL), "--user", "daemon-reload"]),
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

    def test_old_start_boundary_collapses_independent_process_failures(self) -> None:
        executable_failures = {
            self.classifier.classify_failure(
                b"", b"SECPAL_TARGET_ERR_V2:126:51,238\n", 126,
                target_bound=True, line_rules=self.classifier.LINE_RULES,
            )
            for _producer in ("runuser", "env", "systemctl")
        }
        completed_client_failures = {
            self.classifier.classify_failure(
                b"", b"SECPAL_TARGET_ERR_V2:1:51,238\n", 1,
                target_bound=True, line_rules=self.classifier.LINE_RULES,
            )
            for _producer in ("manager-request", "service-exec-main-status-126")
        }
        self.assertEqual(
            {("qualify-quadlet-start", "command-failed")}, executable_failures
        )
        self.assertEqual(
            {("qualify-quadlet-start", "command-failed")},
            completed_client_failures,
        )

    def test_start_observers_distinguish_real_exec_boundaries_and_job_status(
        self,
    ) -> None:
        self.assertTrue(START_RUNUSER.is_file())
        self.assertTrue(START_ENV.is_file())
        self.assertTrue(START_SYSTEMCTL.is_file())
        runuser = load_script(START_RUNUSER, "rocky_start_runuser")
        env_helper = load_script(START_ENV, "rocky_start_env")
        systemctl = load_script(START_SYSTEMCTL, "rocky_start_systemctl")
        runtime = types.SimpleNamespace(
            pw_uid=os.getuid(), pw_gid=os.getgid(), pw_dir=str(Path.home())
        )
        unit = "secpal-host-qualification-abc123.service"
        target_arguments = runuser.target_arguments(runtime, unit)
        env_arguments = target_arguments[4:]
        systemctl_arguments = ["--user", "start", unit]

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def executable(name: str, body: str) -> Path:
                path = root / name
                path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
                path.chmod(0o700)
                return path

            cannot_execute = root / "cannot-execute"
            cannot_execute.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            cannot_execute.chmod(0o600)
            missing_executable = root / "missing-executable"
            fake_runuser = executable(
                "runuser",
                'while [ "$1" != -- ]; do shift; done; shift; exec "$@"',
            )
            runuser_rejects = executable("runuser-rejects", "exit 1")
            env_succeeds = Path("/usr/bin/env")
            client_fails = executable(
                "systemctl-request-fails",
                'case " $* " in\n'
                '  *" --property=Result "*)\n'
                "    printf '%s\\n' 'Result=success' 'ExecMainCode=0' "
                "'ExecMainStatus=0'; exit 0;;\n"
                '  *) exit 1;;\n'
                "esac",
            )
            property_observation_fails = executable(
                "systemctl-show-fails", "exit 1"
            )
            service_exits_126 = executable(
                "systemctl-service-fails",
                'case " $* " in\n'
                '  *" --property=Result "*)\n'
                "    printf '%s\\n' 'Result=exit-code' 'ExecMainCode=1' "
                "'ExecMainStatus=126'; exit 0;;\n"
                '  *) exit 1;;\n'
                "esac",
            )
            client_succeeds = executable("systemctl-success", "exit 0")

            status, facts = runuser.execute_start(
                target_arguments,
                runtime=runtime,
                runuser_path=cannot_execute,
                env_helper_path=START_ENV,
            )
            self.assertEqual(126, status)
            self.assertEqual("runuser-exec-failed", facts["stage"])

            status, facts = runuser.execute_start(
                target_arguments,
                runtime=runtime,
                runuser_path=missing_executable,
                env_helper_path=START_ENV,
            )
            self.assertEqual(127, status)
            self.assertEqual("runuser-exec-failed", facts["stage"])

            status, facts = runuser.execute_start(
                target_arguments,
                runtime=runtime,
                runuser_path=runuser_rejects,
                env_helper_path=START_ENV,
            )
            self.assertEqual(1, status)
            self.assertEqual("runuser-invocation-failed", facts["stage"])

            status, records = env_helper.execute_env(
                env_arguments,
                runtime=runtime,
                env_path=cannot_execute,
                systemctl_helper_path=START_SYSTEMCTL,
            )
            self.assertEqual(126, status)
            self.assertEqual(("env-entered", "env-exec-failed"), records)

            status, facts = systemctl.execute_systemctl(
                systemctl_arguments,
                runtime=runtime,
                systemctl_path=cannot_execute,
            )
            self.assertEqual(126, status)
            self.assertEqual("systemctl-exec-failed", facts["stage"])

            status, facts = systemctl.execute_systemctl(
                systemctl_arguments,
                runtime=runtime,
                systemctl_path=missing_executable,
            )
            self.assertEqual(127, status)
            self.assertEqual("systemctl-exec-failed", facts["stage"])

            status, facts = systemctl.execute_systemctl(
                systemctl_arguments,
                runtime=runtime,
                systemctl_path=client_fails,
            )
            self.assertEqual(1, status)
            self.assertEqual("systemctl-request-failed", facts["stage"])
            self.assertIsNone(facts["service_result"])

            status, facts = systemctl.execute_systemctl(
                systemctl_arguments,
                runtime=runtime,
                systemctl_path=property_observation_fails,
            )
            self.assertEqual(1, status)
            self.assertEqual("diagnostic-unavailable", facts["stage"])
            self.assertIsNone(facts["service_result"])

            status, facts = systemctl.execute_systemctl(
                systemctl_arguments,
                runtime=runtime,
                systemctl_path=service_exits_126,
            )
            self.assertEqual(1, status)
            self.assertEqual("service-job-failed", facts["stage"])
            self.assertEqual("exit-code", facts["service_result"])
            self.assertEqual(1, facts["exec_main_code"])
            self.assertEqual(126, facts["exec_main_status"])

            status, facts = systemctl.execute_systemctl(
                systemctl_arguments,
                runtime=runtime,
                systemctl_path=client_succeeds,
            )
            self.assertEqual(0, status)
            self.assertEqual("success", facts["stage"])

            with open(os.devnull, "w", encoding="ascii") as devnull, mock.patch.object(
                env_helper.sys, "stderr", devnull
            ):
                status, records = env_helper.execute_env(
                    env_arguments,
                    runtime=runtime,
                    env_path=env_succeeds,
                    systemctl_helper_path=cannot_execute,
                )
            self.assertEqual(126, status)
            self.assertEqual(("env-entered",), records)

            self.assertTrue(fake_runuser.is_file())

    def test_start_protocol_setup_failure_never_claims_an_exec_failure(self) -> None:
        runuser = load_script(START_RUNUSER, "rocky_start_runuser_setup_failure")
        env_helper = load_script(START_ENV, "rocky_start_env_setup_failure")
        runtime = types.SimpleNamespace(
            pw_uid=os.getuid(), pw_gid=os.getgid(), pw_dir=str(Path.home())
        )
        unit = "secpal-host-qualification-abc123.service"
        target_arguments = runuser.target_arguments(runtime, unit)

        with mock.patch.object(
            runuser.tempfile, "TemporaryFile", side_effect=OSError("full")
        ):
            with self.assertRaises(runuser.DiagnosticUnavailable):
                runuser.execute_start(target_arguments, runtime=runtime)

        with mock.patch.object(
            env_helper.tempfile, "TemporaryFile", side_effect=OSError("full")
        ):
            with self.assertRaises(env_helper.DiagnosticUnavailable):
                env_helper.execute_env(target_arguments[4:], runtime=runtime)

    def test_active_observers_distinguish_real_exec_boundaries_and_request_status(
        self,
    ) -> None:
        runuser = load_script(ACTIVE_RUNUSER, "rocky_active_runuser")
        env_helper = load_script(ACTIVE_ENV, "rocky_active_env")
        systemctl = load_script(ACTIVE_SYSTEMCTL, "rocky_active_systemctl")
        runtime = types.SimpleNamespace(
            pw_uid=os.getuid(), pw_gid=os.getgid(), pw_dir=str(Path.home())
        )
        unit = "secpal-host-qualification-abc123.service"
        target_arguments = runuser.target_arguments(runtime, unit)
        env_arguments = target_arguments[4:]
        systemctl_arguments = ["--user", "is-active", "--quiet", unit]

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def executable(name: str, body: str) -> Path:
                path = root / name
                path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
                path.chmod(0o700)
                return path

            cannot_execute = root / "cannot-execute"
            cannot_execute.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            cannot_execute.chmod(0o600)
            missing_executable = root / "missing-executable"
            runuser_rejects = executable("runuser-rejects", "exit 1")
            request_fails = executable("systemctl-request-fails", "exit 3")
            request_succeeds = executable("systemctl-success", "exit 0")

            status, facts = runuser.execute_active(
                target_arguments, runtime=runtime, runuser_path=cannot_execute
            )
            self.assertEqual(126, status)
            self.assertEqual("runuser-exec-failed", facts["stage"])

            status, facts = runuser.execute_active(
                target_arguments, runtime=runtime, runuser_path=missing_executable
            )
            self.assertEqual(127, status)
            self.assertEqual("runuser-exec-failed", facts["stage"])

            status, facts = runuser.execute_active(
                target_arguments, runtime=runtime, runuser_path=runuser_rejects
            )
            self.assertEqual(1, status)
            self.assertEqual("runuser-invocation-failed", facts["stage"])

            output = RetainedBytesIO()
            status = env_helper.execute_env(
                env_arguments,
                runtime=runtime,
                env_path=cannot_execute,
                systemctl_helper_path=ACTIVE_SYSTEMCTL,
                output=output,
            )
            self.assertEqual(126, status)
            self.assertEqual(
                ["env-entered", "env-exec-failed"],
                [json.loads(line)["stage"] for line in output.getvalue().splitlines()],
            )

            output = RetainedBytesIO()
            with open(os.devnull, "w", encoding="ascii") as devnull, mock.patch.object(
                env_helper.sys, "stderr", devnull
            ):
                status = env_helper.execute_env(
                    env_arguments,
                    runtime=runtime,
                    env_path=Path("/usr/bin/env"),
                    systemctl_helper_path=cannot_execute,
                    output=output,
                )
            self.assertEqual(126, status)
            self.assertEqual(
                ["env-entered"],
                [json.loads(line)["stage"] for line in output.getvalue().splitlines()],
            )

            status, stage = systemctl.execute_systemctl(
                systemctl_arguments,
                runtime=runtime,
                systemctl_path=cannot_execute,
            )
            self.assertEqual((126, "systemctl-exec-failed"), (status, stage))
            status, stage = systemctl.execute_systemctl(
                systemctl_arguments,
                runtime=runtime,
                systemctl_path=missing_executable,
            )
            self.assertEqual((127, "systemctl-exec-failed"), (status, stage))
            status, stage = systemctl.execute_systemctl(
                systemctl_arguments,
                runtime=runtime,
                systemctl_path=request_fails,
            )
            self.assertEqual((3, "systemctl-request-failed"), (status, stage))
            status, stage = systemctl.execute_systemctl(
                systemctl_arguments,
                runtime=runtime,
                systemctl_path=request_succeeds,
            )
            self.assertEqual((0, "success"), (status, stage))

    def test_active_protocol_frames_each_exact_numeric_producer(self) -> None:
        runuser = load_script(ACTIVE_RUNUSER, "rocky_active_protocol")
        cases = (
            (b"", 126, "runuser-invocation-failed"),
            (
                b'{"kind":"env","schema_version":1,"stage":"env-entered"}\n',
                126,
                "env-command-exec-failed",
            ),
            (
                b'{"kind":"env","schema_version":1,"stage":"env-entered"}\n'
                b'{"kind":"env","schema_version":1,"stage":"env-exec-failed"}\n',
                126,
                "env-exec-failed",
            ),
            (
                b'{"kind":"env","schema_version":1,"stage":"env-entered"}\n'
                b'{"kind":"systemctl","schema_version":1,'
                b'"stage":"systemctl-exec-failed","systemctl_client_status":null}\n',
                126,
                "systemctl-exec-failed",
            ),
            (
                b'{"kind":"env","schema_version":1,"stage":"env-entered"}\n'
                b'{"kind":"systemctl","schema_version":1,'
                b'"stage":"systemctl-request-failed","systemctl_client_status":3}\n',
                3,
                "systemctl-request-failed",
            ),
        )
        for payload, status, expected in cases:
            with self.subTest(stage=expected):
                self.assertEqual(expected, runuser.parse_protocol(payload, status)["stage"])

    def test_active_protocol_setup_failure_cannot_replace_the_target_request(
        self,
    ) -> None:
        runuser = load_script(ACTIVE_RUNUSER, "rocky_active_setup_failure")
        runtime = types.SimpleNamespace(
            pw_uid=os.getuid(), pw_gid=os.getgid(), pw_dir=str(Path.home())
        )
        arguments = runuser.target_arguments(
            runtime, "secpal-host-qualification-abc123.service"
        )
        with mock.patch.object(
            runuser.tempfile, "TemporaryFile", side_effect=OSError("full")
        ):
            with self.assertRaises(runuser.DiagnosticUnavailable):
                runuser.execute_active(arguments, runtime=runtime)
        env_helper = load_script(ACTIVE_ENV, "rocky_active_env_setup_failure")
        with mock.patch.object(
            env_helper.tempfile, "TemporaryFile", side_effect=OSError("full")
        ):
            with self.assertRaises(env_helper.DiagnosticUnavailable):
                env_helper.execute_env(
                    arguments[4:], runtime=runtime, output=RetainedBytesIO()
                )

    def test_start_protocol_explicitly_frames_diagnostic_unavailability(self) -> None:
        runuser = load_script(START_RUNUSER, "rocky_start_runuser_unavailable")
        unavailable = (
            b'{"kind":"env","schema_version":1,'
            b'"stage":"diagnostic-unavailable"}\n'
        )
        facts = runuser.parse_protocol(unavailable, 1)
        self.assertEqual("diagnostic-unavailable", facts["stage"])
        self.assertEqual(1, facts["runuser_status"])
        self.assertIsNone(facts["systemctl_client_status"])

    def test_runtime_start_helpers_use_isolated_python_startup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "sitecustomize-loaded"
            (root / "sitecustomize.py").write_text(
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('loaded', encoding='ascii')\n",
                encoding="utf-8",
            )
            for helper in (
                START_RUNUSER,
                START_ENV,
                START_SYSTEMCTL,
                ACTIVE_RUNUSER,
                ACTIVE_ENV,
                ACTIVE_SYSTEMCTL,
            ):
                with self.subTest(helper=helper.name):
                    self.assertTrue(
                        helper.read_bytes().startswith(b"#!/usr/bin/python3 -I\n")
                    )
                    result = subprocess.run(
                        [helper, "--help"],
                        check=False,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        env={**os.environ, "PYTHONPATH": str(root)},
                        timeout=10,
                    )
                    self.assertIn(result.returncode, range(128))
                    self.assertFalse(marker.exists())

    def test_start_observation_fd_exists_only_for_the_exact_helper(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        trace = TRACE.read_text(encoding="utf-8")
        self.assertNotIn('6>"$start_observation"', runner)
        self.assertIn(
            'exec 6>/var/lib/secpal-rocky/evidence/quadlet-start-observation.json',
            trace,
        )
        self.assertIn('/usr/sbin/runuser "$@"', trace)
        self.assertNotIn("SECPAL_START_OBSERVATION_PATH", runner + trace)

    def test_active_observation_fd_exists_only_for_the_exact_helper(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        trace = TRACE.read_text(encoding="utf-8")
        self.assertNotIn('7>"$active_observation"', runner)
        self.assertIn(
            'exec 7>/var/lib/secpal-rocky/evidence/quadlet-active-observation.json',
            trace,
        )
        self.assertIn('/usr/sbin/runuser "$@"', trace)
        self.assertNotIn("SECPAL_ACTIVE_OBSERVATION_PATH", runner + trace)
        with tempfile.TemporaryDirectory() as directory:
            observation = Path(directory) / "observation.json"
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    "if { : >&7; } 2>/dev/null; then exit 99; fi",
                ],
                check=False,
                env={
                    **os.environ,
                    "BASH_ENV": str(TRACE),
                },
            )
            self.assertEqual(0, result.returncode)
            self.assertFalse(observation.exists())

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
        self.assertEqual(
            ("qualification-harness", "representation-invalid"),
            self.classify(
                status=0,
                marker="qualify-workload-primary command-failed",
            ),
        )
        self.assertEqual(
            ("qualify-avc-correlation", "invariant-failed"),
            self.classify(
                status=0,
                marker="qualify-avc-correlation invariant-failed",
            ),
        )
        start_cases = (
            (
                {
                    "schema_version": 1, "stage": "runuser-exec-failed",
                    "runuser_status": None, "systemctl_client_status": None,
                    "service_result": None, "exec_main_code": None,
                    "exec_main_status": None,
                },
                126, "qualify-quadlet-start-runuser", "exec-failed",
            ),
            (
                {
                    "schema_version": 1, "stage": "env-exec-failed",
                    "runuser_status": 126, "systemctl_client_status": None,
                    "service_result": None, "exec_main_code": None,
                    "exec_main_status": None,
                },
                126, "qualify-quadlet-start-env", "exec-failed",
            ),
            (
                {
                    "schema_version": 1, "stage": "systemctl-request-failed",
                    "runuser_status": 1, "systemctl_client_status": 1,
                    "service_result": None, "exec_main_code": None,
                    "exec_main_status": None,
                },
                1, "qualify-quadlet-start-systemctl", "request-failed",
            ),
            (
                {
                    "schema_version": 1, "stage": "service-job-failed",
                    "runuser_status": 1, "systemctl_client_status": 1,
                    "service_result": "exit-code", "exec_main_code": 1,
                    "exec_main_status": 126,
                },
                1, "qualify-quadlet-start-service-job", "job-failed",
            ),
        )
        for observation, status, operation, reason in start_cases:
            with self.subTest(operation=operation):
                actual_operation, actual_reason, diagnostic = (
                    self.classifier.admit_quadlet_start_observation(
                        observation, status
                    )
                )
                self.assertEqual((operation, reason), (actual_operation, actual_reason))
                self.classifier.validate_admitted_quadlet_start_diagnostic(
                    diagnostic, operation, reason, status
                )
                observed.add(operation)
        active_cases = (
            (
                {
                    "schema_version": 1,
                    "stage": "runuser-exec-failed",
                    "runuser_status": None,
                    "systemctl_client_status": None,
                },
                126,
                "qualify-quadlet-active-state-runuser",
                "exec-failed",
            ),
            (
                {
                    "schema_version": 1,
                    "stage": "env-exec-failed",
                    "runuser_status": 126,
                    "systemctl_client_status": None,
                },
                126,
                "qualify-quadlet-active-state-env",
                "exec-failed",
            ),
            (
                {
                    "schema_version": 1,
                    "stage": "systemctl-request-failed",
                    "runuser_status": 3,
                    "systemctl_client_status": 3,
                },
                3,
                "qualify-quadlet-active-state-systemctl",
                "request-failed",
            ),
        )
        for observation, status, operation, reason in active_cases:
            with self.subTest(operation=operation):
                actual_operation, actual_reason, diagnostic = (
                    self.classifier.admit_quadlet_active_observation(
                        observation, status
                    )
                )
                self.assertEqual((operation, reason), (actual_operation, actual_reason))
                self.classifier.validate_admitted_quadlet_active_diagnostic(
                    diagnostic, operation, reason, status
                )
                observed.add(operation)
        primary_cases = (
            (
                {"schema_version": 1, "stage": "runuser-exec-failed",
                 "runuser_status": None, "podman_status": None},
                126, "qualify-workload-primary-runuser", "exec-failed",
            ),
            (
                {"schema_version": 1, "stage": "env-preparation-failed",
                 "runuser_status": 126, "podman_status": None},
                126, "qualify-workload-primary-env", "invariant-failed",
            ),
            (
                {"schema_version": 1, "stage": "podman-internal-failed",
                 "runuser_status": 125, "podman_status": 125},
                125, "qualify-workload-primary-podman", "request-failed",
            ),
            (
                {"schema_version": 1, "stage": "podman-oci-status-126",
                 "runuser_status": 126, "podman_status": 126},
                126, "qualify-workload-primary-podman-oci", "invocation-failed",
            ),
        )
        for observation, status, operation, reason in primary_cases:
            with self.subTest(operation=operation):
                actual_operation, actual_reason, diagnostic = (
                    self.classifier.admit_primary_workload_observation(
                        observation, status
                    )
                )
                self.assertEqual((operation, reason), (actual_operation, actual_reason))
                self.classifier.validate_admitted_primary_workload_diagnostic(
                    diagnostic, operation, reason, status
                )
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

    def test_exact_start_trigger_is_consumed_once_across_runtime_subshell(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            harness = root / "qualify-production-host.sh"
            trace = root / "rocky-target-qualification-trace.sh"
            helper = root / "rocky-start-runuser"
            real_runuser = root / "runuser"
            helper_log = root / "helper.log"
            observation = root / "start-observation.json"
            lines = ["set -euo pipefail"] + [""] * 238
            for line_number, source in {
                37: "run_as_service_account() (",
                38: (
                    "  runuser --user secpal-runtime -- env "
                    "-u CONTAINER_HOST -u CONTAINER_CONNECTION "
                    'HOME=/home/secpal-runtime XDG_RUNTIME_DIR=/run/user/1001 '
                    "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1001/bus "
                    '"$@"'
                ),
                39: ")",
                50: "user_systemctl() {",
                51: '  run_as_service_account systemctl --user "$@"',
                52: "}",
                236: 'unit_name="secpal-host-qualification-Ab12Cd"',
                238: 'user_systemctl start "${unit_name}.service"',
                239: "run_as_service_account test later-runtime-call",
            }.items():
                lines[line_number - 1] = source
            harness.write_text("\n".join(lines) + "\n", encoding="utf-8")
            helper.write_text(
                "#!/bin/sh\n"
                "printf 'helper\\n' >>\"$SECPAL_HELPER_LOG\"\n"
                "case \"$*\" in\n"
                "  *'systemctl --user start'*) printf 'observed\\n' >&6 ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            real_runuser.write_text(
                "#!/bin/sh\n"
                "printf 'real\\n' >>\"$SECPAL_HELPER_LOG\"\n",
                encoding="utf-8",
            )
            helper.chmod(0o755)
            real_runuser.chmod(0o755)
            trace.write_text(
                TRACE.read_text(encoding="utf-8")
                .replace(
                    "/opt/secpal-control/libexec/rocky-start-runuser",
                    os.fspath(helper),
                )
                .replace(
                    "/var/lib/secpal-rocky/evidence/quadlet-start-observation.json",
                    os.fspath(observation),
                )
                .replace(
                    "/opt/secpal-control/libexec/rocky-primary-runuser",
                    os.fspath(real_runuser),
                )
                .replace("/usr/sbin/runuser", os.fspath(real_runuser)),
                encoding="utf-8",
            )
            trace.chmod(0o755)
            observation.write_bytes(b"")
            observation.chmod(0o600)
            event_read, event_write = os.pipe()
            ack_read, ack_write = os.pipe()
            try:
                result = subprocess.run(
                    ["bash", harness],
                    check=False,
                    env={
                        **os.environ,
                        "BASH_ENV": os.fspath(trace),
                        "SECPAL_HELPER_LOG": os.fspath(helper_log),
                    },
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    pass_fds=tuple({4, 5, event_write, ack_read}),
                    close_fds=True,
                    preexec_fn=lambda: (
                        os.dup2(event_write, 4),
                        os.dup2(ack_read, 5),
                    ),
                )
            finally:
                os.close(event_read)
                os.close(event_write)
                os.close(ack_read)
                os.close(ack_write)
            self.assertEqual(0, result.returncode)
            self.assertEqual(
                ["helper", "real"],
                helper_log.read_text(encoding="ascii").splitlines(),
            )
            self.assertEqual(b"observed\n", observation.read_bytes())

    def test_exact_active_trigger_is_consumed_once_across_runtime_subshell(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            harness = root / "qualify-production-host.sh"
            trace = root / "rocky-target-qualification-trace.sh"
            helper = root / "rocky-active-runuser"
            real_runuser = root / "runuser"
            helper_log = root / "helper.log"
            observation = root / "active-observation.json"
            lines = ["set -euo pipefail"] + [""] * 240
            for line_number, source in {
                37: "run_as_service_account() (",
                38: (
                    "  runuser --user secpal-runtime -- env "
                    "-u CONTAINER_HOST -u CONTAINER_CONNECTION "
                    'HOME=/home/secpal-runtime XDG_RUNTIME_DIR=/run/user/1001 '
                    "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1001/bus "
                    '"$@"'
                ),
                39: ")",
                50: "user_systemctl() {",
                51: '  run_as_service_account systemctl --user "$@"',
                52: "}",
                236: 'unit_name="secpal-host-qualification-Ab12Cd"',
                239: 'user_systemctl is-active --quiet "${unit_name}.service"',
                240: "run_as_service_account test later-runtime-call",
            }.items():
                lines[line_number - 1] = source
            harness.write_text("\n".join(lines) + "\n", encoding="utf-8")
            helper.write_text(
                "#!/bin/sh\n"
                "printf 'helper\\n' >>\"$SECPAL_HELPER_LOG\"\n"
                "printf 'observed\\n' >&7\n",
                encoding="utf-8",
            )
            real_runuser.write_text(
                "#!/bin/sh\n"
                "printf 'real\\n' >>\"$SECPAL_HELPER_LOG\"\n",
                encoding="utf-8",
            )
            helper.chmod(0o755)
            real_runuser.chmod(0o755)
            trace.write_text(
                TRACE.read_text(encoding="utf-8")
                .replace(
                    "/opt/secpal-control/libexec/rocky-active-runuser",
                    os.fspath(helper),
                )
                .replace(
                    "/var/lib/secpal-rocky/evidence/quadlet-active-observation.json",
                    os.fspath(observation),
                )
                .replace(
                    "/opt/secpal-control/libexec/rocky-primary-runuser",
                    os.fspath(real_runuser),
                )
                .replace("/usr/sbin/runuser", os.fspath(real_runuser)),
                encoding="utf-8",
            )
            trace.chmod(0o755)
            observation.write_bytes(b"")
            observation.chmod(0o600)
            event_read, event_write = os.pipe()
            ack_read, ack_write = os.pipe()
            try:
                result = subprocess.run(
                    ["bash", harness],
                    check=False,
                    env={
                        **os.environ,
                        "BASH_ENV": os.fspath(trace),
                        "SECPAL_HELPER_LOG": os.fspath(helper_log),
                    },
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    pass_fds=tuple({4, 5, event_write, ack_read}),
                    close_fds=True,
                    preexec_fn=lambda: (
                        os.dup2(event_write, 4),
                        os.dup2(ack_read, 5),
                    ),
                )
            finally:
                os.close(event_read)
                os.close(event_write)
                os.close(ack_read)
                os.close(ack_write)
            self.assertEqual(0, result.returncode)
            self.assertEqual(
                ["helper", "real"],
                helper_log.read_text(encoding="ascii").splitlines(),
            )
            self.assertEqual(b"observed\n", observation.read_bytes())

    def test_reload_trigger_cannot_capture_later_primary_workload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            harness = root / "qualify-production-host.sh"
            trace = root / "rocky-target-qualification-trace.sh"
            helper_log = root / "helper.log"
            start_observation = root / "start-observation.json"
            active_observation = root / "active-observation.json"
            primary_observation = root / "primary-observation.json"
            paths = {
                "reload": root / "rocky-reload-runuser",
                "start": root / "rocky-start-runuser",
                "active": root / "rocky-active-runuser",
                "primary": root / "rocky-primary-runuser",
                "real": root / "runuser",
            }
            lines = ["set -euo pipefail"] + [""] * 248
            for line_number, source in {
                37: "run_as_service_account() (",
                38: (
                    "  runuser --user secpal-runtime -- env "
                    "-u CONTAINER_HOST -u CONTAINER_CONNECTION "
                    'HOME=/home/secpal-runtime XDG_RUNTIME_DIR=/run/user/1001 '
                    "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1001/bus "
                    '"$@"'
                ),
                39: ")",
                46: "rootless_podman() {",
                47: '  run_as_service_account podman "$@"',
                48: "}",
                50: "user_systemctl() {",
                51: '  run_as_service_account systemctl --user "$@"',
                52: "}",
                236: (
                    'unit_name=secpal-host-qualification-Ab12Cd '
                    'container_a=secpal-host-qualification-Ab12Cd-a '
                    'state_a=/var/tmp/secpal-host-qualification-Ab12Cd/state-a '
                    'image=docker.io/library/alpine@sha256:' + "a" * 64
                ),
                237: "user_systemctl daemon-reload",
                238: 'user_systemctl start "${unit_name}.service"',
                239: 'user_systemctl is-active --quiet "${unit_name}.service"',
                245: 'rootless_podman run --detach --name "$container_a" \\',
                246: "  --security-opt no-new-privileges --cap-drop all \\",
                247: "  --user 65532:65532 --network pasta \\",
                248: '  -v "${state_a}:/state:Z" "$image" sleep infinity >/dev/null',
            }.items():
                lines[line_number - 1] = source
            harness.write_text("\n".join(lines) + "\n", encoding="utf-8")
            for name, path in paths.items():
                descriptor = ""
                if name == "start":
                    descriptor = "printf 'observed\\n' >&6\n"
                elif name == "active":
                    descriptor = "printf 'observed\\n' >&7\n"
                path.write_text(
                    "#!/bin/sh\n"
                    f"printf '{name}\\n' >>\"$SECPAL_HELPER_LOG\"\n"
                    + descriptor,
                    encoding="utf-8",
                )
                path.chmod(0o755)
            rendered = TRACE.read_text(encoding="utf-8")
            for installed, replacement in (
                ("/opt/secpal-control/libexec/rocky-reload-runuser", paths["reload"]),
                ("/opt/secpal-control/libexec/rocky-start-runuser", paths["start"]),
                ("/opt/secpal-control/libexec/rocky-active-runuser", paths["active"]),
                ("/opt/secpal-control/libexec/rocky-primary-runuser", paths["primary"]),
                ("/var/lib/secpal-rocky/evidence/quadlet-start-observation.json", start_observation),
                ("/var/lib/secpal-rocky/evidence/quadlet-active-observation.json", active_observation),
                ("/usr/sbin/runuser", paths["real"]),
            ):
                rendered = rendered.replace(installed, os.fspath(replacement))
            trace.write_text(rendered, encoding="utf-8")
            trace.chmod(0o755)
            for observation in (
                start_observation,
                active_observation,
                primary_observation,
            ):
                observation.write_bytes(b"")
                observation.chmod(0o600)
            event_read, event_write = os.pipe()
            ack_read, ack_write = os.pipe()
            try:
                result = subprocess.run(
                    ["bash", harness],
                    check=False,
                    env={
                        **os.environ,
                        "BASH_ENV": os.fspath(trace),
                        "SECPAL_HELPER_LOG": os.fspath(helper_log),
                    },
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    pass_fds=tuple({4, 5, event_write, ack_read}),
                    close_fds=True,
                    preexec_fn=lambda: (
                        os.dup2(event_write, 4),
                        os.dup2(ack_read, 5),
                    ),
                )
            finally:
                os.close(event_read)
                os.close(event_write)
                os.close(ack_read)
                os.close(ack_write)
            self.assertEqual(0, result.returncode)
            self.assertEqual(
                ["reload", "start", "active", "primary"],
                helper_log.read_text(encoding="ascii").splitlines(),
            )
            self.assertEqual(b"observed\n", start_observation.read_bytes())
            self.assertEqual(b"observed\n", active_observation.read_bytes())

            helper_log.write_bytes(b"")
            runtime = types.SimpleNamespace(
                pw_uid=os.getuid(), pw_dir=os.fspath(Path.home())
            )
            stale = subprocess.run(
                [
                    "bash",
                    "-c",
                    'export SECPAL_RELOAD_EXACT_CALL=1; runuser "$@"',
                    "bash",
                    *self.primary_runuser_arguments(runtime),
                ],
                check=False,
                env={
                    **os.environ,
                    "BASH_ENV": os.fspath(trace),
                    "SECPAL_HELPER_LOG": os.fspath(helper_log),
                },
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.assertEqual(0, stale.returncode)
            self.assertEqual(
                ["primary"],
                helper_log.read_text(encoding="ascii").splitlines(),
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
        zero_status_diagnostic = dict(
            document,
            operation="qualification-harness",
            reason="representation-invalid",
            exit_status=0,
        )
        self.assertEqual(
            [], list(validator.iter_errors(zero_status_diagnostic))
        )
        self.assertTrue(list(validator.iter_errors(dict(
            zero_status_diagnostic,
            operation="qualify-workload-primary",
            reason="command-failed",
        ))))
        for mutation in (
            dict(document, stdout="untrusted"),
            dict(document, operation="arbitrary-command"),
            dict(document, reason="some-error-text"),
            dict(document, qualification_run_id="0"),
            dict(document, diagnostic_input_bytes=139_521),
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
        historical_current_start = dict(
            document,
            target_sha=self.classifier.HISTORICAL_TARGET_SHA,
            harness_sha256=self.classifier.HISTORICAL_HARNESS_SHA256,
            operation="qualify-quadlet-start-service-job",
            reason="job-failed",
            quadlet_start_diagnostic={
                "classification": "service-job-failed",
                "observation_complete": True,
                "runuser_status": 1,
                "systemctl_client_status": 1,
                "service_result": "exit-code",
                "exec_main_code": 1,
                "exec_main_status": 126,
            },
        )
        self.assertTrue(list(validator.iter_errors(historical_current_start)))
        current_active = dict(
            document,
            operation="qualify-quadlet-active-state-systemctl",
            reason="request-failed",
            exit_status=3,
            quadlet_active_state_diagnostic={
                "classification": "systemctl-request-failed",
                "observation_complete": True,
                "runuser_status": 3,
                "systemctl_client_status": 3,
            },
        )
        self.assertEqual([], list(validator.iter_errors(current_active)))
        self.assertTrue(
            list(
                validator.iter_errors(
                    dict(
                        current_active,
                        operation="qualify-quadlet-active-state-env",
                    )
                )
            )
        )
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

    def test_trusted_validator_recomputes_quadlet_start_classification(self) -> None:
        operation, reason, diagnostic = (
            self.classifier.admit_quadlet_start_observation(
                {
                    "schema_version": 1,
                    "stage": "service-job-failed",
                    "runuser_status": 1,
                    "systemctl_client_status": 1,
                    "service_result": "exit-code",
                    "exec_main_code": 1,
                    "exec_main_status": 126,
                },
                1,
            )
        )
        valid_diagnostic = dict(diagnostic)
        document = {
            "schema_version": 1,
            "phase": "target-qualification",
            "target_sha": self.classifier.EXPECTED_TARGET_SHA,
            "trusted_control_sha": "c" * 40,
            "qualification_run_id": "12345",
            "qualification_run_attempt": "1",
            "harness_sha256": self.classifier.EXPECTED_HARNESS_SHA256,
            "operation": operation,
            "reason": reason,
            "exit_status": 1,
            "diagnostic_input_sha256": "b" * 64,
            "diagnostic_input_bytes": 100,
            "quadlet_start_diagnostic": diagnostic,
        }
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
            document["quadlet_start_diagnostic"]["service_result"] = "success"
            path.write_text(json.dumps(document), encoding="utf-8")
            self.assertNotEqual(
                0, subprocess.run(command, check=False, capture_output=True).returncode
            )
            document["quadlet_start_diagnostic"] = valid_diagnostic
            document["operation"] = "qualify-quadlet-start-systemctl"
            path.write_text(json.dumps(document), encoding="utf-8")
            self.assertNotEqual(
                0, subprocess.run(command, check=False, capture_output=True).returncode
            )

    def test_trusted_validator_recomputes_quadlet_active_classification(self) -> None:
        operation, reason, diagnostic = (
            self.classifier.admit_quadlet_active_observation(
                {
                    "schema_version": 1,
                    "stage": "systemctl-request-failed",
                    "runuser_status": 3,
                    "systemctl_client_status": 3,
                },
                3,
            )
        )
        valid_diagnostic = dict(diagnostic)
        document = {
            "schema_version": 1,
            "phase": "target-qualification",
            "target_sha": self.classifier.EXPECTED_TARGET_SHA,
            "trusted_control_sha": "c" * 40,
            "qualification_run_id": "12345",
            "qualification_run_attempt": "1",
            "harness_sha256": self.classifier.EXPECTED_HARNESS_SHA256,
            "operation": operation,
            "reason": reason,
            "exit_status": 3,
            "diagnostic_input_sha256": "b" * 64,
            "diagnostic_input_bytes": 100,
            "quadlet_active_state_diagnostic": diagnostic,
        }
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
            document["quadlet_active_state_diagnostic"][
                "systemctl_client_status"
            ] = 1
            path.write_text(json.dumps(document), encoding="utf-8")
            self.assertNotEqual(
                0, subprocess.run(command, check=False, capture_output=True).returncode
            )
            document["quadlet_active_state_diagnostic"] = valid_diagnostic
            document["operation"] = "qualify-quadlet-active-state-env"
            path.write_text(json.dumps(document), encoding="utf-8")
            self.assertNotEqual(
                0, subprocess.run(command, check=False, capture_output=True).returncode
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
        direct_failure = runner.split(
            'if [[ "$status" -ne 0 || "${#representation_option[@]}" -ne 0 ]]; then',
            1,
        )[1].split("fi", 1)[0]
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
        self.assertIn(
            '--exit-status "$status" --trusted-marker "$qualification_marker"',
            runner,
        )
        self.assertNotIn(
            '--exit-status "$admission_status" --trusted-marker', runner
        )

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

    def test_target_capture_bounds_output_without_limiting_target_files(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertNotIn("ulimit -f 128", runner)
        self.assertIn("capture_bounded() {", runner)
        self.assertIn('/usr/bin/head -c "$maximum"', runner)
        self.assertIn("/usr/bin/cat >/dev/null", runner)
        self.assertIn('capture_bounded 65537 "$stdout"', runner)
        self.assertIn(
            'capture_bounded 4097 "$qualification_trace" <"$trace_fifo"', runner
        )
        self.assertIn('pipeline_statuses=("${PIPESTATUS[@]}")', runner)
        self.assertIn('wait "$trace_capture_pid"', runner)
        self.assertNotIn("\n  status=1\n", runner)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            execution = subprocess.run(
                [
                    "bash",
                    "-ceu",
                    r"""
stdout="$1/stdout"
trace="$1/trace"
trace_fifo="$1/trace.fifo"
policy="$1/policy"
cleanup_policy="$1/cleanup-policy"
capture_bounded() {
  local maximum="$1" output="$2" head_status=0 drain_status=0
  head -c "$maximum" >"$output" || head_status=$?
  cat >/dev/null || drain_status=$?
  ((head_status == 0 && drain_status == 0))
}
mkfifo -m 0600 "$trace_fifo"
capture_bounded 4097 "$trace" <"$trace_fifo" &
trace_capture_pid=$!
set +e
bash -ceu '
  policy="$1"
  cleanup_policy="$2"
  cleanup() {
    dd if=/dev/zero of="$cleanup_policy" bs=1024 count=256 status=none
  }
  trap cleanup EXIT
  dd if=/dev/zero of="$policy" bs=1024 count=256 status=none
  printf trace >&3
  printf pass
' bash "$policy" "$cleanup_policy" 3>"$trace_fifo" 2>&1 |
  capture_bounded 65537 "$stdout"
pipeline_statuses=("${PIPESTATUS[@]}")
wait "$trace_capture_pid"
trace_capture_status=$?
set -e
test "${pipeline_statuses[0]}" -eq 0
test "${pipeline_statuses[1]}" -eq 0
test "$trace_capture_status" -eq 0
""",
                    "bash",
                    str(root),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, execution.returncode, execution.stderr)
            self.assertEqual(256 * 1024, (root / "policy").stat().st_size)
            self.assertEqual(256 * 1024, (root / "cleanup-policy").stat().st_size)
            self.assertEqual(b"pass", (root / "stdout").read_bytes())
            self.assertEqual(b"trace", (root / "trace").read_bytes())

            overflow = subprocess.run(
                [
                    "bash",
                    "-ceu",
                    r'''
set +e
capture_bounded() {
  local maximum="$1" output="$2" head_status=0 drain_status=0
  head -c "$maximum" >"$output" || head_status=$?
  cat >/dev/null || drain_status=$?
  ((head_status == 0 && drain_status == 0))
}
python3 -c 'import os; os.write(1, b"x" * 70000)' 2>&1 |
  capture_bounded 65537 "$1/overflow"
statuses=("${PIPESTATUS[@]}")
set -e
test "${statuses[0]}" -eq 0
test "${statuses[1]}" -eq 0
test "$(stat -c %s "$1/overflow")" -eq 65537
''',
                    "bash",
                    str(root),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, overflow.returncode, overflow.stderr)

    def test_success_observers_drain_bounded_output_and_timeout(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        function = re.search(
            r"\ndef run_bounded\(.*?(?=\n\npayload =)", runner, re.DOTALL
        )
        self.assertIsNotNone(function)
        namespace = {
            "os": os,
            "signal": __import__("signal"),
            "subprocess": subprocess,
            "threading": threading,
            "time": __import__("time"),
        }
        exec(function.group(0), namespace)
        run_bounded = namespace["run_bounded"]
        status, stdout, stderr, invalid = run_bounded(
            [
                sys.executable,
                "-c",
                "import os; os.write(1, b'x' * 70000); "
                "os.write(2, b'y' * 70000)",
            ],
            stdout_limit=64,
            stderr_limit=32,
            timeout=5,
        )
        self.assertEqual(0, status)
        self.assertLessEqual(len(stdout), 65)
        self.assertLessEqual(len(stderr), 33)
        self.assertTrue(invalid)
        status, _stdout, _stderr, invalid = run_bounded(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            stdout_limit=64,
            stderr_limit=32,
            timeout=0.1,
        )
        self.assertNotEqual(0, status)
        self.assertTrue(invalid)
        started = __import__("time").monotonic()
        status, _stdout, _stderr, invalid = run_bounded(
            [
                sys.executable,
                "-c",
                "import subprocess, sys; "
                "subprocess.Popen([sys.executable, '-c', "
                "'import time; time.sleep(30)'], stdout=sys.stdout, stderr=sys.stderr)",
            ],
            stdout_limit=64,
            stderr_limit=32,
            timeout=5,
        )
        self.assertEqual(0, status)
        self.assertTrue(invalid)
        self.assertLess(__import__("time").monotonic() - started, 4)
        acquire = namespace["acquire_audit_events"]
        no_match = (1, b"", b"<no matches>\n", False)
        namespace["run_bounded"] = mock.Mock(
            side_effect=(no_match, (0, b"event", b"", False))
        )
        with mock.patch.object(namespace["time"], "sleep") as pause:
            self.assertEqual(b"event", acquire(["/usr/sbin/ausearch"]))
        pause.assert_called_once_with(0.5)
        namespace["run_bounded"] = mock.Mock(
            return_value=(1, b"unexpected", b"", False)
        )
        self.assertIsNone(acquire(["/usr/sbin/ausearch"]))
        namespace["run_bounded"] = mock.Mock(
            return_value=(1, b"", b"warning\n", False)
        )
        self.assertIsNone(acquire(["/usr/sbin/ausearch"]))
        namespace["run_bounded"] = mock.Mock(return_value=no_match)
        with mock.patch.object(namespace["time"], "sleep") as pause:
            self.assertEqual(b"", acquire(["/usr/sbin/ausearch"]))
        self.assertEqual(11, pause.call_count)
        self.assertIn('timeout=10,\n        cwd=str(runtime_home)', runner)

    def test_avc_admission_correlates_one_audit_event_without_cross_record_greed(
        self,
    ) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertIn("date -u '+%m/%d/%y %H:%M:%S'", runner)
        self.assertIn(
            'datetime.strptime(audit_baseline, "%m/%d/%y %H:%M:%S")',
            runner,
        )
        function = re.search(
            r"\ndef audit_event_id\(.*?(?=\n\navc_events =)",
            runner,
            re.DOTALL,
        )
        self.assertIsNotNone(function)
        namespace = {"datetime": __import__("datetime").datetime, "re": re}
        exec(function.group(0), namespace)
        correlate = namespace["correlated_avc_events"]
        process = "system_u:system_r:container_t:s0:c1,c2"
        storage = "system_u:object_r:container_file_t:s0:c1,c2"
        event_41 = ("08/31/26 00:43:39.673", "41")

        unrelated = (
            "type=AVC msg=audit(08/31/26 00:43:39.672:40) : "
            "avc: denied { read } "
            'name="unrelated" scontext=system_u:system_r:other_t:s0 '
            "tcontext=system_u:object_r:other_t:s0 tclass=dir permissive=0"
        )
        relevant = (
            "type=AVC msg=audit(08/31/26 00:43:39.673:41) : "
            "avc: denied { read } "
            f'name="marker" scontext={process} tcontext={storage} '
            "tclass=dir permissive=0"
        )
        trailing = (
            "type=AVC msg=audit(08/31/26 00:43:39.674:42) : "
            "avc: denied { write } "
            'name="other" scontext=system_u:system_r:third_t:s0 '
            f"tcontext={storage} tclass=dir permissive=0"
        )
        self.assertEqual(set(), correlate(
            "\n".join((unrelated, relevant, trailing)), process, storage
        ))
        self.assertEqual(set(), correlate(
            "\n".join((relevant, relevant)), process, storage
        ))
        second = relevant.replace(":41) :", ":43) :")
        self.assertEqual(set(), correlate(
            "\n".join((relevant, second)), process, storage
        ))
        self.assertEqual(set(), correlate(
            relevant.replace("permissive=0", "permissive=1"), process, storage
        ))
        self.assertEqual(set(), correlate(
            relevant.replace("tclass=dir", "tclass=socket"), process, storage
        ))
        event_id = namespace["audit_event_id"]
        interpreted_avc = relevant.replace(' name="marker"', "")
        interpreted_proctitle = (
            "type=PROCTITLE "
            "msg=audit(08/31/26 00:43:39.673:41) : "
            "proctitle=cat /foreign/marker"
        )
        interpreted_event = "\n".join((interpreted_avc, interpreted_proctitle))
        self.assertEqual({event_41}, correlate(interpreted_event, process, storage))
        self.assertEqual(set(), correlate(
            "\n".join((interpreted_event, interpreted_proctitle)),
            process,
            storage,
        ))
        self.assertEqual(set(), correlate(
            "\n".join((interpreted_event, interpreted_avc)),
            process,
            storage,
        ))
        second_proctitle = interpreted_proctitle.replace(":41) :", ":43) :")
        self.assertEqual({event_41, (event_41[0], "43")}, correlate(
            "\n".join((interpreted_event, second, second_proctitle)),
            process,
            storage,
        ))
        self.assertEqual(set(), correlate(
            "\n".join((
                interpreted_avc,
                interpreted_proctitle.replace(":41) :", ":42) :"),
            )),
            process,
            storage,
        ))
        self.assertEqual(set(), correlate(
            interpreted_event.replace("type=PROCTITLE", "type=EXECVE"),
            process,
            storage,
        ))
        self.assertEqual(set(), correlate(
            interpreted_event.replace(
                "/foreign/marker",
                "/unbound/marker",
            ),
            process,
            storage,
        ))
        source_only = interpreted_avc.replace(
            f"tcontext={storage}", "tcontext=system_u:object_r:other_t:s0"
        )
        target_only = interpreted_avc.replace(
            f"scontext={process}", "scontext=system_u:system_r:other_t:s0"
        )
        self.assertEqual(set(), correlate(
            "\n".join((source_only, target_only, interpreted_proctitle)),
            process,
            storage,
        ))
        path = (
            "type=PATH msg=audit(08/31/26 00:43:39.673:41) : item=0 "
            'name="/var/tmp/secpal-host-qualification-Ab12Cd/state-a/marker" '
            "nametype=NORMAL"
        )
        self.assertEqual(set(), correlate(
            "\n".join((relevant.replace(' name="marker"', ""), path)),
            process,
            storage,
        ))
        self.assertEqual(event_41, event_id(relevant))
        self.assertEqual(event_41, event_id(interpreted_avc))
        raw_event = interpreted_event.replace(
            "msg=audit(08/31/26 00:43:39.673:41) :",
            "msg=audit(1.2:41):",
        )
        self.assertIsNone(event_id(raw_event.splitlines()[0]))
        self.assertIsNone(correlate(raw_event, process, storage))
        self.assertIsNone(correlate(
            "\n".join((interpreted_event, raw_event)),
            process,
            storage,
        ))
        self.assertEqual(
            set(),
            correlate(
                interpreted_event.replace("tclass=dir", "tclass=file"),
                process,
                storage,
            ),
        )
        self.assertIsNone(event_id(interpreted_avc.replace(".673", "")))
        self.assertIsNone(event_id(interpreted_avc.replace(") :", "):")))
        self.assertIsNone(event_id(interpreted_avc.replace("08/31", "99/31")))
        self.assertIsNone(
            event_id(interpreted_avc.replace("08/31/26", "08/31/2026"))
        )
        cross_timestamp_marker = interpreted_proctitle.replace(
            "00:43:39.673:41", "00:44:40.000:41"
        )
        self.assertEqual(
            set(),
            correlate(
                "\n".join((interpreted_avc, cross_timestamp_marker)),
                process,
                storage,
            ),
        )
        self.assertEqual(
            {event_41, (event_41[0], "43")},
            correlate(
                interpreted_event
                + "\n"
                + interpreted_event.replace(":41) :", ":43) :"),
                process,
                storage,
            ),
        )

    def test_avc_admission_reads_logs_when_python_stdin_is_a_heredoc(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertIn(
            'audit_date, audit_time = audit_checkpoint.groups()',
            runner,
        )
        self.assertIn(
            '"/usr/sbin/ausearch", "--input-logs", "-m", "AVC", "-ts",',
            runner,
        )
        self.assertIn('stderr in {b"", b"<no matches>\\n"}', runner)
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "ausearch"
            executable.write_text(
                "#!/bin/sh\n"
                "if test \"$#\" -eq 7 && test \"$1\" = --input-logs && "
                "test \"$5\" = 01/01/2026 && test \"$6\" = 00:00:00 && "
                "test \"$7\" = -i; then\n"
                "  printf '%s\\n' 'type=AVC msg=audit(1.2:41): admitted'\n"
                "  exit 0\n"
                "fi\n"
                "cat\n"
                "exit 1\n",
                encoding="utf-8",
            )
            executable.chmod(0o755)
            environment = {
                **os.environ,
                "PATH": f"{directory}:{os.environ.get('PATH', os.defpath)}",
            }
            script = r'''
python3 - <<'PY'
import subprocess
without_logs = subprocess.run(
    ["ausearch", "-m", "AVC", "-ts", "01/01/2026", "00:00:00"],
    check=False, capture_output=True, text=True,
)
combined = subprocess.run(
    ["ausearch", "--input-logs", "-m", "AVC", "-ts", "01/01/2026 00:00:00"],
    check=False, capture_output=True, text=True,
)
with_logs = subprocess.run(
    ["ausearch", "--input-logs", "-m", "AVC", "-ts", "01/01/2026", "00:00:00", "-i"],
    check=False, capture_output=True, text=True,
)
if without_logs.returncode != 1 or without_logs.stdout != "":
    raise SystemExit(1)
if combined.returncode != 1 or combined.stdout != "":
    raise SystemExit(2)
if with_logs.returncode != 0 or not with_logs.stdout.startswith("type=AVC "):
    raise SystemExit(3)
PY
'''
            result = subprocess.run(
                ["bash", "-ceu", script],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
            )
            self.assertEqual(0, result.returncode, result.stderr)

    def test_cleanup_podman_observer_uses_validated_runtime_home_cwd(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertIn(
            'runtime_home = Path(runtime_account.pw_dir)',
            runner,
        )
        self.assertIn(
            'home_metadata.st_uid == runtime_account.pw_uid',
            runner,
        )
        self.assertIn('runtime_home == Path("/home/secpal-runtime")', runner)
        self.assertIn(
            'cwd=str(runtime_home) if name == "podman" else None',
            runner,
        )
        function = re.search(
            r"\ndef runtime_home_admitted\(.*?(?=\n\npayload =)",
            runner,
            re.DOTALL,
        )
        self.assertIsNotNone(function)
        fake_pwd = types.SimpleNamespace(getpwnam=mock.Mock())
        namespace = {"os": os, "Path": Path, "pwd": fake_pwd, "stat": stat}
        exec(function.group(0), namespace)
        admitted = namespace["runtime_home_admitted"]
        admitted_home = namespace["admitted_runtime_home"]
        account = types.SimpleNamespace(pw_uid=1001, pw_gid=1001)
        home = types.SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o700, st_uid=1001, st_gid=1001
        )
        parent = types.SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0
        )
        self.assertTrue(
            admitted(Path("/home/secpal-runtime"), account, home, parent)
        )
        self.assertFalse(
            admitted(
                Path("/home/secpal-runtime"),
                account,
                types.SimpleNamespace(
                    st_mode=stat.S_IFDIR | 0o600, st_uid=1001, st_gid=1001
                ),
                parent,
            )
        )
        fake_pwd.getpwnam.side_effect = KeyError("missing")
        self.assertIsNone(admitted_home())
        fake_pwd.getpwnam.side_effect = None
        fake_pwd.getpwnam.return_value = types.SimpleNamespace(
            pw_uid=1001,
            pw_gid=1001,
            pw_dir="/home/secpal-runtime",
        )
        with mock.patch.object(Path, "lstat", side_effect=OSError("missing")):
            self.assertIsNone(admitted_home())
        self.assertFalse(
            admitted(
                Path("/home/secpal-runtime"),
                account,
                home,
                types.SimpleNamespace(
                    st_mode=stat.S_IFDIR | 0o777, st_uid=0, st_gid=0
                ),
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            blocked = root / "blocked"
            runtime_home = root / "runtime-home"
            blocked.mkdir(mode=0o700)
            runtime_home.mkdir(mode=0o700)
            original = Path.cwd()
            os.chdir(blocked)
            blocked.chmod(0)
            try:
                inherited = subprocess.run(
                    [sys.executable, "-c", "import os; os.chdir('.')"],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                bounded = subprocess.run(
                    [sys.executable, "-c", "import os; os.chdir('.')"],
                    check=False,
                    capture_output=True,
                    text=True,
                    cwd=runtime_home,
                )
            finally:
                blocked.chmod(0o700)
                os.chdir(original)
            self.assertNotEqual(0, inherited.returncode)
            self.assertEqual(0, bounded.returncode, bounded.stderr)


if __name__ == "__main__":
    unittest.main()
