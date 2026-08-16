#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Tests for bounded inert cloud target diagnostics."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import runpy
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts/ci-cloud/bounded-target-diagnostic.py"
HARNESS = ROOT / "scripts/quadlet-integration.py"
FETCHER = ROOT / "scripts/fetch-oci-attestation.py"


def load_helper():
    spec = importlib.util.spec_from_file_location(
        "ci_cloud_target_diagnostic", HELPER
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load target diagnostic helper")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TargetDiagnosticTests(unittest.TestCase):
    def setUp(self) -> None:
        self.helper = load_helper()

    @staticmethod
    def private_file(directory: str) -> Path:
        path = Path(directory) / "diagnostic"
        descriptor = os.open(
            path,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            0o600,
        )
        os.close(descriptor)
        return path

    def test_capture_completes_repeated_short_writes(self) -> None:
        payload = (
            b"first line\n"
            b"SECPAL_TARGET_DIAGNOSTIC_V1:workload-runtime-admission\n"
            b"ERROR: final target failure\n"
        )
        real_write = os.write

        def short_write(descriptor: int, value: bytes) -> int:
            return real_write(descriptor, bytes(value[:3]))

        with tempfile.TemporaryDirectory() as directory:
            path = self.private_file(directory)
            stdin = SimpleNamespace(buffer=io.BytesIO(payload))
            with mock.patch.object(self.helper.sys, "stdin", stdin), mock.patch.object(
                self.helper.os, "write", side_effect=short_write
            ):
                self.helper.capture(path)
            self.assertEqual(
                (
                    f"{len(payload)} 0 workload-runtime-admission "
                    "unreported none\n"
                ).encode("ascii"),
                path.read_bytes(),
            )

    def test_emitted_json_line_is_content_free_and_byte_bounded(self) -> None:
        secret = b"synthetic-workload-password-never-log"
        payload = (
            b"SECPAL_TARGET_DIAGNOSTIC_V1:workload-runtime-admission\n"
            + (b"\xff" * (20 * 1024))
            + b"\nSECPAL_TARGET_DIAGNOSTIC_V1:workload-api-attestation-fetch\n"
            + b"SECPAL_TARGET_DIAGNOSTIC_FAILURE_V1:"
            + b"workload-api-attestation-fetch:command-exit:69\n"
            + b"PASSWORD="
            + secret
            + b"\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = self.private_file(directory)
            stdin = SimpleNamespace(buffer=io.BytesIO(payload))
            with mock.patch.object(self.helper.sys, "stdin", stdin):
                self.helper.capture(path)
            self.assertNotIn(secret, path.read_bytes())
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.helper.emit(path, "workload-prepare-start", "7")

        rendered = output.getvalue()
        self.assertLessEqual(
            len(rendered.encode("utf-8")),
            self.helper.MAX_EMITTED_BYTES,
        )
        prefix = "Target phase diagnostic: "
        self.assertTrue(rendered.startswith(prefix))
        document = json.loads(rendered.removeprefix(prefix))
        self.assertEqual(
            {
                "phase",
                "status",
                "stage",
                "failure_reason",
                "command_status",
                "output_bytes",
                "output_truncated",
            },
            set(document),
        )
        self.assertEqual("workload-prepare-start", document["phase"])
        self.assertEqual(7, document["status"])
        self.assertEqual("workload-api-attestation-fetch", document["stage"])
        self.assertEqual("command-exit", document["failure_reason"])
        self.assertEqual(69, document["command_status"])
        self.assertEqual(self.helper.MAX_CAPTURE_BYTES, document["output_bytes"])
        self.assertTrue(document["output_truncated"])
        self.assertNotIn(secret.decode("ascii"), rendered)

    def test_unreviewed_stage_marker_is_not_emitted(self) -> None:
        payload = (
            b"SECPAL_TARGET_DIAGNOSTIC_V1:workload-api-attestation-fetch\n"
            b"SECPAL_TARGET_DIAGNOSTIC_V1:arbitrary-target-controlled-value\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = self.private_file(directory)
            stdin = SimpleNamespace(buffer=io.BytesIO(payload))
            with mock.patch.object(self.helper.sys, "stdin", stdin):
                self.helper.capture(path)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.helper.emit(path, "workload-prepare-start", "1")

        document = json.loads(
            output.getvalue().removeprefix("Target phase diagnostic: ")
        )
        self.assertEqual("workload-api-attestation-fetch", document["stage"])
        self.assertEqual("unreported", document["failure_reason"])
        self.assertIsNone(document["command_status"])
        self.assertNotIn("arbitrary-target-controlled-value", output.getvalue())

    def test_wrong_phase_and_unreviewed_failure_reason_are_not_emitted(self) -> None:
        payload = (
            b"SECPAL_TARGET_DIAGNOSTIC_V1:workload-api-image-pull\n"
            b"SECPAL_TARGET_DIAGNOSTIC_FAILURE_V1:"
            b"workload-api-image-pull:arbitrary-target-value:17\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = self.private_file(directory)
            stdin = SimpleNamespace(buffer=io.BytesIO(payload))
            with mock.patch.object(self.helper.sys, "stdin", stdin):
                self.helper.capture(path)
            same_phase_output = io.StringIO()
            with contextlib.redirect_stdout(same_phase_output):
                self.helper.emit(path, "workload-prepare-start", "1")
            wrong_phase_output = io.StringIO()
            with contextlib.redirect_stdout(wrong_phase_output):
                self.helper.emit(path, "host", "1")

        same_phase = json.loads(
            same_phase_output.getvalue().removeprefix("Target phase diagnostic: ")
        )
        self.assertEqual("workload-api-image-pull", same_phase["stage"])
        self.assertEqual("unreported", same_phase["failure_reason"])
        self.assertIsNone(same_phase["command_status"])
        wrong_phase = json.loads(
            wrong_phase_output.getvalue().removeprefix("Target phase diagnostic: ")
        )
        self.assertEqual("unreported", wrong_phase["stage"])
        self.assertEqual("unreported", wrong_phase["failure_reason"])
        self.assertIsNone(wrong_phase["command_status"])

    def test_specific_child_reason_precedes_generic_parent_exit(self) -> None:
        payload = (
            b"SECPAL_TARGET_DIAGNOSTIC_V1:workload-api-attestation-fetch\n"
            b"SECPAL_TARGET_DIAGNOSTIC_FAILURE_V1:"
            b"workload-api-attestation-fetch:registry-request-failed:none\n"
            b"SECPAL_TARGET_DIAGNOSTIC_FAILURE_V1:"
            b"workload-api-attestation-fetch:command-exit:1\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = self.private_file(directory)
            stdin = SimpleNamespace(buffer=io.BytesIO(payload))
            with mock.patch.object(self.helper.sys, "stdin", stdin):
                self.helper.capture(path)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.helper.emit(path, "workload-prepare-start", "1")

        document = json.loads(
            output.getvalue().removeprefix("Target phase diagnostic: ")
        )
        self.assertEqual("registry-request-failed", document["failure_reason"])
        self.assertIsNone(document["command_status"])

    def test_pull_output_is_classified_without_persisting_content(self) -> None:
        cases = (
            (b"writing blob: file too large", "file-size-limit-exceeded"),
            (b"copying layer: no space left on device", "storage-write-failed"),
            (b"dial tcp: network is unreachable", "registry-request-failed"),
            (b"reading manifest: unauthorized", "registry-response-rejected"),
        )
        for diagnostic, expected in cases:
            with (
                self.subTest(expected=expected),
                tempfile.TemporaryDirectory() as directory,
            ):
                secret = b"synthetic-registry-secret-never-persist"
                payload = (
                    b"SECPAL_TARGET_DIAGNOSTIC_V1:workload-api-image-pull\n"
                    + diagnostic
                    + b": "
                    + secret
                    + b"\nSECPAL_TARGET_DIAGNOSTIC_FAILURE_V1:"
                    b"workload-api-image-pull:command-exit:125\n"
                )
                path = self.private_file(directory)
                stdin = SimpleNamespace(buffer=io.BytesIO(payload))
                with mock.patch.object(self.helper.sys, "stdin", stdin):
                    self.helper.capture(path)
                self.assertNotIn(secret, path.read_bytes())
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.helper.emit(path, "workload-prepare-start", "1")

            rendered = output.getvalue()
            document = json.loads(
                rendered.removeprefix("Target phase diagnostic: ")
            )
            self.assertEqual("workload-api-image-pull", document["stage"])
            self.assertEqual(expected, document["failure_reason"])
            self.assertIsNone(document["command_status"])
            self.assertNotIn(secret.decode("ascii"), rendered)

    def test_pull_classifier_spans_chunks_beyond_the_capture_limit(self) -> None:
        stage = b"SECPAL_TARGET_DIAGNOSTIC_V1:workload-api-image-pull\n"
        split_prefix = b"writing blob: file too "
        padding = b"x" * (64 * 1024 - len(stage) - len(split_prefix))
        secret = b"synthetic-tail-secret-never-persist"
        payload = (
            stage
            + padding
            + split_prefix
            + b"large: "
            + secret
            + b"\nSECPAL_TARGET_DIAGNOSTIC_FAILURE_V1:"
            b"workload-api-image-pull:command-exit:125\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = self.private_file(directory)
            stdin = SimpleNamespace(buffer=io.BytesIO(payload))
            with mock.patch.object(self.helper.sys, "stdin", stdin):
                self.helper.capture(path)
            self.assertNotIn(secret, path.read_bytes())
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.helper.emit(path, "workload-prepare-start", "1")

        document = json.loads(
            output.getvalue().removeprefix("Target phase diagnostic: ")
        )
        self.assertEqual("file-size-limit-exceeded", document["failure_reason"])
        self.assertIsNone(document["command_status"])
        self.assertEqual(self.helper.MAX_CAPTURE_BYTES, document["output_bytes"])
        self.assertTrue(document["output_truncated"])

    def test_pull_sigxfsz_status_is_classified_without_command_output(self) -> None:
        payload = (
            b"SECPAL_TARGET_DIAGNOSTIC_V1:workload-api-image-pull\n"
            b"SECPAL_TARGET_DIAGNOSTIC_FAILURE_V1:"
            b"workload-api-image-pull:command-exit:153\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = self.private_file(directory)
            stdin = SimpleNamespace(buffer=io.BytesIO(payload))
            with mock.patch.object(self.helper.sys, "stdin", stdin):
                self.helper.capture(path)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.helper.emit(path, "workload-prepare-start", "1")

        document = json.loads(
            output.getvalue().removeprefix("Target phase diagnostic: ")
        )
        self.assertEqual("file-size-limit-exceeded", document["failure_reason"])
        self.assertIsNone(document["command_status"])

    def test_explicit_pull_reason_precedes_output_classification(self) -> None:
        payload = (
            b"SECPAL_TARGET_DIAGNOSTIC_V1:workload-api-image-pull\n"
            b"file too large\n"
            b"SECPAL_TARGET_DIAGNOSTIC_FAILURE_V1:"
            b"workload-api-image-pull:registry-request-failed:none\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = self.private_file(directory)
            stdin = SimpleNamespace(buffer=io.BytesIO(payload))
            with mock.patch.object(self.helper.sys, "stdin", stdin):
                self.helper.capture(path)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.helper.emit(path, "workload-prepare-start", "1")

        document = json.loads(
            output.getvalue().removeprefix("Target phase diagnostic: ")
        )
        self.assertEqual("registry-request-failed", document["failure_reason"])
        self.assertIsNone(document["command_status"])

    def test_pull_patterns_do_not_reclassify_other_stages(self) -> None:
        payload = (
            b"SECPAL_TARGET_DIAGNOSTIC_V1:workload-gh-cli-staging\n"
            b"file too large\n"
            b"SECPAL_TARGET_DIAGNOSTIC_FAILURE_V1:"
            b"workload-gh-cli-staging:command-exit:153\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = self.private_file(directory)
            stdin = SimpleNamespace(buffer=io.BytesIO(payload))
            with mock.patch.object(self.helper.sys, "stdin", stdin):
                self.helper.capture(path)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.helper.emit(path, "workload-prepare-start", "1")

        document = json.loads(
            output.getvalue().removeprefix("Target phase diagnostic: ")
        )
        self.assertEqual("command-exit", document["failure_reason"])
        self.assertEqual(153, document["command_status"])

    def test_maximum_closed_failure_marker_accepts_none_status(self) -> None:
        stage = "s" * 64
        reason = "r" * 64
        payload = (
            f"SECPAL_TARGET_DIAGNOSTIC_V1:{stage}\n"
            f"SECPAL_TARGET_DIAGNOSTIC_FAILURE_V1:"
            f"{stage}:{reason}:none\n"
        ).encode("ascii")
        with tempfile.TemporaryDirectory() as directory:
            path = self.private_file(directory)
            stdin = SimpleNamespace(buffer=io.BytesIO(payload))
            with (
                mock.patch.object(self.helper.sys, "stdin", stdin),
                mock.patch.object(self.helper, "ADMITTED_STAGES", {stage}),
                mock.patch.object(self.helper, "FAILURE_REASONS", {reason}),
            ):
                self.helper.capture(path)
            self.assertEqual(
                f"{len(payload)} 0 {stage} {reason} none\n".encode("ascii"),
                path.read_bytes(),
            )

    def test_target_harness_and_trusted_helper_share_the_closed_stage_set(self) -> None:
        harness_stages = runpy.run_path(os.fspath(HARNESS))[
            "CLOUD_DIAGNOSTIC_STAGES"
        ]
        self.assertEqual(
            harness_stages,
            self.helper.ADMITTED_STAGES - {"host-contract"},
        )
        harness_reasons = runpy.run_path(os.fspath(HARNESS))[
            "CLOUD_DIAGNOSTIC_FAILURE_REASONS"
        ]
        self.assertLessEqual(harness_reasons, self.helper.FAILURE_REASONS)
        self.assertEqual(
            {"file-size-limit-exceeded", "storage-write-failed"},
            self.helper.FAILURE_REASONS - harness_reasons,
        )
        fetcher = runpy.run_path(os.fspath(FETCHER))
        self.assertEqual(
            fetcher["DIAGNOSTIC_STAGES"],
            {
                "workload-api-attestation-fetch",
                "workload-frontend-attestation-fetch",
            },
        )
        self.assertLessEqual(
            fetcher["DIAGNOSTIC_FAILURE_REASONS"],
            harness_reasons,
        )


if __name__ == "__main__":
    unittest.main()
