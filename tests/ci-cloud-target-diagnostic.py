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
                    f"{len(payload)} 0 workload-runtime-admission\n"
                ).encode("ascii"),
                path.read_bytes(),
            )

    def test_emitted_json_line_is_content_free_and_byte_bounded(self) -> None:
        secret = b"synthetic-workload-password-never-log"
        payload = (
            b"SECPAL_TARGET_DIAGNOSTIC_V1:workload-runtime-admission\n"
            + (b"\xff" * (20 * 1024))
            + b"\nSECPAL_TARGET_DIAGNOSTIC_V1:workload-api-attestation-fetch\n"
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
            {"phase", "status", "stage", "output_bytes", "output_truncated"},
            set(document),
        )
        self.assertEqual("workload-prepare-start", document["phase"])
        self.assertEqual(7, document["status"])
        self.assertEqual("workload-api-attestation-fetch", document["stage"])
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
        self.assertNotIn("arbitrary-target-controlled-value", output.getvalue())

    def test_target_harness_and_trusted_helper_share_the_closed_stage_set(self) -> None:
        harness_stages = runpy.run_path(os.fspath(HARNESS))[
            "CLOUD_DIAGNOSTIC_STAGES"
        ]
        self.assertEqual(
            harness_stages,
            self.helper.ADMITTED_STAGES - {"host-contract"},
        )


if __name__ == "__main__":
    unittest.main()
