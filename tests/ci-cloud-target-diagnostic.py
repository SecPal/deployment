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
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts/ci-cloud/bounded-target-diagnostic.py"


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
        payload = b"first line\nERROR: final target failure\n"
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
            self.assertEqual(payload, path.read_bytes())

    def test_emitted_json_line_obeys_the_byte_limit(self) -> None:
        payload = (b"\xff" * (16 * 1024 - 32)) + b"\nERROR: final failure\n"
        with tempfile.TemporaryDirectory() as directory:
            path = self.private_file(directory)
            path.write_bytes(payload)
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
        self.assertEqual("workload-prepare-start", document["phase"])
        self.assertEqual(7, document["status"])
        self.assertTrue(document["output"].endswith("ERROR: final failure"))


if __name__ == "__main__":
    unittest.main()
