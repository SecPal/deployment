#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Regression tests for bounded early cloud-bootstrap failure evidence."""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WRITER = ROOT / "scripts" / "ci-cloud" / "write-bootstrap-failure.py"
TARGET_SHA = "a" * 40


class BootstrapFailureEvidenceTests(unittest.TestCase):
    def invoke(
        self, output_dir: Path, *, stage: str = "cloud-init"
    ) -> subprocess.CompletedProcess[str]:
        arguments = [
            "python3",
            str(WRITER),
            str(output_dir),
            "digitalocean",
            "fra1",
            "intel",
            TARGET_SHA,
            "12345",
            "1",
            "debian-13-x64",
            "234194767",
            "s-4vcpu-8gb-intel",
            stage,
            "1",
        ]
        return subprocess.run(arguments, check=False, capture_output=True, text=True)

    def test_writes_closed_structured_failure_and_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary)
            completed = self.invoke(output_dir)
            self.assertEqual(0, completed.returncode, completed.stderr)
            document = json.loads(
                (output_dir / "bootstrap-failure.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                {"schema_version", "workflow", "test"}, set(document)
            )
            self.assertEqual(
                {
                    "provider",
                    "region",
                    "profile",
                    "machine_type",
                    "provider_image",
                    "failure_stage",
                    "orchestration_exit_status",
                    "result",
                    "failed_admission_invariants",
                },
                set(document["test"]),
            )
            self.assertEqual("failed", document["test"]["result"])
            self.assertEqual(
                "CI_CLOUD_REMOTE_ORCHESTRATION",
                document["test"]["failed_admission_invariants"][0],
            )
            summary = (output_dir / "summary.md").read_text(encoding="utf-8")
            self.assertIn("cloud-init", summary)
            self.assertIn(TARGET_SHA, summary)

    def test_rejects_arbitrary_failure_stage_without_writing_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary)
            completed = self.invoke(output_dir, stage="arbitrary-shell-text")
            self.assertNotEqual(0, completed.returncode)
            self.assertEqual([], list(output_dir.iterdir()))

    def test_rejects_existing_output_to_prevent_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary)
            first = self.invoke(output_dir)
            second = self.invoke(output_dir)
            self.assertEqual(0, first.returncode, first.stderr)
            self.assertNotEqual(0, second.returncode)


if __name__ == "__main__":
    unittest.main()
