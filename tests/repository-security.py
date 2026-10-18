#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Deployment admission composes the pinned organization scanner, fail closed."""

from __future__ import annotations

import itertools
import subprocess
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PIN = "6a6758681f4ebc46b4a33d442846d33d6b79785c"
ACTION = "SecPal/.github/.github/actions/trivy-repository-scan@" + PIN
CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
GATE = ROOT / "scripts/require-repository-security.sh"


class RepositorySecurityTests(unittest.TestCase):
    def setUp(self):
        self.workflow = yaml.load(
            (ROOT / ".github/workflows/quality.yml").read_text(),
            Loader=yaml.BaseLoader,
        )

    def test_exact_read_only_scanner_without_caller_policy_inputs(self):
        job = self.workflow["jobs"]["repository-security"]
        self.assertEqual(job["runs-on"], "ubuntu-24.04")
        self.assertEqual(job["timeout-minutes"], "20")
        self.assertEqual(job["permissions"], {"contents": "read"})
        self.assertNotIn("secrets", job)
        self.assertNotIn("env", job)
        checkout, scan, acceptance = job["steps"]
        self.assertEqual(checkout["uses"], CHECKOUT)
        self.assertEqual(
            checkout["with"],
            {"ref": "${{ github.sha }}", "persist-credentials": "false"},
        )
        self.assertEqual(scan["uses"], ACTION)
        self.assertEqual(scan["id"], "scan")
        for field in ("with", "env", "continue-on-error"):
            self.assertNotIn(field, scan)
        self.assertEqual(
            job["outputs"]["gate-state"], "${{ steps.scan.outputs.gate-state }}"
        )
        self.assertEqual(acceptance["env"], {
            "SCAN_RESULT": "${{ steps.scan.outcome }}",
            "GATE_STATE": "${{ steps.scan.outputs.gate-state }}",
        })
        self.assertEqual(
            acceptance["run"],
            'bash scripts/require-repository-security.sh "$SCAN_RESULT" "$GATE_STATE"',
        )
        self.assertEqual(self.workflow["permissions"], {"contents": "read"})

    def test_existing_required_check_cannot_succeed_after_failed_or_skipped_scan(self):
        job = self.workflow["jobs"]["repository-contract"]
        self.assertEqual(job["name"], "Repository Contract")
        self.assertEqual(job["needs"], "repository-security")
        self.assertEqual(job["if"], "${{ always() }}")
        admission = job["steps"][1]
        self.assertEqual(admission["env"], {
            "SCAN_RESULT": "${{ needs.repository-security.result }}",
            "GATE_STATE": "${{ needs.repository-security.outputs.gate-state }}",
        })
        self.assertEqual(
            admission["run"],
            'bash scripts/require-repository-security.sh "$SCAN_RESULT" "$GATE_STATE"',
        )
        self.assertNotIn("continue-on-error", admission)
        self.assertNotIn("if", admission)

    def test_admission_only_accepts_successful_clean_evidence_output(self):
        for result, state in itertools.product(
            ("success", "failure", "cancelled", "skipped", ""),
            ("CLEAN", "ACTIONABLE", "REVIEW_REQUIRED", "UNKNOWN_STALE", "",
             '{"gate_state":"CLEAN"}', "CLEAN;true"),
        ):
            with self.subTest(result=result, state=state):
                observed = subprocess.run(
                    ["bash", str(GATE), result, state], capture_output=True,
                    text=True, check=False,
                )
                self.assertEqual(
                    observed.returncode == 0, (result, state) == ("success", "CLEAN")
                )
        for arguments in ([], ["success"], ["success", "CLEAN", "override"]):
            self.assertNotEqual(
                subprocess.run(["bash", str(GATE), *arguments],
                               capture_output=True, check=False).returncode, 0
            )

    def test_offline_preflight_keeps_the_admission_regression(self):
        self.assertIn("python3 tests/repository-security.py",
                      (ROOT / "scripts/preflight.sh").read_text())


if __name__ == "__main__":
    unittest.main()
