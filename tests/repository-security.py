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
GATE = ROOT / "scripts/require-repository-security.sh"


class RepositorySecurityTests(unittest.TestCase):
    def setUp(self):
        self.workflow = yaml.load(
            (ROOT / ".github/workflows/quality.yml").read_text(),
            Loader=yaml.BaseLoader,
        )

    def test_pinned_read_only_scanner_without_caller_policy_inputs(self):
        job = self.workflow["jobs"]["repository-security"]
        self.assertEqual(job["runs-on"], "ubuntu-24.04")
        self.assertEqual(job["timeout-minutes"], "20")
        self.assertEqual(job["permissions"], {"contents": "read"})
        self.assertNotIn("secrets", job)
        self.assertNotIn("env", job)
        _, _, checkout, scan, acceptance = job["steps"]
        self.assertRegex(checkout["uses"], r"\Aactions/checkout@[0-9a-f]{40}\Z")
        self.assertEqual(
            checkout["with"],
            {"ref": "${{ github.sha }}", "persist-credentials": "false"},
        )
        self.assertRegex(
            scan["uses"],
            r"\ASecPal/\.github/\.github/actions/trivy-repository-scan@[0-9a-f]{40}\Z",
        )
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

    def test_existing_security_check_requires_both_codeql_analyses(self):
        jobs = self.workflow["jobs"]
        analysis = jobs["source-analysis"]
        self.assertEqual(analysis["strategy"], {
            "fail-fast": "false", "matrix": {"language": ["python", "actions"]},
        })
        self.assertEqual(analysis["permissions"], {"contents": "read", "security-events": "write"})
        checkout, initialize, analyze = analysis["steps"]
        self.assertEqual(checkout["with"], {"ref": "${{ github.sha }}", "persist-credentials": "false"})
        self.assertRegex(initialize["uses"], r"\Agithub/codeql-action/init@[0-9a-f]{40}\Z")
        self.assertEqual(analyze["uses"], initialize["uses"].replace("/init@", "/analyze@"))
        self.assertEqual(initialize["with"], {"languages": "${{ matrix.language }}"})
        self.assertEqual(analyze["with"], {"category": "/language:${{ matrix.language }}"})
        for step in (checkout, initialize, analyze):
            self.assertNotIn("if", step)
            self.assertNotIn("continue-on-error", step)
        required = jobs["repository-security"]
        self.assertEqual(required["name"], "Repository Security")
        self.assertEqual(required["needs"], "source-analysis")
        self.assertEqual(required["if"], "${{ always() }}")
        cancellation, gate = required["steps"][:2]
        self.assertEqual(cancellation["if"], "${{ cancelled() }}")
        self.assertEqual(cancellation["run"], "exit 1")
        self.assertNotIn("continue-on-error", cancellation)
        self.assertEqual(gate["if"], "${{ always() }}")
        self.assertEqual(gate["env"], {"ANALYSIS_RESULT": "${{ needs.source-analysis.result }}"})
        self.assertNotIn("continue-on-error", gate)
        for outcome in ("success", "failure", "cancelled", "skipped", ""):
            with self.subTest(outcome=outcome):
                observed = subprocess.run(
                    ["bash", "-e", "-c", gate["run"]], check=False,
                    env={"ANALYSIS_RESULT": outcome},
                )
                self.assertEqual(observed.returncode == 0, outcome == "success")

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
