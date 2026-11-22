#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Deployment admission composes the pinned organization scanner, fail closed."""

from __future__ import annotations

import itertools
import re
import shlex
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

    def test_daily_assessment_only_reuses_the_required_source_scan(self):
        daily = yaml.load(
            (ROOT / ".github/workflows/daily-repository-security.yml").read_text(),
            Loader=yaml.BaseLoader,
        )
        self.assertEqual(set(daily), {"name", "on", "permissions", "jobs"})
        self.assertEqual(daily["on"], {
            "schedule": [{"cron": "23 3 * * *"}], "workflow_dispatch": "",
        })
        self.assertEqual(daily["permissions"], {"contents": "read"})
        self.assertEqual(set(daily["jobs"]), {"repository-security"})
        job = daily["jobs"]["repository-security"]
        self.assertEqual(set(job), {"name", "runs-on", "timeout-minutes", "steps"})
        required = self.workflow["jobs"]["repository-security"]
        for field in ("runs-on", "timeout-minutes"):
            self.assertEqual(job[field], required[field])
        admission, *scan = job["steps"]
        self.assertEqual(scan, required["steps"][2:])
        self.assertEqual(set(admission), {"name", "shell", "run"})
        self.assertEqual(admission["shell"], "bash")

    def test_daily_events_admit_only_exact_protected_main(self):
        daily = yaml.load(
            (ROOT / ".github/workflows/daily-repository-security.yml").read_text(),
            Loader=yaml.BaseLoader,
        )
        admission = daily["jobs"]["repository-security"]["steps"][0]
        invalid_contexts = (
            {"GITHUB_REPOSITORY": "Other/deployment"},
            {"GITHUB_REF": "refs/heads/topic"},
            {"GITHUB_REF": "refs/tags/main"},
            {"GITHUB_REF_PROTECTED": "false"},
            {"GITHUB_REF_PROTECTED": ""},
            {"GITHUB_SHA": "main"},
            {"GITHUB_SHA": "a" * 39},
            {"GITHUB_SHA": ""},
            {"GITHUB_EVENT_NAME": "pull_request"},
        )
        for event, changes in itertools.product(
            ("schedule", "workflow_dispatch"), ({}, *invalid_contexts)
        ):
            with self.subTest(event=event, changes=changes):
                observed = subprocess.run(
                    ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", admission["run"]],
                    env={
                        "GITHUB_EVENT_NAME": event,
                        "GITHUB_REPOSITORY": "SecPal/deployment",
                        "GITHUB_REF": "refs/heads/main",
                        "GITHUB_REF_PROTECTED": "true",
                        "GITHUB_SHA": "a" * 40,
                        **changes,
                    },
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(observed.returncode, 1 if changes else 0)
                self.assertEqual(observed.stdout, "")
                if changes:
                    self.assertIn("requires protected SecPal/deployment main", observed.stderr)

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

    def test_python_workflows_consume_distinct_pinned_inventories(self):
        environments = {
            "quality": ("3.15.2", "quality"),
            "local-integration": ("3.13.14", "integration"),
            "rocky-evidence-architecture": ("${{ matrix.python }}", "schema"),
            "rocky-cloud-qualification": ("3.12.13", "qualification"),
        }
        for name, (python, inventory) in environments.items():
            with self.subTest(workflow=name):
                workflow = yaml.load(
                    (ROOT / f".github/workflows/{name}.yml").read_text(),
                    Loader=yaml.BaseLoader,
                )
                steps = [step for job in workflow["jobs"].values()
                         for step in job.get("steps", [])]
                install, = [step for step in steps if "python -m pip install" in step.get("run", "")]
                runtime, = [step for step in steps if step.get("uses", "").startswith("actions/setup-python@")]
                self.assertEqual(runtime["with"]["python-version"], python)
                if inventory == "schema":
                    gate = workflow["jobs"]["architecture-gate"]
                    self.assertEqual(gate["strategy"]["matrix"]["python"], ["3.12.13", "3.13.14"])
                commands = install["run"].replace("\\\n", " ").splitlines()
                command, = [shlex.split(line) for line in commands if line.startswith("python -m pip install")]
                options = ["--only-binary=:all:"]
                if inventory in ("quality", "integration"):
                    options = ["--build-constraint", "requirements/build/requirements.txt"]
                self.assertEqual(command, [
                    "python", "-m", "pip", "install", "--disable-pip-version-check", "--no-deps",
                    *options, "--requirement", f"requirements/{inventory}/requirements.txt",
                ])
                self.assertIn("python -m pip check", commands)

    def test_pip_inventory_is_pinned_and_has_one_owner_per_package(self):
        dependencies = {
            "schema": None,
            "qualification": "schema",
            "quality": "qualification",
            "integration": "quality",
            "build": None,
        }
        paths = set((ROOT / "requirements").glob("*/requirements.txt"))
        self.assertEqual(paths, {
            ROOT / f"requirements/{name}/requirements.txt" for name in dependencies
        })
        owners = {}
        for name, parent in dependencies.items():
            lines = [
                line for line in (ROOT / f"requirements/{name}/requirements.txt").read_text().splitlines()
                if line and not line.startswith("#")
            ]
            references = [line for line in lines if line.startswith("-r ")]
            self.assertEqual(references, [] if parent is None else [f"-r ../{parent}/requirements.txt"])
            pins = [line for line in lines if line not in references]
            self.assertTrue(pins, name)
            for pin in pins:
                match = re.fullmatch(r'([\w.-]+)==[0-9][\w.+!-]*(; python_version < "3\.13")?', pin)
                self.assertIsNotNone(match, pin)
                package = re.sub(r"[-_.]+", "-", match[1]).lower()
                self.assertNotIn(package, owners)
                owners[package] = name
                self.assertEqual(match[2] is not None, package == "typing-extensions")
        self.assertEqual(owners["jsonschema"], "schema")
        self.assertEqual(owners["pyyaml"], "qualification")
        self.assertEqual(owners["psycopg"], "integration")
        for package in ("reuse", "shellcheck-py", "yamllint"):
            self.assertEqual(owners[package], "quality")

        dependabot = yaml.load((ROOT / ".github/dependabot.yml").read_text(), Loader=yaml.BaseLoader)
        pip, = [entry for entry in dependabot["updates"] if entry["package-ecosystem"] == "pip"]
        self.assertCountEqual(pip["directories"], [f"/requirements/{name}" for name in dependencies])
        self.assertEqual(pip["schedule"]["interval"], "daily")
        auto_merge = yaml.load(
            (ROOT / ".github/workflows/dependabot-auto-merge.yml").read_text(),
            Loader=yaml.BaseLoader,
        )
        ecosystems = auto_merge["jobs"]["auto-merge"]["with"]["allowed-ecosystems"].split(",")
        self.assertNotIn("pip", ecosystems)


if __name__ == "__main__":
    unittest.main()
