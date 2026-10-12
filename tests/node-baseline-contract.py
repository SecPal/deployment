#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Enforce the active deployment Node contract through repository preflight."""

import json
from pathlib import Path
import re
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]


class NodeBaselineContract(unittest.TestCase):
    def test_local_manifest_and_lockfile_select_the_same_exact_node_26(self):
        version = (ROOT / ".nvmrc").read_text().strip()
        self.assertRegex(version, r"^26\.\d+\.\d+$")
        manifest = json.loads((ROOT / "package.json").read_text())
        lockfile = json.loads((ROOT / "package-lock.json").read_text())
        self.assertEqual(manifest["engines"]["node"], version)
        self.assertEqual(lockfile["packages"][""]["engines"], manifest["engines"])
        self.assertEqual(
            lockfile["packages"][""]["devDependencies"], manifest["devDependencies"]
        )

    def test_workflow_node_consumers_use_local_version_selection(self):
        workflows_with_node = set()
        for workflow in sorted((ROOT / ".github/workflows").glob("*.y*ml")):
            document = yaml.safe_load(workflow.read_text())
            for job_name, job in document["jobs"].items():
                node_configured = False
                for step in job.get("steps", []):
                    if str(step.get("uses", "")).startswith("actions/setup-node@"):
                        with self.subTest(workflow=workflow.name, job=job_name):
                            settings = step.get("with", {})
                            self.assertEqual(settings.get("node-version-file"), ".nvmrc")
                            self.assertNotIn("node-version", settings)
                            workflows_with_node.add(workflow.name)
                            node_configured = True
                    if re.search(
                        r"(?:^|[;&|()\s])(?:node|npm|npx|pnpm|yarn)(?=$|\s)",
                        step.get("run", ""),
                    ):
                        with self.subTest(workflow=workflow.name, job=job_name):
                            self.assertTrue(node_configured, "Set up Node before using it")
        self.assertTrue(
            {"quality.yml", "local-integration.yml"}.issubset(workflows_with_node)
        )


if __name__ == "__main__":
    unittest.main()
