#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Enforce the active deployment Node contract through repository preflight."""

import io
import json
from pathlib import Path
import shlex
import shutil
import tempfile
import unittest
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]


class NodeBaselineContract(unittest.TestCase):
    def test_local_manifest_and_lockfile_select_the_same_exact_node_26(self):
        version = (ROOT / ".nvmrc").read_text().strip()
        self.assertEqual(version, "26.11.1")
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
                    command = shlex.shlex(
                        step.get("run", ""), posix=True, punctuation_chars=True
                    )
                    command.whitespace_split = True
                    if any(
                        Path(token).name in {"node", "npm", "npx", "pnpm", "yarn"}
                        for token in command
                    ):
                        with self.subTest(workflow=workflow.name, job=job_name):
                            self.assertTrue(node_configured, "Set up Node before using it")
        self.assertTrue(
            {"quality.yml", "local-integration.yml"}.issubset(workflows_with_node)
        )


class NodeBaselineRegressionContract(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="node-baseline-")
        self.addCleanup(self.directory.cleanup)
        self.fixture = Path(self.directory.name)
        for relative in (
            ".nvmrc", "package.json", "package-lock.json", ".github/workflows"
        ):
            source, target = ROOT / relative, self.fixture / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if source.is_dir():
                shutil.copytree(source, target)
            else:
                shutil.copy2(source, target)

    def check_rejected(self):
        with mock.patch.dict(globals(), ROOT=self.fixture):
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(NodeBaselineContract)
            result = unittest.TextTestRunner(stream=io.StringIO()).run(suite)
        self.assertFalse(result.wasSuccessful(), "The regressed contract was accepted")

    def test_consistent_older_node_26_is_rejected(self):
        for relative in (".nvmrc", "package.json", "package-lock.json"):
            path = self.fixture / relative
            path.write_text(path.read_text().replace("26.11.1", "26.10.0"))
        self.check_rejected()

    def test_shell_command_forms_before_setup_are_rejected(self):
        workflow = self.fixture / ".github/workflows/quality.yml"
        original = workflow.read_text()
        for command in (
            "npm;", "'node' --version", "/usr/bin/node --version", "node>version.txt"
        ):
            with self.subTest(command=command):
                workflow.write_text(
                    original.replace(
                        "    steps:\n",
                        f"    steps:\n      - run: {json.dumps(command)}\n",
                        1,
                    )
                )
                self.check_rejected()


if __name__ == "__main__":
    unittest.main()
