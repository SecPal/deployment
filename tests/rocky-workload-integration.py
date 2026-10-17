#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Repository evidence for the Rocky-to-workload orchestration seam."""

from __future__ import annotations
import hashlib
import importlib.util
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts" / "ci-cloud"


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), SCRIPTS / name)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class RockyWorkloadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.loader = load("workload-source-loader.py")
        cls.runner = load("run-rocky-workload-qualification.py")
        cls.controller = load("admit-rocky-workload.py")

    def test_signaled_collection_cannot_become_success(self):
        with mock.patch.object(self.runner.subprocess, "run",
                               return_value=SimpleNamespace(returncode=-9)):
            status, _ = self.runner.command("baseline", ["unused"], capture=True,
                                            allow_failure=True)
        self.assertEqual(137, status)

    def test_control_source_transport_requires_all_bootstrap_digests_before_install(self):
        sources = {name: (SCRIPTS / name).read_text() for name in self.loader.SOURCES}
        manifest = {name: hashlib.sha256(value.encode()).hexdigest()
                    for name, value in sources.items()}
        self.assertEqual(set(sources), set(self.loader.admit_sources(
            json.dumps(sources).encode(), manifest)))
        for mutation in ("changed", "extra", "missing", "duplicate"):
            candidate = dict(sources)
            if mutation == "changed":
                candidate["workload-purity.py"] += "\\n"
            elif mutation == "extra":
                candidate["../../arbitrary.py"] = "code"
            elif mutation == "missing":
                del candidate["workload-admission.py"]
            payload = json.dumps(candidate)
            if mutation == "duplicate":
                payload = payload[:-1] + ', "workload-purity.py": "other"}'
            with self.assertRaises(ValueError):
                self.loader.admit_sources(payload.encode(), manifest)

    def test_phase_failure_still_collects_and_cleans_without_target_grading(self):
        calls = []
        def execute(phase):
            calls.append(phase)
            return (7 if phase == "workload_prepare_start" else 0), "{}"
        files, statuses = self.runner.run_phases(execute)
        self.assertEqual(list(self.runner.PHASES), calls)
        self.assertEqual(7, statuses["workload_prepare_start"])
        self.assertEqual(0, statuses["post_cleanup"])
        self.assertEqual(set(self.runner.FILES.values()), set(files))
        self.assertNotIn("result", files)

    def test_failed_baseline_never_starts_candidate_but_attempts_cleanup(self):
        calls = []
        def execute(phase):
            calls.append(phase)
            return (1 if phase == "baseline" else 0), "{}"
        _, statuses = self.runner.run_phases(execute)
        self.assertNotIn("workload_prepare_start", calls)
        self.assertNotEqual(0, statuses["workload_prepare_start"])
        self.assertIn("workload_cleanup", calls)
        self.assertIn("post_cleanup", calls)

    def test_interruption_preserves_final_cleanup_attempt(self):
        calls = []
        def execute(phase):
            calls.append(phase)
            if phase == "workload_prepare_start":
                raise KeyboardInterrupt()
            return 0, "{}"
        with self.assertRaises(KeyboardInterrupt):
            self.runner.run_phases(execute)
        self.assertEqual(["workload_cleanup", "trusted_quadlet_normalize_cleanup",
                          "post_cleanup"], calls[-3:])

    def bundle(self):
        fixtures = runpy.run_path(str(ROOT / "tests" / "ci-cloud-evidence.py"))
        document = fixtures["valid_document"]()
        files = {name: json.dumps(document["workload"][name])
                 for name in ("baseline", "live", "post_cleanup")}
        for mode in ("live", "cleanup"):
            files[mode + "_normalization"] = json.dumps(
                document["test"]["normalization_diagnostics"][mode])
        statuses = dict(document["test"]["phase_exit_statuses"])
        statuses.update(document["test"]["collection_exit_statuses"])
        return {"control_sha": "b" * 40, "workflow": document["workflow"],
                "files": files, "statuses": statuses}

    def admit(self, bundle):
        with tempfile.TemporaryDirectory() as directory:
            return self.controller.admit(bundle, "b" * 40, bundle["workflow"],
                                         Path(directory))

    def test_full_existing_pipeline_and_independent_schema_admission(self):
        self.assertEqual("passed", self.admit(self.bundle())["test"]["result"])

    def test_observation_cannot_supply_a_result_or_substitute_target(self):
        for mutation in ("forged-result", "target"):
            bundle = self.bundle()
            live = json.loads(bundle["files"]["live"])
            if mutation == "forged-result":
                live["result"] = "passed"
            else:
                live["target_sha"] = "c" * 40
            bundle["files"]["live"] = json.dumps(live)
            with self.assertRaises(ValueError):
                self.admit(bundle)

    def test_transport_rejects_stale_control_run_extra_fields_and_bad_status(self):
        for mutation in ("control", "run", "extra", "status", "oversize"):
            bundle = self.bundle()
            expected = dict(bundle["workflow"])
            if mutation == "control":
                bundle["control_sha"] = "c" * 40
            elif mutation == "run":
                bundle["workflow"]["run_id"] = "999"
            elif mutation == "extra":
                bundle["files"]["target_result"] = "passed"
            elif mutation == "status":
                bundle["statuses"]["baseline"] = True
            else:
                bundle["files"]["live"] = "x" * (256 * 1024 + 1)
            with tempfile.TemporaryDirectory() as directory, self.assertRaises(ValueError):
                self.controller.admit(bundle, "b" * 40, expected, Path(directory))

    def test_failed_cleanup_and_partial_collection_cannot_pass(self):
        for mutation in ("cleanup", "partial"):
            bundle = self.bundle()
            if mutation == "cleanup":
                bundle["statuses"]["workload_cleanup"] = 7
            else:
                bundle["files"]["live"] = ""
                bundle["statuses"]["live"] = 255
            self.assertEqual("failed", self.admit(bundle)["test"]["result"])

    def test_workflow_uses_current_control_and_retains_frozen_target_and_cleanup(self):
        workflow = (ROOT / ".github/workflows/rocky-cloud-qualification.yml").read_text()
        self.assertIn("admit-rocky-workload.py", workflow)
        self.assertIn("secpal-run-rocky-workload-qualification", workflow)
        self.assertIn("402c22b0a1d69a5a3dba74ffb68cf016caba606b", workflow)
        self.assertIn("436756f79c7f120d5c4b9fc15b12b2fd91da0fdea5e93ed2907172a73c2861ac", workflow)
        self.assertIn("PROVIDER_RUN_RESOURCE_SET_ABSENT", workflow)
        runner = (SCRIPTS / "run-rocky-workload-qualification.py").read_text()
        self.assertEqual(self.loader.TARGET, self.runner.TARGET)
        self.assertEqual(self.loader.HARNESS, self.runner.HARNESS)
        self.assertIn('"env", "-i"', runner)
        self.assertNotIn("guarded_decision", runner)


if __name__ == "__main__":
    unittest.main()
