#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Adversarial checks of the current workload purity contract."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import socket
import subprocess
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts" / "ci-cloud"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("test fixture module unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class WorkloadPurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.purity = load(SCRIPTS / "workload-purity.py", "purity_test")
        cls.assembler = load(SCRIPTS / "assemble-evidence.py", "purity_assembler")
        cls.validator = load(SCRIPTS / "validate-evidence.py", "purity_validator")
        cls.workload_fixture = load(
            ROOT / "tests" / "ci-cloud-workload-evidence.py", "purity_workload_fixture"
        )
        cls.host_fixture = load(
            ROOT / "tests" / "ci-cloud-evidence.py", "purity_host_fixture"
        )
        cls.collector_source = (SCRIPTS / "collect-workload-evidence.py").read_text()
        cls.admission_source = (SCRIPTS / "workload-admission.py").read_text()

    def assert_mutation(self, *, collector=None, admission=None, identity: str) -> None:
        with self.assertRaises(self.purity.PurityViolation) as caught:
            self.purity.check_sources(
                collector if collector is not None else self.collector_source,
                admission if admission is not None else self.admission_source,
            )
        self.assertEqual(identity, caught.exception.identity)

    def test_current_sources_are_pure(self) -> None:
        self.purity.check_sources(self.collector_source, self.admission_source)
        self.assertIn("purity.check_files(purity_path.parent)",
                      (ROOT / "scripts" / "validate-ci-cloud.py").read_text())
        self.assertIn("python3 tests/ci-cloud-workload-purity.py",
                      (ROOT / "scripts" / "preflight.sh").read_text())

    def test_current_main_decision_characterization(self) -> None:
        base = self.workload_fixture.valid_observations()
        mutations = (
            lambda x: x.pop("baseline"),
            lambda x: x.pop("live"),
            lambda x: x.pop("post_cleanup"),
            lambda x: x["baseline"].update(phase="live"),
            lambda x: x["live"].update(phase="baseline"),
            lambda x: x["post_cleanup"].update(phase="live"),
            lambda x: x.update(target_sha="bad"),
            lambda x: x.update(instance="wrong"),
            lambda x: x["baseline"].update(collector_uid=0),
            lambda x: x["live"].update(collector_gid=0),
            lambda x: x["post_cleanup"].update(complete=False),
            lambda x: x["baseline"].update(migration_invocation_count=1),
            lambda x: x["baseline"].update(podman_api=True),
            lambda x: x["live"].update(installed_units=[]),
            lambda x: x["live"].update(networks=[]),
            lambda x: x["live"].update(volumes=[]),
            lambda x: x["post_cleanup"]["containers"].append("unexpected"),
            lambda x: x["baseline"]["control_resources"].update(network_present=False),
            lambda x: x["live"]["containers"][0].update(role="unknown"),
            lambda x: x["live"]["processes"][0].update(count=257),
        )
        candidates = [base, None]
        for mutate in mutations:
            candidate = copy.deepcopy(base)
            mutate(candidate)
            candidates.append(candidate)
        self.assertEqual(22, len(candidates))
        admission = self.assembler.load_workload_admission()
        decisions = [self.assembler.load_workload_purity().guarded_decision(
            admission, candidate) for candidate in candidates]
        digest = hashlib.sha256(json.dumps(
            decisions, sort_keys=True, separators=(",", ":")
        ).encode()).hexdigest()
        # Fresh characterization of the accepted #121 protected-main source.
        self.assertEqual(
            "389c95b76e8c185fd4f6696b66441c28ddb0f82fe65e818b7574dc1207b08e04",
            digest,
        )

    def test_static_capability_mutations(self) -> None:
        admission = self.admission_source
        collector = self.collector_source
        cases = (
            (None, admission.replace("import re\n", "import re\nimport os\n", 1),
             "PURITY_UNDECLARED_IMPORT"),
            (None, admission.replace("from typing import Any", "from typing import Any, Literal", 1),
             "PURITY_UNDECLARED_IMPORTED_MEMBER"),
            (None, admission.replace("re.fullmatch(", "re.compile(", 1),
             "PURITY_UNDECLARED_MODULE_ATTRIBUTE"),
            (collector.replace(
                "def parsed_manager_environment(output: str) -> dict[str, str] | None:\n",
                "def injected_helper():\n    return open('/tmp/impure')\n\n"
                "def parsed_manager_environment(output: str) -> dict[str, str] | None:\n"
                "    injected_helper()\n", 1), None,
             "PURITY_REACHABLE_IMPURE_CALLEE"),
            (collector.replace(
                "def parsed_manager_environment(output: str) -> dict[str, str] | None:\n",
                "def parsed_manager_environment(output: str) -> dict[str, str] | None:\n"
                "    [open('/tmp/impure') for _ in ()]\n", 1), None,
             "PURITY_UNDECLARED_NORMALIZATION_GLOBAL"),
            (collector.replace(
                "def parsed_manager_environment(output: str) -> dict[str, str] | None:\n",
                "def parsed_manager_environment(output: str) -> dict[str, str] | None:\n"
                "    getattr(output, 'x')\n", 1), None,
             "PURITY_DYNAMIC_CAPABILITY"),
            (collector.replace(
                "def parsed_manager_environment(output: str) -> dict[str, str] | None:\n",
                "def parsed_manager_environment(output: str) -> dict[str, str] | None:\n"
                "    type('Dynamic', (), {})\n", 1), None,
             "PURITY_DYNAMIC_CAPABILITY"),
            (collector + "\nADMISSION_CONTRACT = {}\n", None,
             "PURITY_CONTRACT_REBIND"),
            (None, admission.replace(
                "def workload_admission_failures(observations: object) -> list[str]:\n",
                "PRIVATE = ()\n\ndef workload_admission_failures(observations: object) -> list[str]:\n"
                "    return PRIVATE\n", 1),
             "PURITY_UNDECLARED_CONTRACT_GLOBAL"),
            (None, admission.replace(
                "def workload_admission_failures(observations: object) -> list[str]:\n",
                "def workload_admission_failures(observations: object) -> list[str]:\n"
                "    ROLE_CONTRACTS['api']['identity'] = (0, 0)\n", 1),
             "PURITY_CONTRACT_REBIND"),
            (collector.replace(
                "def parsed_manager_environment(output: str) -> dict[str, str] | None:\n",
                "def parsed_manager_environment(output: str) -> dict[str, str] | None:\n"
                "    re = output\n", 1), None,
             "PURITY_DYNAMIC_CAPABILITY"),
            (collector + "\nre = subprocess\n", None,
             "PURITY_IMPORT_SIDE_EFFECT"),
            (collector + "\nnormalized_mounts = subprocess.run\n", None,
             "PURITY_IMPORT_SIDE_EFFECT"),
            (None, admission.replace("return module.ADMISSION_CONTRACT",
                                     "return module.__dict__", 1),
             "PURITY_IMPORT_SIDE_EFFECT"),
        )
        for index, (candidate_collector, candidate_admission, identity) in enumerate(cases):
            with self.subTest(index=index):
                self.assert_mutation(collector=candidate_collector,
                                     admission=candidate_admission, identity=identity)

    def test_removed_module_attribute_rule_exposes_mutant(self) -> None:
        mutant = self.admission_source.replace("re.fullmatch(", "re.compile(", 1)
        self.assert_mutation(admission=mutant,
                             identity="PURITY_UNDECLARED_MODULE_ATTRIBUTE")
        original = self.purity.MODULE_ATTRIBUTES
        try:
            self.purity.MODULE_ATTRIBUTES = original | {"re.compile"}
            self.purity.check_sources(self.collector_source, mutant)
        finally:
            self.purity.MODULE_ATTRIBUTES = original

    def test_import_time_side_effects_stop_before_execution(self) -> None:
        with tempfile.TemporaryDirectory(prefix="secpal-purity-") as directory:
            fixture = Path(directory)
            marker = fixture / "marker"
            for name, injected in (
                ("file", f"open({str(marker)!r}, 'w').write('bad')"),
                ("process", "subprocess.run(['true'])"),
                ("network", "import socket\nsocket.socket()"),
            ):
                with self.subTest(name=name):
                    (fixture / "collect-workload-evidence.py").write_text(
                        self.collector_source + "\n" + injected + "\n"
                    )
                    (fixture / "workload-admission.py").write_text(self.admission_source)
                    with self.assertRaises(self.purity.PurityViolation):
                        self.purity.load_checked_admission(fixture)
                    with patch.object(self.assembler, "WORKLOAD_COLLECTOR",
                                      fixture / "collect-workload-evidence.py"):
                        with self.assertRaises(self.assembler.load_workload_purity().PurityViolation):
                            self.assembler.load_workload_collector()
                    with patch.object(self.assembler, "WORKLOAD_ADMISSION",
                                      fixture / "workload-admission.py"):
                        with self.assertRaises(self.assembler.load_workload_purity().PurityViolation):
                            self.assembler.load_workload_admission()
                    self.assertFalse(marker.exists())

    def assembled_with(self, decision, *, invalid=False):
        observations = self.workload_fixture.valid_observations()
        if invalid:
            observations["baseline"].pop("complete")
        host = self.host_fixture.valid_document()
        host.pop("host_admission")
        host.pop("workload")
        host["schema_version"] = 1
        statuses = {name: 0 for name in (
            "host", "workload_prepare_start", "workload_cleanup",
            "trusted_quadlet_normalize_live", "trusted_quadlet_normalize_cleanup",
        )}
        collection = {name: 0 for name in ("baseline", "live", "post_cleanup")}
        diagnostics = {
            mode: {"mode": mode, "status": 0, "stage": "complete",
                   "failure_reason": None, "command_status": None}
            for mode in ("live", "cleanup")
        }
        module = types.SimpleNamespace(workload_admission_failures=decision)
        with patch.object(self.assembler, "load_workload_admission", return_value=module):
            return self.assembler.assemble(
                host, observations["baseline"], observations["live"],
                observations["post_cleanup"], diagnostics, statuses, collection,
            )

    def test_real_assembler_guard_rejects_runtime_capabilities(self) -> None:
        with tempfile.TemporaryDirectory(prefix="secpal-purity-") as directory:
            marker = Path(directory) / "marker"
            attempts = (
                ("process", lambda _: subprocess.run(["true"], check=True),
                 "PURITY_RUNTIME_PROCESS"),
                ("file-read", lambda _: marker.read_text(),
                 "PURITY_RUNTIME_FILESYSTEM"),
                ("file-write", lambda _: marker.write_text("bad"),
                 "PURITY_RUNTIME_FILESYSTEM"),
                ("network", lambda _: socket.socket(),
                 "PURITY_RUNTIME_NETWORK"),
            )
            for name, attempt, identity in attempts:
                with self.subTest(name=name):
                    document = self.assembled_with(attempt)
                    self.assertIn(identity,
                                  document["workload"]["failed_admission_invariants"])
                    self.assertFalse(marker.exists())
            marker.write_text("controller orchestration remains outside the guard")
            self.assertEqual("controller orchestration remains outside the guard",
                             marker.read_text())

    def test_nested_contract_assignment_cannot_change_decision(self) -> None:
        admission = self.assembler.load_workload_admission()
        observations = self.workload_fixture.valid_observations()
        before = self.purity.guarded_decision(admission, observations)
        with self.assertRaises((AttributeError, TypeError)):
            admission._CONTRACT["ROLE_CONTRACTS"]["api"].identity = (0, 0)
        with self.assertRaises(TypeError):
            admission._CONTRACT["HEALTH_INTERVAL_USEC"]["api"] = 0
        self.assertEqual(before, self.purity.guarded_decision(admission, observations))

    def test_refusal_branch_is_guarded(self) -> None:
        def refusal_only(evidence):
            if "complete" not in evidence["baseline"]:
                return open("/tmp/secpal-refusal-probe").read()
            return []

        document = self.assembled_with(refusal_only, invalid=True)
        self.assertIn("PURITY_RUNTIME_FILESYSTEM",
                      document["workload"]["failed_admission_invariants"])

    def test_real_validator_recomputation_is_guarded(self) -> None:
        document = self.assembled_with(lambda _: [])
        original = self.validator.load_trusted_module
        with tempfile.TemporaryDirectory(prefix="secpal-purity-") as directory:
            marker = Path(directory) / "marker"
            attempts = (
                (lambda _: subprocess.run(["true"], check=True),
                 "PURITY_RUNTIME_PROCESS"),
                (lambda _: marker.write_text("bad"),
                 "PURITY_RUNTIME_FILESYSTEM"),
                (lambda _: socket.socket(),
                 "PURITY_RUNTIME_NETWORK"),
            )
            for attempt, identity in attempts:
                def loader(path, name):
                    if path == self.validator.WORKLOAD_ADMISSION_PATH:
                        return types.SimpleNamespace(workload_admission_failures=attempt)
                    return original(path, name)

                with patch.object(self.validator, "load_trusted_module", side_effect=loader):
                    _, workload_failures, _ = self.validator.recompute_admission(document)
                self.assertIn(identity, workload_failures)
                self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
