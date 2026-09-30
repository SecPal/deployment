#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Agreement and pipeline tests for the current #119 workload contract layers."""

from __future__ import annotations

import ast
import copy
import importlib.util
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker, ValidationError


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schemas/ci-cloud-evidence.schema.json").read_text())


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class WorkloadLayerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        scripts = ROOT / "scripts" / "ci-cloud"
        cls.collector = load(scripts / "collect-workload-evidence.py", "layer_collector")
        cls.admission = load(scripts / "workload-admission.py", "layer_admission")
        cls.assembler = load(scripts / "assemble-evidence.py", "layer_assembler")
        cls.validator = load(scripts / "validate-evidence.py", "layer_validator")
        cls.workload_fixture = load(
            ROOT / "tests" / "ci-cloud-workload-evidence.py", "layer_workload_fixture"
        )
        cls.host_fixture = load(
            ROOT / "tests" / "ci-cloud-evidence.py", "layer_host_fixture"
        )
        cls.schema_validator = Draft202012Validator(SCHEMA, format_checker=FormatChecker())

    def assembled(self, observations=None):
        if observations is None:
            observations = self.workload_fixture.valid_observations()
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
            mode: {
                "mode": mode, "status": 0, "stage": "complete",
                "failure_reason": None, "command_status": None,
            }
            for mode in ("live", "cleanup")
        }
        return self.assembler.assemble(
            host, observations["baseline"], observations["live"],
            observations["post_cleanup"], diagnostics, statuses, collection,
        )

    def test_closed_surfaces_and_target_has_no_workload_decision(self) -> None:
        collector = self.collector
        self.assertFalse(hasattr(collector, "workload_admission_failures"))
        self.assertIn("collect_live", collector.COLLECTION_SURFACE)
        self.assertIn("normalize_quadlet_runtime", collector.COLLECTION_SURFACE)
        self.assertNotIn("normalize_quadlet_runtime", collector.NORMALIZATION_SURFACE)
        self.assertIn("normalized_network_endpoints", collector.NORMALIZATION_SURFACE)
        self.assertEqual(set(collector.ADMISSION_CONTRACT), set(self.admission._CONTRACT))
        source = (ROOT / "scripts" / "ci-cloud" / "workload-admission.py").read_text()
        bindings = {
            node.targets[0].id: node.value.slice.value
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, ast.Subscript)
            and isinstance(node.value.value, ast.Name)
            and node.value.value.id == "_CONTRACT"
            and isinstance(node.value.slice, ast.Constant)
        }
        self.assertEqual({name: name for name in collector.ADMISSION_CONTRACT}, bindings)
        with self.assertRaises(TypeError):
            collector.ADMISSION_CONTRACT["unreviewed"] = object()
        self.assertEqual([], self.admission.workload_admission_failures(
            self.workload_fixture.valid_observations()
        ))

    def test_canonical_roles_and_schema_agree(self) -> None:
        defs = SCHEMA["$defs"]
        self.assertEqual(set(self.collector.ROLES), set(defs["workloadRole"]["enum"]))
        logical = defs["generatedServiceFact"]["properties"]["logical_name"]
        self.assertEqual(set(self.collector.GENERATED_LOGICAL_NAMES), set(logical["enum"]))
        self.assertEqual(
            set(self.collector.LIVE_OBSERVATION_FIELDS),
            set(defs["liveObservation"]["required"]),
        )
        self.assertEqual(
            set(self.collector.CLEANUP_OBSERVATION_FIELDS),
            set(defs["cleanupObservation"]["required"]),
        )
        self.assertEqual(
            set(self.collector.BASELINE_OBSERVATION_FIELDS),
            set(defs["baselineObservation"]["required"]),
        )
        self.assertEqual(
            {"$ref": "#/$defs/workloadProcessList"},
            defs["liveObservation"]["properties"]["processes"],
        )
        self.assertEqual(
            {"$ref": "#/$defs/cleanupInventoryNames"},
            defs["cleanupObservation"]["properties"]["owned_units"],
        )
        self.assertEqual(
            {"$ref": "#/$defs/workloadPublishedPorts"},
            defs["containerFact"]["properties"]["published_ports"],
        )

    def test_canonical_unit_names_and_schema_agree(self) -> None:
        defs = SCHEMA["$defs"]
        instance = "a" * 12
        for name in self.collector.expected_unit_names(instance):
            Draft202012Validator(defs["quadletUnitName"]).validate(name)
        for logical_name in self.collector.GENERATED_LOGICAL_NAMES:
            service = f"secpal-int-{instance}-{logical_name}.service"
            source = self.collector.expected_generated_source(instance, logical_name)
            Draft202012Validator(defs["generatedServiceName"]).validate(service)
            Draft202012Validator(defs["quadletSourcePath"]).validate(str(source))
        for rejected in ("secpal-int-aaaaaaaaaaaa-valkey.container", "obsolete.service"):
            # Closed role identity is enforced by admission even when a broad
            # structural name pattern can parse the representation.
            self.assertNotIn(rejected, self.collector.expected_unit_names(instance))

    def test_current_representation_normalizes_into_accepted_pipeline(self) -> None:
        observations = self.workload_fixture.valid_observations()
        container = observations["live"]["containers"][0]
        mounts = []
        for fact in container["mounts"]:
            raw = {
                "Type": fact["type"], "Destination": fact["destination"],
                "RW": fact["rw"],
            }
            raw["Name" if fact["type"] == "volume" else "Source"] = fact["source"]
            mounts.append(raw)
        normalized_mounts, complete = self.collector.normalized_mounts(mounts)
        self.assertTrue(complete)
        self.assertEqual(container["mounts"], normalized_mounts)
        normalized_command, complete = self.collector.normalized_command(container["command"])
        self.assertTrue(complete)
        self.assertEqual(container["command"], normalized_command)
        tmpfs = container["tmpfs"][0]
        options = ",".join([
            *tmpfs["flags"], f"size={tmpfs['size_bytes']}",
            f"mode={tmpfs['mode']}", f"uid={tmpfs['uid']}", f"gid={tmpfs['gid']}",
        ])
        normalized_tmpfs, complete = self.collector.normalized_tmpfs(
            {tmpfs["destination"]: options}
        )
        self.assertTrue(complete)
        self.assertEqual([tmpfs], normalized_tmpfs)
        document = self.assembled(observations)
        self.schema_validator.validate(document)
        self.assertEqual("passed", document["workload"]["result"])
        self.assertEqual(document, self.validator.validate_document(document))

    def test_semantic_mutations_fail_at_controller_admission(self) -> None:
        mutations = {
            "unknown_role": lambda x: x["live"]["containers"][0].update(role="valkey"),
            "obsolete_role": lambda x: x["live"]["containers"][0].update(role="worker"),
            "wrong_image": lambda x: x["live"]["containers"][0].update(
                image_digest="sha256:" + "0" * 64
            ),
            "wrong_generated_unit": lambda x: x["live"]["generated_services"][0].update(
                unit="obsolete.service"
            ),
            "provenance_free": lambda x: x["live"]["generated_services"][0].update(
                source_path=""
            ),
            "duplicate_container": lambda x: x["live"]["containers"].append(
                copy.deepcopy(x["live"]["containers"][0])
            ),
            "missing_container": lambda x: x["live"]["containers"].pop(),
            "wrong_ports": lambda x: x["live"]["containers"][0].update(
                published_ports=["invalid"]
            ),
            "wrong_process_count": lambda x: x["live"]["processes"][0].update(count=257),
            "wrong_cleanup": lambda x: x["post_cleanup"]["containers"].append(
                "secpal-int-aaaaaaaaaaaa-api"
            ),
            "contradictory_sha": lambda x: x["live"].update(target_sha="b" * 40),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                observations = self.workload_fixture.valid_observations()
                mutate(observations)
                failures = self.admission.workload_admission_failures(observations)
                self.assertTrue(failures)
                document = self.assembled(observations)
                self.assertEqual("failed", document["workload"]["result"])
                self.assertTrue(document["workload"]["failed_admission_invariants"])
                try:
                    self.schema_validator.validate(document)
                except ValidationError:
                    with self.assertRaises(ValueError):
                        self.validator.validate_document(document)
                    continue
                if name == "contradictory_sha":
                    with self.assertRaisesRegex(ValueError, "exact target SHA"):
                        self.validator.validate_document(document)
                else:
                    self.assertEqual(document, self.validator.validate_document(document))

    def test_unknown_or_over_limit_facts_fail_schema(self) -> None:
        mutations = (
            lambda x: x["live"].pop("podman_rootless"),
            lambda x: x["live"].update(unknown_fact=True),
            lambda x: x["live"].update(processes=x["live"]["processes"] * 257),
        )
        for mutate in mutations:
            observations = self.workload_fixture.valid_observations()
            mutate(observations)
            document = self.assembled(observations)
            self.assertTrue(list(self.schema_validator.iter_errors(document)))
            with self.assertRaises(ValueError):
                self.validator.validate_document(document)

    def test_network_representation_rejects_malformed_or_excessive_input(self) -> None:
        instance = "a" * 12
        network = f"secpal-int-{instance}-application"
        endpoint = {
            "IPAddress": "10.88.0.2", "IPPrefixLen": 24,
            "Gateway": "10.88.0.1", "GlobalIPv6Address": "",
            "GlobalIPv6PrefixLen": 0, "IPv6Gateway": "",
            "NetworkID": "1" * 64, "Aliases": ["api", "123456789abc"],
        }
        names, facts, complete = self.collector.normalized_network_endpoints(
            {network: endpoint}, network
        )
        self.assertTrue(complete)
        self.assertEqual([network], names)
        self.assertEqual(("api", "123456789abc"), facts[network].aliases)
        malformed = copy.deepcopy(endpoint)
        malformed["Aliases"] = ["api", "api"]
        self.assertFalse(self.collector.normalized_network_endpoints(
            {network: malformed}, network
        )[2])
        self.assertFalse(self.collector.normalized_network_endpoints(
            {str(index): endpoint for index in range(17)}, network
        )[2])


if __name__ == "__main__":
    unittest.main()
