#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Focused security and robustness regressions for the production validator."""

from __future__ import annotations

import copy
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from unittest import mock

import yaml


sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = ROOT / "scripts/validate-production-contract.py"
INVENTORY_PATH = ROOT / "config/production/inventory.example.yaml"
HOST_FACTS_PATH = ROOT / "tests/fixtures/production-host/valid-amd64.yaml"


def load_validator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("production_contract_validator", VALIDATOR_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("production contract validator could not be imported")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_mapping(path: Path) -> dict[str, object]:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise AssertionError(f"fixture root must be a mapping: {path}")
    return loaded


class ProductionContractRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.validator = load_validator()
        cls.inventory = load_mapping(INVENTORY_PATH)
        cls.host_facts = load_mapping(HOST_FACTS_PATH)

    def write_temporary_document(self, raw: str) -> Path:
        temporary = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False)
        self.addCleanup(Path(temporary.name).unlink, missing_ok=True)
        with temporary:
            temporary.write(raw)
        return Path(temporary.name)

    def assert_contract_violation(self, action: object) -> None:
        if not callable(action):
            raise AssertionError("contract-violation assertion requires a callable")
        with self.assertRaises(self.validator.ContractViolation):
            action()

    def test_noncanonical_numeric_ipv4_origins_are_rejected(self) -> None:
        for hostname in ("127.1", "0177.0.0.1", "0x7f.1"):
            with self.subTest(hostname=hostname):
                self.assert_contract_violation(
                    lambda hostname=hostname: self.validator.validate_origin(
                        f"https://{hostname}", "inventory.origins.frontend"
                    )
                )

    def test_yaml_merge_cannot_hide_secret_bearing_input(self) -> None:
        marker = "synthetic-hidden-secret"
        document = self.write_temporary_document(
            f"<<: {{backup: {{password: {marker}}}}}\n"
            "backup: {target: external}\n"
        )
        with self.assertRaises(self.validator.ContractViolation) as context:
            self.validator.read_document(document, "inventory")
        self.assertNotIn(marker, str(context.exception))

    def test_nonrecursive_yaml_aliases_remain_supported(self) -> None:
        document = self.write_temporary_document(
            "shared: &shared [safe]\n"
            "copy: *shared\n"
        )
        loaded = self.validator.read_document(document, "inventory")
        self.assertEqual(loaded["shared"], ["safe"])
        self.assertIs(loaded["shared"], loaded["copy"])

    def test_fine_grained_github_pat_shape_is_rejected(self) -> None:
        synthetic_token = "github_pat_" + ("A" * 22) + "_" + ("B" * 59)
        self.assert_contract_violation(
            lambda: self.validator.scan_forbidden_input(
                {"credential_reference": f"external-secret://{synthetic_token}"}
            )
        )

    def test_host_facts_schema_version_requires_an_exact_integer(self) -> None:
        for malformed_version in (True, 1.0):
            with self.subTest(schema_version=malformed_version):
                facts = copy.deepcopy(self.host_facts)
                facts["schema_version"] = malformed_version
                self.assert_contract_violation(
                    lambda facts=facts: self.validator.validate_host_facts(
                        self.inventory, facts
                    )
                )

    def test_inventory_schema_version_requires_an_exact_integer(self) -> None:
        for malformed_version in (True, 1.0):
            with self.subTest(schema_version=malformed_version):
                inventory = copy.deepcopy(self.inventory)
                inventory["schema_version"] = malformed_version
                self.assert_contract_violation(
                    lambda inventory=inventory: self.validator.validate_inventory(
                        inventory
                    )
                )

    def test_public_address_must_be_global_or_documentation_only(self) -> None:
        inventory = copy.deepcopy(self.inventory)
        host = inventory["host"]
        if not isinstance(host, dict):
            raise AssertionError("host inventory fixture must be a mapping")
        host["public_address"] = "100.64.0.1"
        self.assert_contract_violation(
            lambda: self.validator.validate_inventory(inventory)
        )

    def test_per_path_capacity_cannot_exceed_host_totals(self) -> None:
        for path_fact, total_fact in (
            ("free_bytes", "storage_total_bytes"),
            ("free_inodes", "total_inodes"),
        ):
            with self.subTest(path_fact=path_fact):
                facts = copy.deepcopy(self.host_facts)
                resources = facts["resources"]
                if not isinstance(resources, dict):
                    raise AssertionError("host resource fixture must be a mapping")
                storage = resources["storage"]
                if not isinstance(storage, dict):
                    raise AssertionError("host storage fixture must be a mapping")
                docker_data = storage["docker_data"]
                if not isinstance(docker_data, dict):
                    raise AssertionError("Docker storage fixture must be a mapping")
                total = resources[total_fact]
                if not isinstance(total, int):
                    raise AssertionError("host total fixture must be an integer")
                docker_data[path_fact] = total + 1
                self.assert_contract_violation(
                    lambda facts=facts: self.validator.validate_host_facts(
                        self.inventory, facts
                    )
                )

    def test_private_address_fact_order_is_not_significant(self) -> None:
        inventory = copy.deepcopy(self.inventory)
        host = inventory["host"]
        if not isinstance(host, dict):
            raise AssertionError("host inventory fixture must be a mapping")
        host["private_addresses"] = ["10.0.0.10", "10.0.0.11"]
        facts = copy.deepcopy(self.host_facts)
        network = facts["network"]
        if not isinstance(network, dict):
            raise AssertionError("host network fixture must be a mapping")
        network["private_addresses"] = ["10.0.0.11", "10.0.0.10"]

        self.validator.validate_inventory(inventory)
        self.validator.validate_host_facts(inventory, facts)

    def test_duplicate_private_address_facts_are_rejected(self) -> None:
        facts = copy.deepcopy(self.host_facts)
        network = facts["network"]
        if not isinstance(network, dict):
            raise AssertionError("host network fixture must be a mapping")
        network["private_addresses"] = ["10.0.0.10", "10.0.0.10"]
        self.assert_contract_violation(
            lambda: self.validator.validate_host_facts(self.inventory, facts)
        )

    def test_oversized_yaml_integer_is_translated(self) -> None:
        document = self.write_temporary_document(
            "schema_version: " + ("9" * 5000) + "\n"
        )
        self.assert_contract_violation(
            lambda: self.validator.read_document(document, "inventory")
        )

    def test_sensitive_mapping_keys_are_redacted_from_errors(self) -> None:
        synthetic_token = "ghp_" + ("A" * 36)
        for case, action in (
            (
                "forbidden-field",
                lambda: self.validator.scan_forbidden_input(
                    {f"{synthetic_token}_token": "synthetic"}
                ),
            ),
            (
                "unknown-field",
                lambda: self.validator.validate_inventory(
                    {**copy.deepcopy(self.inventory), synthetic_token: "synthetic"}
                ),
            ),
        ):
            with self.subTest(case=case):
                with self.assertRaises(self.validator.ContractViolation) as context:
                    action()
                self.assertNotIn(synthetic_token, str(context.exception))

    def test_release_candidate_kernel_is_rejected_at_stable_floor(self) -> None:
        facts = copy.deepcopy(self.host_facts)
        kernel = facts["kernel"]
        if not isinstance(kernel, dict):
            raise AssertionError("kernel fixture must be a mapping")
        for release in ("6.8.0-rc1", "6.8.0-rc", "6.8.0-RC2-generic"):
            with self.subTest(release=release):
                kernel["release"] = release
                self.assert_contract_violation(
                    lambda: self.validator.validate_host_facts(self.inventory, facts)
                )

    def test_loader_recursion_error_is_translated(self) -> None:
        document = self.write_temporary_document("schema_version: 1\n")
        with mock.patch.object(self.validator.yaml, "load", side_effect=RecursionError):
            self.assert_contract_violation(
                lambda: self.validator.read_document(document, "inventory")
            )

    def test_recursive_scan_error_is_translated(self) -> None:
        document = self.write_temporary_document("schema_version: 1\n")
        with mock.patch.object(
            self.validator, "scan_forbidden_input", side_effect=RecursionError
        ):
            self.assert_contract_violation(
                lambda: self.validator.read_document(document, "inventory")
            )

    def test_unbounded_runtime_version_component_is_rejected_deterministically(self) -> None:
        oversized_version = ("9" * 5000) + ".0.0"
        self.assert_contract_violation(
            lambda: self.validator.parse_version(
                oversized_version, "host facts.runtime.docker_engine_version"
            )
        )

    def test_unbounded_kernel_version_component_is_rejected_deterministically(self) -> None:
        facts = copy.deepcopy(self.host_facts)
        kernel = facts["kernel"]
        if not isinstance(kernel, dict):
            raise AssertionError("kernel fixture must be a mapping")
        kernel["release"] = ("9" * 5000) + ".8.0"
        self.assert_contract_violation(
            lambda: self.validator.validate_host_facts(self.inventory, facts)
        )


if __name__ == "__main__":
    unittest.main()
