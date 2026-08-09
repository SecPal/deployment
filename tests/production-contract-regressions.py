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


def nested_mapping(document: dict[str, object], *path: str) -> dict[str, object]:
    current = document
    for segment in path:
        child = current[segment]
        if not isinstance(child, dict):
            raise AssertionError(f"fixture path must be a mapping: {'.'.join(path)}")
        current = child
    return current


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

    def assert_contract_violation(
        self, action: object, expected_message: str | None = None
    ) -> None:
        if not callable(action):
            raise AssertionError("contract-violation assertion requires a callable")
        with self.assertRaises(self.validator.ContractViolation) as context:
            action()
        if expected_message is not None:
            self.assertIn(expected_message, str(context.exception))

    def assert_closed_keyset(
        self,
        expected: set[str],
        document: dict[str, object],
        schema: dict[str, object],
    ) -> None:
        self.assertEqual(expected, set(document))
        self.assertEqual(expected, set(schema["required"]))
        self.assertEqual(expected, set(schema["properties"]))

    def validate_synthetic_inventory(self, inventory: dict[str, object]) -> None:
        self.validator.validate_inventory(inventory, synthetic=True)

    def test_noncanonical_numeric_ipv4_origins_are_rejected(self) -> None:
        for hostname in ("127.1", "0177.0.0.1", "0x7f.1"):
            with self.subTest(hostname=hostname):
                self.assert_contract_violation(
                    lambda hostname=hostname: self.validator.validate_origin(
                        f"https://{hostname}", "inventory.origins.frontend"
                    )
                )

    def test_hostnames_must_be_dns_names(self) -> None:
        for hostname in (
            "127.0.0.1",
            "127.1",
            "192.0.2.10",
            "0177.0.0.1",
            "0x7f.1",
        ):
            with self.subTest(hostname=hostname):
                self.assert_contract_violation(
                    lambda hostname=hostname: self.validator.validate_hostname(
                        hostname, "inventory.host.hostname"
                    )
                )

    def test_malformed_bracketed_origins_are_translated(self) -> None:
        for origin in (
            "https://[foo)",
            "https://[foo",
            "https://foo]",
            "https://[]",
            "https://[gg::1]",
        ):
            with self.subTest(origin=origin):
                self.assert_contract_violation(
                    lambda origin=origin: self.validator.validate_origin(
                        origin, "inventory.origins.frontend"
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
                    lambda inventory=inventory: self.validate_synthetic_inventory(
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
            lambda: self.validate_synthetic_inventory(inventory)
        )

    def test_multicast_public_addresses_are_rejected(self) -> None:
        for address in ("224.0.0.1", "ff0e::1"):
            with self.subTest(address=address):
                inventory = copy.deepcopy(self.inventory)
                host = inventory["host"]
                if not isinstance(host, dict):
                    raise AssertionError("host inventory fixture must be a mapping")
                host["public_address"] = address
                self.assert_contract_violation(
                    lambda inventory=inventory: self.validate_synthetic_inventory(
                        inventory
                    )
                )

    def test_deprecated_site_local_public_address_is_rejected(self) -> None:
        inventory = copy.deepcopy(self.inventory)
        host = inventory["host"]
        if not isinstance(host, dict):
            raise AssertionError("host inventory fixture must be a mapping")
        host["public_address"] = "fec0::1"
        self.assert_contract_violation(
            lambda: self.validate_synthetic_inventory(inventory)
        )

    def test_non_public_special_purpose_ipv6_addresses_are_rejected(self) -> None:
        host = copy.deepcopy(nested_mapping(self.inventory, "host"))
        for address in (
            "2001:20::1",  # ORCHIDv2
            "2001:30::1",  # Drone Remote ID Protocol Entity Tags
            "2002::1",  # deprecated 6to4
            "2620:4f:8000::1",  # AS112 direct delegation
            "5f00::1",  # Segment Routing SIDs
        ):
            with self.subTest(address=address):
                host["public_address"] = address
                self.assert_contract_violation(
                    lambda: self.validator.validate_addresses(host, synthetic=False),
                    "not an eligible global-unicast host address",
                )

    def test_ipv4_mapped_ipv6_public_addresses_are_rejected(self) -> None:
        inventory = copy.deepcopy(self.inventory)
        host = nested_mapping(inventory, "host")
        host["public_address"] = "::ffff:8.8.8.8"
        self.assert_contract_violation(
            lambda: self.validate_synthetic_inventory(inventory)
        )

    def test_documentation_public_addresses_require_synthetic_mode(self) -> None:
        self.assert_contract_violation(
            lambda: self.validator.validate_inventory(self.inventory)
        )
        self.validator.validate_inventory(self.inventory, synthetic=True)
        host = copy.deepcopy(nested_mapping(self.inventory, "host"))
        host["public_address"] = "3fff::10"
        self.assert_contract_violation(
            lambda: self.validator.validate_addresses(host, synthetic=False),
            "explicit synthetic mode",
        )
        self.validator.validate_addresses(host, synthetic=True)

    def test_documentation_origins_require_synthetic_mode(self) -> None:
        origin = "https://app.example.invalid"
        self.assert_contract_violation(
            lambda: self.validator.validate_origin(
                origin, "inventory.origins.frontend"
            ),
            "reserved DNS name",
        )
        self.validator.validate_origin(
            origin, "inventory.origins.frontend", synthetic=True
        )

    def test_non_documentation_special_use_origins_are_rejected(self) -> None:
        for hostname in (
            "app.internal.alt",
            "app.home.arpa",
            "app.local",
            "service.onion",
        ):
            with self.subTest(hostname=hostname):
                for synthetic in (False, True):
                    with self.subTest(synthetic=synthetic):
                        self.assert_contract_violation(
                            lambda hostname=hostname, synthetic=synthetic: (
                                self.validator.validate_origin(
                                    f"https://{hostname}",
                                    "inventory.origins.frontend",
                                    synthetic=synthetic,
                                )
                            ),
                            "special-use DNS name",
                        )

    def test_scoped_ipv6_addresses_are_rejected(self) -> None:
        for address in ("2001:db8::1%eth0", "fd00::1%2"):
            with self.subTest(address=address):
                self.assert_contract_violation(
                    lambda address=address: self.validator.parse_address(
                        address, "inventory.host.public_address"
                    )
                )

    def test_semantic_duplicate_inventory_addresses_are_rejected(self) -> None:
        inventory = copy.deepcopy(self.inventory)
        host = inventory["host"]
        if not isinstance(host, dict):
            raise AssertionError("host inventory fixture must be a mapping")
        host["private_addresses"] = ["fd00::1", "fd00:0::1"]
        self.assert_contract_violation(
            lambda: self.validate_synthetic_inventory(inventory)
        )

    def test_public_address_fact_comparison_is_semantic(self) -> None:
        inventory = copy.deepcopy(self.inventory)
        host = inventory["host"]
        if not isinstance(host, dict):
            raise AssertionError("host inventory fixture must be a mapping")
        host["public_address"] = "2001:0db8::10"
        facts = copy.deepcopy(self.host_facts)
        network = facts["network"]
        if not isinstance(network, dict):
            raise AssertionError("host network fixture must be a mapping")
        network["public_address"] = "2001:db8::10"

        self.validate_synthetic_inventory(inventory)
        self.validator.validate_host_facts(inventory, facts)

    def test_host_fact_hostname_comparison_is_case_insensitive(self) -> None:
        inventory = copy.deepcopy(self.inventory)
        host = inventory["host"]
        if not isinstance(host, dict):
            raise AssertionError("host inventory fixture must be a mapping")
        host["hostname"] = "SecPal-Host.EXAMPLE.invalid"
        facts = copy.deepcopy(self.host_facts)
        facts["hostname"] = "secpal-host.example.invalid"

        self.validate_synthetic_inventory(inventory)
        self.validator.validate_host_facts(inventory, facts)

    def test_runtime_requires_direct_local_cli_operation(self) -> None:
        facts = copy.deepcopy(self.host_facts)
        nested_mapping(facts, "runtime", "api")["connection"] = "remote"
        self.assert_contract_violation(
            lambda: self.validator.validate_host_facts(self.inventory, facts)
        )

    def test_effective_oci_runtime_must_be_crun(self) -> None:
        facts = copy.deepcopy(self.host_facts)
        nested_mapping(facts, "runtime")["effective_oci_runtime"] = "runc"
        self.assert_contract_violation(
            lambda: self.validator.validate_host_facts(self.inventory, facts),
            "effective_oci_runtime",
        )

    def test_podman_api_and_remote_operation_are_rejected(self) -> None:
        mutations = (
            ("remote", True),
            ("service_enabled", True),
            ("socket_enabled", True),
            ("tcp_listener", True),
            ("application_dependency", True),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                facts = copy.deepcopy(self.host_facts)
                nested_mapping(facts, "runtime", "api")[field] = value
                self.assert_contract_violation(
                    lambda facts=facts: self.validator.validate_host_facts(
                        self.inventory, facts
                    )
                )

    def test_rootful_podman_is_rejected(self) -> None:
        facts = copy.deepcopy(self.host_facts)
        nested_mapping(facts, "runtime")["rootless"] = False
        self.assert_contract_violation(
            lambda: self.validator.validate_host_facts(self.inventory, facts)
        )

    def test_legacy_docker_runtime_is_rejected_by_the_production_contract(self) -> None:
        facts = copy.deepcopy(self.host_facts)
        facts["runtime"] = {
            "docker_engine_version": "29.6.2",
            "docker_compose_version": "2.40.3",
            "rootless": False,
        }
        self.assert_contract_violation(
            lambda: self.validator.validate_host_facts(
                self.inventory, facts
            )
        )

    def test_runtime_schema_requires_rootless_podman_quadlet_admission(self) -> None:
        schema = self.validator.read_schema(
            self.validator.HOST_FACTS_SCHEMA_PATH, "host-facts"
        )
        runtime = nested_mapping(schema, "properties", "runtime")
        properties = nested_mapping(runtime, "properties")

        self.assertEqual(properties["engine"], {"const": "podman"})
        self.assertEqual(properties["rootless"], {"const": True})
        for required_fact in (
            "user_namespace",
            "systemd_user",
            "quadlet",
            "storage",
        ):
            self.assertIn(required_fact, runtime["required"])

        graphroot = nested_mapping(
            properties, "storage", "properties", "graphroot"
        )
        self.assertEqual(graphroot["type"], "string")

    def test_public_application_storage_requires_inventory_and_host_facts(self) -> None:
        inventory = copy.deepcopy(self.inventory)
        inventory_resources = inventory["resources"]
        if not isinstance(inventory_resources, dict):
            raise AssertionError("inventory resource fixture must be a mapping")
        inventory_storage = inventory_resources["storage"]
        if not isinstance(inventory_storage, dict):
            raise AssertionError("inventory storage fixture must be a mapping")
        inventory_storage.pop("public_application_storage", None)
        self.assert_contract_violation(
            lambda: self.validate_synthetic_inventory(inventory)
        )

        facts = copy.deepcopy(self.host_facts)
        fact_resources = facts["resources"]
        if not isinstance(fact_resources, dict):
            raise AssertionError("host resource fixture must be a mapping")
        fact_storage = fact_resources["storage"]
        if not isinstance(fact_storage, dict):
            raise AssertionError("host storage fixture must be a mapping")
        fact_storage.pop("public_application_storage", None)
        self.assert_contract_violation(
            lambda: self.validator.validate_host_facts(self.inventory, facts)
        )

    def test_runtime_versions_reject_zero_padded_components(self) -> None:
        for version in ("05.4.2", "5.04.2", "5.4.02"):
            with self.subTest(version=version):
                self.assert_contract_violation(
                    lambda version=version: self.validator.parse_version(
                        version, "host facts.runtime.version"
                    )
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
                runtime_storage = storage["podman_graph_root"]
                if not isinstance(runtime_storage, dict):
                    raise AssertionError("Podman storage fixture must be a mapping")
                total = resources[total_fact]
                if not isinstance(total, int):
                    raise AssertionError("host total fixture must be an integer")
                runtime_storage[path_fact] = total + 1
                self.assert_contract_violation(
                    lambda facts=facts: self.validator.validate_host_facts(
                        self.inventory, facts
                    )
                )

    def test_storage_absolute_and_percentage_facts_must_be_consistent(self) -> None:
        for absolute_field, percentage_field, total_field in (
            ("free_bytes", "free_percent", "storage_total_bytes"),
            ("free_inodes", "free_inode_percent", "total_inodes"),
        ):
            with self.subTest(absolute_field=absolute_field):
                facts = copy.deepcopy(self.host_facts)
                resources = nested_mapping(facts, "resources")
                runtime_storage = nested_mapping(
                    resources, "storage", "podman_graph_root"
                )
                runtime_storage[absolute_field] = resources[total_field]
                runtime_storage[percentage_field] = 20
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

        self.validate_synthetic_inventory(inventory)
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
                lambda: self.validate_synthetic_inventory(
                    {**copy.deepcopy(self.inventory), synthetic_token: "synthetic"}
                ),
            ),
        ):
            with self.subTest(case=case):
                with self.assertRaises(self.validator.ContractViolation) as context:
                    action()
                self.assertNotIn(synthetic_token, str(context.exception))

    def test_plain_secret_bearing_field_names_are_redacted_from_errors(self) -> None:
        marker = "syntheticcredential"
        with self.assertRaises(self.validator.ContractViolation) as context:
            self.validator.scan_forbidden_input({f"{marker}_token": "synthetic"})
        self.assertNotIn(marker, str(context.exception))

    def test_service_account_cannot_use_privileged_identities(self) -> None:
        for field, identity in (
            ("name", "root"),
            ("group", "adm"),
            ("group", "backup"),
            ("group", "bin"),
            ("group", "disk"),
            ("group", "docker"),
            ("group", "input"),
            ("group", "kmem"),
            ("group", "lxd"),
            ("group", "operator"),
            ("group", "render"),
            ("group", "root"),
            ("group", "shadow"),
            ("group", "ssl-cert"),
            ("group", "staff"),
            ("group", "sudo"),
            ("group", "systemd-journal"),
            ("group", "tape"),
            ("group", "tty"),
            ("group", "video"),
        ):
            with self.subTest(field=field, identity=identity):
                inventory = copy.deepcopy(self.inventory)
                service_account = nested_mapping(inventory, "service_account")
                service_account[field] = identity
                self.assert_contract_violation(
                    lambda inventory=inventory: (
                        self.validate_synthetic_inventory(inventory)
                    )
                )

    def test_service_account_cannot_have_supplementary_groups(self) -> None:
        facts = copy.deepcopy(self.host_facts)
        nested_mapping(facts, "service_account")["supplementary_gids"] = [1000]
        self.assert_contract_violation(
            lambda: self.validator.validate_host_facts(self.inventory, facts)
        )

    def test_effective_service_identity_must_match_the_inventory(self) -> None:
        for field in ("uid", "gid"):
            with self.subTest(field=field):
                facts = copy.deepcopy(self.host_facts)
                service_account = nested_mapping(facts, "service_account")
                service_account[field] = 0
                self.assert_contract_violation(
                    lambda facts=facts: self.validator.validate_host_facts(
                        self.inventory, facts
                    ),
                    "service-account",
                )

    def test_host_facts_enforce_the_service_account_boundary(self) -> None:
        facts = copy.deepcopy(self.host_facts)
        self.validator.validate_host_facts(self.inventory, facts)

        mutations = (
            ("name", "different-account"),
            ("group", "different-group"),
            ("home", "/var/lib/different-account"),
            ("home_uid", 20000),
            ("home_gid", 0),
            ("home_mode", "0770"),
            ("home_local", False),
            ("containers_configuration_account_writable", True),
            ("shell", "/bin/bash"),
            ("interactive_login", True),
            ("sudo_authorized", True),
            ("host_privilege_authorized", True),
            ("rootful_runtime_authorized", True),
            ("system_unit_authorized", True),
            ("remote_runtime_authorized", True),
        )
        for field, value in mutations:
            with self.subTest(field=field, case="unsafe"):
                candidate = copy.deepcopy(facts)
                nested_mapping(candidate, "service_account")[field] = value
                self.assert_contract_violation(
                    lambda candidate=candidate: self.validator.validate_host_facts(
                        self.inventory, candidate
                    )
                )
            with self.subTest(field=field, case="missing"):
                candidate = copy.deepcopy(facts)
                nested_mapping(candidate, "service_account").pop(field)
                self.assert_contract_violation(
                    lambda candidate=candidate: self.validator.validate_host_facts(
                        self.inventory, candidate
                    )
                )

    def test_host_facts_reject_direct_root_ssh(self) -> None:
        facts = copy.deepcopy(self.host_facts)
        self.validator.validate_host_facts(self.inventory, facts)

        for value in (None, True):
            with self.subTest(value=value):
                candidate = copy.deepcopy(facts)
                if value is None:
                    candidate.pop("ssh")
                else:
                    nested_mapping(candidate, "ssh")[
                        "direct_root_login_permitted"
                    ] = value
                self.assert_contract_violation(
                    lambda candidate=candidate: self.validator.validate_host_facts(
                        self.inventory, candidate
                    )
                )

    def test_host_facts_must_report_podman_installation_source(self) -> None:
        facts = copy.deepcopy(self.host_facts)
        runtime = nested_mapping(facts, "runtime")
        runtime.pop("installation", None)
        self.assert_contract_violation(
            lambda: self.validator.validate_host_facts(self.inventory, facts),
            "installation",
        )

    def test_podman_installation_contract_is_exact(self) -> None:
        mutations = (
            ("source", "external-repository"),
            ("distribution", "ubuntu"),
            ("release_codename", "stable"),
            ("external_repository", True),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                facts = copy.deepcopy(self.host_facts)
                installation = nested_mapping(facts, "runtime", "installation")
                installation[field] = value
                self.assert_contract_violation(
                    lambda facts=facts: self.validator.validate_host_facts(
                        self.inventory, facts
                    )
                )

    def test_required_runtime_packages_are_exact_and_compatibility_is_absent(self) -> None:
        for package, replacement in (
            ("podman", "podman-remote"),
            ("conmon", ""),
            ("crun", "runc"),
            ("netavark", ""),
            ("aardvark_dns", ""),
            ("passt", "slirp4netns"),
            ("uidmap", ""),
            ("dbus_user_session", "dbus-x11"),
        ):
            with self.subTest(package=package):
                facts = copy.deepcopy(self.host_facts)
                packages = nested_mapping(
                    facts, "runtime", "installation", "installed_packages"
                )
                packages[package] = replacement
                self.assert_contract_violation(
                    lambda facts=facts: self.validator.validate_host_facts(
                        self.inventory, facts
                    )
                )

        for package in (
            "podman",
            "conmon",
            "crun",
            "netavark",
            "aardvark_dns",
            "passt",
            "uidmap",
            "dbus_user_session",
        ):
            with self.subTest(package=package, provenance="backports"):
                facts = copy.deepcopy(self.host_facts)
                suites = nested_mapping(
                    facts, "runtime", "installation", "package_suites"
                )
                suites[package] = "trixie-backports"
                self.assert_contract_violation(
                    lambda facts=facts: self.validator.validate_host_facts(
                        self.inventory, facts
                    )
                )

        facts = copy.deepcopy(self.host_facts)
        installation = nested_mapping(facts, "runtime", "installation")
        installation["forbidden_packages_present"] = ["podman-docker"]
        self.assert_contract_violation(
            lambda: self.validator.validate_host_facts(self.inventory, facts)
        )

    def test_user_namespace_helpers_account_and_sources_are_exact(self) -> None:
        mutations = (
            (("account",), "other-account"),
            (("newuidmap_effective",), False),
            (("newgidmap_effective",), False),
            (("subuid", "source"), "/etc/subgid"),
            (("subgid", "source"), "/etc/subuid"),
            (("subuid", "source_entry_count"), 2),
            (("subgid", "overlaps_other_accounts"), True),
            (("subuid", "overlaps_host_identities"), True),
        )
        for path, value in mutations:
            with self.subTest(path=path):
                facts = copy.deepcopy(self.host_facts)
                user_namespace = nested_mapping(facts, "runtime", "user_namespace")
                target = user_namespace
                for segment in path[:-1]:
                    target = nested_mapping(target, segment)
                target[path[-1]] = value
                self.assert_contract_violation(
                    lambda facts=facts: self.validator.validate_host_facts(
                        self.inventory, facts
                    )
                )

    def test_systemd_user_and_quadlet_trust_boundary_is_exact(self) -> None:
        mutations = (
            (("systemd_user", "manager_available"), False),
            (("systemd_user", "starts_at_boot"), False),
            (("systemd_user", "linger_enabled"), False),
            (("systemd_user", "dbus_session_available"), False),
            (("systemd_user", "runtime_directory_uid"), 0),
            (("systemd_user", "runtime_directory_gid"), 0),
            (("systemd_user", "runtime_directory_mode"), "0755"),
            (("systemd_user", "runtime_directory_local"), False),
            (("quadlet", "available"), False),
            (("quadlet", "orchestrator"), "podman-compose"),
            (("quadlet", "definition_directory_uid"), 20000),
            (("quadlet", "definition_directory_gid"), 20000),
            (("quadlet", "definition_directory_mode"), "0775"),
            (("quadlet", "unit_files_uid"), 20000),
            (("quadlet", "unit_files_gid"), 20000),
            (("quadlet", "unit_files_mode"), "0664"),
            (
                ("quadlet", "effective_search_paths"),
                ["/run/user/20000/containers/systemd"],
            ),
            (
                ("quadlet", "persistent_search_path_configuration_account_writable"),
                True,
            ),
            (("quadlet", "tree_symlinks_present"), True),
            (("quadlet", "service_account_can_read"), False),
            (("quadlet", "service_account_can_traverse"), False),
            (("quadlet", "service_account_can_write"), True),
        )
        for path, value in mutations:
            with self.subTest(path=path):
                facts = copy.deepcopy(self.host_facts)
                nested_mapping(facts, "runtime", path[0])[path[1]] = value
                self.assert_contract_violation(
                    lambda facts=facts: self.validator.validate_host_facts(
                        self.inventory, facts
                    )
                )

    def test_rootless_network_storage_and_registry_boundaries_are_exact(self) -> None:
        mutations = (
            (("network", "backend"), "cni"),
            (("network", "dns_backend"), "none"),
            (("network", "rootless_transport"), "slirp4netns"),
            (("network", "host_network"), True),
            (("network", "unprivileged_port_override"), True),
            (("storage", "driver"), "vfs"),
            (("storage", "graphroot_uid"), 0),
            (("storage", "graphroot_gid"), 0),
            (("storage", "graphroot_mode"), "0755"),
            (("storage", "graphroot_writable"), False),
            (("storage", "runroot_uid"), 0),
            (("storage", "runroot_gid"), 0),
            (("storage", "runroot_mode"), "0777"),
            (("storage", "runroot_local"), False),
            (("storage", "runroot_writable"), False),
            (("storage", "graphroot_reconstructable"), False),
            (("registries", "secpal_mirrors"), ["mirror.example.invalid"]),
            (("registries", "secpal_location_rewrite"), True),
            (("registries", "ghcr_insecure"), True),
            (("registries", "fallback_enabled"), True),
            (("registries", "short_name_resolution_required"), True),
        )
        for path, value in mutations:
            with self.subTest(path=path):
                facts = copy.deepcopy(self.host_facts)
                nested_mapping(facts, "runtime", path[0])[path[1]] = value
                self.assert_contract_violation(
                    lambda facts=facts: self.validator.validate_host_facts(
                        self.inventory, facts
                    )
                )

    def test_rootless_runtime_owner_must_match_the_service_account(self) -> None:
        for field, value in (("owner_uid", 0), ("owner_gid", 0)):
            with self.subTest(field=field):
                facts = copy.deepcopy(self.host_facts)
                nested_mapping(facts, "runtime")[field] = value
                self.assert_contract_violation(
                    lambda facts=facts: self.validator.validate_host_facts(
                        self.inventory, facts
                    ),
                    "rootless Podman authority",
                )

    def test_subordinate_id_facts_must_match_inventory(self) -> None:
        for dimension, field in (("subuid", "uid"), ("subgid", "gid")):
            with self.subTest(dimension=dimension):
                facts = copy.deepcopy(self.host_facts)
                selected_range = nested_mapping(
                    facts, "runtime", "user_namespace", dimension
                )
                selected_range["start"] = nested_mapping(
                    self.inventory, "service_account", "subordinate_ids", field
                )["start"] + 1
                self.assert_contract_violation(
                    lambda facts=facts: self.validator.validate_host_facts(
                        self.inventory, facts
                    ),
                    dimension,
                )

    def test_host_facts_require_exact_debian_13_identity(self) -> None:
        self.validator.validate_host_facts(self.inventory, self.host_facts)

        for field, value in (
            ("id", "ubuntu"),
            ("version_id", "12"),
            ("version_id", "14"),
            ("version_codename", "bookworm"),
            ("version_codename", "testing"),
            ("version_codename", "unstable"),
        ):
            with self.subTest(field=field, value=value):
                facts = copy.deepcopy(self.host_facts)
                os_facts = nested_mapping(facts, "os")
                os_facts[field] = value
                self.assert_contract_violation(
                    lambda: self.validator.validate_host_facts(self.inventory, facts)
                )

    def test_ubuntu_host_facts_are_rejected(self) -> None:
        facts = copy.deepcopy(self.host_facts)
        facts["os"] = {
            "id": "ubuntu",
            "version_id": "24.04",
            "installation_profile": "ubuntu-server",
        }
        kernel = nested_mapping(facts, "kernel")
        kernel["release"] = "6.8.0"
        kernel["package_source"] = "ubuntu-archive"
        kernel.pop("package_suite")
        kernel.pop("package_owned")
        self.assert_contract_violation(
            lambda: self.validator.validate_host_facts(self.inventory, facts)
        )

    def test_debian_release_suites_are_codename_pinned(self) -> None:
        for suites in (
            ["trixie", "trixie-updates"],
            ["stable", "trixie-security", "trixie-updates"],
            ["testing", "trixie-security", "trixie-updates"],
            ["unstable", "trixie-security", "trixie-updates"],
            ["sid", "trixie-security", "trixie-updates"],
            ["trixie", "trixie-security", "trixie-backports"],
        ):
            with self.subTest(suites=suites):
                facts = copy.deepcopy(self.host_facts)
                nested_mapping(facts, "os")["debian_release_suites"] = suites
                self.assert_contract_violation(
                    lambda facts=facts: self.validator.validate_host_facts(
                        self.inventory, facts
                    )
                )

    def test_debian_release_suite_order_is_not_significant(self) -> None:
        facts = copy.deepcopy(self.host_facts)
        nested_mapping(facts, "os")["debian_release_suites"] = [
            "trixie-updates",
            "trixie",
            "trixie-security",
        ]
        self.validator.validate_host_facts(self.inventory, facts)

    def test_debian_archive_provenance_is_exact(self) -> None:
        for field, value in (
            ("release_origins", ["Debian", "Debian derivative"]),
            ("archive_keyring_package", "custom-keyring"),
            ("release_signatures_verified", False),
        ):
            with self.subTest(field=field):
                facts = copy.deepcopy(self.host_facts)
                provenance = nested_mapping(facts, "os", "package_provenance")
                provenance[field] = value
                self.assert_contract_violation(
                    lambda facts=facts: self.validator.validate_host_facts(
                        self.inventory, facts
                    )
                )

    def test_debian_security_update_policy_is_fail_closed(self) -> None:
        mutations = (
            ("mechanism", "manual"),
            ("automatic", False),
            ("release_codename", "stable"),
            ("security_suite", "stable-security"),
            ("normal_updates_automatic", True),
            ("major_release_upgrades_automatic", True),
            ("automatic_reboot", True),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                facts = copy.deepcopy(self.host_facts)
                update_policy = nested_mapping(facts, "os", "security_updates")
                update_policy[field] = value
                self.assert_contract_violation(
                    lambda facts=facts: self.validator.validate_host_facts(
                        self.inventory, facts
                    )
                )

    def test_host_facts_require_debian_kernel_package_provenance(self) -> None:
        mutations = (
            ("package_source", "local-build"),
            ("package_source", "mainline"),
            ("package_source", "ubuntu-archive"),
            ("package_suite", "trixie-backports"),
            ("package_owned", False),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                facts = copy.deepcopy(self.host_facts)
                kernel = nested_mapping(facts, "kernel")
                kernel[field] = value
                self.assert_contract_violation(
                    lambda facts=facts: self.validator.validate_host_facts(
                        self.inventory, facts
                    )
                )

    def test_kernel_series_is_exactly_debian_13_stable(self) -> None:
        for release in ("6.11.99+deb13-amd64", "6.13.0+deb13-amd64"):
            with self.subTest(release=release):
                facts = copy.deepcopy(self.host_facts)
                nested_mapping(facts, "kernel")["release"] = release
                self.assert_contract_violation(
                    lambda facts=facts: self.validator.validate_host_facts(
                        self.inventory, facts
                    )
                )

    def test_kernel_package_architecture_matches_host(self) -> None:
        facts = copy.deepcopy(self.host_facts)
        nested_mapping(facts, "kernel")["package_architecture"] = "arm64"
        self.assert_contract_violation(
            lambda: self.validator.validate_host_facts(self.inventory, facts),
            "kernel package architecture",
        )

    def test_podman_updates_require_controlled_maintenance(self) -> None:
        for field, value in (
            ("automatic", True),
            ("automatic_service_restart", True),
            ("major_version_automatic", True),
            ("image_auto_update", True),
            ("auto_update_timer_enabled", True),
        ):
            with self.subTest(field=field):
                facts = copy.deepcopy(self.host_facts)
                nested_mapping(facts, "runtime", "updates")[field] = value
                self.assert_contract_violation(
                    lambda facts=facts: self.validator.validate_host_facts(
                        self.inventory, facts
                    )
                )

    def test_managed_paths_cannot_target_system_directories(self) -> None:
        for path_name, unsafe_path in (
            ("configuration", "/etc"),
            ("deployment_state", "/usr/local/secpal"),
            ("runtime_secrets", "/run/secpal"),
            ("podman_graph_root", "/var/lib"),
            ("podman_graph_root", "/var/lib/dpkg"),
            ("podman_graph_root", "/var/lib/postgresql"),
        ):
            with self.subTest(path_name=path_name):
                inventory = copy.deepcopy(self.inventory)
                path_contract = nested_mapping(inventory, "paths", path_name)
                path_contract["path"] = unsafe_path
                self.assert_contract_violation(
                    lambda inventory=inventory: (
                        self.validate_synthetic_inventory(inventory)
                    )
                )

    def test_service_account_home_stays_in_its_dedicated_subtree(self) -> None:
        for unsafe_home in (
            "/var/lib/dpkg",
            "/var/lib/docker",
            "/var/lib/postgresql",
            "/var/lib/secpal-other",
        ):
            with self.subTest(unsafe_home=unsafe_home):
                inventory = copy.deepcopy(self.inventory)
                nested_mapping(inventory, "service_account")["home"] = unsafe_home
                self.assert_contract_violation(
                    lambda inventory=inventory: self.validate_synthetic_inventory(
                        inventory
                    )
                )

        inventory = copy.deepcopy(self.inventory)
        nested_mapping(inventory, "service_account")[
            "home"
        ] = "/var/lib/secpal/account"
        self.validate_synthetic_inventory(inventory)

    def test_configuration_and_deployment_state_require_filesystem_facts(self) -> None:
        for path_name in ("configuration", "deployment_state"):
            with self.subTest(path_name=path_name):
                inventory = copy.deepcopy(self.inventory)
                nested_mapping(inventory, "paths", path_name)["path"] += "-moved"
                self.validate_synthetic_inventory(inventory)
                self.assert_contract_violation(
                    lambda: self.validator.validate_host_facts(
                        inventory, self.host_facts
                    ),
                    path_name,
                )

    def test_all_managed_paths_require_identity_resolution(self) -> None:
        facts = copy.deepcopy(self.host_facts)
        nested_mapping(facts, "resolved_paths")["configuration"] = "/etc"
        self.assert_contract_violation(
            lambda: self.validator.validate_host_facts(self.inventory, facts),
            "resolved path",
        )

    def test_managed_filesystems_must_not_be_read_only(self) -> None:
        for read_only in (None, True):
            with self.subTest(read_only=read_only):
                facts = copy.deepcopy(self.host_facts)
                filesystem = nested_mapping(
                    facts, "filesystems", "postgresql_data"
                )
                if read_only is None:
                    filesystem.pop("mount_read_only")
                else:
                    filesystem["mount_read_only"] = read_only
                self.assert_contract_violation(
                    lambda facts=facts: self.validator.validate_host_facts(
                        self.inventory, facts
                    )
                )

    def test_managed_path_metadata_and_ancestry_are_effective(self) -> None:
        mutations = (
            ("configuration", "uid", 20000, "effective path ownership"),
            ("deployment_state", "gid", 0, "effective path ownership"),
            ("logs", "uid", 0, "effective path ownership"),
            ("backup_staging", "mode", "0777", "effective path mode"),
            (
                "configuration",
                "ancestors_service_account_can_write",
                True,
                "effective path ancestry",
            ),
        )
        for path_name, field, value, message in mutations:
            with self.subTest(path_name=path_name, field=field):
                facts = copy.deepcopy(self.host_facts)
                nested_mapping(facts, "filesystems", path_name)[field] = value
                self.assert_contract_violation(
                    lambda facts=facts: self.validator.validate_host_facts(
                        self.inventory, facts
                    ),
                    message,
                )

    def test_every_managed_path_enforces_service_account_write_policy(self) -> None:
        filesystems = nested_mapping(self.host_facts, "filesystems")
        paths = nested_mapping(self.inventory, "paths")
        for path_name, filesystem in filesystems.items():
            with self.subTest(path_name=path_name):
                if not isinstance(filesystem, dict):
                    raise AssertionError("filesystem fact must be a mapping")
                path_contract = paths[path_name]
                if not isinstance(path_contract, dict):
                    raise AssertionError("path contract must be a mapping")
                expected_write = self.validator.OWNER_ROLE_SERVICE_ACCOUNT_WRITE[
                    path_contract["owner_role"]
                ]
                self.assertIs(filesystem["service_account_can_write"], expected_write)
                facts = copy.deepcopy(self.host_facts)
                nested_mapping(facts, "filesystems", path_name)[
                    "service_account_can_write"
                ] = not expected_write
                self.assert_contract_violation(
                    lambda facts=facts: self.validator.validate_host_facts(
                        self.inventory, facts
                    ),
                    "effective path access",
                )

    def test_delegated_paths_cannot_claim_service_account_ownership(self) -> None:
        paths = nested_mapping(self.inventory, "paths")
        filesystems = nested_mapping(self.host_facts, "filesystems")
        service_uid = nested_mapping(self.inventory, "service_account")["uid"]
        for path_name in filesystems:
            path_contract = paths[path_name]
            if not isinstance(path_contract, dict):
                raise AssertionError("path contract must be a mapping")
            if path_contract["uid"] is not None:
                continue
            with self.subTest(path_name=path_name):
                facts = copy.deepcopy(self.host_facts)
                filesystem = nested_mapping(facts, "filesystems", path_name)
                filesystem["uid"] = service_uid
                filesystem["service_account_can_write"] = False
                self.assert_contract_violation(
                    lambda facts=facts: self.validator.validate_host_facts(
                        self.inventory, facts
                    ),
                    "contradicts ownership",
                )

    def test_policy_keysets_are_closed_across_schema_fixtures_and_validator(self) -> None:
        inventory_schema = self.validator.read_schema(
            self.validator.INVENTORY_SCHEMA_PATH, "inventory"
        )
        host_schema = self.validator.read_schema(
            self.validator.HOST_FACTS_SCHEMA_PATH, "host-facts"
        )

        canonical_paths = set(self.validator.CANONICAL_PATHS)
        inventory_paths = nested_mapping(self.inventory, "paths")
        inventory_path_schema = nested_mapping(
            inventory_schema, "properties", "paths"
        )
        self.assert_closed_keyset(
            canonical_paths, inventory_paths, inventory_path_schema
        )
        canonical_owner_roles = {
            contract["owner_role"]
            for contract in self.validator.CANONICAL_PATHS.values()
        }
        self.assertEqual(
            canonical_owner_roles,
            set(self.validator.OWNER_ROLE_SERVICE_ACCOUNT_WRITE),
        )

        resolved_path_keys = canonical_paths | {
            "service_account_home",
            "systemd_runtime_directory",
            "podman_runroot",
        }
        fact_resolved_paths = nested_mapping(self.host_facts, "resolved_paths")
        resolved_path_schema = nested_mapping(
            host_schema, "properties", "resolved_paths"
        )
        self.assert_closed_keyset(
            resolved_path_keys, fact_resolved_paths, resolved_path_schema
        )

        filesystem_paths = set(self.validator.FILESYSTEM_PATH_KEYS)
        fact_filesystems = nested_mapping(self.host_facts, "filesystems")
        filesystem_schema = nested_mapping(host_schema, "properties", "filesystems")
        self.assert_closed_keyset(
            filesystem_paths, fact_filesystems, filesystem_schema
        )

        headroom_paths = set(self.validator.HEADROOM_MINIMUMS)
        inventory_storage = nested_mapping(self.inventory, "resources", "storage")
        fact_storage = nested_mapping(self.host_facts, "resources", "storage")
        inventory_storage_schema = nested_mapping(
            inventory_schema, "properties", "resources", "properties", "storage"
        )
        fact_storage_schema = nested_mapping(
            host_schema, "properties", "resources", "properties", "storage"
        )
        self.assert_closed_keyset(
            headroom_paths, inventory_storage, inventory_storage_schema
        )
        self.assert_closed_keyset(headroom_paths, fact_storage, fact_storage_schema)

    def test_release_candidate_kernel_is_rejected_at_stable_floor(self) -> None:
        facts = copy.deepcopy(self.host_facts)
        kernel = nested_mapping(facts, "kernel")
        for release in (
            "6.12.0-rc1",
            "6.12.0-rc",
            "6.12.0-rcfoo",
            "6.12.0-RC2-amd64",
            "6.12.0-061200rc1-amd64",
            "6.12.0-foo-rc1",
        ):
            with self.subTest(release=release):
                kernel["release"] = release
                self.assert_contract_violation(
                    lambda: self.validator.validate_host_facts(self.inventory, facts)
                )
        kernel["release"] = "6.12.0-notrc1-amd64"
        self.validator.validate_host_facts(self.inventory, facts)

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
                oversized_version, "host facts.runtime.version"
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

    def test_unicode_kernel_version_digits_are_rejected(self) -> None:
        facts = copy.deepcopy(self.host_facts)
        kernel = facts["kernel"]
        if not isinstance(kernel, dict):
            raise AssertionError("kernel fixture must be a mapping")
        kernel["release"] = "6.12.1١"
        self.assert_contract_violation(
            lambda: self.validator.validate_host_facts(self.inventory, facts)
        )

    def test_private_addresses_require_explicit_private_use_ranges(self) -> None:
        for address in ("192.0.2.20", "198.18.0.1", "2001:db8::20"):
            with self.subTest(address=address):
                inventory = copy.deepcopy(self.inventory)
                host = inventory["host"]
                if not isinstance(host, dict):
                    raise AssertionError("host inventory fixture must be a mapping")
                host["private_addresses"] = [address]
                self.assert_contract_violation(
                    lambda inventory=inventory: self.validate_synthetic_inventory(
                        inventory
                    )
                )

        inventory = copy.deepcopy(self.inventory)
        host = inventory["host"]
        if not isinstance(host, dict):
            raise AssertionError("host inventory fixture must be a mapping")
        host["private_addresses"] = ["fd00::20"]
        self.validate_synthetic_inventory(inventory)

    def test_reserved_ipv6_ranges_are_not_public_addresses(self) -> None:
        for address in ("5f00::1", "4000::1"):
            with self.subTest(address=address):
                inventory = copy.deepcopy(self.inventory)
                nested_mapping(inventory, "host")["public_address"] = address
                self.assert_contract_violation(
                    lambda inventory=inventory: self.validate_synthetic_inventory(
                        inventory
                    )
                )

    def test_public_address_fact_requires_a_string(self) -> None:
        for address in (3221225994, b"\xc0\x00\x02\x0a"):
            with self.subTest(address=address):
                facts = copy.deepcopy(self.host_facts)
                network = facts["network"]
                if not isinstance(network, dict):
                    raise AssertionError("host network fixture must be a mapping")
                network["public_address"] = address
                self.assert_contract_violation(
                    lambda facts=facts: self.validator.validate_host_facts(
                        self.inventory, facts
                    )
                )

    def test_origins_reject_empty_query_and_fragment_delimiters(self) -> None:
        for suffix in ("?", "#", "?#"):
            with self.subTest(suffix=suffix):
                self.assert_contract_violation(
                    lambda suffix=suffix: self.validator.validate_origin(
                        f"https://app.example.invalid{suffix}",
                        "inventory.origins.frontend",
                    )
                )

    def test_origins_reject_other_parser_normalized_forms(self) -> None:
        for origin in (
            "\nhttps://app.example.invalid",
            "https://app.example.invalid\n",
            "https://app.exam\tple.invalid",
            "HTTPS://app.example.invalid",
            "https://app.example.invalid:",
            "https://app.example.invalid:0443",
        ):
            with self.subTest(origin=repr(origin)):
                self.assert_contract_violation(
                    lambda origin=origin: self.validator.validate_origin(
                        origin, "inventory.origins.frontend"
                    )
                )

    def test_inventory_integer_fields_reject_integral_floats(self) -> None:
        cases = (
            ("service-account-uid", ("service_account", "uid")),
            ("service-account-gid", ("service_account", "gid")),
            ("path-uid", ("paths", "configuration", "uid")),
            ("path-gid", ("paths", "configuration", "gid")),
            (
                "container-uid",
                ("paths", "private_application_storage", "container_uid"),
            ),
            (
                "subuid-start",
                ("service_account", "subordinate_ids", "uid", "start"),
            ),
            ("decision-issue", ("paths", "runtime_secrets", "decision_issue")),
            ("resource-floor", ("resources", "logical_cpus")),
            (
                "storage-floor",
                ("resources", "storage", "podman_graph_root", "minimum_free_percent"),
            ),
        )
        for case, path in cases:
            with self.subTest(case=case):
                inventory = copy.deepcopy(self.inventory)
                target = inventory
                for key in path[:-1]:
                    child = target[key]
                    if not isinstance(child, dict):
                        raise AssertionError(f"inventory path {path!r} must be a mapping")
                    target = child
                target[path[-1]] = float(target[path[-1]])
                self.assert_contract_violation(
                    lambda inventory=inventory: self.validate_synthetic_inventory(
                        inventory
                    )
                )

    def test_paths_enforce_filesystem_byte_limits(self) -> None:
        self.validator.validate_absolute_path(
            "/srv/" + ("a" * 255), "inventory.paths.configuration.path"
        )
        for path in (
            "/srv/" + ("a" * 256),
            "/srv/" + ("é" * 128),
            "/" + "/".join(["a" * 255] * 16),
        ):
            with self.subTest(encoded_length=len(path.encode("utf-8"))):
                self.assert_contract_violation(
                    lambda path=path: self.validator.validate_absolute_path(
                        path, "inventory.paths.configuration.path"
                    )
                )

    def test_paths_reject_ascii_control_characters(self) -> None:
        for path in ("/srv/line\nbreak", "/srv/tab\tname", "/srv/delete\x7fname"):
            with self.subTest(path=repr(path)):
                self.assert_contract_violation(
                    lambda path=path: self.validator.validate_absolute_path(
                        path, "inventory.paths.configuration.path"
                    )
                )

    def test_repository_schema_rejects_duplicate_json_keys(self) -> None:
        schema = self.write_temporary_document(
            '{"type":"object","type":"array"}\n'
        )
        self.assert_contract_violation(
            lambda: self.validator.read_schema(schema, "inventory")
        )


if __name__ == "__main__":
    unittest.main()
