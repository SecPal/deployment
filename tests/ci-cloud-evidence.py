#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Negative tests for bounded non-secret cloud evidence."""

from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path

import jsonschema


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = ROOT / "scripts" / "ci-cloud" / "validate-evidence.py"
WORKLOAD_TEST_PATH = ROOT / "tests" / "ci-cloud-workload-evidence.py"


def load_validator():
    spec = importlib.util.spec_from_file_location("ci_cloud_evidence", VALIDATOR_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load evidence validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def valid_workload() -> dict[str, object]:
    spec = importlib.util.spec_from_file_location(
        "ci_cloud_workload_test_fixtures", WORKLOAD_TEST_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load workload evidence fixture")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.valid_observations()


def valid_document() -> dict[str, object]:
    runtime_package_names = {
        "podman", "conmon", "crun", "netavark", "aardvark-dns", "passt",
        "uidmap", "dbus-user-session",
    }
    bootstrap_package_names = {
        "aardvark-dns", "apparmor", "apparmor-utils", "crun", "curl",
        "dbus-user-session", "git", "gh", "jq", "netavark", "passt", "podman",
        "python3", "python3-jsonschema", "python3-yaml", "uidmap",
        "unattended-upgrades",
    }
    packages = {
        name: {
            "version": "1.0-1",
            "architecture": "amd64",
            "origin": "Debian",
            "suite": "trixie",
        }
        for name in runtime_package_names | bootstrap_package_names
    }
    packages["dbus-user-session"]["architecture"] = "all"
    return {
        "schema_version": 2,
        "workflow": {
            "repository": "SecPal/deployment",
            "run_id": "12345",
            "run_attempt": "1",
            "target_sha": "a" * 40,
        },
        "test": {
            "provider": "digitalocean",
            "region": "fra1",
            "profile": "amd",
            "machine_type": "s-4vcpu-8gb-amd",
            "provider_image": {
                "slug": "debian-13-x64",
                "id": "123456789",
            },
            "started_at": "2026-08-09T12:00:00Z",
            "ended_at": "2026-08-09T12:10:00Z",
            "phase_exit_statuses": {
                "host": 0,
                "workload_prepare_start": 0,
                "workload_cleanup": 0,
                "trusted_quadlet_normalize_live": 0,
                "trusted_quadlet_normalize_cleanup": 0,
            },
            "collection_exit_statuses": {
                "baseline": 0,
                "live": 0,
                "post_cleanup": 0,
            },
            "result": "passed",
            "failed_admission_invariants": [],
        },
        "host_admission": {
            "result": "passed",
            "failed_admission_invariants": [],
        },
        "platform": {
            "os_release": {
                "ID": "debian",
                "VERSION_ID": "13",
                "VERSION_CODENAME": "trixie",
                "PRETTY_NAME": "Debian GNU/Linux 13 (trixie)",
            },
            "architecture": "amd64",
            "uname": "Linux fixture 6.12.0-amd64 x86_64 GNU/Linux",
            "kernel": "6.12.0-amd64",
            "cpu": {"vendor": "AuthenticAMD", "model": "DO-Premium-AMD"},
            "virtualization": "kvm",
            "logical_cpu": 8,
            "memory_bytes": 17179869184,
            "root_filesystem_bytes": 171798691840,
        },
        "apt": {
            "source_files": ["/etc/apt/sources.list.d/debian.sources"],
            "source_hosts": ["deb.debian.org", "security.debian.org"],
            "configured_suites": ["trixie", "trixie-security", "trixie-updates"],
            "release_origins": ["Debian"],
            "verified_release_suites": ["trixie", "trixie-security", "trixie-updates"],
            "release_signatures_verified": True,
            "debian_archive_keyring_version": "2025.1",
            "runtime_packages": {
                name: copy.deepcopy(packages[name]) for name in runtime_package_names
            },
            "bootstrap_packages": {
                name: copy.deepcopy(packages[name]) for name in bootstrap_package_names
            },
            "forbidden_packages_present": [],
        },
        "host": {
            "kernel_package": {
                "name": "linux-image-6.12.0-amd64",
                "version": "6.12.0-1",
                "architecture": "amd64",
                "origin": "Debian",
                "suite": "trixie-security",
                "owned": True,
                "status": "install ok installed",
                "maintainer": "Debian Kernel Team <debian-kernel@lists.debian.org>",
                "database_files_safe": True,
                "files_verified": True,
                "provenance_basis": "active-apt-policy",
            },
            "filesystem": {
                "type": "ext4",
                "read_only": False,
                "overlayfs_supported": True,
                "d_type": True,
            },
            "security_updates": {
                "mechanism": "unattended-upgrades",
                "automatic": True,
                "timer_enabled": True,
                "security_suite": "trixie-security",
                "normal_updates_automatic": False,
                "major_release_upgrades_automatic": False,
                "automatic_reboot": False,
                "runtime_packages_excluded": True,
            },
            "required_tools": {
                "present": [
                    "aa-status", "apt-cache", "apt-config", "bash", "curl",
                    "df", "dpkg", "dpkg-query", "findmnt", "getent", "gh",
                    "git", "id", "install", "jq", "loginctl", "lscpu", "mktemp",
                    "newgidmap", "newuidmap", "podman", "python3", "realpath",
                    "sha256sum", "ss", "stat", "systemd-detect-virt",
                    "systemctl", "timedatectl", "uname",
                ],
                "missing": [],
            },
            "clock": {"synchronized": True},
            "ssh": {"root_login_denied": True},
            "cloud_identity": {
                "probe_supported": False,
                "probe_succeeded": False,
                "identity_present": False,
            },
        },
        "runtime": {
            "podman": {
                "version": "podman version 5.4.2",
                "rootless": True,
                "seccomp_enabled": True,
                "apparmor_enabled": False,
                "oci_runtime": "crun",
                "network_backend": "netavark",
                "rootless_network_command": "pasta",
                "cgroup_version": "v2",
            },
            "crun_version": "crun version 1.18",
            "crun_features": "seccomp systemd",
            "netavark_version": "netavark 1.14",
            "aardvark_version": "aardvark-dns 1.14",
            "pasta_version": "pasta 0.0",
            "passt_version": "passt 0.0",
            "uidmap": {
                "newuidmap": "/usr/bin/newuidmap",
                "newgidmap": "/usr/bin/newgidmap",
                "subuid": {
                    "start": 200000,
                    "count": 65536,
                    "entry_count": 1,
                    "overlap": False,
                },
                "subgid": {
                    "start": 200000,
                    "count": 65536,
                    "entry_count": 1,
                    "overlap": False,
                },
                "mapping_effective": True,
            },
            "cgroup_version": "v2",
            "systemd_version": "systemd 257",
            "apparmor_host": {"kernel_enabled": True, "loaded_profiles": 10, "enforcing_profiles": 4},
            "systemd_user": {
                "manager_available": True,
                "starts_at_boot": True,
                "linger_enabled": True,
                "dbus_session_available": True,
                "runtime_directory": "/run/user/20000",
                "runtime_directory_uid": 20000,
                "runtime_directory_gid": 20000,
                "runtime_directory_mode": "0700",
            },
            "quadlet": {
                "generator_path": "/usr/lib/systemd/user-generators/podman-user-generator",
                "effective_search_paths": ["/etc/containers/systemd/users/20000"],
                "definitions_uid": 0,
                "definitions_gid": 0,
                "definitions_mode": "0755",
                "tree_symlinks_present": False,
                "service_account_can_write": False,
            },
            "storage": {
                "driver": "overlay",
                "graphroot": "/home/secpal-ci/.local/share/containers/storage",
                "runroot": "/run/user/20000/containers",
            },
            "api": {
                "system_service_active": False,
                "system_service_enabled": False,
                "system_socket_active": False,
                "system_socket_enabled": False,
                "user_service_active": False,
                "user_service_enabled": False,
                "user_socket_active": False,
                "user_socket_enabled": False,
                "tcp_listener": False,
                "unix_listener": False,
                "service_process": False,
                "process_scan_incomplete": False,
                "listener_scan_incomplete": False,
                "connection_scan_incomplete": False,
                "remote_connection": False,
            },
            "updates": {
                "auto_update_timer_enabled": False,
                "auto_update_timer_active": False,
            },
            "registries": {
                "ghcr_insecure": False,
                "secpal_mirrors": [],
                "secpal_location_rewrite": False,
            },
        },
        "workload": valid_workload(),
    }


class EvidenceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.validator = load_validator()

    def test_complete_evidence_accepts_host_apparmor_with_podman_capability_false(self) -> None:
        document = valid_document()
        schema = json.loads(
            (ROOT / "schemas" / "ci-cloud-evidence.schema.json").read_text(
                encoding="utf-8"
            )
        )
        jsonschema.Draft202012Validator(schema).validate(document)
        self.assertEqual(document, self.validator.validate_document(document))

    def test_d1_and_d1a_results_are_distinct_and_both_required(self) -> None:
        document = valid_document()
        document["host_admission"]["result"] = "failed"
        with self.assertRaisesRegex(ValueError, "host admission"):
            self.validator.validate_document(document)

        document = valid_document()
        del document["workload"]["post_cleanup"]
        with self.assertRaisesRegex(ValueError, "workload|incomplete|declared schema"):
            self.validator.validate_document(document)

    def test_schema_forbids_passed_d1a_with_invalid_live_or_cleanup_state(self) -> None:
        schema = json.loads(
            (ROOT / "schemas" / "ci-cloud-evidence.schema.json").read_text(
                encoding="utf-8"
            )
        )
        for mutate in (
            lambda document: document["workload"]["live"].__setitem__(
                "complete", False
            ),
            lambda document: document["workload"]["post_cleanup"].__setitem__(
                "containers", ["secpal-int-aaaaaaaaaaaa-api"]
            ),
            lambda document: document["workload"]["post_cleanup"][
                "control_resources"
            ].__setitem__("network_present", False),
        ):
            with self.subTest(mutate=mutate):
                document = valid_document()
                mutate(document)
                errors = list(
                    jsonschema.Draft202012Validator(schema).iter_errors(document)
                )
                self.assertTrue(errors)

    def test_target_controlled_status_cannot_replace_independent_workload_facts(self) -> None:
        document = valid_document()
        document["workload"] = {
            "protocol_version": 1,
            "instance": "aaaaaaaaaaaa",
            "target_status": "passed",
        }
        with self.assertRaisesRegex(ValueError, "workload|incomplete|declared schema"):
            self.validator.validate_document(document)

    def test_workload_instance_is_bound_to_the_exact_target_sha(self) -> None:
        document = valid_document()

        def replace_instance(value: object) -> object:
            if isinstance(value, str):
                return value.replace("aaaaaaaaaaaa", "bbbbbbbbbbbb")
            if isinstance(value, list):
                return [replace_instance(item) for item in value]
            if isinstance(value, dict):
                return {
                    key: replace_instance(item) for key, item in value.items()
                }
            return value

        document["workload"] = replace_instance(document["workload"])
        with self.assertRaisesRegex(ValueError, "workload instance"):
            self.validator.validate_document(document)

    def test_phase_failure_is_preserved_and_forces_d1a_failure(self) -> None:
        document = valid_document()
        document["test"]["phase_exit_statuses"]["workload_prepare_start"] = 7
        document["test"]["result"] = "failed"
        document["test"]["failed_admission_invariants"] = [
            "TARGET_WORKLOAD_PREPARE_START"
        ]
        document["workload"]["result"] = "failed"
        document["workload"]["failed_admission_invariants"] = [
            "TARGET_WORKLOAD_PREPARE_START"
        ]
        self.assertEqual(document, self.validator.validate_document(document))

    def test_host_phase_failure_forces_only_d1_host_admission_failure(self) -> None:
        document = valid_document()
        document["test"]["phase_exit_statuses"]["host"] = 7
        document["test"]["result"] = "failed"
        document["test"]["failed_admission_invariants"] = [
            "TARGET_HOST_CONTRACT"
        ]
        document["host_admission"] = {
            "result": "failed",
            "failed_admission_invariants": ["TARGET_HOST_CONTRACT"],
        }
        self.assertEqual("passed", document["workload"]["result"])
        self.assertEqual(document, self.validator.validate_document(document))

    def test_cleanup_collection_failure_cannot_report_conformance(self) -> None:
        document = valid_document()
        document["test"]["collection_exit_statuses"]["post_cleanup"] = 124
        with self.assertRaisesRegex(ValueError, "result|admission failures"):
            self.validator.validate_document(document)

    def test_unknown_workload_field_is_rejected(self) -> None:
        document = valid_document()
        document["workload"]["live"]["target_claimed_ready"] = True
        with self.assertRaisesRegex(ValueError, "unknown|declared schema"):
            self.validator.validate_document(document)

    def test_schema_rejects_missing_or_state_contradictory_user_namespace_facts(self) -> None:
        schema = json.loads(
            (ROOT / "schemas" / "ci-cloud-evidence.schema.json").read_text(
                encoding="utf-8"
            )
        )
        schema_validator = jsonschema.Draft202012Validator(schema)
        mutations = (
            lambda namespace: namespace.pop("process_identity"),
            lambda namespace: namespace.__setitem__("uid_map", []),
            lambda namespace: namespace.__setitem__("podman_uid_map", []),
            lambda namespace: namespace["uid_map"][0].__setitem__(
                "target_claimed_safe", True
            ),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                document = valid_document()
                mutate(
                    document["workload"]["live"]["containers"][4][
                        "user_namespace"
                    ]
                )
                with self.assertRaises(jsonschema.ValidationError):
                    schema_validator.validate(document)
                with self.assertRaises(ValueError):
                    self.validator.validate_document(document)

        document = valid_document()
        exited = document["workload"]["live"]["containers"][3]
        exited["user_namespace"]["process_identity"] = "user:[4026540999]"
        with self.assertRaises(jsonschema.ValidationError):
            schema_validator.validate(document)
        with self.assertRaises(ValueError):
            self.validator.validate_document(document)

    def test_validator_recomputes_namespace_identity_separation(self) -> None:
        document = valid_document()
        namespace = document["workload"]["live"]["containers"][4][
            "user_namespace"
        ]
        namespace["process_identity"] = namespace["collector_identity"]
        with self.assertRaisesRegex(ValueError, "workload admission failures"):
            self.validator.validate_document(document)

    def test_validator_recomputes_configured_mapping_consistency(self) -> None:
        document = valid_document()
        namespace = document["workload"]["live"]["containers"][4][
            "user_namespace"
        ]
        inconsistent = [
            {"container_id": 0, "host_id": 3_000_000_000, "size": 65_536}
        ]
        namespace["configured_uid_map"] = copy.deepcopy(inconsistent)
        namespace["configured_gid_map"] = copy.deepcopy(inconsistent)
        with self.assertRaisesRegex(ValueError, "workload admission failures"):
            self.validator.validate_document(document)

    def test_service_environment_evidence_cannot_contain_values(self) -> None:
        document = valid_document()
        document["workload"]["live"]["generated_services"][0]["environment"] = [
            "DB_PASSWORD=synthetic-placeholder"
        ]
        with self.assertRaises(ValueError):
            self.validator.validate_document(document)

    def test_unprefixed_resource_cannot_survive_validator_recomputation(self) -> None:
        document = valid_document()
        document["workload"]["live"]["all_containers"].append(
            "target-created-rogue"
        )
        with self.assertRaisesRegex(ValueError, "workload admission failures"):
            self.validator.validate_document(document)

    def test_complete_gcp_axion_evidence_is_accepted(self) -> None:
        document = valid_document()
        document["test"].update(
            {
                "provider": "gcp",
                "region": "europe-west3-a",
                "profile": "axion",
                "machine_type": "c4a-standard-4",
                "provider_image": {
                    "slug": "debian-cloud/debian-13-arm64",
                    "id": "https://www.googleapis.com/compute/v1/projects/debian-cloud/global/images/debian-13-trixie-arm64-v20260801",
                },
            }
        )
        document["platform"].update(
            {
                "architecture": "arm64",
                "uname": "Linux fixture 6.12.0-arm64 aarch64 GNU/Linux",
                "kernel": "6.12.0-arm64",
                "cpu": {"vendor": "ARM", "model": "Neoverse-V2"},
            }
        )
        document["host"]["kernel_package"].update(
            {"name": "linux-image-6.12.0-arm64", "architecture": "arm64"}
        )
        document["host"]["cloud_identity"].update(
            {"probe_supported": True, "probe_succeeded": True}
        )
        for package_group in ("runtime_packages", "bootstrap_packages"):
            for package in document["apt"][package_group].values():
                if package["architecture"] != "all":
                    package["architecture"] = "arm64"
        self.assertEqual(document, self.validator.validate_document(document))

    def test_gcp_evidence_rejects_attached_cloud_identity(self) -> None:
        document = valid_document()
        document["test"].update(
            {
                "provider": "gcp",
                "region": "europe-west3-a",
                "profile": "axion",
                "machine_type": "c4a-standard-4",
                "provider_image": {
                    "slug": "debian-cloud/debian-13-arm64",
                    "id": "https://www.googleapis.com/compute/v1/projects/debian-cloud/global/images/debian-13-trixie-arm64-v20260801",
                },
            }
        )
        document["host"]["cloud_identity"] = {
            "probe_supported": True,
            "probe_succeeded": True,
            "identity_present": True,
        }
        with self.assertRaisesRegex(ValueError, "effective facts"):
            self.validator.validate_document(document)

    def test_incomplete_evidence_is_rejected(self) -> None:
        document = valid_document()
        del document["runtime"]
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self.validator.validate_document(document)

    def test_credential_like_field_is_rejected(self) -> None:
        document = valid_document()
        document["runtime"]["access_token"] = "synthetic"
        with self.assertRaisesRegex(ValueError, "credential-like field"):
            self.validator.validate_document(document)

    def test_credential_like_value_is_rejected(self) -> None:
        document = valid_document()
        document["runtime"]["crun_features"] = "Authorization: Bearer syntheticvalue"
        with self.assertRaisesRegex(ValueError, "credential-like value"):
            self.validator.validate_document(document)

    def test_result_cannot_hide_failed_admission(self) -> None:
        document = valid_document()
        document["test"]["failed_admission_invariants"] = ["D1_HOST_APPARMOR"]
        with self.assertRaisesRegex(ValueError, "contradicts"):
            self.validator.validate_document(document)

    def test_result_cannot_hide_nonconforming_effective_fact(self) -> None:
        document = valid_document()
        document["apt"]["release_signatures_verified"] = False
        with self.assertRaisesRegex(ValueError, "effective facts"):
            self.validator.validate_document(document)

    def test_malformed_effective_fact_fails_closed(self) -> None:
        document = valid_document()
        document["platform"]["logical_cpu"] = "eight"
        with self.assertRaisesRegex(ValueError, "malformed"):
            self.validator.validate_document(document)

    def test_unknown_nested_field_is_rejected(self) -> None:
        document = copy.deepcopy(valid_document())
        document["runtime"]["podman"]["cloud_identity"] = "none"
        with self.assertRaisesRegex(ValueError, "unknown"):
            self.validator.validate_document(document)

    def test_declared_schema_rejects_invalid_run_identity(self) -> None:
        document = valid_document()
        document["workflow"]["run_id"] = "0"
        with self.assertRaisesRegex(ValueError, "declared schema"):
            self.validator.validate_document(document)

    def test_declared_schema_rejects_duplicate_array_values(self) -> None:
        document = valid_document()
        document["apt"]["source_files"] = ["/etc/apt/sources.list"] * 2
        with self.assertRaisesRegex(ValueError, "declared schema"):
            self.validator.validate_document(document)

    def test_unknown_kernel_provenance_basis_fails_closed(self) -> None:
        document = valid_document()
        document["host"]["kernel_package"]["provenance_basis"] = "provider-label"
        with self.assertRaisesRegex(ValueError, "admission failures"):
            self.validator.validate_document(document)

    def test_unavailable_kernel_provenance_fails_admission(self) -> None:
        document = valid_document()
        document["host"]["kernel_package"].update(
            {
                "origin": "",
                "suite": "",
                "provenance_basis": "unavailable",
            }
        )
        document["test"].update(
            {
                "result": "failed",
                "failed_admission_invariants": ["D1_KERNEL_PACKAGE_PROVENANCE"],
            }
        )
        document["host_admission"].update(
            {
                "result": "failed",
                "failed_admission_invariants": ["D1_KERNEL_PACKAGE_PROVENANCE"],
            }
        )
        self.assertEqual(document, self.validator.validate_document(document))

    def test_installed_dpkg_kernel_provenance_is_rejected(self) -> None:
        document = valid_document()
        document["host"]["kernel_package"].update(
            {
                "origin": "",
                "suite": "",
                "provenance_basis": "installed-dpkg",
            }
        )
        document["test"].update(
            {
                "result": "failed",
                "failed_admission_invariants": ["D1_KERNEL_PACKAGE_PROVENANCE"],
            }
        )
        document["host_admission"].update(
            {
                "result": "failed",
                "failed_admission_invariants": ["D1_KERNEL_PACKAGE_PROVENANCE"],
            }
        )
        with self.assertRaisesRegex(ValueError, "declared schema"):
            self.validator.validate_document(document)

    def test_declared_schema_rejects_unavailable_memory_evidence(self) -> None:
        document = valid_document()
        document["platform"]["memory_bytes"] = 0
        schema = json.loads(
            (ROOT / "schemas" / "ci-cloud-evidence.schema.json").read_text(
                encoding="utf-8"
            )
        )
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.Draft202012Validator(schema).validate(document)
        with self.assertRaises(ValueError):
            self.validator.validate_document(document)

    def test_rejects_digitalocean_evidence_with_gcp_image_id(self) -> None:
        document = valid_document()
        document["test"]["provider_image"]["id"] = (
            "https://www.googleapis.com/compute/v1/projects/debian-cloud/"
            "global/images/debian-13-trixie-arm64-v20260801"
        )
        with self.assertRaisesRegex(ValueError, "provider image identity"):
            self.validator.validate_document(document)

    def test_declared_schema_binds_image_id_to_provider(self) -> None:
        document = valid_document()
        document["test"]["provider_image"]["id"] = (
            "https://www.googleapis.com/compute/v1/projects/debian-cloud/"
            "global/images/debian-13-trixie-arm64-v20260801"
        )
        schema = json.loads(
            (ROOT / "schemas" / "ci-cloud-evidence.schema.json").read_text(
                encoding="utf-8"
            )
        )
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.Draft202012Validator(schema).validate(document)

    def test_gcp_image_without_codename_is_rejected(self) -> None:
        document = valid_document()
        document["test"]["provider_image"]["id"] = (
            "https://www.googleapis.com/compute/v1/projects/debian-cloud/"
            "global/images/debian-13-arm64-v20260801"
        )
        with self.assertRaisesRegex(ValueError, "provider image identity"):
            self.validator.validate_document(document)

    def test_declared_schema_binds_the_complete_provider_selection(self) -> None:
        document = valid_document()
        document["test"]["profile"] = "axion"
        schema = json.loads(
            (ROOT / "schemas" / "ci-cloud-evidence.schema.json").read_text(
                encoding="utf-8"
            )
        )
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.Draft202012Validator(schema).validate(document)


if __name__ == "__main__":
    unittest.main()
