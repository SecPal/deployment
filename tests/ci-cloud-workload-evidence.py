#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Contract tests for trusted D.1a Quadlet workload observations."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
COLLECTOR_PATH = ROOT / "scripts" / "ci-cloud" / "collect-workload-evidence.py"
ASSEMBLER_PATH = ROOT / "scripts" / "ci-cloud" / "assemble-evidence.py"
RUNNER_PATH = ROOT / "scripts" / "ci-cloud" / "run-remote-conformance.sh"
TARGET_PATH = ROOT / "scripts" / "ci-cloud" / "target-conformance.sh"

ROLES = (
    "secrets-init", "postgres", "valkey", "migrate", "api",
    "worker-general", "worker-hash-chain", "scheduler", "frontend", "gateway",
)
ROLE_NETWORKS = {
    "secrets-init": (),
    "postgres": ("application",),
    "valkey": ("application",),
    "migrate": ("application",),
    "api": ("application", "edge"),
    "worker-general": ("application",),
    "worker-hash-chain": ("application",),
    "scheduler": ("application",),
    "frontend": ("edge",),
    "gateway": ("edge",),
}
HEALTHY_ROLES = {"postgres", "valkey", "api", "frontend", "gateway"}


def load_collector():
    spec = importlib.util.spec_from_file_location(
        "ci_cloud_workload_collector", COLLECTOR_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load workload collector")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_assembler():
    spec = importlib.util.spec_from_file_location(
        "ci_cloud_evidence_assembler", ASSEMBLER_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load evidence assembler")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def valid_observations() -> dict[str, object]:
    instance = "aaaaaaaaaaaa"
    prefix = f"secpal-int-{instance}"
    unit_names = sorted(
        [f"{prefix}-{role}.container" for role in ROLES]
        + [f"{prefix}-{name}.network" for name in ("application", "edge")]
        + [f"{prefix}-{name}.volume" for name in ("secrets", "private-storage", "postgres")]
        + [f"{prefix}.target"]
    )
    units = [
        {
            "name": name,
            "path": (
                f"/etc/systemd/user/{name}"
                if name.endswith(".target")
                else f"/etc/containers/systemd/users/20000/{name}"
            ),
            "uid": 0,
            "gid": 0,
            "mode": "0644",
            "sha256": f"{index + 1:064x}",
        }
        for index, name in enumerate(unit_names)
    ]
    generated_names = (
        *ROLES,
        "application-network", "edge-network",
        "secrets-volume", "private-storage-volume", "postgres-volume",
    )
    services = [
        {
            "logical_name": logical_name,
            "unit": f"{prefix}-{logical_name}.service",
            "fragment_path": f"/run/user/20000/systemd/generator/{prefix}-{logical_name}.service",
            "fragment_uid": 20000,
            "fragment_gid": 20000,
            "fragment_mode": "0644",
            "drop_in_paths": [],
            "drop_in_owners": [],
        }
        for logical_name in generated_names
    ]
    containers = []
    for role in ROLES:
        one_shot = role in {"secrets-init", "migrate"}
        containers.append(
            {
                "role": role,
                "name": f"{prefix}-{role}",
                "state": "exited" if one_shot else "running",
                "exit_code": 0,
                "health": "healthy" if role in HEALTHY_ROLES else "none",
                "oci_runtime": "crun",
                "rootless": True,
                "privileged": False,
                "pid_mode": "private",
                "userns_mode": "private",
                "network_mode": "private",
                "cap_add": [],
                "devices_present": False,
                "podman_socket_mount": False,
                "remote_api_environment": False,
                "security_opt": ["no-new-privileges"],
                "networks": [f"{prefix}-{network}" for network in ROLE_NETWORKS[role]],
                "published_ports": ["127.0.0.1:18443:8443/tcp"] if role == "gateway" else [],
                "auto_update": False,
                "image": f"localhost/secpal-ci-{role}@sha256:{'a' * 64}",
            }
        )
    return {
        "protocol_version": 1,
        "instance": instance,
        "result": "passed",
        "failed_admission_invariants": [],
        "baseline": {
            "phase": "baseline",
            "target_admitted": True,
            "collector_uid": 20000,
            "collector_gid": 20000,
            "complete": True,
            "containers": [],
            "networks": ["podman", "secpal-ci-unrelated-control-network"],
            "volumes": ["secpal-ci-unrelated-control-volume"],
            "control_resources": {
                "network_present": True,
                "volume_present": True,
            },
        },
        "live": {
            "phase": "live",
            "target_admitted": True,
            "collector_uid": 20000,
            "collector_gid": 20000,
            "complete": True,
            "quadlet_search_paths": ["/etc/containers/systemd/users/20000"],
            "installed_units": units,
            "generated_services": services,
            "containers": containers,
            "podman_rootless": True,
            "oci_runtime": "crun",
            "singleton_roles": {"scheduler": 1, "worker-hash-chain": 1},
            "networks": [f"{prefix}-application", f"{prefix}-edge"],
            "volumes": [f"{prefix}-postgres", f"{prefix}-private-storage", f"{prefix}-secrets"],
            "all_containers": sorted(item["name"] for item in containers),
            "all_networks": sorted(
                [
                    "podman",
                    "secpal-ci-unrelated-control-network",
                    f"{prefix}-application",
                    f"{prefix}-edge",
                ]
            ),
            "all_volumes": sorted(
                [
                    "secpal-ci-unrelated-control-volume",
                    f"{prefix}-postgres",
                    f"{prefix}-private-storage",
                    f"{prefix}-secrets",
                ]
            ),
            "migration": {"observed": True, "exit_code": 0},
            "readiness": {"observed": True, "ready_roles": sorted(set(ROLES) - {"secrets-init", "migrate"})},
            "podman_api": False,
            "control_resources": {
                "network_present": True,
                "volume_present": True,
            },
        },
        "post_cleanup": {
            "phase": "post-cleanup",
            "target_admitted": True,
            "collector_uid": 20000,
            "collector_gid": 20000,
            "complete": True,
            "owned_units": [],
            "generated_services": [],
            "containers": [],
            "networks": [],
            "volumes": [],
            "all_containers": [],
            "all_networks": ["podman", "secpal-ci-unrelated-control-network"],
            "all_volumes": ["secpal-ci-unrelated-control-volume"],
            "control_resources": {
                "network_present": True,
                "volume_present": True,
            },
        },
    }


class WorkloadEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.collector = load_collector()
        cls.assembler = load_assembler()

    def test_synthetic_complete_trusted_orchestration_sequence(self) -> None:
        observations = valid_observations()
        host = {
            "schema_version": 1,
            "workflow": {"target_sha": "a" * 40},
            "test": {"failed_admission_invariants": []},
            "platform": {},
            "apt": {},
            "host": {},
            "runtime": {},
        }
        document = self.assembler.assemble(
            host,
            observations["baseline"],
            observations["live"],
            observations["post_cleanup"],
            {"host": 0, "workload_prepare_start": 0, "workload_cleanup": 0},
            {"baseline": 0, "live": 0, "post_cleanup": 0},
        )
        self.assertEqual("passed", document["workload"]["result"])
        self.assertEqual("live", document["workload"]["live"]["phase"])
        self.assertEqual(
            "post-cleanup", document["workload"]["post_cleanup"]["phase"]
        )
        self.assertEqual([], document["workload"]["post_cleanup"]["containers"])

    def test_host_phase_failure_remains_in_d1_host_admission(self) -> None:
        observations = valid_observations()
        host = {
            "schema_version": 1,
            "workflow": {"target_sha": "a" * 40},
            "test": {
                "failed_admission_invariants": ["TARGET_CONFORMANCE_ENTRYPOINT"]
            },
            "platform": {},
            "apt": {},
            "host": {},
            "runtime": {},
        }
        document = self.assembler.assemble(
            host,
            observations["baseline"],
            observations["live"],
            observations["post_cleanup"],
            {"host": 7, "workload_prepare_start": 0, "workload_cleanup": 0},
            {"baseline": 0, "live": 0, "post_cleanup": 0},
        )
        self.assertEqual(
            {
                "result": "failed",
                "failed_admission_invariants": ["TARGET_HOST_CONTRACT"],
            },
            document["host_admission"],
        )
        self.assertEqual("passed", document["workload"]["result"])

    def assert_failure(self, mutation, expected: str) -> None:
        observations = valid_observations()
        mutation(observations)
        self.assertIn(expected, self.collector.workload_admission_failures(observations))

    def test_exact_snapshot_contains_sixteen_root_owned_units(self) -> None:
        live = valid_observations()["live"]
        self.assertEqual(16, len(live["installed_units"]))
        self.assertEqual(
            [], self.collector.workload_admission_failures(valid_observations())
        )

    def test_collection_requires_exact_sha_and_rootless_identity_admission(self) -> None:
        with mock.patch.object(os, "getuid", return_value=0), mock.patch.object(
            os, "getgid", return_value=0
        ):
            with self.assertRaisesRegex(ValueError, "UID/GID 20000"):
                self.collector.admit_collection_context(
                    "live", "a" * 40, "aaaaaaaaaaaa", self.collector.CHECKOUT
                )
        with mock.patch.object(os, "getuid", return_value=20000), mock.patch.object(
            os, "getgid", return_value=20000
        ), mock.patch.object(
            self.collector, "checked_output", return_value="b" * 40
        ):
            with self.assertRaisesRegex(ValueError, "exact target SHA"):
                self.collector.admit_collection_context(
                    "live", "a" * 40, "aaaaaaaaaaaa", self.collector.CHECKOUT
                )

    def test_collection_rejects_arbitrary_phase_instance_and_checkout_path(self) -> None:
        for phase, sha, instance, checkout in (
            ("command=/bin/sh", "a" * 40, "aaaaaaaaaaaa", Path("/home/secpal-ci/deployment-target")),
            ("live", "a" * 40, "chosen-by-target", Path("/home/secpal-ci/deployment-target")),
            ("live", "a" * 40, "aaaaaaaaaaaa", Path("/tmp/target")),
        ):
            with self.subTest(phase=phase, instance=instance, checkout=checkout):
                with self.assertRaises(ValueError):
                    self.collector.admit_collection_context(phase, sha, instance, checkout)

    def test_network_listing_accepts_podman_lowercase_name(self) -> None:
        with mock.patch.object(
            self.collector,
            "json_array",
            return_value=([{"name": "secpal-ci-unrelated-control-network"}], True),
        ):
            self.assertEqual(
                (["secpal-ci-unrelated-control-network"], True),
                self.collector.names_from_listing(["podman", "network", "ls"]),
            )

    def test_inventory_rejects_unprefixed_target_resources_and_cleanup_leaks(self) -> None:
        for phase, field in (
            ("live", "all_containers"),
            ("live", "all_networks"),
            ("live", "all_volumes"),
            ("post_cleanup", "all_containers"),
            ("post_cleanup", "all_networks"),
            ("post_cleanup", "all_volumes"),
        ):
            with self.subTest(phase=phase, field=field):
                self.assert_failure(
                    lambda evidence, phase=phase, field=field: evidence[phase][
                        field
                    ].append("target-created-rogue"),
                    "D1A_RESOURCE_INVENTORY",
                )

    def test_baseline_rejects_preexisting_fixture_resources(self) -> None:
        self.assert_failure(
            lambda evidence: evidence["baseline"]["containers"].append(
                "secpal-int-aaaaaaaaaaaa-api"
            ),
            "D1A_BASELINE_INVENTORY",
        )

    def test_false_green_target_status_cannot_replace_live_observation(self) -> None:
        self.assert_failure(
            lambda evidence: evidence.__setitem__("live", None),
            "D1A_LIVE_OBSERVATION",
        )

    def test_generated_unit_outside_trusted_generator_path_is_rejected(self) -> None:
        self.assert_failure(
            lambda evidence: evidence["live"]["generated_services"][0].__setitem__(
                "fragment_path", "/home/secpal-ci/.config/systemd/user/escape.service"
            ),
            "D1A_GENERATED_UNITS",
        )

    def test_unexpected_missing_and_duplicate_containers_are_rejected(self) -> None:
        for mutate in (
            lambda value: value.append(copy.deepcopy(value[0])),
            lambda value: value.pop(),
            lambda value: value[0].__setitem__("role", "unexpected"),
        ):
            self.assert_failure(
                lambda evidence, mutate=mutate: mutate(evidence["live"]["containers"]),
                "D1A_CONTAINER_SET",
            )

    def test_duplicate_singleton_roles_are_rejected(self) -> None:
        self.assert_failure(
            lambda evidence: evidence["live"]["singleton_roles"].__setitem__(
                "scheduler", 2
            ),
            "D1A_SINGLETON_ROLES",
        )

    def test_rootful_remote_host_network_privilege_and_auto_update_are_rejected(self) -> None:
        mutations = (
            ("rootless", False, "D1A_ROOTLESS"),
            ("oci_runtime", "runc", "D1A_OCI_RUNTIME"),
            ("privileged", True, "D1A_PRIVILEGE_BOUNDARY"),
            ("pid_mode", "host", "D1A_HOST_NAMESPACES"),
            ("userns_mode", "host", "D1A_HOST_NAMESPACES"),
            ("network_mode", "host", "D1A_HOST_NETWORK"),
            ("auto_update", True, "D1A_AUTO_UPDATE_DISABLED"),
        )
        for field, value, invariant in mutations:
            with self.subTest(field=field):
                self.assert_failure(
                    lambda evidence, field=field, value=value: evidence["live"]["containers"][4].__setitem__(field, value),
                    invariant,
                )
        self.assert_failure(
            lambda evidence: evidence["live"]["containers"][4].__setitem__(
                "cap_add", ["SYS_ADMIN"]
            ),
            "D1A_PRIVILEGE_BOUNDARY",
        )
        self.assert_failure(
            lambda evidence: evidence["live"]["containers"][4].__setitem__(
                "image", "docker.io/secpal/api:latest"
            ),
            "D1A_IMAGE_PROVENANCE",
        )

    def test_each_container_requires_its_exact_fixture_network(self) -> None:
        self.assert_failure(
            lambda evidence: evidence["live"]["containers"][4].__setitem__(
                "networks", ["podman"]
            ),
            "D1A_CONTAINER_NETWORKS",
        )

    def test_only_gateway_may_publish_its_exact_loopback_port(self) -> None:
        self.assert_failure(
            lambda evidence: evidence["live"]["containers"][4].__setitem__(
                "published_ports", ["127.0.0.1:18443:8443/tcp"]
            ),
            "D1A_PUBLISHED_PORTS",
        )
        self.assert_failure(
            lambda evidence: evidence["live"]["containers"][-1].__setitem__(
                "published_ports", []
            ),
            "D1A_PUBLISHED_PORTS",
        )
        self.assert_failure(
            lambda evidence: evidence["live"]["containers"][-1].__setitem__(
                "networks", ["secpal-int-aaaaaaaaaaaa-application"]
            ),
            "D1A_CONTAINER_NETWORKS",
        )

    def test_container_inspection_missing_security_facts_is_incomplete(self) -> None:
        inspection = {
            "Name": "secpal-int-aaaaaaaaaaaa-api",
            "State": {
                "Status": "running",
                "ExitCode": 0,
                "Healthcheck": {"Status": "healthy"},
            },
            "Config": {
                "Labels": {},
                "Env": [],
                "Image": f"localhost/secpal-ci-api@sha256:{'a' * 64}",
            },
            "HostConfig": {
                "Privileged": False,
                "PidMode": "private",
                "UsernsMode": "private",
                "NetworkMode": "private",
                "SecurityOpt": ["no-new-privileges"],
                "CapAdd": [],
                "Devices": [],
            },
            "NetworkSettings": {
                "Networks": {"secpal-int-aaaaaaaaaaaa-application": {}},
                "Ports": {},
            },
            "Mounts": [],
            "OCIRuntime": "crun",
            "ImageName": f"localhost/secpal-ci-api@sha256:{'a' * 64}",
        }
        required_fields = (
            (inspection, "OCIRuntime"),
            (inspection, "Mounts"),
            (inspection["Config"], "Env"),
            (inspection["HostConfig"], "CapAdd"),
            (inspection["HostConfig"], "Devices"),
            (inspection["NetworkSettings"], "Ports"),
        )
        for owner, field in required_fields:
            with self.subTest(field=field):
                candidate = copy.deepcopy(inspection)
                if owner is inspection:
                    del candidate[field]
                elif owner is inspection["Config"]:
                    del candidate["Config"][field]
                elif owner is inspection["HostConfig"]:
                    del candidate["HostConfig"][field]
                else:
                    del candidate["NetworkSettings"][field]
                with mock.patch.object(
                    self.collector,
                    "names_from_listing",
                    return_value=(["secpal-int-aaaaaaaaaaaa-api"], True),
                ), mock.patch.object(
                    self.collector, "json_array", return_value=([candidate], True)
                ):
                    _, complete = self.collector.container_facts(
                        "aaaaaaaaaaaa", rootless=True
                    )
                self.assertFalse(complete)

    def test_podman_healthcheck_and_global_rootless_fact_are_used(self) -> None:
        inspection = {
            "Name": "secpal-int-aaaaaaaaaaaa-api",
            "State": {
                "Status": "running",
                "ExitCode": 0,
                "Healthcheck": {"Status": "healthy"},
            },
            "Config": {
                "Labels": {},
                "Env": [],
                "Image": f"localhost/secpal-ci-api@sha256:{'a' * 64}",
            },
            "HostConfig": {
                "Privileged": False,
                "PidMode": "private",
                "UsernsMode": "private",
                "NetworkMode": "private",
                "SecurityOpt": ["no-new-privileges"],
                "CapAdd": [],
                "Devices": [],
            },
            "NetworkSettings": {
                "Networks": {"secpal-int-aaaaaaaaaaaa-application": {}},
                "Ports": {},
            },
            "Mounts": [],
            "OCIRuntime": "crun",
            "ImageName": f"localhost/secpal-ci-api@sha256:{'a' * 64}",
        }
        with mock.patch.object(
            self.collector,
            "names_from_listing",
            return_value=(["secpal-int-aaaaaaaaaaaa-api"], True),
        ), mock.patch.object(
            self.collector, "json_array", return_value=([inspection], True)
        ):
            facts, complete = self.collector.container_facts(
                "aaaaaaaaaaaa", rootless=True
            )
        self.assertTrue(complete)
        self.assertEqual("healthy", facts[0]["health"])
        self.assertTrue(facts[0]["rootless"])

    def test_no_new_privileges_requires_the_exact_security_option(self) -> None:
        self.assert_failure(
            lambda evidence: evidence["live"]["containers"][4].__setitem__(
                "security_opt",
                ["seccomp=/home/secpal-ci/no-new-privileges.json"],
            ),
            "D1A_SECURITY_OPTIONS",
        )

    def test_remote_or_socket_api_evidence_is_rejected(self) -> None:
        observations = valid_observations()
        observations["live"]["podman_api"] = True
        self.assertIn(
            "D1A_PODMAN_API_DISABLED",
            self.collector.workload_admission_failures(observations),
        )
        self.assert_failure(
            lambda evidence: evidence["live"]["containers"][4].__setitem__(
                "podman_socket_mount", True
            ),
            "D1A_PODMAN_API_DISABLED",
        )
        self.assert_failure(
            lambda evidence: evidence["live"]["containers"][4].__setitem__(
                "remote_api_environment", True
            ),
            "D1A_PODMAN_API_DISABLED",
        )

    def test_process_scan_failure_marks_podman_api_observation_incomplete(self) -> None:
        with mock.patch.object(
            self.collector,
            "command_result",
            side_effect=lambda arguments, timeout=20: (
                (0, "", True) if arguments[:2] == ["ss", "-lxnp"] else (3, "", True)
            ),
        ), mock.patch.object(
            self.collector, "json_array", return_value=([], True)
        ), mock.patch.object(
            self.collector.Path, "iterdir", return_value=(Path("/proc/123"),)
        ), mock.patch.object(
            self.collector.Path, "open", side_effect=OSError("hidden process")
        ):
            self.assertEqual((True, False), self.collector.podman_api_facts())

    def test_migration_and_readiness_must_be_independently_observed(self) -> None:
        self.assert_failure(
            lambda evidence: evidence["live"]["migration"].__setitem__("observed", False),
            "D1A_MIGRATION",
        )
        self.assert_failure(
            lambda evidence: evidence["live"]["readiness"].__setitem__("observed", False),
            "D1A_READINESS",
        )
        self.assert_failure(
            lambda evidence: evidence["live"]["containers"][4].__setitem__(
                "health", "none"
            ),
            "D1A_READINESS",
        )

    def test_cleanup_claim_fails_while_any_owned_resource_remains(self) -> None:
        for field, value in (
            ("owned_units", ["remaining.container"]),
            ("generated_services", ["remaining.service"]),
            ("containers", ["remaining"]),
            ("networks", ["remaining"]),
            ("volumes", ["remaining"]),
        ):
            with self.subTest(field=field):
                self.assert_failure(
                    lambda evidence, field=field, value=value: evidence["post_cleanup"].__setitem__(field, value),
                    "D1A_CLEANUP_ABSENCE",
                )

    def test_cleanup_must_preserve_unrelated_control_resources(self) -> None:
        self.assert_failure(
            lambda evidence: evidence["post_cleanup"]["control_resources"].__setitem__(
                "network_present", False
            ),
            "D1A_CONTROL_RESOURCES_PRESERVED",
        )

    def test_cleanup_generator_scan_failure_marks_observation_incomplete(self) -> None:
        with mock.patch.object(
            self.collector.Path, "iterdir", return_value=iter(())
        ), mock.patch.object(
            self.collector.Path, "glob", side_effect=PermissionError("hidden")
        ), mock.patch.object(
            self.collector,
            "resource_inventory",
            return_value=(
                {"containers": [], "networks": [], "volumes": []},
                True,
            ),
        ), mock.patch.object(
            self.collector,
            "control_resource_facts",
            return_value={"network_present": True, "volume_present": True},
        ):
            observation = self.collector.collect_post_cleanup("aaaaaaaaaaaa")
        self.assertFalse(observation["complete"])

    def test_truncated_unknown_and_contradictory_observations_fail_closed(self) -> None:
        for mutate in (
            lambda evidence: evidence["baseline"].__setitem__("complete", False),
            lambda evidence: evidence["live"].__setitem__("complete", False),
            lambda evidence: evidence["live"].__setitem__("target_status", "passed"),
            lambda evidence: evidence["post_cleanup"].__setitem__("complete", False),
        ):
            observations = valid_observations()
            mutate(observations)
            self.assertTrue(self.collector.workload_admission_failures(observations))

    def test_runner_uses_only_literal_target_phases_and_always_collects_cleanup(self) -> None:
        runner = RUNNER_PATH.read_text(encoding="utf-8")
        for literal in ("v1 host", "v1 workload-prepare-start", "v1 workload-cleanup"):
            self.assertIn(literal, runner)
        self.assertNotIn("SECPAL_TARGET_COMMAND", runner)
        self.assertNotIn("sudo", runner)
        self.assertIn("collect-workload-evidence.py", runner)
        self.assertLess(
            runner.index('bootstrap_stage="collector-baseline"'),
            runner.index('bootstrap_stage="target-workload-prepare-start"'),
        )
        self.assertLess(
            runner.index("v1 workload-prepare-start"),
            runner.index('"live"'),
        )
        self.assertLess(
            runner.index("v1 workload-cleanup"),
            runner.rindex('"post-cleanup"'),
        )
        self.assertIn("trap collect_cleanup_after_interruption INT TERM HUP", runner)
        self.assertEqual(3, runner.count("ulimit -f 32768"))
        self.assertEqual(
            3,
            runner.count("cd /home/secpal-ci/deployment-target"),
        )

    def test_target_entrypoint_has_closed_versioned_phase_parser(self) -> None:
        target = TARGET_PATH.read_text(encoding="utf-8")
        self.assertIn('[[ "$#" -eq 2 && "$1" == v1 ]]', target)
        self.assertIn("host | workload-prepare-start | workload-cleanup", target)
        self.assertNotIn("eval", target)
        self.assertNotIn("source ", target)


if __name__ == "__main__":
    unittest.main()
