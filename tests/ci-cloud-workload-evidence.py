#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Contract tests for trusted D.1a Quadlet workload observations."""

from __future__ import annotations

import copy
import importlib.util
import io
import json
import os
import subprocess
import tempfile
import time
import types
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
ROLE_VOLUME_MOUNTS = {
    "secrets-init": (
        ("secrets", "/run/secpal-secrets", True),
        ("postgres", "/var/lib/postgresql/data", True),
        ("private-storage", "/mnt/secpal-private-storage", True),
    ),
    "postgres": (
        ("secrets", "/run/secpal-secrets", False),
        ("postgres", "/var/lib/postgresql/data", True),
    ),
    "valkey": (("secrets", "/run/secpal-secrets", False),),
    **{
        role: (
            ("secrets", "/run/secpal-secrets", False),
            ("private-storage", "/app/storage/app/private", True),
        )
        for role in (
            "migrate", "api", "worker-general", "worker-hash-chain", "scheduler"
        )
    },
    "frontend": (),
    "gateway": (),
}
API_BINDS = (
    ("container-entrypoint.sh", "/run/secpal/container-entrypoint.sh"),
    ("phase-b-runtime-probe.php", "/run/secpal/phase-b-runtime-probe.php"),
)
ROLE_BINDS = {
    "secrets-init": (
        ("init-local-secrets.sh", "/run/secpal/init-local-secrets.sh"),
        ("quadlet-oneshot-entrypoint.sh", "/run/secpal/quadlet-oneshot-entrypoint.sh"),
    ),
    "postgres": (),
    "valkey": (("valkey-entrypoint.sh", "/run/secpal/valkey-entrypoint.sh"),),
    "migrate": API_BINDS
    + (("quadlet-oneshot-entrypoint.sh", "/run/secpal/quadlet-oneshot-entrypoint.sh"),),
    "api": API_BINDS,
    "worker-general": API_BINDS,
    "worker-hash-chain": API_BINDS,
    "scheduler": API_BINDS,
    "frontend": (),
    "gateway": (("Caddyfile", "/etc/caddy/Caddyfile"),),
}
API_TMPFS = (
    ("/tmp", 32, "0700", True),
    ("/config", 16, "0700", True),
    ("/data", 16, "0700", True),
    ("/app/storage/app/public", 32, "0750", False),
    ("/app/storage/framework/cache/data", 32, "0750", True),
    ("/app/storage/framework/sessions", 32, "0750", True),
    ("/app/storage/framework/views", 32, "0750", True),
    ("/app/storage/logs", 32, "0750", True),
    ("/app/bootstrap/cache", 16, "0750", True),
)
ROLE_TMPFS = {
    "secrets-init": (("/tmp", 16, "0700", True),),
    "postgres": (("/tmp", 32, "0700", True), ("/run/postgresql", 16, "0750", True)),
    "valkey": (("/tmp", 16, "0700", True), ("/data", 32, "0700", True)),
    "migrate": API_TMPFS,
    "api": API_TMPFS,
    "worker-general": API_TMPFS,
    "worker-hash-chain": API_TMPFS,
    "scheduler": API_TMPFS,
    "frontend": (("/tmp", 32, "0700", True),),
    "gateway": (("/tmp", 16, "0700", True), ("/config", 16, "0700", True), ("/data", 32, "0700", True)),
}
ROLE_IDENTITIES = {
    "secrets-init": (0, 0), "postgres": (999, 999), "valkey": (10002, 10002),
    "migrate": (10001, 10001), "api": (10001, 10001),
    "worker-general": (10001, 10001), "worker-hash-chain": (10001, 10001),
    "scheduler": (10001, 10001), "frontend": (101, 101),
    "gateway": (10003, 10003),
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
            "active_state": "active",
            "sub_state": (
                "exited"
                if logical_name in {"secrets-init", "migrate"}
                or logical_name.endswith(("-network", "-volume"))
                else "running"
            ),
            "result": "success",
            "exec_main_status": 0,
            "main_pid": (
                0
                if logical_name in {"secrets-init", "migrate"}
                or logical_name.endswith(("-network", "-volume"))
                else 1000 + generated_names.index(logical_name)
            ),
            "control_group": (
                ""
                if logical_name in {"secrets-init", "migrate"}
                or logical_name.endswith(("-network", "-volume"))
                else (
                    "/user.slice/user-20000.slice/user@20000.service/app.slice/"
                    f"{prefix}-{logical_name}.service"
                )
            ),
            "invocation_id": f"{generated_names.index(logical_name) + 1:032x}",
        }
        for logical_name in generated_names
    ]
    containers = []
    for role_index, role in enumerate(ROLES, start=1):
        one_shot = role in {"secrets-init", "migrate"}
        mounts = sorted(
            [
                {
                    "type": "volume",
                    "source": f"{prefix}-{kind}",
                    "destination": destination,
                    "rw": writable,
                }
                for kind, destination, writable in ROLE_VOLUME_MOUNTS[role]
            ]
            + [
                {
                    "type": "bind",
                    "source": (
                        f"/home/secpal-ci/quadlet-fixture/{instance}/assets/"
                        f"{asset_name}"
                    ),
                    "destination": destination,
                    "rw": False,
                }
                for asset_name, destination in ROLE_BINDS[role]
            ],
            key=lambda item: item["destination"],
        )
        uid, gid = ROLE_IDENTITIES[role]
        tmpfs = sorted(
            [
                {
                    "destination": destination,
                    "size_bytes": size_mib * 1024 * 1024,
                    "mode": mode,
                    "uid": uid,
                    "gid": gid,
                    "flags": sorted(
                        ["rprivate", "tmpcopyup", "nosuid", "nodev"]
                        + (["noexec"] if noexec else [])
                    ),
                }
                for destination, size_mib, mode, noexec in ROLE_TMPFS[role]
            ],
            key=lambda item: item["destination"],
        )
        lifecycle_statuses = (
            ("create", "start", "died") if one_shot else ("create", "start")
        )
        capabilities = (
            ["CAP_CHOWN", "CAP_FOWNER"] if role == "secrets-init" else []
        )
        containers.append(
            {
                "id": f"{role_index + 1:064x}",
                "role": role,
                "name": f"{prefix}-{role}",
                "state": "exited" if one_shot else "running",
                "pid": 0 if one_shot else 2000 + role_index,
                "exit_code": 0,
                "health": "healthy" if role in HEALTHY_ROLES else "none",
                "oci_runtime": "crun",
                "rootless": True,
                "privileged": False,
                "pid_mode": "private",
                "userns_mode": "private",
                "ipc_mode": "private",
                "uts_mode": "private",
                "network_mode": "private",
                "cap_add": capabilities,
                "effective_caps": capabilities,
                "bounding_caps": capabilities,
                "devices_present": False,
                "mounts": mounts,
                "tmpfs": tmpfs,
                "remote_api_environment": False,
                "security_opt": ["no-new-privileges"],
                "lifecycle_events": [
                    {"status": status, "time_nano": role_index * 10 + index}
                    for index, status in enumerate(lifecycle_statuses, start=1)
                ],
                "networks": [f"{prefix}-{network}" for network in ROLE_NETWORKS[role]],
                "published_ports": ["127.0.0.1:18443:8443/tcp"] if role == "gateway" else [],
                "auto_update": False,
                "systemd_unit": f"{prefix}-{role}.service",
                "container_cgroup": (
                    ""
                    if one_shot
                    else (
                        "/user.slice/user-20000.slice/user@20000.service/"
                        f"app.slice/{prefix}-{role}.service/container"
                    )
                ),
                "lifecycle_service_invocation": (
                    f"{generated_names.index(role) + 1:032x}" if one_shot else ""
                ),
                "image": (
                    f"localhost/secpal-ci-{role}@sha256:{role_index:064x}"
                ),
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
            "migration_invocation_count": 0,
            "podman_api": False,
            "user_work": {
                "active_units": ["dbus.service", "dbus.socket"],
                "jobs": [],
            },
            "containers": [],
            "networks": ["podman", "secpal-ci-unrelated-control-network"],
            "volumes": ["secpal-ci-unrelated-control-volume"],
            "control_resources": {
                "network_present": True,
                "volume_present": True,
                "network_id": "b" * 64,
                "volume_created_at": "2026-08-14T12:00:00Z",
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
            "migration": {
                "observed": True,
                "state": "exited",
                "exit_code": 0,
                "invocation_count": 1,
            },
            "readiness": {"observed": True, "ready_roles": sorted(set(ROLES) - {"secrets-init", "migrate"})},
            "podman_api": False,
            "control_resources": {
                "network_present": True,
                "volume_present": True,
                "network_id": "b" * 64,
                "volume_created_at": "2026-08-14T12:00:00Z",
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
            "migration_invocation_count": 1,
            "podman_api": False,
            "user_work": {
                "active_units": ["dbus.service", "dbus.socket"],
                "jobs": [],
            },
            "control_resources": {
                "network_present": True,
                "volume_present": True,
                "network_id": "b" * 64,
                "volume_created_at": "2026-08-14T12:00:00Z",
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
            self.collector, "checked_output", return_value="a" * 40
        ), mock.patch.object(
            self.collector, "checkout_tree_clean", return_value=False
        ):
            with self.assertRaisesRegex(ValueError, "clean target tree"):
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

    def test_checkout_tree_admission_rejects_tracked_and_untracked_changes(self) -> None:
        clean = ((0, "", True), (0, "", True), (0, "", True))
        dirty_cases = (
            ((1, "", True), (0, "", True), (0, "", True)),
            ((0, "", True), (1, "", True), (0, "", True)),
            ((0, "", True), (0, "", True), (0, "generated.py", True)),
            ((0, "", True), (0, "", True), (0, "", False)),
        )
        with mock.patch.object(self.collector, "command_result", side_effect=clean):
            self.assertTrue(
                self.collector.checkout_tree_clean(Path("/checkout"), "a" * 40)
            )
        for results in dirty_cases:
            with self.subTest(results=results), mock.patch.object(
                self.collector, "command_result", side_effect=results
            ):
                self.assertFalse(
                    self.collector.checkout_tree_clean(Path("/checkout"), "a" * 40)
                )

    def test_collector_git_ignores_target_global_config_and_replace_refs(self) -> None:
        environment = self.collector.command_environment()
        self.assertEqual("/dev/null", environment["GIT_CONFIG_GLOBAL"])
        self.assertEqual("1", environment["GIT_CONFIG_NOSYSTEM"])
        self.assertEqual("1", environment["GIT_NO_REPLACE_OBJECTS"])

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

    def test_resource_name_evidence_is_truncated_fail_closed_at_schema_bound(self) -> None:
        rows = [{"Name": f"resource-{index:03d}"} for index in range(129)]
        with mock.patch.object(
            self.collector, "json_array", return_value=(rows, True)
        ):
            names, complete = self.collector.names_from_listing(
                ["podman", "network", "ls"]
            )
        self.assertEqual(128, len(names))
        self.assertFalse(complete)

    def test_control_resource_identity_uses_bounded_podman_inspection(self) -> None:
        network_id = "b" * 64
        created_at = "2026-08-14T12:00:00Z"
        with mock.patch.object(
            self.collector,
            "json_array",
            side_effect=[
                ([{"name": "secpal-ci-unrelated-control-network", "id": network_id}], True),
                ([{"Name": "secpal-ci-unrelated-control-volume", "CreatedAt": created_at}], True),
            ],
        ):
            facts, complete = self.collector.control_resource_facts()
        self.assertTrue(complete)
        self.assertEqual(network_id, facts["network_id"])
        self.assertEqual(created_at, facts["volume_created_at"])

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

    def test_baseline_rejects_a_migration_run_by_the_host_phase(self) -> None:
        self.assert_failure(
            lambda evidence: evidence["baseline"].__setitem__(
                "migration_invocation_count", 1
            ),
            "D1A_BASELINE_MIGRATION",
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

    def test_generated_drop_in_owner_and_mode_are_admitted_independently(self) -> None:
        def add_untrusted_drop_in(evidence) -> None:
            service = evidence["live"]["generated_services"][0]
            service["drop_in_paths"] = [
                "/run/user/20000/systemd/generator/secpal-int-aaaaaaaaaaaa-api.service.d/10.conf"
            ]
            service["drop_in_owners"] = [
                {"uid": 0, "gid": 0, "mode": "0600"}
            ]

        self.assert_failure(add_untrusted_drop_in, "D1A_GENERATED_UNITS")

    def test_effective_service_state_is_required_for_every_generated_unit(self) -> None:
        for field, value in (
            ("active_state", "inactive"),
            ("exec_main_status", False),
            ("main_pid", True),
        ):
            with self.subTest(field=field):
                self.assert_failure(
                    lambda evidence, field=field, value=value: evidence["live"][
                        "generated_services"
                    ][4].__setitem__(field, value),
                    "D1A_SERVICE_STATE",
                )

    def test_each_container_is_bound_to_its_generated_systemd_service(self) -> None:
        self.assert_failure(
            lambda evidence: evidence["live"]["containers"][4].__setitem__(
                "container_cgroup", "/user.slice/unrelated.service/container"
            ),
            "D1A_SERVICE_BINDING",
        )
        self.assert_failure(
            lambda evidence: evidence["live"]["containers"][3].__setitem__(
                "lifecycle_service_invocation", "f" * 32
            ),
            "D1A_SERVICE_BINDING",
        )
        self.assert_failure(
            lambda evidence: evidence["live"]["containers"][4].__setitem__(
                "systemd_unit", "unrelated.service"
            ),
            "D1A_SERVICE_BINDING",
        )
        self.assert_failure(
            lambda evidence: evidence["live"]["containers"][4].__setitem__(
                "pid", True
            ),
            "D1A_SERVICE_BINDING",
        )

    def test_running_container_binding_uses_the_effective_service_cgroup(self) -> None:
        unit = "secpal-int-aaaaaaaaaaaa-api.service"
        control_group = (
            "/user.slice/user-20000.slice/user@20000.service/app.slice/" + unit
        )
        services = [
            {
                "logical_name": "api",
                "unit": unit,
                "active_state": "active",
                "sub_state": "running",
                "result": "success",
                "exec_main_status": 0,
                "main_pid": 123,
                "control_group": control_group,
                "invocation_id": "a" * 32,
            }
        ]
        containers = [
            {
                "id": "b" * 64,
                "role": "api",
                "name": "secpal-int-aaaaaaaaaaaa-api",
                "state": "running",
                "pid": 456,
                "systemd_unit": unit,
            }
        ]
        with mock.patch.object(
            self.collector,
            "process_control_group",
            return_value=(f"{control_group}/container", True),
        ):
            bound, complete = self.collector.bind_container_services(
                services, containers
        )
        self.assertTrue(complete)
        self.assertEqual(
            f"{control_group}/container", bound[0]["container_cgroup"]
        )
        self.assertEqual("", bound[0]["lifecycle_service_invocation"])

    def test_exited_container_binding_requires_lifecycle_execution_identity(self) -> None:
        unit = "secpal-int-aaaaaaaaaaaa-migrate.service"
        services = [
            {
                "logical_name": "migrate",
                "unit": unit,
                "active_state": "active",
                "sub_state": "exited",
                "result": "success",
                "exec_main_status": 0,
                "main_pid": 0,
                "control_group": "",
                "invocation_id": "a" * 32,
            }
        ]
        containers = [
            {
                "id": "b" * 64,
                "role": "migrate",
                "name": "secpal-int-aaaaaaaaaaaa-migrate",
                "state": "exited",
                "pid": 0,
                "systemd_unit": unit,
            }
        ]
        with mock.patch.object(
            self.collector,
            "exited_container_execution_matches",
            create=True,
            return_value=(False, True),
        ) as correlate:
            bound, complete = self.collector.bind_container_services(
                services, containers
            )
        correlate.assert_called_once()
        correlated_service, correlated_container = correlate.call_args.args
        self.assertEqual(unit, correlated_service["unit"])
        self.assertEqual("b" * 64, correlated_container["id"])
        self.assertTrue(complete)
        self.assertEqual("", bound[0]["container_cgroup"])
        self.assertEqual("", bound[0]["lifecycle_service_invocation"])

    def test_exited_container_execution_identity_is_exact_and_unique(self) -> None:
        service = {
            "unit": "secpal-int-aaaaaaaaaaaa-migrate.service",
            "invocation_id": "a" * 32,
        }
        container = {
            "id": "b" * 64,
            "name": "secpal-int-aaaaaaaaaaaa-migrate",
            "lifecycle_events": [
                {"status": "create", "time_nano": 1},
                {"status": "start", "time_nano": 2},
                {"status": "died", "time_nano": 3},
            ],
        }
        matching_record = json.dumps(
            {
                "_SYSTEMD_INVOCATION_ID": "a" * 32,
                "_EXE": "/usr/bin/podman",
                "_CMDLINE": (
                    "/usr/bin/podman run --name "
                    "secpal-int-aaaaaaaaaaaa-migrate fixture-image"
                ),
                "MESSAGE": "b" * 64,
            }
        )
        with mock.patch.object(
            self.collector,
            "command_result",
            return_value=(0, matching_record, True),
        ):
            self.assertEqual(
                (True, True),
                self.collector.exited_container_execution_matches(
                    service, container
                ),
            )
        for output in (
            "",
            f"{matching_record}\n{matching_record}",
            matching_record.replace("/usr/bin/podman", "/usr/bin/false"),
        ):
            with self.subTest(output=output), mock.patch.object(
                self.collector,
                "command_result",
                return_value=(0, output, True),
            ):
                self.assertEqual(
                    (False, True),
                    self.collector.exited_container_execution_matches(
                        service, container
                    ),
                )

    def test_podman_inspect_output_cannot_prove_a_service_launch(self) -> None:
        service = {
            "unit": "secpal-int-aaaaaaaaaaaa-migrate.service",
            "invocation_id": "a" * 32,
        }
        container = {
            "id": "b" * 64,
            "name": "secpal-int-aaaaaaaaaaaa-migrate",
            "lifecycle_events": [
                {"status": "create", "time_nano": 1},
                {"status": "start", "time_nano": 2},
                {"status": "died", "time_nano": 3},
            ],
        }
        inspect_record = json.dumps(
            {
                "_SYSTEMD_INVOCATION_ID": "a" * 32,
                "_EXE": "/usr/bin/podman",
                "_CMDLINE": (
                    "/usr/bin/podman inspect --format {{.Id}} " + "b" * 64
                ),
                "MESSAGE": "b" * 64,
            }
        )
        with mock.patch.object(
            self.collector,
            "command_result",
            return_value=(0, inspect_record, True),
        ):
            self.assertEqual(
                (False, True),
                self.collector.exited_container_execution_matches(
                    service, container
                ),
            )

    def test_command_output_limit_terminates_a_noisy_child_early(self) -> None:
        program = (
            "import sys,time;"
            f"sys.stdout.write('x'*{self.collector.MAX_OUTPUT + 1});"
            "sys.stdout.flush();time.sleep(10)"
        )
        started = time.monotonic()
        status, output, complete = self.collector.command_result(
            ["/usr/bin/python3", "-c", program], timeout=2
        )
        elapsed = time.monotonic() - started
        self.assertEqual(255, status)
        self.assertEqual("", output)
        self.assertFalse(complete)
        self.assertLess(elapsed, 1.5)

    def test_cleanup_scans_generated_drop_in_directories_and_files(self) -> None:
        prefix = "secpal-int-aaaaaaaaaaaa-api.service"
        with tempfile.TemporaryDirectory() as temporary_directory:
            generator_base = Path(temporary_directory)
            generator = generator_base / "generator"
            generator.mkdir()
            drop_in = generator / f"{prefix}.d"
            drop_in.mkdir()
            (drop_in / "10-dependency.conf").write_text(
                "[Unit]\n", encoding="utf-8"
            )
            with mock.patch.object(self.collector, "GENERATOR_BASE", generator_base), \
                mock.patch.object(self.collector, "GENERATOR_ROOTS", (generator,)):
                artifacts, complete = self.collector.generated_cleanup_artifacts(
                    "aaaaaaaaaaaa"
                )
        self.assertTrue(complete)
        self.assertEqual(
            [
                f"generator/{prefix}.d",
                f"generator/{prefix}.d/10-dependency.conf",
            ],
            artifacts,
        )

    def test_cleanup_scans_all_three_user_generator_output_directories(self) -> None:
        prefix = "secpal-int-aaaaaaaaaaaa-api.service"
        with tempfile.TemporaryDirectory() as temporary_directory:
            generator_base = Path(temporary_directory)
            roots = tuple(
                generator_base / name
                for name in ("generator.early", "generator", "generator.late")
            )
            for root in roots:
                root.mkdir()
            (roots[0] / prefix).touch()
            drop_in = roots[2] / f"{prefix}.d"
            drop_in.mkdir()
            (drop_in / "10-late.conf").touch()
            with mock.patch.object(
                self.collector, "GENERATOR_BASE", generator_base, create=True
            ), mock.patch.object(
                self.collector, "GENERATOR_ROOTS", roots, create=True
            ):
                artifacts, complete = self.collector.generated_cleanup_artifacts(
                    "aaaaaaaaaaaa"
                )
        self.assertTrue(complete)
        self.assertEqual(
            [
                f"generator.early/{prefix}",
                f"generator.late/{prefix}.d",
                f"generator.late/{prefix}.d/10-late.conf",
            ],
            artifacts,
        )

    def test_cleanup_generator_scan_is_bounded_even_by_unrelated_entries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            generator_base = Path(temporary_directory)
            generator = generator_base / "generator"
            generator.mkdir()
            for index in range(1025):
                (generator / f"unrelated-{index:04d}").touch()
            with mock.patch.object(self.collector, "GENERATOR_BASE", generator_base), \
                mock.patch.object(self.collector, "GENERATOR_ROOTS", (generator,)):
                artifacts, complete = self.collector.generated_cleanup_artifacts(
                    "aaaaaaaaaaaa"
                )
        self.assertEqual([], artifacts)
        self.assertFalse(complete)

    def test_cleanup_generator_evidence_cannot_exceed_schema_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            generator_base = Path(temporary_directory)
            generator = generator_base / "generator"
            generator.mkdir()
            for index in range(129):
                (generator / f"secpal-int-aaaaaaaaaaaa-{index:03d}.service").touch()
            with mock.patch.object(self.collector, "GENERATOR_BASE", generator_base), \
                mock.patch.object(self.collector, "GENERATOR_ROOTS", (generator,)):
                artifacts, complete = self.collector.generated_cleanup_artifacts(
                    "aaaaaaaaaaaa"
                )
        self.assertEqual(128, len(artifacts))
        self.assertFalse(complete)

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
            ("ipc_mode", "host", "D1A_HOST_NAMESPACES"),
            ("uts_mode", "host", "D1A_HOST_NAMESPACES"),
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
            lambda evidence: evidence["live"]["containers"][0].__setitem__(
                "effective_caps", ["CAP_CHOWN", "CAP_FOWNER", "CAP_SYS_ADMIN"]
            ),
            "D1A_PRIVILEGE_BOUNDARY",
        )
        self.assert_failure(
            lambda evidence: evidence["live"]["containers"][4].__setitem__(
                "image", "docker.io/secpal/api:latest"
            ),
            "D1A_IMAGE_PROVENANCE",
        )

    def test_api_and_frontend_require_distinct_image_identities(self) -> None:
        self.assert_failure(
            lambda evidence: evidence["live"]["containers"][8].__setitem__(
                "image",
                "localhost/secpal-ci-frontend@sha256:"
                + evidence["live"]["containers"][4]["image"].rsplit(":", 1)[1],
            ),
            "D1A_IMAGE_ROLE_SEPARATION",
        )

    def test_secrets_initializer_requires_exact_bounded_capabilities(self) -> None:
        observations = valid_observations()
        self.assertNotIn(
            "D1A_PRIVILEGE_BOUNDARY",
            self.collector.workload_admission_failures(observations),
        )
        for field in ("cap_add", "effective_caps", "bounding_caps"):
            with self.subTest(field=field):
                self.assert_failure(
                    lambda evidence, field=field: evidence["live"]["containers"][
                        0
                    ].__setitem__(field, ["CAP_CHOWN"]),
                    "D1A_PRIVILEGE_BOUNDARY",
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
            "Id": "c" * 64,
            "Name": "secpal-int-aaaaaaaaaaaa-api",
            "State": {
                "Status": "running",
                "Pid": 2345,
                "ExitCode": 0,
                "Healthcheck": {"Status": "healthy"},
            },
            "Config": {
                "Labels": {
                    "PODMAN_SYSTEMD_UNIT": "secpal-int-aaaaaaaaaaaa-api.service"
                },
                "Env": [],
                "Image": f"localhost/secpal-ci-api@sha256:{'a' * 64}",
            },
            "HostConfig": {
                "Privileged": False,
                "PidMode": "private",
                "UsernsMode": "private",
                "IpcMode": "private",
                "UTSMode": "private",
                "NetworkMode": "private",
                "SecurityOpt": ["no-new-privileges"],
                "CapAdd": [],
                "Devices": [],
                "Tmpfs": {},
            },
            "NetworkSettings": {
                "Networks": {"secpal-int-aaaaaaaaaaaa-application": {}},
                "Ports": {},
            },
            "Mounts": [],
            "OCIRuntime": "crun",
            "EffectiveCaps": [],
            "BoundingCaps": [],
            "ImageName": f"localhost/secpal-ci-api@sha256:{'a' * 64}",
        }
        required_fields = (
            (inspection, "Id"),
            (inspection, "OCIRuntime"),
            (inspection, "Mounts"),
            (inspection, "EffectiveCaps"),
            (inspection, "BoundingCaps"),
            (inspection["State"], "Pid"),
            (inspection["Config"], "Env"),
            (inspection["HostConfig"], "CapAdd"),
            (inspection["HostConfig"], "Devices"),
            (inspection["HostConfig"], "Tmpfs"),
            (inspection["NetworkSettings"], "Ports"),
        )
        for owner, field in required_fields:
            with self.subTest(field=field):
                candidate = copy.deepcopy(inspection)
                if owner is inspection:
                    del candidate[field]
                elif owner is inspection["State"]:
                    del candidate["State"][field]
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
                ), mock.patch.object(
                    self.collector,
                    "container_lifecycle_events",
                    return_value=([{"status": "create", "time_nano": 1}, {"status": "start", "time_nano": 2}], True),
                ):
                    _, complete = self.collector.container_facts(
                        "aaaaaaaaaaaa", rootless=True
                    )
                self.assertFalse(complete)

    def test_podman_healthcheck_and_global_rootless_fact_are_used(self) -> None:
        inspection = {
            "Id": "c" * 64,
            "Name": "secpal-int-aaaaaaaaaaaa-api",
            "State": {
                "Status": "running",
                "Pid": 2345,
                "ExitCode": 0,
                "Healthcheck": {"Status": "healthy"},
            },
            "Config": {
                "Labels": {
                    "PODMAN_SYSTEMD_UNIT": "secpal-int-aaaaaaaaaaaa-api.service"
                },
                "Env": [],
                "Image": f"localhost/secpal-ci-api@sha256:{'a' * 64}",
            },
            "HostConfig": {
                "Privileged": False,
                "PidMode": "private",
                "UsernsMode": "private",
                "IpcMode": "private",
                "UTSMode": "private",
                "NetworkMode": "private",
                "SecurityOpt": ["no-new-privileges"],
                "CapAdd": [],
                "Devices": [],
                "Tmpfs": {},
            },
            "NetworkSettings": {
                "Networks": {"secpal-int-aaaaaaaaaaaa-application": {}},
                "Ports": {},
            },
            "Mounts": [],
            "OCIRuntime": "crun",
            "EffectiveCaps": [],
            "BoundingCaps": [],
            "ImageName": f"localhost/secpal-ci-api@sha256:{'a' * 64}",
        }
        with mock.patch.object(
            self.collector,
            "names_from_listing",
            return_value=(["secpal-int-aaaaaaaaaaaa-api"], True),
        ), mock.patch.object(
            self.collector, "json_array", return_value=([inspection], True)
        ), mock.patch.object(
            self.collector,
            "container_lifecycle_events",
            return_value=([{"status": "create", "time_nano": 1}, {"status": "start", "time_nano": 2}], True),
        ):
            facts, complete = self.collector.container_facts(
                "aaaaaaaaaaaa", rootless=True
            )
        self.assertTrue(complete)
        self.assertEqual("healthy", facts[0]["health"])

        inspection["HostConfig"]["UsernsMode"] = ""
        with mock.patch.object(
            self.collector,
            "names_from_listing",
            return_value=(["secpal-int-aaaaaaaaaaaa-api"], True),
        ), mock.patch.object(
            self.collector, "json_array", return_value=([inspection], True)
        ), mock.patch.object(
            self.collector,
            "container_lifecycle_events",
            return_value=([{"status": "create", "time_nano": 1}, {"status": "start", "time_nano": 2}], True),
        ):
            facts, complete = self.collector.container_facts(
                "aaaaaaaaaaaa", rootless=True
            )
        self.assertTrue(complete)
        self.assertEqual("host", facts[0]["userns_mode"])
        self.assertTrue(facts[0]["rootless"])

    def test_no_new_privileges_requires_the_exact_security_option(self) -> None:
        self.assert_failure(
            lambda evidence: evidence["live"]["containers"][4].__setitem__(
                "security_opt",
                ["seccomp=/home/secpal-ci/no-new-privileges.json"],
            ),
            "D1A_SECURITY_OPTIONS",
        )

    def test_no_new_privileges_does_not_admit_a_custom_seccomp_profile(self) -> None:
        self.assert_failure(
            lambda evidence: evidence["live"]["containers"][4].__setitem__(
                "security_opt",
                ["no-new-privileges", "seccomp=/tmp/allow-all.json"],
            ),
            "D1A_SECURITY_OPTIONS",
        )

    def test_control_volume_cannot_be_consumed_by_a_fixture_container(self) -> None:
        self.assert_failure(
            lambda evidence: evidence["live"]["containers"][4].__setitem__(
                "mounts",
                [
                    {
                        "type": "volume",
                        "source": "secpal-ci-unrelated-control-volume",
                        "destination": "/data",
                        "rw": True,
                    }
                ],
            ),
            "D1A_VOLUME_TOPOLOGY",
        )

    def test_role_mount_topology_is_closed(self) -> None:
        mutations = {
            "missing": lambda mounts: mounts.pop(),
            "unexpected": lambda mounts: mounts.append(
                {
                    **copy.deepcopy(mounts[0]),
                    "source": "secpal-int-aaaaaaaaaaaa-unexpected",
                    "destination": "/unexpected",
                }
            ),
            "wrong-access": lambda mounts: mounts[0].__setitem__(
                "rw", not mounts[0]["rw"]
            ),
            "wrong-type": lambda mounts: mounts[0].__setitem__("type", "bind"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                observations = valid_observations()
                mounts = observations["live"]["containers"][4]["mounts"]
                mutate(mounts)
                self.assertIn(
                    "D1A_VOLUME_TOPOLOGY",
                    self.collector.workload_admission_failures(observations),
                )

        observations = valid_observations()
        api_bind = next(
            mount
            for mount in observations["live"]["containers"][4]["mounts"]
            if mount["type"] == "bind"
        )
        api_bind["source"] = "/tmp/target-selected-entrypoint.sh"
        self.assertIn(
            "D1A_VOLUME_TOPOLOGY",
            self.collector.workload_admission_failures(observations),
        )

    def test_role_tmpfs_topology_is_closed(self) -> None:
        mutations = {
            "missing": lambda tmpfs: tmpfs.pop(),
            "wrong-size": lambda tmpfs: tmpfs[0].__setitem__("size_bytes", 1),
            "wrong-identity": lambda tmpfs: tmpfs[0].__setitem__("uid", 0),
            "privilege-option": lambda tmpfs: tmpfs[0]["flags"].remove("nosuid"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                observations = valid_observations()
                tmpfs = observations["live"]["containers"][4]["tmpfs"]
                mutate(tmpfs)
                self.assertIn(
                    "D1A_TMPFS_TOPOLOGY",
                    self.collector.workload_admission_failures(observations),
                )

        observations = valid_observations()
        observations["live"]["containers"][4]["tmpfs"][0]["flags"].append("rw")
        observations["live"]["containers"][4]["tmpfs"][0]["flags"].sort()
        self.assertNotIn(
            "D1A_TMPFS_TOPOLOGY",
            self.collector.workload_admission_failures(observations),
        )

    def test_tmpfs_options_are_typed_and_reject_unknown_flags(self) -> None:
        options = {
            "/tmp": (
                "rw,rprivate,tmpcopyup,nosuid,nodev,noexec,"
                "size=32m,mode=0700,uid=10001,gid=10001"
            )
        }
        facts, complete = self.collector.normalized_tmpfs(options)
        self.assertTrue(complete)
        self.assertEqual(32 * 1024 * 1024, facts[0]["size_bytes"])
        self.assertEqual("0700", facts[0]["mode"])
        self.assertEqual(10001, facts[0]["uid"])
        self.assertIn("rw", facts[0]["flags"])

        invalid = dict(options)
        invalid["/tmp"] += ",suid"
        self.assertEqual(([], False), self.collector.normalized_tmpfs(invalid))

    def test_container_lifecycle_is_exact_and_ordered(self) -> None:
        mutations = {
            "missing-start": lambda events: events.pop(1),
            "duplicate-start": lambda events: events.insert(
                1, copy.deepcopy(events[1])
            ),
            "wrong-order": lambda events: events.reverse(),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                observations = valid_observations()
                events = observations["live"]["containers"][3][
                    "lifecycle_events"
                ]
                mutate(events)
                self.assertIn(
                    "D1A_CONTAINER_LIFECYCLE",
                    self.collector.workload_admission_failures(observations),
                )

    def test_lifecycle_event_collection_is_bounded_and_exact(self) -> None:
        container_id = "b" * 64
        valid = "\n".join(
            json.dumps(
                {
                    "Type": "container",
                    "status": status,
                    "id": container_id,
                    "timeNano": index,
                }
            )
            for index, status in enumerate(
                ("create", "init", "start", "died"), start=1
            )
        )
        with mock.patch.object(
            self.collector, "command_result", return_value=(0, valid, True)
        ) as command:
            events, complete = self.collector.container_lifecycle_events(
                container_id
            )
        self.assertTrue(complete)
        self.assertIn("--since=4h", command.call_args.args[0])
        self.assertEqual(["create", "start", "died"], [e["status"] for e in events])

        duplicate = valid + "\n" + json.dumps(
            {
                "Type": "container",
                "status": "start",
                "id": container_id,
                "timeNano": 5,
            }
        )
        with mock.patch.object(
            self.collector, "command_result", return_value=(0, duplicate, True)
        ):
            events, _ = self.collector.container_lifecycle_events(container_id)
        self.assertEqual(
            ["create", "start", "died", "start"],
            [event["status"] for event in events],
        )

    def test_remote_or_socket_api_evidence_is_rejected(self) -> None:
        observations = valid_observations()
        observations["live"]["podman_api"] = True
        self.assertIn(
            "D1A_PODMAN_API_DISABLED",
            self.collector.workload_admission_failures(observations),
        )
        self.assert_failure(
            lambda evidence: evidence["live"]["containers"][4]["mounts"].append(
                {
                    "type": "bind",
                    "source": "/run/user/20000/podman/podman.sock",
                    "destination": "/run/podman/podman.sock",
                    "rw": True,
                }
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
            self.collector,
            "user_socket_activation_facts",
            return_value=(False, True),
        ), mock.patch.object(
            self.collector.Path, "iterdir", return_value=(Path("/proc/123"),)
        ), mock.patch.object(
            self.collector.Path, "open", side_effect=OSError("hidden process")
        ):
            self.assertEqual((True, False), self.collector.podman_api_facts())

    def test_podman_api_scan_uses_executable_identity_not_argv_zero(self) -> None:
        process = Path("/proc/123")
        metadata = types.SimpleNamespace(st_dev=1, st_ino=2)
        with mock.patch.object(
            self.collector,
            "command_result",
            side_effect=lambda arguments, timeout=20: (
                (0, "", True) if arguments[:2] == ["ss", "-lxnp"] else (3, "", True)
            ),
        ), mock.patch.object(
            self.collector, "json_array", return_value=([], True)
        ), mock.patch.object(
            self.collector,
            "user_socket_activation_facts",
            return_value=(False, True),
        ), mock.patch.object(
            self.collector.Path, "iterdir", return_value=(process,)
        ), mock.patch.object(
            self.collector.Path,
            "open",
            return_value=io.BytesIO(b"renamed-client\0system\0service\0--time=0\0"),
        ), mock.patch.object(
            self.collector.Path, "stat", return_value=metadata
        ):
            self.assertEqual((True, True), self.collector.podman_api_facts())

    def test_podman_api_rejects_arbitrary_active_user_socket_units(self) -> None:
        listing = "\n".join(
            (
                "dbus.socket loaded active listening D-Bus User Message Bus Socket",
                "hidden.socket loaded active listening Hidden activation socket",
            )
        )
        with mock.patch.object(
            self.collector, "command_result", return_value=(0, listing, True)
        ):
            unsafe, complete = self.collector.user_socket_activation_facts()
        self.assertTrue(complete)
        self.assertTrue(unsafe)

    def test_migration_and_readiness_must_be_independently_observed(self) -> None:
        self.assert_failure(
            lambda evidence: evidence["live"]["migration"].__setitem__("observed", False),
            "D1A_MIGRATION",
        )
        self.assert_failure(
            lambda evidence: evidence["live"]["migration"].__setitem__(
                "state", "running"
            ),
            "D1A_MIGRATION",
        )
        self.assert_failure(
            lambda evidence: evidence["live"]["migration"].__setitem__(
                "invocation_count", 2
            ),
            "D1A_MIGRATION",
        )
        self.assert_failure(
            lambda evidence: evidence["live"]["readiness"].__setitem__("observed", False),
            "D1A_READINESS",
        )

    def test_post_cleanup_rechecks_migration_count_and_podman_api(self) -> None:
        self.assert_failure(
            lambda evidence: evidence["post_cleanup"].__setitem__(
                "migration_invocation_count", 2
            ),
            "D1A_CLEANUP_MIGRATION",
        )
        self.assert_failure(
            lambda evidence: evidence["post_cleanup"].__setitem__(
                "podman_api", True
            ),
            "D1A_PODMAN_API_DISABLED",
        )

    def test_post_cleanup_rejects_target_scheduled_user_work(self) -> None:
        observations = valid_observations()
        observations["baseline"]["user_work"] = {
            "active_units": ["dbus.service", "dbus.socket"],
            "jobs": [],
        }
        observations["post_cleanup"]["user_work"] = {
            "active_units": [
                "dbus.service",
                "dbus.socket",
                "delayed-migration.timer",
            ],
            "jobs": [],
        }
        self.assertIn(
            "D1A_PENDING_USER_WORK",
            self.collector.workload_admission_failures(observations),
        )

    def test_cleanup_collector_uses_the_shared_lifecycle_guard(self) -> None:
        controls = {
            "network_present": True,
            "volume_present": True,
            "network_id": "b" * 64,
            "volume_created_at": "2026-08-14T12:00:00Z",
        }
        with mock.patch.object(
            self.collector.Path, "iterdir", return_value=iter(())
        ), mock.patch.object(
            self.collector,
            "generated_cleanup_artifacts",
            return_value=([], True),
        ), mock.patch.object(
            self.collector,
            "resource_inventory",
            return_value=({"containers": [], "networks": [], "volumes": []}, True),
        ), mock.patch.object(
            self.collector,
            "control_resource_facts",
            return_value=(controls, True),
        ), mock.patch.object(
            self.collector,
            "lifecycle_guard_facts",
            return_value=(
                {"migration_invocation_count": 1, "podman_api": False},
                True,
            ),
        ) as guard:
            observation = self.collector.collect_post_cleanup("aaaaaaaaaaaa")
        guard.assert_called_once_with("aaaaaaaaaaaa")
        self.assertEqual(1, observation["migration_invocation_count"])
        self.assertFalse(observation["podman_api"])

    def test_migration_invocations_are_counted_from_systemd_journal_ids(self) -> None:
        first = "a" * 32
        second = "b" * 32
        journal = "\n".join(
            json.dumps({"_SYSTEMD_INVOCATION_ID": value})
            for value in (first, first, second)
        )
        arguments = []

        def collect(command, timeout=20):
            arguments.extend(command)
            return 0, journal, True

        with mock.patch.object(self.collector, "command_result", side_effect=collect):
            self.assertEqual(
                (2, True),
                self.collector.migration_invocation_facts("aaaaaaaaaaaa"),
            )
        self.assertIn("--output-fields=_SYSTEMD_INVOCATION_ID", arguments)
        self.assertNotIn("--all", arguments)
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
        self.assert_failure(
            lambda evidence: evidence["post_cleanup"]["control_resources"].__setitem__(
                "network_id", "c" * 64
            ),
            "D1A_CONTROL_RESOURCES_PRESERVED",
        )

    def test_cleanup_generator_scan_failure_marks_observation_incomplete(self) -> None:
        with mock.patch.object(
            self.collector.Path, "iterdir", return_value=iter(())
        ), mock.patch.object(
            self.collector,
            "generated_cleanup_artifacts",
            return_value=([], False),
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
            return_value=(
                {
                    "network_present": True,
                    "volume_present": True,
                    "network_id": "b" * 64,
                    "volume_created_at": "2026-08-14T12:00:00Z",
                },
                True,
            ),
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
        self.assertIn("collect_workload_phase()", runner)
        self.assertEqual(
            1,
            runner.count("< scripts/ci-cloud/collect-workload-evidence.py"),
        )
        self.assertLess(
            runner.index('bootstrap_stage="collector-baseline"'),
            runner.index('bootstrap_stage="target-workload-prepare-start"'),
        )
        self.assertLess(
            runner.index('bootstrap_stage="target-host"'),
            runner.index('bootstrap_stage="collector-post-cleanup"'),
        )
        self.assertIn("workload_evidence_finalized=true", runner)
        self.assertIn(
            "collect_workload_live() { collect_workload_phase live; }",
            runner,
        )
        self.assertIn(
            "collect_workload_post_cleanup() { "
            "collect_workload_phase post-cleanup; }",
            runner,
        )
        self.assertIn("trap collect_cleanup_after_interruption INT TERM HUP", runner)
        self.assertIn("run_target_phase()", runner)
        self.assertEqual(1, runner.count("ulimit -f 32768"))
        self.assertEqual(
            1,
            runner.count("cd /home/secpal-ci/deployment-target"),
        )
        self.assertEqual(
            1,
            runner.count('diff-index --quiet --no-ext-diff "$1" --'),
        )
        self.assertEqual(1, runner.count('read-tree --reset "$1"'))
        self.assertEqual(1, runner.count("ls-files --others"))
        host_collection = runner.split("collect_host_and_assemble()", 1)[1]
        host_collection = host_collection.split(
            "collect_cleanup_after_interruption()", 1
        )[0]
        self.assertIn(
            "timeout --signal=TERM --kill-after=30s 12m \\\n    ssh",
            host_collection,
        )
        self.assertNotIn("write_incomplete_", runner)

    def test_control_resource_ssh_operations_have_outer_deadlines(self) -> None:
        runner = RUNNER_PATH.read_text(encoding="utf-8")
        self.assertIn("run_control_resource()", runner)
        helper = runner.split("run_control_resource()", 1)[1].split(
            "run_target_phase()", 1
        )[0]
        self.assertEqual(
            1,
            helper.count("timeout --signal=TERM --kill-after=15s 3m"),
        )
        for operation in (
            "create-network",
            "create-volume",
            "remove-network",
            "remove-volume",
        ):
            self.assertIn(
                f"{operation})",
                helper,
                operation,
            )

    def test_namespace_sharing_network_modes_are_rejected_by_prefix(self) -> None:
        for network_mode in ("container:deadbeef", "ns:/proc/1/ns/net"):
            with self.subTest(network_mode=network_mode):
                self.assert_failure(
                    lambda evidence, mode=network_mode: evidence["live"][
                        "containers"
                    ][0].__setitem__("network_mode", mode),
                    "D1A_HOST_NETWORK",
                )

    def test_malformed_observation_becomes_closed_incomplete_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "live.json"
            path.write_text('{"phase":', encoding="utf-8")
            observation = self.assembler.read_observation(
                path, "live", collection_status=255
            )
        self.assertEqual("live", observation["phase"])
        self.assertFalse(observation["target_admitted"])
        self.assertFalse(observation["complete"])
        self.assertEqual(
            {
                "observed": False,
                "state": "unknown",
                "exit_code": -1,
                "invocation_count": 0,
            },
            observation["migration"],
        )

    def test_target_entrypoint_has_closed_versioned_phase_parser(self) -> None:
        target = TARGET_PATH.read_text(encoding="utf-8")
        self.assertIn('[[ "$#" -eq 2 && "$1" == v1 ]]', target)
        self.assertIn("host | workload-prepare-start | workload-cleanup", target)
        self.assertNotIn("eval", target)
        self.assertNotIn("source ", target)


if __name__ == "__main__":
    unittest.main()
