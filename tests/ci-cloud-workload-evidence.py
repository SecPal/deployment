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
import re
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
PODMAN_54_USERNS_FIXTURE = (
    ROOT / "tests" / "fixtures" / "podman-5.4.2-rootless-userns.json"
)

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
API_ENTRYPOINT = ("/bin/bash", "/run/secpal/container-entrypoint.sh")
ROLE_EXECUTION = {
    "secrets-init": (
        ("/bin/bash", "/run/secpal/init-local-secrets.sh"), (), ()
    ),
    "migrate": (API_ENTRYPOINT, ("php", "artisan", "migrate", "--force"), ()),
    "api": (
        API_ENTRYPOINT,
        ("frankenphp", "run", "--config", "/etc/frankenphp/Caddyfile"),
        ("CMD", "/usr/local/bin/secpal-http-live"),
    ),
    "worker-general": (
        API_ENTRYPOINT,
        (
            "php", "artisan", "queue:work",
            "--queue=merkle,opentimestamp,default", "--sleep=1", "--tries=3",
            "--timeout=90",
        ),
        (),
    ),
    "worker-hash-chain": (
        API_ENTRYPOINT,
        (
            "php", "artisan", "queue:work", "--queue=activity-hash-chain",
            "--sleep=1", "--tries=3", "--timeout=90",
        ),
        (),
    ),
    "scheduler": (
        API_ENTRYPOINT, ("php", "artisan", "schedule:work"), ()
    ),
}


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
            "fragment_sha256": f"{generated_names.index(logical_name) + 101:064x}",
            "source_path": str(
                (
                    Path("/etc/containers/systemd/users/20000")
                    / (
                        f"{prefix}-{logical_name}.container"
                        if logical_name in ROLES
                        else f"{prefix}-{logical_name.removesuffix('-network')}.network"
                        if logical_name.endswith("-network")
                        else f"{prefix}-{logical_name.removesuffix('-volume')}.volume"
                    )
                )
            ),
            "drop_in_paths": [],
            "drop_in_owners": [],
            "drop_in_sha256": [],
            "environment": sorted(
                {
                    "CONTAINERS_CONF",
                    "CONTAINERS_CONF_OVERRIDE",
                    "CONTAINERS_CONF_MODULES",
                    "PODMAN_USERNS",
                }
            ),
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
        entrypoint, command, healthcheck = ROLE_EXECUTION.get(
            role, ((), (), ())
        )
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
        collector_map = [
            {"container_id": 0, "host_id": 0, "size": 4_294_967_295}
        ]
        process_map = [
            {"container_id": 0, "host_id": 20_000, "size": 1},
            {"container_id": 1, "host_id": 200_000, "size": 65_536},
        ]
        configured_map = [
            {"container_id": 0, "host_id": 0, "size": 65_537}
        ]
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
                "configured_user": f"{uid}:{gid}",
                "effective_uid": uid if not one_shot else -1,
                "effective_gid": gid if not one_shot else -1,
                "effective_supplementary_gids": (
                    [gid] if not one_shot else []
                ),
                "read_only_rootfs": True,
                "entrypoint": list(entrypoint),
                "command": list(command),
                "healthcheck_command": list(healthcheck),
                "pid_mode": "private",
                "user_namespace": {
                    "compat_mode": "",
                    "create_options": [],
                    "process_identity": (
                        "" if one_shot else f"user:[{4_026_540_000 + role_index}]"
                    ),
                    "collector_identity": "user:[4026531837]",
                    "uid_map": [] if one_shot else copy.deepcopy(process_map),
                    "gid_map": [] if one_shot else copy.deepcopy(process_map),
                    "collector_uid_map": copy.deepcopy(collector_map),
                    "collector_gid_map": copy.deepcopy(collector_map),
                    "configured_uid_map": (
                        copy.deepcopy(configured_map) if one_shot else []
                    ),
                    "configured_gid_map": (
                        copy.deepcopy(configured_map) if one_shot else []
                    ),
                    "podman_uid_map": copy.deepcopy(process_map),
                    "podman_gid_map": copy.deepcopy(process_map),
                },
                "ipc_mode": "private",
                "uts_mode": "private",
                "network_mode": "private",
                "cap_add": capabilities,
                "group_add": [],
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
                "published_ports": ["127.0.0.1:51530:8443/tcp"] if role == "gateway" else [],
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
                    f"localhost/secpal-ci-{role}@sha256:"
                    f"{(5 if role in {'secrets-init', 'migrate', 'api', 'worker-general', 'worker-hash-chain', 'scheduler'} else role_index):064x}"
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
            "processes": [],
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
            "podman_api": False,
            "user_work": {
                "active_units": sorted(
                    ["dbus.service", "dbus.socket"]
                    + [service["unit"] for service in services]
                    + [f"{prefix}.target"]
                ),
                "jobs": [],
            },
            "processes": [],
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
            "processes": [],
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
            {
                "host": 0,
                "workload_prepare_start": 0,
                "workload_cleanup": 0,
                "trusted_quadlet_normalize_live": 0,
                "trusted_quadlet_normalize_cleanup": 0,
            },
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
            {
                "host": 7,
                "workload_prepare_start": 0,
                "workload_cleanup": 0,
                "trusted_quadlet_normalize_live": 0,
                "trusted_quadlet_normalize_cleanup": 0,
            },
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

    def test_each_trusted_quadlet_normalization_status_is_authoritative(self) -> None:
        observations = valid_observations()
        for phase, invariant in (
            ("trusted_quadlet_normalize_live", "TRUSTED_QUADLET_NORMALIZE_LIVE"),
            (
                "trusted_quadlet_normalize_cleanup",
                "TRUSTED_QUADLET_NORMALIZE_CLEANUP",
            ),
        ):
            host = {
                "schema_version": 1,
                "workflow": {"target_sha": "a" * 40},
                "test": {"failed_admission_invariants": []},
                "platform": {},
                "apt": {},
                "host": {},
                "runtime": {},
            }
            statuses = {
                "host": 0,
                "workload_prepare_start": 0,
                "workload_cleanup": 0,
                "trusted_quadlet_normalize_live": 0,
                "trusted_quadlet_normalize_cleanup": 0,
            }
            statuses[phase] = 1
            document = self.assembler.assemble(
                host,
                observations["baseline"],
                observations["live"],
                observations["post_cleanup"],
                statuses,
                {"baseline": 0, "live": 0, "post_cleanup": 0},
            )
            self.assertEqual("failed", document["workload"]["result"])
            self.assertIn(
                invariant,
                document["workload"]["failed_admission_invariants"],
            )

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
        self.assertEqual("/dev/null", environment["CONTAINERS_CONF"])
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
            lambda evidence: evidence["live"]["containers"][9].__setitem__(
                "role", "scheduler"
            ),
            "D1A_SINGLETON_ROLES",
        )

    def test_rootful_remote_host_network_privilege_and_auto_update_are_rejected(self) -> None:
        mutations = (
            ("rootless", False, "D1A_ROOTLESS"),
            ("oci_runtime", "runc", "D1A_OCI_RUNTIME"),
            ("privileged", True, "D1A_PRIVILEGE_BOUNDARY"),
            ("pid_mode", "host", "D1A_HOST_NAMESPACES"),
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

    def test_effective_user_namespace_facts_fail_closed(self) -> None:
        mutations = (
            lambda fact: fact.__setitem__(
                "process_identity", fact["collector_identity"]
            ),
            lambda fact: fact.__setitem__("process_identity", ""),
            lambda fact: fact.__setitem__("uid_map", []),
            lambda fact: fact.__setitem__("gid_map", []),
            lambda fact: fact["uid_map"].append(
                {"container_id": 10_000, "host_id": 240_000, "size": 10}
            ),
            lambda fact: fact.__setitem__(
                "uid_map",
                [{"container_id": 0, "host_id": 20_000, "size": 10_001}],
            ),
            lambda fact: fact.__setitem__(
                "gid_map",
                [{"container_id": 0, "host_id": 20_000, "size": 10_001}],
            ),
            lambda fact: fact.__setitem__(
                "uid_map",
                [
                    {"container_id": index, "host_id": 200_000 + index, "size": 1}
                    for index in range(17)
                ],
            ),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                self.assert_failure(
                    lambda evidence, mutate=mutate: mutate(
                        evidence["live"]["containers"][4]["user_namespace"]
                    ),
                    "D1A_HOST_NAMESPACES",
                )

    def test_explicit_user_namespace_joins_are_rejected(self) -> None:
        for mode in ("host", "container:0123456789abcdef", "ns:/proc/1/ns/user"):
            with self.subTest(mode=mode):
                self.assert_failure(
                    lambda evidence, mode=mode: evidence["live"]["containers"][4][
                        "user_namespace"
                    ].__setitem__("create_options", [mode]),
                    "D1A_HOST_NAMESPACES",
                )
                self.assert_failure(
                    lambda evidence, mode=mode: evidence["live"]["containers"][4][
                        "user_namespace"
                    ].__setitem__("compat_mode", mode),
                    "D1A_HOST_NAMESPACES",
                )

    def test_service_environment_cannot_supply_user_namespace_defaults(self) -> None:
        for name in (
            "PODMAN_USERNS",
            "CONTAINERS_CONF",
            "CONTAINERS_CONF_OVERRIDE",
            "CONTAINERS_CONF_MODULES",
            "XDG_CONFIG_HOME",
            "HOME",
        ):
            with self.subTest(name=name):
                self.assert_failure(
                    lambda evidence, name=name: evidence["live"]
                    ["generated_services"][4].__setitem__("environment", [name]),
                    "D1A_HOST_NAMESPACES",
                )

    def test_service_environment_values_are_discarded_from_evidence(self) -> None:
        self.assertEqual(
            (["DB_PASSWORD", "PATH"], True),
            self.collector.normalized_service_environment(
                "PATH=/usr/bin DB_PASSWORD=synthetic-placeholder"
            ),
        )

    def test_generated_service_requires_effective_local_config_pins(self) -> None:
        trusted = (
            "CONTAINERS_CONF=/dev/null CONTAINERS_CONF_OVERRIDE=/dev/null "
            "CONTAINERS_CONF_MODULES= PODMAN_USERNS= PATH=/usr/bin"
        )
        self.assertTrue(
            self.collector.service_config_environment_is_trusted(trusted)
        )
        for value in (
            trusted.replace("CONTAINERS_CONF=/dev/null ", ""),
            trusted.replace(
                "CONTAINERS_CONF_OVERRIDE=/dev/null",
                "CONTAINERS_CONF_OVERRIDE=/tmp/target.conf",
            ),
            trusted.replace(
                "CONTAINERS_CONF_MODULES=",
                "CONTAINERS_CONF_MODULES=target",
            ),
            trusted.replace("PODMAN_USERNS=", "PODMAN_USERNS=host"),
        ):
            with self.subTest(value=value):
                self.assertFalse(
                    self.collector.service_config_environment_is_trusted(value)
                )

    def test_generated_service_cannot_drop_or_replace_the_trusted_config_pin(self) -> None:
        self.assertTrue(
            self.collector.service_environment_controls_are_trusted("", "", "")
        )
        for values in (
            ("/home/secpal-ci/target.env", "", ""),
            ("", "CONTAINERS_CONF", ""),
            ("", "", "CONTAINERS_CONF"),
        ):
            with self.subTest(values=values):
                self.assertFalse(
                    self.collector.service_environment_controls_are_trusted(*values)
                )

        direct = (
            "{ path=/usr/bin/podman ; argv[]=/usr/bin/podman run --name fixture ; "
            "ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; "
            "code=(null) ; status=0/0 }"
        )
        network = direct.replace("podman run", "podman network create")
        volume = direct.replace("podman run", "podman volume create")
        self.assertTrue(self.collector.direct_podman_exec_start(direct, "api"))
        self.assertTrue(
            self.collector.direct_podman_exec_start(
                network, "application-network"
            )
        )
        self.assertTrue(
            self.collector.direct_podman_exec_start(volume, "secrets-volume")
        )
        self.assertFalse(
            self.collector.direct_podman_exec_start(network, "api")
        )
        self.assertFalse(
            self.collector.direct_podman_exec_start(network, "target-network")
        )
        for value in (
            "",
            direct + " " + direct,
            direct.replace("path=/usr/bin/podman", "path=/usr/bin/env"),
            direct.replace("argv[]=/usr/bin/podman", "argv[]=/usr/bin/env"),
        ):
            with self.subTest(value=value):
                self.assertFalse(
                    self.collector.direct_podman_exec_start(value, "api")
                )

    def test_generated_service_rejects_non_quadlet_auxiliary_commands(self) -> None:
        properties = {
            name: "" for name in (
                "ExecCondition", "ExecStartPre", "ExecStartPost", "ExecReload",
                "ExecStop", "ExecStopPost",
            )
        }
        properties["ExecStop"] = (
            "{ path=/usr/bin/podman ; argv[]=/usr/bin/podman rm -v -f -i ; "
            "ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; "
            "code=(null) ; status=0/0 }"
        )
        properties["ExecStopPost"] = (
            "{ path=/usr/bin/podman ; argv[]=/usr/bin/podman rm -v -f -i ; }"
        )
        self.assertTrue(
            self.collector.service_execution_controls_are_trusted(
                properties, "api"
            )
        )
        for name in properties:
            with self.subTest(name=name):
                overridden = dict(properties)
                overridden[name] = (
                    "{ path=/usr/bin/systemctl ; argv[]=/usr/bin/systemctl "
                    "--user set-environment CONTAINERS_CONF=/tmp/target.conf ; }"
                )
                self.assertFalse(
                    self.collector.service_execution_controls_are_trusted(
                        overridden, "api"
                    )
                )

        incomplete = dict(properties)
        incomplete.pop("ExecStop")
        self.assertFalse(
            self.collector.service_execution_controls_are_trusted(
                incomplete, "api"
            )
        )
        no_hooks = {name: "" for name in properties}
        self.assertTrue(
            self.collector.service_execution_controls_are_trusted(
                no_hooks, "application-network"
            )
        )
        self.assertTrue(
            self.collector.service_execution_controls_are_trusted(
                no_hooks, "secrets-volume"
            )
        )

    def test_target_quadlet_source_cannot_add_auxiliary_commands(self) -> None:
        safe = b"[Container]\nImage=example.invalid/image@sha256:synthetic\n"
        self.assertTrue(
            self.collector.quadlet_content_has_no_auxiliary_execution_directives(
                safe
            )
        )
        for directive in (
            "ExecCondition", "ExecStartPre", "ExecStartPost", "ExecReload",
            "ExecStop", "ExecStopPost",
        ):
            with self.subTest(directive=directive):
                self.assertFalse(
                    self.collector.quadlet_content_has_no_auxiliary_execution_directives(
                        safe
                        + f"[Service]\n{directive}=/usr/bin/true\n".encode()
                    )
                )

    def test_configured_mapping_must_match_the_effective_kernel_mapping(self) -> None:
        self.assert_failure(
            lambda evidence: evidence["live"]["containers"][4]["user_namespace"].update(
                {
                    "configured_uid_map": [
                        {"container_id": 0, "host_id": 3_000_000_000, "size": 65_536}
                    ],
                    "configured_gid_map": [
                        {"container_id": 0, "host_id": 3_000_000_000, "size": 65_536}
                    ],
                }
            ),
            "D1A_HOST_NAMESPACES",
        )

    def test_auto_mapping_uses_kernel_derived_host_process_identity(self) -> None:
        observations = valid_observations()
        container = observations["live"]["containers"][4]
        service = observations["live"]["generated_services"][4]
        namespace = container["user_namespace"]
        auto_map = [{"container_id": 0, "host_id": 200_000, "size": 65_536}]
        namespace["create_options"] = ["auto"]
        namespace["uid_map"] = copy.deepcopy(auto_map)
        namespace["gid_map"] = copy.deepcopy(auto_map)
        observations["live"]["processes"] = [
            {
                "executable": "/usr/bin/php",
                "control_group": service["control_group"] + "/container",
                "uid": 210_001,
                "gid": 210_001,
                "count": 1,
            }
        ]
        self.assertEqual([], self.collector.workload_admission_failures(observations))

    def test_exited_user_namespace_requires_explicit_mapping_and_lifecycle(self) -> None:
        for mutate in (
            lambda container: container["user_namespace"].update(
                {"configured_uid_map": [], "configured_gid_map": []}
            ),
            lambda container: container["user_namespace"].__setitem__(
                "create_options", ["unknown"]
            ),
            lambda container: container["user_namespace"].__setitem__(
                "create_options", ["auto"]
            ),
            lambda container: container["user_namespace"].__setitem__(
                "configured_uid_map",
                [{"container_id": 0, "host_id": 1, "size": 10_001}],
            ),
            lambda container: container.__setitem__(
                "lifecycle_service_invocation", ""
            ),
        ):
            with self.subTest(mutate=mutate):
                self.assert_failure(
                    lambda evidence, mutate=mutate: mutate(
                        evidence["live"]["containers"][3]
                    ),
                    "D1A_HOST_NAMESPACES",
                )

    def test_podman_54_empty_compatibility_mode_is_not_host_evidence(self) -> None:
        capture = json.loads(PODMAN_54_USERNS_FIXTURE.read_text(encoding="utf-8"))
        self.assertIn("local rootless Podman 5.4.2 capture", capture["capture_source"])
        self.assertEqual("5.4.2", capture["podman_version"])
        self.assertTrue(capture["rootless"])
        self.assertEqual("", capture["default"]["HostConfig.UsernsMode"])
        self.assertEqual("", capture["auto"]["HostConfig.UsernsMode"])
        self.assertFalse(capture["default"]["HostConfig.IDMappings_present"])
        self.assertFalse(capture["auto"]["HostConfig.IDMappings_present"])
        self.assertEqual(
            (["auto"], True),
            self.collector.configured_userns_options(
                capture["auto"]["Config.CreateCommand"]
            ),
        )
        self.assertEqual(
            (
                capture["rootless_outer_kernel_maps"]["uid_map"],
                True,
            ),
            self.collector.parse_id_map(
                b"0 1000 1\n1 100000 65536\n"
            ),
        )

        for create_options in ([], ["auto"]):
            observations = valid_observations()
            namespace = observations["live"]["containers"][4]["user_namespace"]
            namespace["compat_mode"] = ""
            namespace["create_options"] = create_options
            if create_options:
                auto_map = [
                    {"container_id": 0, "host_id": 200_000, "size": 65_536}
                ]
                namespace["uid_map"] = copy.deepcopy(auto_map)
                namespace["gid_map"] = copy.deepcopy(auto_map)
            self.assertNotIn(
                "D1A_HOST_NAMESPACES",
                self.collector.workload_admission_failures(observations),
            )

    def test_id_map_parser_rejects_malformed_and_incomplete_kernel_maps(self) -> None:
        valid = b"         0      20000          1\n         1     200000      65536\n"
        expected = [
            {"container_id": 0, "host_id": 20_000, "size": 1},
            {"container_id": 1, "host_id": 200_000, "size": 65_536},
        ]
        self.assertEqual((expected, True), self.collector.parse_id_map(valid))
        for value in (
            b"",
            b"0 20000\n",
            b"0 x 1\n",
            b"0 20000 0\n",
            b"0 20000 10\n5 20010 10\n",
            b"0 20000 10\n10 20005 10\n",
            valid + b"1",
        ):
            with self.subTest(value=value):
                self.assertFalse(self.collector.parse_id_map(value)[1])

    def test_podman_57_configured_mapping_shape_is_supported(self) -> None:
        expected = [{"container_id": 0, "host_id": 1, "size": 65_536}]
        self.assertEqual(
            (expected, expected, True),
            self.collector.configured_id_maps(
                {"UidMap": ["0:1:65536"], "GidMap": ["0:1:65536"]}
            ),
        )

    def test_configured_mapping_composes_through_rootless_outer_mapping(self) -> None:
        outer = [
            {"container_id": 0, "host_id": 20_000, "size": 1},
            {"container_id": 1, "host_id": 200_000, "size": 65_536},
        ]
        self.assertEqual(
            [{"container_id": 0, "host_id": 200_000, "size": 65_536}],
            self.collector.compose_id_maps(
                [{"container_id": 0, "host_id": 1, "size": 65_536}], outer
            ),
        )
        self.assertIsNone(
            self.collector.compose_id_maps(
                [{"container_id": 0, "host_id": 3_000_000_000, "size": 65_536}],
                outer,
            )
        )

    def test_user_namespace_creation_options_are_derived_from_runtime_command(self) -> None:
        for command in (
            ["/usr/bin/podman", "create", "--userns=auto", "fixture"],
            ["/usr/bin/podman", "run", "--userns", "auto", "fixture"],
        ):
            with self.subTest(command=command):
                self.assertEqual(
                    (["auto"], True),
                    self.collector.configured_userns_options(command),
                )
        self.assertEqual(
            (["auto", "host"], False),
            self.collector.configured_userns_options(
                [
                    "/usr/bin/podman", "run", "--userns=auto",
                    "--userns=host", "fixture",
                ]
            ),
        )
        for command in (
            ["/usr/bin/podman", "--module=target.conf", "run", "fixture"],
            ["/usr/bin/podman", "--module", "target.conf", "run", "fixture"],
        ):
            with self.subTest(command=command):
                self.assertEqual(
                    ([], False),
                    self.collector.configured_userns_options(command),
                )

    def test_user_namespace_creation_options_match_the_evidence_schema_bound(self) -> None:
        bounded = "a" * 256
        self.assertEqual(
            ([bounded], True),
            self.collector.configured_userns_options(
                ["/usr/bin/podman", "create", f"--userns={bounded}", "fixture"]
            ),
        )
        for command in (
            ["/usr/bin/podman", "create", f"--userns={'a' * 257}", "fixture"],
            ["/usr/bin/podman", "create", "--userns", "a" * 257, "fixture"],
        ):
            with self.subTest(command=command):
                self.assertEqual(
                    ([], False),
                    self.collector.configured_userns_options(command),
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

    def test_secrets_initializer_requires_the_api_image_digest(self) -> None:
        observations = valid_observations()
        containers = observations["live"]["containers"]
        api = next(item for item in containers if item["role"] == "api")
        secrets_init = next(
            item for item in containers if item["role"] == "secrets-init"
        )
        api_digest = api["image"].rsplit("@sha256:", 1)[1]
        secrets_init["image"] = (
            "localhost/secpal-ci-secrets-init@sha256:" + api_digest
        )
        self.assertNotIn(
            "D1A_EXECUTION_CONTRACT",
            self.collector.workload_admission_failures(observations),
        )
        secrets_init["image"] = (
            "localhost/secpal-ci-secrets-init@sha256:" + "f" * 64
        )
        self.assertIn(
            "D1A_EXECUTION_CONTRACT",
            self.collector.workload_admission_failures(observations),
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
                "User": "10001:10001",
                "Entrypoint": list(API_ENTRYPOINT),
                "Cmd": list(ROLE_EXECUTION["api"][1]),
                "Healthcheck": {"Test": list(ROLE_EXECUTION["api"][2])},
                "CreateCommand": ["/usr/bin/podman", "run"],
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
                "GroupAdd": [],
                "Devices": [],
                "Tmpfs": {},
                "ReadonlyRootfs": True,
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
            (inspection["Config"], "User"),
            (inspection["Config"], "Entrypoint"),
            (inspection["Config"], "Cmd"),
            (inspection["Config"], "Healthcheck"),
            (inspection["Config"], "CreateCommand"),
            (inspection["HostConfig"], "CapAdd"),
            (inspection["HostConfig"], "GroupAdd"),
            (inspection["HostConfig"], "Devices"),
            (inspection["HostConfig"], "Tmpfs"),
            (inspection["HostConfig"], "ReadonlyRootfs"),
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
                ), mock.patch.object(
                    self.collector,
                    "effective_user_namespace_facts",
                    return_value=({}, 10001, 10001, [10001], True),
                ):
                    _, complete = self.collector.container_facts(
                        "aaaaaaaaaaaa", rootless=True,
                        podman_uid_map=[], podman_gid_map=[],
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
                "User": "10001:10001",
                "Entrypoint": list(API_ENTRYPOINT),
                "Cmd": list(ROLE_EXECUTION["api"][1]),
                "Healthcheck": {"Test": list(ROLE_EXECUTION["api"][2])},
                "CreateCommand": ["/usr/bin/podman", "run"],
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
                "GroupAdd": [],
                "Devices": [],
                "Tmpfs": {},
                "ReadonlyRootfs": True,
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
        namespace_facts = {
            "process_identity": "user:[4026540001]",
            "collector_identity": "user:[4026531837]",
            "uid_map": [
                {"container_id": 0, "host_id": 20_000, "size": 1},
                {"container_id": 1, "host_id": 200_000, "size": 65_536},
            ],
            "gid_map": [
                {"container_id": 0, "host_id": 20_000, "size": 1},
                {"container_id": 1, "host_id": 200_000, "size": 65_536},
            ],
            "collector_uid_map": [
                {"container_id": 0, "host_id": 0, "size": 4_294_967_295}
            ],
            "collector_gid_map": [
                {"container_id": 0, "host_id": 0, "size": 4_294_967_295}
            ],
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
        ), mock.patch.object(
            self.collector,
            "effective_user_namespace_facts",
            return_value=(namespace_facts, 10001, 10001, [10001], True),
        ):
            facts, complete = self.collector.container_facts(
                "aaaaaaaaaaaa", rootless=True,
                podman_uid_map=namespace_facts["uid_map"],
                podman_gid_map=namespace_facts["gid_map"],
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
        ), mock.patch.object(
            self.collector,
            "effective_user_namespace_facts",
            return_value=(namespace_facts, 10001, 10001, [10001], True),
        ):
            facts, complete = self.collector.container_facts(
                "aaaaaaaaaaaa", rootless=True,
                podman_uid_map=namespace_facts["uid_map"],
                podman_gid_map=namespace_facts["gid_map"],
            )
        self.assertTrue(complete)
        self.assertEqual("", facts[0]["user_namespace"]["compat_mode"])
        self.assertEqual(
            "user:[4026540001]",
            facts[0]["user_namespace"]["process_identity"],
        )
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

        exec_event = valid + "\n" + json.dumps(
            {
                "Type": "container",
                "status": "exec",
                "id": container_id,
                "timeNano": 5,
            }
        )
        with mock.patch.object(
            self.collector, "command_result", return_value=(0, exec_event, True)
        ):
            _, complete = self.collector.container_lifecycle_events(container_id)
        self.assertFalse(complete)

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

    def test_podman_api_accepts_trusted_debian_agent_socket_units(self) -> None:
        trusted = {
            "dbus.socket": "dbus.service",
            "dirmngr.socket": "dirmngr.service",
            "gpg-agent-browser.socket": "gpg-agent.service",
            "gpg-agent-extra.socket": "gpg-agent.service",
            "gpg-agent-ssh.socket": "gpg-agent.service",
            "gpg-agent.socket": "gpg-agent.service",
            "keyboxd.socket": "keyboxd.service",
            "ssh-agent.socket": "ssh-agent.service",
        }
        trusted_services = set(trusted.values())
        listing = "\n".join(
            f"{name} loaded active listening trusted fixture"
            for name in trusted
        )

        def command_result(
            arguments: list[str], timeout: int = 20
        ) -> tuple[int, str, bool]:
            del timeout
            if arguments[:5] == [
                "systemctl", "--user", "list-units", "--type=socket",
                "--state=active",
            ]:
                return 0, listing, True
            if arguments[:3] == ["systemctl", "--user", "show"]:
                name = arguments[3]
                if name in trusted_services:
                    return (
                        0,
                        f"FragmentPath=/usr/lib/systemd/user/{name}\n"
                        "DropInPaths=",
                        True,
                    )
                return (
                    0,
                    "\n".join(
                        (
                            f"FragmentPath=/usr/lib/systemd/user/{name}",
                            "DropInPaths=",
                            f"Triggers={trusted[name]}",
                        )
                    ),
                    True,
                )
            raise AssertionError(f"unexpected command: {arguments}")

        with mock.patch.object(
            self.collector, "command_result", side_effect=command_result
        ), mock.patch.object(
            self.collector, "root_owned_systemd_unit", return_value=True
        ):
            unsafe, complete = self.collector.user_socket_activation_facts()
        self.assertTrue(complete)
        self.assertFalse(unsafe)

    def test_podman_api_rejects_user_controlled_agent_service(self) -> None:
        listing = "\n".join(
            (
                "dbus.socket loaded active listening trusted fixture",
                "gpg-agent.socket loaded active listening trusted fixture",
            )
        )
        valid_service = {
            "FragmentPath": "/usr/lib/systemd/user/gpg-agent.service",
            "DropInPaths": "",
        }
        mutations = {
            "FragmentPath": (
                "/home/secpal-ci/.config/systemd/user/gpg-agent.service"
            ),
            "DropInPaths": (
                "/home/secpal-ci/.config/systemd/user/"
                "gpg-agent.service.d/override.conf"
            ),
        }

        for field, value in mutations.items():
            with self.subTest(field=field):
                observed_service = {**valid_service, field: value}

                def command_result(
                    arguments: list[str], timeout: int = 20
                ) -> tuple[int, str, bool]:
                    del timeout
                    if arguments[:5] == [
                        "systemctl", "--user", "list-units", "--type=socket",
                        "--state=active",
                    ]:
                        return 0, listing, True
                    if arguments[:4] == [
                        "systemctl", "--user", "show", "dbus.socket",
                    ]:
                        return (
                            0,
                            "FragmentPath=/usr/lib/systemd/user/dbus.socket\n"
                            "DropInPaths=\nTriggers=dbus.service",
                            True,
                        )
                    if arguments[:4] == [
                        "systemctl", "--user", "show", "gpg-agent.socket",
                    ]:
                        return (
                            0,
                            "FragmentPath=/usr/lib/systemd/user/"
                            "gpg-agent.socket\nDropInPaths=\n"
                            "Triggers=gpg-agent.service",
                            True,
                        )
                    if arguments[:4] == [
                        "systemctl", "--user", "show", "dbus.service",
                    ]:
                        return (
                            0,
                            "FragmentPath=/usr/lib/systemd/user/dbus.service\n"
                            "DropInPaths=",
                            True,
                        )
                    if arguments[:4] == [
                        "systemctl", "--user", "show", "gpg-agent.service",
                    ]:
                        return (
                            0,
                            "\n".join(
                                f"{name}={item}"
                                for name, item in observed_service.items()
                            ),
                            True,
                        )
                    raise AssertionError(f"unexpected command: {arguments}")

                with mock.patch.object(
                    self.collector, "command_result", side_effect=command_result
                ), mock.patch.object(
                    self.collector,
                    "root_owned_systemd_unit",
                    return_value=True,
                ):
                    unsafe, complete = self.collector.user_socket_activation_facts()
                self.assertTrue(complete)
                self.assertTrue(unsafe)

    def test_podman_api_rejects_modified_debian_agent_socket_units(self) -> None:
        listing = "\n".join(
            (
                "dbus.socket loaded active listening trusted fixture",
                "gpg-agent.socket loaded active listening trusted fixture",
            )
        )
        valid = {
            "FragmentPath": "/usr/lib/systemd/user/gpg-agent.socket",
            "DropInPaths": "",
            "Triggers": "gpg-agent.service",
        }
        mutations = {
            "FragmentPath": "/home/secpal-ci/.config/systemd/user/gpg-agent.socket",
            "DropInPaths": "/home/secpal-ci/.config/systemd/user/override.conf",
            "Triggers": "attacker.service",
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                observed = {**valid, field: value}

                def command_result(
                    arguments: list[str], timeout: int = 20
                ) -> tuple[int, str, bool]:
                    del timeout
                    if arguments[:5] == [
                        "systemctl", "--user", "list-units", "--type=socket",
                        "--state=active",
                    ]:
                        return 0, listing, True
                    if arguments[:4] == [
                        "systemctl", "--user", "show", "dbus.socket",
                    ]:
                        return (
                            0,
                            "FragmentPath=/usr/lib/systemd/user/dbus.socket\n"
                            "DropInPaths=\nTriggers=dbus.service",
                            True,
                        )
                    if arguments[:4] == [
                        "systemctl", "--user", "show", "dbus.service",
                    ]:
                        return (
                            0,
                            "FragmentPath=/usr/lib/systemd/user/dbus.service\n"
                            "DropInPaths=",
                            True,
                        )
                    if arguments[:4] == [
                        "systemctl", "--user", "show", "gpg-agent.socket",
                    ]:
                        return (
                            0,
                            "\n".join(
                                f"{name}={item}" for name, item in observed.items()
                            ),
                            True,
                        )
                    raise AssertionError(f"unexpected command: {arguments}")

                with mock.patch.object(
                    self.collector,
                    "command_result",
                    side_effect=command_result,
                ), mock.patch.object(
                    self.collector, "root_owned_systemd_unit", return_value=True
                ):
                    unsafe, complete = self.collector.user_socket_activation_facts()
                self.assertTrue(complete)
                self.assertTrue(unsafe)

    def test_systemd_unit_admission_requires_root_ownership(self) -> None:
        metadata = types.SimpleNamespace(
            st_mode=self.collector.stat.S_IFREG | 0o644,
            st_uid=20000,
            st_gid=20000,
            st_nlink=1,
        )
        with mock.patch.object(
            self.collector.Path, "lstat", return_value=metadata
        ):
            self.assertFalse(
                self.collector.root_owned_systemd_unit(
                    Path("/usr/lib/systemd/user/gpg-agent.service")
                )
            )

    def test_migration_and_readiness_are_derived_from_raw_facts(self) -> None:
        self.assert_failure(
            lambda evidence: next(
                item for item in evidence["live"]["containers"]
                if item["role"] == "migrate"
            ).__setitem__("state", "running"),
            "D1A_MIGRATION",
        )
        self.assert_failure(
            lambda evidence: evidence["post_cleanup"].__setitem__(
                "migration_invocation_count", 2
            ),
            "D1A_MIGRATION",
        )
        self.assert_failure(
            lambda evidence: next(
                item for item in evidence["live"]["containers"]
                if item["role"] == "api"
            ).__setitem__("health", "unhealthy"),
            "D1A_READINESS",
        )

    def test_runtime_identity_and_read_only_rootfs_are_contract_facts(self) -> None:
        identity = valid_observations()
        identity["live"]["containers"][8]["configured_user"] = "0:0"
        identity["live"]["containers"][8]["effective_uid"] = 0
        identity["live"]["containers"][8]["effective_gid"] = 0
        self.assertIn(
            "D1A_RUNTIME_IDENTITY",
            self.collector.workload_admission_failures(identity),
        )

        writable = valid_observations()
        writable["live"]["containers"][8]["read_only_rootfs"] = False
        self.assertIn(
            "D1A_READ_ONLY_ROOTFS",
            self.collector.workload_admission_failures(writable),
        )

    def test_migration_admission_binds_the_exact_configured_command(self) -> None:
        def mutate_role(role, field, value):
            observations = valid_observations()
            container = next(
                item for item in observations["live"]["containers"]
                if item["role"] == role
            )
            container[field] = value
            self.assertIn(
                "D1A_EXECUTION_CONTRACT",
                self.collector.workload_admission_failures(observations),
            )

        mutate_role("migrate", "command", ["true"])
        mutate_role(
            "api", "healthcheck_command",
            ["CMD", "php", "artisan", "migrate", "--force"],
        )
        mutate_role("postgres", "command", ["php", "artisan", "migrate"])

    def test_loaded_services_are_bound_to_root_owned_quadlet_sources(self) -> None:
        wrong_source = valid_observations()
        wrong_source["live"]["generated_services"][0]["source_path"] = (
            "/home/secpal-ci/.config/containers/systemd/attacker.container"
        )
        self.assertIn(
            "D1A_GENERATED_PROVENANCE",
            self.collector.workload_admission_failures(wrong_source),
        )

        wrong_digest = valid_observations()
        wrong_digest["live"]["generated_services"][0]["fragment_sha256"] = ""
        self.assertIn(
            "D1A_GENERATED_PROVENANCE",
            self.collector.workload_admission_failures(wrong_digest),
        )

        contradictory_drop_ins = valid_observations()
        contradictory_drop_ins["live"]["generated_services"][0][
            "drop_in_sha256"
        ] = ["a" * 64]
        self.assertIn(
            "D1A_GENERATED_PROVENANCE",
            self.collector.workload_admission_failures(contradictory_drop_ins),
        )

    def test_live_user_work_rejects_unrelated_target_services(self) -> None:
        observations = valid_observations()
        baseline = observations["baseline"]["user_work"]
        generated = [
            service["unit"] for service in observations["live"]["generated_services"]
        ]
        observations["live"]["user_work"] = {
            "active_units": sorted([
                *baseline["active_units"],
                *generated,
                f"secpal-int-{observations['instance']}.target",
            ]),
            "jobs": [],
        }
        observations["live"]["processes"] = []
        observations["baseline"]["processes"] = []
        observations["post_cleanup"]["processes"] = []
        self.assertEqual(
            [], self.collector.workload_admission_failures(observations)
        )
        observations["live"]["user_work"]["active_units"].append(
            "hidden-scheduler.service"
        )
        self.assertIn(
            "D1A_LIVE_USER_WORK",
            self.collector.workload_admission_failures(observations),
        )

    def test_live_user_work_includes_the_active_fixture_target(self) -> None:
        observations = valid_observations()
        fixture_target = f"secpal-int-{observations['instance']}.target"
        self.assertIn(
            fixture_target,
            observations["live"]["user_work"]["active_units"],
        )
        self.assertNotIn(
            "D1A_LIVE_USER_WORK",
            self.collector.workload_admission_failures(observations),
        )
        observations["live"]["user_work"]["active_units"].remove(
            fixture_target
        )
        self.assertIn(
            "D1A_LIVE_USER_WORK",
            self.collector.workload_admission_failures(observations),
        )

    def test_live_process_delta_is_confined_to_generated_service_cgroups(self) -> None:
        observations = valid_observations()
        baseline_process = {
            "executable": "/usr/lib/systemd/systemd",
            "control_group": "/user.slice/user-20000.slice/user@20000.service/init.scope",
            "uid": 20000,
            "gid": 20000,
            "count": 1,
        }
        observations["baseline"]["processes"] = [baseline_process]
        observations["post_cleanup"]["processes"] = [baseline_process]
        observations["live"]["processes"] = [
            baseline_process,
            {
                "executable": "/usr/bin/php",
                "control_group": (
                    "/user.slice/user-20000.slice/user@20000.service/app.slice/"
                    f"secpal-int-{observations['instance']}-scheduler.service/container"
                ),
                "uid": 210000,
                "gid": 210000,
                "count": 1,
            },
        ]
        baseline = observations["baseline"]["user_work"]
        observations["live"]["user_work"] = {
            "active_units": sorted(
                [
                    *baseline["active_units"],
                    *[
                        service["unit"]
                        for service in observations["live"]["generated_services"]
                    ],
                    f"secpal-int-{observations['instance']}.target",
                ]
            ),
            "jobs": [],
        }
        self.assertEqual(
            [], self.collector.workload_admission_failures(observations)
        )
        observations["live"]["processes"].append(
            {
                "executable": "/usr/bin/php",
                "control_group": (
                    "/user.slice/user-20000.slice/user@20000.service/app.slice/"
                    "hidden-scheduler.service"
                ),
                "uid": 20000,
                "gid": 20000,
                "count": 1,
            }
        )
        self.assertIn(
            "D1A_PROCESS_DELTA",
            self.collector.workload_admission_failures(observations),
        )

        wrong_identity = valid_observations()
        wrong_identity["live"]["processes"] = [{
            "executable": "/usr/bin/php",
            "control_group": (
                "/user.slice/user-20000.slice/user@20000.service/app.slice/"
                f"secpal-int-{wrong_identity['instance']}-scheduler.service/container"
            ),
            "uid": 200001,
            "gid": 200001,
            "count": 1,
        }]
        self.assertIn(
            "D1A_PROCESS_DELTA",
            self.collector.workload_admission_failures(wrong_identity),
        )

        cleanup_leak = valid_observations()
        cleanup_leak["post_cleanup"]["processes"] = [{
            "executable": "/usr/bin/php",
            "control_group": "/user.slice/user-20000.slice/session-stale.scope",
            "uid": 20000,
            "gid": 20000,
            "count": 1,
        }]
        self.assertIn(
            "D1A_PROCESS_DELTA",
            self.collector.workload_admission_failures(cleanup_leak),
        )

    def test_runner_reestablishes_trusted_quadlet_activation_before_live_observation(self) -> None:
        runner = RUNNER_PATH.read_text(encoding="utf-8")
        self.assertIn("normalize_quadlet_runtime()", runner)
        self.assertLess(
            runner.index('bootstrap_stage="target-workload-prepare-start"'),
            runner.index('bootstrap_stage="trusted-quadlet-normalize-live"'),
        )
        self.assertLess(
            runner.index('bootstrap_stage="trusted-quadlet-normalize-live"'),
            runner.index('bootstrap_stage="collector-live"'),
        )
        live_normalization = runner.split(
            'bootstrap_stage="trusted-quadlet-normalize-live"', 1
        )[1].split('bootstrap_stage="collector-live"', 1)[0]
        self.assertIn("normalize_quadlet_runtime live", live_normalization)
        self.assertLess(
            runner.index('bootstrap_stage="target-host"'),
            runner.index('bootstrap_stage="trusted-quadlet-normalize-cleanup"'),
        )
        self.assertLess(
            runner.index('bootstrap_stage="trusted-quadlet-normalize-cleanup"'),
            runner.index('bootstrap_stage="collector-post-cleanup"'),
        )

    def test_target_activation_rejects_overrides_and_injected_dependencies(self) -> None:
        instance = "aaaaaaaaaaaa"
        prefix = f"secpal-int-{instance}"
        required = " ".join(
            f"{prefix}-{role}.service"
            for role in ("gateway", "worker-general", "worker-hash-chain", "scheduler")
        )
        trusted = (
            f"FragmentPath=/etc/systemd/user/{prefix}.target\n"
            "DropInPaths=\nWants=\n"
            f"Requires={required}\n"
        )
        for properties, expected in (
            (trusted, True),
            (trusted.replace("Wants=\n", "Wants=unreviewed.service\n"), False),
            (trusted.replace("Requires=", "Requires=unreviewed.service "), False),
            (trusted.replace("/etc/systemd/user", "/home/secpal-ci/.config/systemd/user"), False),
        ):
            with self.subTest(properties=properties), mock.patch.object(
                self.collector,
                "command_result",
                return_value=(0, properties, True),
            ):
                self.assertEqual(
                    self.collector.target_activation_is_trusted(instance),
                    expected,
                )

    def test_generated_service_dependency_companions_are_rejected(self) -> None:
        instance = "aaaaaaaaaaaa"
        with tempfile.TemporaryDirectory() as directory:
            unit_root = Path(directory)
            trusted = (0, f"UnitPath={unit_root}", True)
            with mock.patch.object(
                self.collector, "command_result", return_value=trusted
            ):
                self.assertTrue(
                    self.collector.generated_dependency_companions_are_absent(
                        instance
                    )
                )
                for suffix in ("wants", "requires"):
                    companion = unit_root / (
                        f"secpal-int-aaaaaaaaaaaa-api.service.{suffix}"
                    )
                    companion.mkdir()
                    with self.subTest(suffix=suffix):
                        self.assertFalse(
                            self.collector.generated_dependency_companions_are_absent(
                                instance
                            )
                        )
                    companion.rmdir()
            for result in (
                (1, "", True),
                (0, "UnitPath=relative/path", True),
                (0, f"UnitPath={unit_root} {unit_root}", True),
            ):
                with self.subTest(result=result), mock.patch.object(
                    self.collector, "command_result", return_value=result
                ):
                    self.assertFalse(
                        self.collector.generated_dependency_companions_are_absent(
                            instance
                        )
                    )

    def test_generated_service_dependencies_are_role_exact(self) -> None:
        instance = "aaaaaaaaaaaa"
        expected = self.collector.expected_generated_service_dependencies(
            instance, "api"
        )
        dependencies = " ".join(sorted(expected))
        properties = {
            "Environment": (
                "CONTAINERS_CONF=/dev/null CONTAINERS_CONF_OVERRIDE=/dev/null "
                "CONTAINERS_CONF_MODULES= PODMAN_USERNS="
            ),
            "EnvironmentFiles": "",
            "PassEnvironment": "",
            "UnsetEnvironment": "",
            "ExecCondition": "",
            "ExecStartPre": "",
            "ExecStart": "{ path=/usr/bin/podman ; argv[]=/usr/bin/podman run ; }",
            "ExecStartPost": "",
            "ExecReload": "",
            "ExecStop": "{ path=/usr/bin/podman ; argv[]=/usr/bin/podman rm ; }",
            "ExecStopPost": "{ path=/usr/bin/podman ; argv[]=/usr/bin/podman rm ; }",
            "Requires": dependencies,
            "After": f"podman-user-wait-network-online.service {dependencies}",
        }
        self.assertTrue(
            self.collector.service_runtime_controls_are_trusted(
                properties, "api", instance
            )
        )
        for name, value in (
            ("Requires", ""),
            ("After", "podman-user-wait-network-online.service"),
            ("Requires", dependencies + " secpal-int-aaaaaaaaaaaa-frontend.service"),
        ):
            mutated = dict(properties)
            mutated[name] = value
            with self.subTest(name=name, value=value):
                self.assertFalse(
                    self.collector.service_runtime_controls_are_trusted(
                        mutated, "api", instance
                    )
                )

    def test_podman_network_online_unit_rejects_user_overrides(self) -> None:
        trusted = (
            "FragmentPath=/usr/lib/systemd/user/"
            "podman-user-wait-network-online.service\nDropInPaths=\n"
        )
        for properties, expected in (
            (trusted, True),
            (trusted.replace("/usr/lib/systemd/user", "/home/user/.config/systemd/user"), False),
            (trusted.replace("DropInPaths=", "DropInPaths=/home/user/override.conf"), False),
        ):
            with self.subTest(properties=properties), mock.patch.object(
                self.collector,
                "command_result",
                return_value=(0, properties, True),
            ):
                self.assertEqual(
                    self.collector.podman_network_online_activation_is_trusted(),
                    expected,
                )

    def test_quadlet_normalization_uses_only_the_fixed_user_manager_contract(self) -> None:
        calls = []
        original_environment = "PATH=/target/bin\nATTACKER_VALUE=present\n"
        trusted_environment = (
            "CONTAINERS_CONF=/dev/null\n"
            "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/20000/bus\n"
            "HOME=/home/secpal-ci\nLANG=C.UTF-8\nLC_ALL=C.UTF-8\n"
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
            "QUADLET_UNIT_DIRS=/etc/containers/systemd/users/20000\n"
            "XDG_RUNTIME_DIR=/run/user/20000\n"
        )
        service_properties = (
            "Environment=CONTAINERS_CONF=/dev/null "
            "CONTAINERS_CONF_OVERRIDE=/dev/null CONTAINERS_CONF_MODULES= "
            "PODMAN_USERNS=\n"
            "EnvironmentFiles=\nPassEnvironment=\nUnsetEnvironment=\n"
            "ExecCondition=\nExecStartPre=\n"
            "ExecStart={ path=/usr/bin/podman ; argv[]=/usr/bin/podman run ; }\n"
            "ExecStartPost=\nExecReload=\n"
            "ExecStop={ path=/usr/bin/podman ; "
            "argv[]=/usr/bin/podman rm -v -f -i ; }\n"
            "ExecStopPost={ path=/usr/bin/podman ; "
            "argv[]=/usr/bin/podman rm -v -f -i ; }\n"
        )
        target_properties = (
            "FragmentPath=/etc/systemd/user/secpal-int-aaaaaaaaaaaa.target\n"
            "DropInPaths=\nWants=\n"
            "Requires=secpal-int-aaaaaaaaaaaa-gateway.service "
            "secpal-int-aaaaaaaaaaaa-worker-general.service "
            "secpal-int-aaaaaaaaaaaa-worker-hash-chain.service "
            "secpal-int-aaaaaaaaaaaa-scheduler.service\n"
        )
        podman_network_online_properties = (
            "FragmentPath=/usr/lib/systemd/user/"
            "podman-user-wait-network-online.service\nDropInPaths=\n"
        )
        environment_reads = 0

        def command_result(arguments, **kwargs):
            nonlocal environment_reads
            calls.append((arguments, kwargs))
            if arguments == ["systemctl", "--user", "show-environment"]:
                environment_reads += 1
                output = (
                    original_environment
                    if environment_reads == 1
                    else trusted_environment
                )
                return 0, output, True
            if arguments == [
                "systemctl", "--user", "show", "--property=UnitPath",
            ]:
                return 0, (
                    "UnitPath=/run/user/20000/systemd/user.control "
                    "/etc/systemd/user"
                ), True
            if arguments[:3] == ["systemctl", "--user", "show"]:
                if arguments[3].endswith(".target"):
                    return 0, target_properties, True
                if arguments[3] == self.collector.PODMAN_NETWORK_ONLINE_UNIT:
                    return 0, podman_network_online_properties, True
                properties = service_properties
                logical_name = arguments[3].removeprefix(
                    "secpal-int-aaaaaaaaaaaa-"
                ).removesuffix(".service")
                dependencies = " ".join(
                    sorted(
                        self.collector.expected_generated_service_dependencies(
                            "aaaaaaaaaaaa", logical_name
                        )
                    )
                )
                after = "podman-user-wait-network-online.service"
                if dependencies:
                    after += f" {dependencies}"
                properties += f"Requires={dependencies}\nAfter={after}\n"
                if any(
                    arguments[3].endswith(f"-{name}-network.service")
                    for name in ("application", "edge")
                ):
                    properties = properties.replace(
                        "podman run", "podman network create"
                    )
                elif any(
                    arguments[3].endswith(f"-{name}-volume.service")
                    for name in ("secrets", "private-storage", "postgres")
                ):
                    properties = properties.replace(
                        "podman run", "podman volume create"
                    )
                if (
                    "-network.service" in arguments[3]
                    or "-volume.service" in arguments[3]
                ):
                    properties = re.sub(
                        r"ExecStop=.*\nExecStopPost=.*\n",
                        "ExecStop=\nExecStopPost=\n",
                        properties,
                    )
                return 0, properties, True
            return 0, "", True

        with mock.patch.object(
            self.collector, "command_result", side_effect=command_result
        ), mock.patch.object(
            self.collector,
            "quadlet_search_paths",
            return_value=["/etc/containers/systemd/users/20000"],
        ), mock.patch.object(
            self.collector,
            "quadlet_source_execution_controls_are_trusted",
            return_value=True,
        ):
            self.assertTrue(
                self.collector.normalize_quadlet_runtime(
                    "aaaaaaaaaaaa", activate=True
                )
            )
        self.assertEqual(
            [
                ([
                    "systemctl", "--user", "stop",
                    "secpal-int-aaaaaaaaaaaa.target",
                    *[
                        f"secpal-int-aaaaaaaaaaaa-{logical_name}.service"
                        for logical_name in self.collector.GENERATED_LOGICAL_NAMES
                    ],
                ], {"timeout": 120}),
                (["systemctl", "--user", "show-environment"], {}),
                ([
                    "systemctl", "--user", "unset-environment",
                    "ATTACKER_VALUE", "PATH",
                ], {}),
                ([
                    "systemctl", "--user", "set-environment",
                    "CONTAINERS_CONF=/dev/null",
                    "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/20000/bus",
                    "HOME=/home/secpal-ci",
                    "LANG=C.UTF-8",
                    "LC_ALL=C.UTF-8",
                    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                    "QUADLET_UNIT_DIRS=/etc/containers/systemd/users/20000",
                    "XDG_RUNTIME_DIR=/run/user/20000",
                ], {}),
                (["systemctl", "--user", "daemon-reload"], {"timeout": 60}),
                ([
                    "systemctl", "--user", "show",
                    "secpal-int-aaaaaaaaaaaa.target",
                    "--property=FragmentPath", "--property=DropInPaths",
                    "--property=Wants", "--property=Requires",
                ], {}),
                ([
                    "systemctl", "--user", "show",
                    "podman-user-wait-network-online.service",
                    "--property=FragmentPath", "--property=DropInPaths",
                ], {}),
                ([
                    "systemctl", "--user", "show", "--property=UnitPath",
                ], {}),
                *[
                    ([
                        "systemctl", "--user", "show",
                        f"secpal-int-aaaaaaaaaaaa-{logical_name}.service",
                        *(
                            f"--property={name}"
                            for name in self.collector.SERVICE_ACTIVATION_PROPERTIES
                        ),
                    ], {})
                    for logical_name in self.collector.GENERATED_LOGICAL_NAMES
                ],
                ([
                    "systemctl", "--user", "start",
                    "secpal-int-aaaaaaaaaaaa.target",
                ], {"timeout": 600}),
                (["systemctl", "--user", "show-environment"], {}),
            ],
            calls,
        )

        with mock.patch.object(
            self.collector,
            "command_result",
            side_effect=(
                (0, original_environment, True),
                (0, "", True),
                (0, "", True),
                (1, "", True),
                (0, trusted_environment, True),
            ),
        ), mock.patch.object(
            self.collector,
            "quadlet_search_paths",
            return_value=["/etc/containers/systemd/users/20000"],
        ), mock.patch.object(
            self.collector,
            "quadlet_source_execution_controls_are_trusted",
            return_value=True,
        ):
            self.assertFalse(
                self.collector.normalize_quadlet_runtime(
                    "aaaaaaaaaaaa", activate=False
                )
            )

    def test_quadlet_normalization_rejects_hooks_before_start(self) -> None:
        calls = []
        original_environment = "PATH=/target/bin\n"
        trusted_environment = (
            "CONTAINERS_CONF=/dev/null\n"
            "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/20000/bus\n"
            "HOME=/home/secpal-ci\nLANG=C.UTF-8\nLC_ALL=C.UTF-8\n"
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
            "QUADLET_UNIT_DIRS=/etc/containers/systemd/users/20000\n"
            "XDG_RUNTIME_DIR=/run/user/20000\n"
        )
        service_properties = (
            "Environment=CONTAINERS_CONF=/dev/null "
            "CONTAINERS_CONF_OVERRIDE=/dev/null CONTAINERS_CONF_MODULES= "
            "PODMAN_USERNS=\n"
            "EnvironmentFiles=\nPassEnvironment=\nUnsetEnvironment=\n"
            "ExecCondition=\nExecStartPre=\n"
            "ExecStart={ path=/usr/bin/podman ; argv[]=/usr/bin/podman run ; }\n"
            "ExecStartPost={ path=/usr/bin/systemctl ; "
            "argv[]=/usr/bin/systemctl --user set-environment "
            "CONTAINERS_CONF=/tmp/target.conf ; }\n"
            "ExecReload=\n"
            "ExecStop={ path=/usr/bin/podman ; "
            "argv[]=/usr/bin/podman rm -v -f -i ; }\n"
            "ExecStopPost={ path=/usr/bin/podman ; "
            "argv[]=/usr/bin/podman rm -v -f -i ; }\n"
            "Requires=secpal-int-aaaaaaaaaaaa-secrets-volume.service "
            "secpal-int-aaaaaaaaaaaa-postgres-volume.service "
            "secpal-int-aaaaaaaaaaaa-private-storage-volume.service\n"
            "After=podman-user-wait-network-online.service "
            "secpal-int-aaaaaaaaaaaa-secrets-volume.service "
            "secpal-int-aaaaaaaaaaaa-postgres-volume.service "
            "secpal-int-aaaaaaaaaaaa-private-storage-volume.service\n"
        )

        def command_result(arguments, **kwargs):
            calls.append((arguments, kwargs))
            if arguments == ["systemctl", "--user", "show-environment"]:
                seen = sum(
                    item == ["systemctl", "--user", "show-environment"]
                    for item, _ in calls
                )
                output = (
                    original_environment if seen == 1 else trusted_environment
                )
                return 0, output, True
            if arguments[:3] == ["systemctl", "--user", "show"]:
                return 0, service_properties, True
            return 0, "", True

        with mock.patch.object(
            self.collector, "command_result", side_effect=command_result
        ), mock.patch.object(
            self.collector,
            "quadlet_search_paths",
            return_value=["/etc/containers/systemd/users/20000"],
        ), mock.patch.object(
            self.collector,
            "quadlet_source_execution_controls_are_trusted",
            return_value=True,
        ):
            self.assertFalse(
                self.collector.normalize_quadlet_runtime(
                    "aaaaaaaaaaaa", activate=True
                )
            )
        self.assertFalse(
            any(
                arguments == [
                    "systemctl", "--user", "start",
                    "secpal-int-aaaaaaaaaaaa.target",
                ]
                for arguments, _ in calls
            )
        )

    def test_process_census_records_bounded_identity_and_cgroup_facts(self) -> None:
        process = Path("/proc/1234")

        def control_group(pid):
            if pid == os.getpid():
                return (
                    "/user.slice/user-20000.slice/user@20000.service/"
                    "session-collector.scope",
                    True,
                )
            return (
                "/user.slice/user-20000.slice/session-attacker.scope",
                True,
            )

        with mock.patch.object(
            self.collector.Path, "iterdir", return_value=(process,)
        ), mock.patch.object(
            self.collector, "process_control_group", side_effect=control_group
        ), mock.patch.object(
            self.collector,
            "process_host_identity",
            return_value=(210000, 210000, True),
        ), mock.patch.object(
            self.collector.os, "readlink", return_value="/usr/bin/php"
        ):
            facts, complete = self.collector.user_process_facts()
        self.assertTrue(complete)
        self.assertEqual(
            [{
                "executable": "/usr/bin/php",
                "control_group": "/user.slice/user-20000.slice/session-attacker.scope",
                "uid": 210000,
                "gid": 210000,
                "count": 1,
            }],
            facts,
        )

    def test_live_collection_fails_closed_when_user_processes_change_mid_observation(self) -> None:
        hidden = [{
            "executable": "/usr/bin/php",
            "control_group": (
                "/user.slice/user-20000.slice/user@20000.service/"
                "hidden.scope"
            ),
            "uid": 20000,
            "gid": 20000,
            "count": 1,
        }]
        empty_inventory = {"containers": [], "networks": [], "volumes": []}
        with mock.patch.object(
            self.collector, "user_work_facts",
            side_effect=(({"active_units": [], "jobs": []}, True),) * 2,
        ), mock.patch.object(
            self.collector, "user_process_facts",
            side_effect=(([], True), (hidden, True)),
        ), mock.patch.object(
            self.collector, "installed_unit_facts", return_value=([], True)
        ), mock.patch.object(
            self.collector, "generated_service_facts", return_value=([], True)
        ), mock.patch.object(
            self.collector,
            "podman_runtime_facts",
            return_value=(True, "crun", True),
        ), mock.patch.object(
            self.collector,
            "podman_outer_id_maps",
            return_value=(
                [{"container_id": 0, "host_id": 0, "size": 4_294_967_295}],
                [{"container_id": 0, "host_id": 0, "size": 4_294_967_295}],
                True,
            ),
        ), mock.patch.object(
            self.collector, "container_facts", return_value=([], True)
        ), mock.patch.object(
            self.collector, "bind_container_services", return_value=([], True)
        ), mock.patch.object(
            self.collector,
            "resource_inventory",
            return_value=(empty_inventory, True),
        ), mock.patch.object(
            self.collector,
            "lifecycle_guard_facts",
            return_value=({"migration_invocation_count": 0, "podman_api": False}, True),
        ), mock.patch.object(
            self.collector, "control_resource_facts", return_value=({}, True)
        ), mock.patch.object(
            self.collector,
            "quadlet_search_paths",
            return_value=["/etc/containers/systemd/users/20000"],
        ):
            observation = self.collector.collect_live("aaaaaaaaaaaa")
        self.assertFalse(observation["complete"])
        self.assertEqual(hidden, observation["processes"])

    def test_container_identity_is_derived_from_live_kernel_namespace_maps(self) -> None:
        collector_map = [
            {"container_id": 0, "host_id": 0, "size": 4_294_967_295}
        ]
        process_map = [
            {"container_id": 0, "host_id": 20_000, "size": 1},
            {"container_id": 1, "host_id": 200_000, "size": 65_536},
        ]
        with mock.patch.object(
            self.collector,
            "user_namespace_identity",
            side_effect=(
                ("user:[4026531837]", True),
                ("user:[4026540001]", True),
                ("user:[4026540001]", True),
            ),
        ), mock.patch.object(
            self.collector,
            "read_id_map",
            side_effect=(
                (collector_map, True),
                (collector_map, True),
                (process_map, True),
                (process_map, True),
            ),
        ), mock.patch.object(
            self.collector,
            "process_status_facts",
            return_value=(210_000, 210_000, [210_000], True),
        ):
            facts, uid, gid, groups, complete = (
                self.collector.effective_user_namespace_facts(1234)
            )
        self.assertTrue(complete)
        self.assertEqual((10001, 10001, [10001]), (uid, gid, groups))
        self.assertEqual("user:[4026540001]", facts["process_identity"])

        with mock.patch.object(
            self.collector,
            "user_namespace_identity",
            side_effect=(
                ("user:[4026531837]", True),
                ("user:[4026531837]", True),
                ("user:[4026531837]", True),
            ),
        ), mock.patch.object(
            self.collector,
            "read_id_map",
            side_effect=(
                (collector_map, True),
                (collector_map, True),
                (collector_map, True),
                (collector_map, True),
            ),
        ), mock.patch.object(
            self.collector,
            "process_status_facts",
            return_value=(20_000, 20_000, [20_000], True),
        ):
            facts, _, _, _, complete = (
                self.collector.effective_user_namespace_facts(1234)
            )
        self.assertTrue(complete)
        self.assertEqual(facts["collector_identity"], facts["process_identity"])

    def test_supplementary_groups_are_inside_the_exact_identity_boundary(self) -> None:
        observations = valid_observations()
        api = next(
            item for item in observations["live"]["containers"]
            if item["role"] == "api"
        )
        api["group_add"] = []
        api["effective_supplementary_gids"] = [10001]
        self.assertNotIn(
            "D1A_PRIVILEGE_BOUNDARY",
            self.collector.workload_admission_failures(observations),
        )
        api["group_add"] = ["0"]
        self.assertIn(
            "D1A_PRIVILEGE_BOUNDARY",
            self.collector.workload_admission_failures(observations),
        )
        api["group_add"] = []
        api["effective_supplementary_gids"] = [0, 10001]
        self.assertIn(
            "D1A_PRIVILEGE_BOUNDARY",
            self.collector.workload_admission_failures(observations),
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
            2,
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

    def test_target_phases_restore_the_fixed_user_bus_environment(self) -> None:
        runner = RUNNER_PATH.read_text(encoding="utf-8")
        helper = runner.split("run_target_phase()", 1)[1].split(
            "run_target_host()", 1
        )[0]
        self.assertIn('[[ -S /run/user/20000/bus ]]', helper)
        self.assertIn("XDG_RUNTIME_DIR=/run/user/20000", helper)
        self.assertIn(
            "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/20000/bus",
            helper,
        )

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
        self.assertNotIn("migration", observation)

    def test_target_entrypoint_has_closed_versioned_phase_parser(self) -> None:
        target = TARGET_PATH.read_text(encoding="utf-8")
        self.assertIn('[[ "$#" -eq 2 && "$1" == v1 ]]', target)
        self.assertIn("host | workload-prepare-start | workload-cleanup", target)
        self.assertNotIn("eval", target)
        self.assertNotIn("source ", target)


if __name__ == "__main__":
    unittest.main()
