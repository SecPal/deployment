#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Validate closed cloud evidence and write a concise non-secret summary."""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import NoReturn

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError


MAX_EVIDENCE_BYTES = 262_144
COLLECTOR_PATH = Path(__file__).with_name("collect-host-evidence.py")
WORKLOAD_COLLECTOR_PATH = Path(__file__).with_name("collect-workload-evidence.py")
SCHEMA_PATH = Path(__file__).resolve().parents[2] / "schemas" / "ci-cloud-evidence.schema.json"
RUNTIME_PACKAGE_NAMES = {
    "podman", "conmon", "crun", "catatonit", "netavark", "aardvark-dns", "passt",
    "uidmap", "dbus-user-session", "dirmngr", "gpg", "gpg-agent",
    "openssh-client",
}
BOOTSTRAP_PACKAGE_NAMES = {
    "aardvark-dns", "apparmor", "apparmor-utils", "catatonit", "crun", "curl",
    "dbus-user-session", "dirmngr", "git", "gh", "gpg", "gpg-agent", "jq",
    "netavark", "openssh-client", "passt", "podman", "python3",
    "python3-jsonschema", "python3-yaml", "uidmap", "unattended-upgrades",
}
FORBIDDEN_KEY = re.compile(r"(?:authorization|credential|password|private.?key|secret|token)", re.IGNORECASE)
FORBIDDEN_VALUE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|"
    r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})\b|"
    r"\b(?:Basic|Bearer) [A-Za-z0-9._~+/=-]{8,}|"
    r"[a-z][a-z0-9+.-]*://[^/@\s]+:[^/@\s]+@",
    re.IGNORECASE,
)


class DuplicateJSONKey(ValueError):
    pass


def fail(message: str) -> NoReturn:
    raise ValueError(message)


def exact_json_loads(payload: bytes) -> object:
    def reject_duplicate_keys(
        pairs: list[tuple[str, object]],
    ) -> dict[str, object]:
        document: dict[str, object] = {}
        for key, value in pairs:
            if key in document:
                raise DuplicateJSONKey(key)
            document[key] = value
        return document

    return json.loads(payload, object_pairs_hook=reject_duplicate_keys)


def exact_keys(value: object, expected: set[str], path: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(f"{path} is incomplete or contains unknown fields")
    return value


def reject_sensitive(value: object, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if FORBIDDEN_KEY.search(str(key)):
                fail(f"credential-like field is forbidden at {path}")
            reject_sensitive(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_sensitive(child, f"{path}[{index}]")
    elif isinstance(value, str) and FORBIDDEN_VALUE.search(value):
        fail(f"credential-like value is forbidden at {path}")


def validate_declared_schema(document: object) -> None:
    try:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        errors = list(
            Draft202012Validator(
                schema,
                format_checker=FormatChecker(),
            ).iter_errors(document)
        )
    except (OSError, UnicodeError, json.JSONDecodeError, SchemaError):
        fail("declared evidence schema is unavailable or invalid")
    if errors:
        first = min(errors, key=lambda error: tuple(str(item) for item in error.path))
        location = "$" + "".join(f"[{item!r}]" for item in first.path)
        fail(f"document violates declared schema at {location}")


def load_trusted_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        fail("trusted admission implementation is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def recompute_admission(
    document: dict[str, object],
) -> tuple[list[str], list[str], list[str]]:
    module = load_trusted_module(COLLECTOR_PATH, "ci_cloud_evidence_collector")
    test = document["test"]
    assert isinstance(test, dict)
    effective_facts = {
        name: document[name] for name in ("platform", "apt", "host", "runtime")
    }
    try:
        host_failures = module.admission_failures(
            effective_facts, str(test["profile"])
        )
    except (AttributeError, KeyError, TypeError, ValueError):
        fail("effective facts are malformed")
    workload_module = load_trusted_module(
        WORKLOAD_COLLECTOR_PATH, "ci_cloud_workload_evidence_collector"
    )
    try:
        workload_failures = workload_module.workload_admission_failures(
            document["workload"]
        )
        phase_statuses = test["phase_exit_statuses"]
        collection_statuses = test["collection_exit_statuses"]
        workload_status_invariants = (
            (
                phase_statuses["workload_prepare_start"],
                "TARGET_WORKLOAD_PREPARE_START",
            ),
            (phase_statuses["workload_cleanup"], "TARGET_WORKLOAD_CLEANUP"),
            (
                phase_statuses["trusted_quadlet_normalize_live"],
                "TRUSTED_QUADLET_NORMALIZE_LIVE",
            ),
            (
                phase_statuses["trusted_quadlet_normalize_cleanup"],
                "TRUSTED_QUADLET_NORMALIZE_CLEANUP",
            ),
            (collection_statuses["baseline"], "TRUSTED_BASELINE_COLLECTION"),
            (collection_statuses["live"], "TRUSTED_LIVE_COLLECTION"),
            (
                collection_statuses["post_cleanup"],
                "TRUSTED_POST_CLEANUP_COLLECTION",
            ),
        )
    except (AttributeError, KeyError, TypeError, ValueError):
        fail("workload evidence is malformed")
    if phase_statuses["host"] != 0:
        host_failures.append("TARGET_HOST_CONTRACT")
    host_failures = list(dict.fromkeys(host_failures))
    workload_failures.extend(
        invariant for value, invariant in workload_status_invariants if value != 0
    )
    workload_failures = list(dict.fromkeys(workload_failures))
    overall = list(dict.fromkeys([*host_failures, *workload_failures]))
    return host_failures, workload_failures, overall


def validate_document(document: object) -> dict[str, object]:
    reject_sensitive(document)
    root = exact_keys(
        document,
        {
            "schema_version", "workflow", "test", "host_admission",
            "platform", "apt", "host", "runtime", "workload",
        },
        "$",
    )
    if root["schema_version"] != 3:
        fail("unsupported evidence schema version")
    workflow = exact_keys(root["workflow"], {"repository", "run_id", "run_attempt", "target_sha"}, "$.workflow")
    test = exact_keys(
        root["test"],
        {
            "provider",
            "region",
            "profile",
            "machine_type",
            "provider_image",
            "started_at",
            "ended_at",
            "normalization_diagnostics",
            "phase_exit_statuses",
            "collection_exit_statuses",
            "result",
            "failed_admission_invariants",
        },
        "$.test",
    )
    host_admission = exact_keys(
        root["host_admission"],
        {"result", "failed_admission_invariants"},
        "$.host_admission",
    )
    phase_statuses = exact_keys(
        test["phase_exit_statuses"],
        {
            "host", "workload_prepare_start", "workload_cleanup",
            "trusted_quadlet_normalize_live",
            "trusted_quadlet_normalize_cleanup",
        },
        "$.test.phase_exit_statuses",
    )
    collection_statuses = exact_keys(
        test["collection_exit_statuses"],
        {"baseline", "live", "post_cleanup"},
        "$.test.collection_exit_statuses",
    )
    normalization_diagnostics = exact_keys(
        test["normalization_diagnostics"],
        {"live", "cleanup"},
        "$.test.normalization_diagnostics",
    )
    workload_module = load_trusted_module(
        WORKLOAD_COLLECTOR_PATH, "ci_cloud_normalization_contract"
    )
    for mode, phase_name in (
        ("live", "trusted_quadlet_normalize_live"),
        ("cleanup", "trusted_quadlet_normalize_cleanup"),
    ):
        diagnostic = exact_keys(
            normalization_diagnostics[mode],
            {"mode", "status", "stage", "failure_reason", "command_status"},
            f"$.test.normalization_diagnostics.{mode}",
        )
        diagnostic_status = diagnostic["status"]
        command_status = diagnostic["command_status"]
        if (
            diagnostic["mode"] != mode
            or type(diagnostic_status) is not int
            or diagnostic_status not in {0, 1}
            or type(diagnostic["stage"]) is not str
            or not isinstance(diagnostic["failure_reason"], (str, type(None)))
            or (
                command_status is not None
                and (type(command_status) is not int or not 0 < command_status <= 255)
            )
        ):
            fail("normalization diagnostic is outside the closed contract")
        if diagnostic_status == 0:
            if (
                phase_statuses[phase_name] != 0
                or diagnostic["stage"] != "complete"
                or diagnostic["failure_reason"] is not None
                or command_status is not None
            ):
                fail("successful normalization diagnostic is inconsistent")
        elif (
            phase_statuses[phase_name] == 0
            or diagnostic["stage"]
            not in workload_module.NORMALIZATION_EVIDENCE_STAGES
            or diagnostic["failure_reason"]
            not in workload_module.NORMALIZATION_FAILURE_REASONS
            or (diagnostic["failure_reason"] == "command-exit")
            != (command_status is not None)
        ):
            fail("failed normalization diagnostic is inconsistent")
    platform = exact_keys(
        root["platform"],
        {"os_release", "architecture", "uname", "kernel", "cpu", "virtualization", "logical_cpu", "memory_bytes", "root_filesystem_bytes"},
        "$.platform",
    )
    apt = exact_keys(
        root["apt"],
        {
            "source_files",
            "source_hosts",
            "configured_suites",
            "release_origins",
            "verified_release_suites",
            "release_signatures_verified",
            "debian_archive_keyring_version",
            "runtime_packages",
            "bootstrap_packages",
            "forbidden_packages_present",
        },
        "$.apt",
    )
    host = exact_keys(
        root["host"],
        {
            "kernel_package",
            "filesystem",
            "security_updates",
            "required_tools",
            "clock",
            "ssh",
            "cloud_identity",
        },
        "$.host",
    )
    runtime = exact_keys(
        root["runtime"],
        {
            "podman",
            "crun_version",
            "crun_features",
            "netavark_version",
            "aardvark_version",
            "pasta_version",
            "passt_version",
            "uidmap",
            "cgroup_version",
            "systemd_version",
            "apparmor_host",
            "systemd_user",
            "quadlet",
            "storage",
            "api",
            "updates",
            "registries",
        },
        "$.runtime",
    )
    workload = exact_keys(
        root["workload"],
        {
            "protocol_version", "instance", "result",
            "failed_admission_invariants", "baseline", "live", "post_cleanup",
        },
        "$.workload",
    )
    baseline = exact_keys(
        workload["baseline"],
        {
            "phase", "target_admitted", "collector_uid", "collector_gid",
            "complete", "containers", "networks", "volumes",
            "migration_invocation_count", "podman_api", "user_work",
            "processes", "control_resources",
        },
        "$.workload.baseline",
    )
    live = exact_keys(
        workload["live"],
        {
            "phase", "target_admitted", "collector_uid", "collector_gid",
            "complete", "quadlet_search_paths", "installed_units",
            "generated_services", "containers", "networks",
            "volumes", "all_containers", "all_networks", "all_volumes",
            "podman_rootless", "oci_runtime",
            "podman_api", "user_work", "processes", "control_resources",
        },
        "$.workload.live",
    )
    post_cleanup = exact_keys(
        workload["post_cleanup"],
        {
            "phase", "target_admitted", "collector_uid", "collector_gid",
            "complete", "owned_units", "generated_services", "containers",
            "networks", "volumes", "all_containers", "all_networks",
            "all_volumes", "migration_invocation_count", "podman_api",
            "user_work", "processes", "control_resources",
        },
        "$.workload.post_cleanup",
    )
    for work_path, user_work in (
        ("$.workload.baseline.user_work", baseline["user_work"]),
        ("$.workload.live.user_work", live["user_work"]),
        ("$.workload.post_cleanup.user_work", post_cleanup["user_work"]),
    ):
        work = exact_keys(
            user_work,
            {"active_units", "jobs", "podman_health_timers"},
            work_path,
        )
        timers = work["podman_health_timers"]
        if not isinstance(timers, list):
            fail(f"{work_path}.podman_health_timers must be a list")
        for timer_index, timer in enumerate(timers):
            exact_keys(
                timer,
                {"container_id", "timer", "service"},
                f"{work_path}.podman_health_timers[{timer_index}]",
            )
    for path, controls in (
        ("$.workload.baseline.control_resources", baseline["control_resources"]),
        ("$.workload.live.control_resources", live["control_resources"]),
        (
            "$.workload.post_cleanup.control_resources",
            post_cleanup["control_resources"],
        ),
    ):
        exact_keys(
            controls,
            {
                "network_present", "volume_present", "network_id",
                "volume_created_at",
            },
            path,
        )
    for index, unit in enumerate(live["installed_units"] if isinstance(live["installed_units"], list) else []):
        exact_keys(
            unit, {"name", "path", "uid", "gid", "mode", "sha256"},
            f"$.workload.live.installed_units[{index}]",
        )
    for index, service in enumerate(live["generated_services"] if isinstance(live["generated_services"], list) else []):
        service_fact = exact_keys(
            service,
            {
                "logical_name", "unit", "fragment_path", "fragment_uid", "fragment_gid",
                "fragment_mode", "drop_in_paths", "drop_in_owners", "active_state",
                "sub_state", "result", "exec_main_status", "main_pid", "control_group",
                "invocation_id", "source_path", "fragment_sha256",
                "drop_in_sha256", "environment",
            },
            f"$.workload.live.generated_services[{index}]",
        )
        for owner_index, owner in enumerate(
            service_fact["drop_in_owners"]
            if isinstance(service_fact["drop_in_owners"], list) else []
        ):
            exact_keys(
                owner, {"uid", "gid", "mode"},
                f"$.workload.live.generated_services[{index}].drop_in_owners[{owner_index}]",
            )
    for index, container in enumerate(live["containers"] if isinstance(live["containers"], list) else []):
        exact_keys(
            container,
            {
                "id", "role", "name", "state", "pid", "exit_code", "health", "oci_runtime",
                "rootless", "privileged", "configured_user", "effective_uid",
                "effective_gid", "effective_supplementary_gids",
                "read_only_rootfs", "entrypoint", "command",
                "healthcheck_command", "pid_mode", "user_namespace",
                "ipc_mode", "uts_mode", "network_mode", "cap_add", "group_add",
                "effective_caps", "bounding_caps", "devices_present",
                "mounts", "tmpfs", "remote_api_environment", "security_opt",
                "lifecycle_events", "networks", "published_ports", "auto_update", "systemd_unit",
                "container_cgroup", "lifecycle_service_invocation", "image",
            },
            f"$.workload.live.containers[{index}]",
        )
        namespace = exact_keys(
            container["user_namespace"],
            {
                "compat_mode", "create_options", "process_identity",
                "collector_identity", "uid_map", "gid_map",
                "collector_uid_map", "collector_gid_map",
                "configured_uid_map", "configured_gid_map", "podman_uid_map",
                "podman_gid_map",
            },
            f"$.workload.live.containers[{index}].user_namespace",
        )
        for map_name in (
            "uid_map", "gid_map", "collector_uid_map", "collector_gid_map",
            "configured_uid_map", "configured_gid_map", "podman_uid_map",
            "podman_gid_map",
        ):
            for map_index, mapping in enumerate(
                namespace[map_name]
                if isinstance(namespace[map_name], list) else []
            ):
                exact_keys(
                    mapping,
                    {"container_id", "host_id", "size"},
                    (
                        f"$.workload.live.containers[{index}].user_namespace."
                        f"{map_name}[{map_index}]"
                    ),
                )
        for mount_index, mount in enumerate(
            container["mounts"] if isinstance(container["mounts"], list) else []
        ):
            exact_keys(
                mount,
                {"type", "source", "destination", "rw"},
                f"$.workload.live.containers[{index}].mounts[{mount_index}]",
            )
        for event_index, event in enumerate(
            container["lifecycle_events"]
            if isinstance(container["lifecycle_events"], list)
            else []
        ):
            exact_keys(
                event,
                {"status", "time_nano"},
                f"$.workload.live.containers[{index}].lifecycle_events[{event_index}]",
            )
        for tmpfs_index, tmpfs in enumerate(
            container["tmpfs"] if isinstance(container["tmpfs"], list) else []
        ):
            exact_keys(
                tmpfs,
                {"destination", "size_bytes", "mode", "uid", "gid", "flags"},
                f"$.workload.live.containers[{index}].tmpfs[{tmpfs_index}]",
            )
    for phase_name, observation in (
        ("baseline", baseline),
        ("live", live),
        ("post_cleanup", post_cleanup),
    ):
        for index, process in enumerate(
            observation["processes"]
            if isinstance(observation["processes"], list) else []
        ):
            exact_keys(
                process,
                {"executable", "control_group", "uid", "gid", "count"},
                f"$.workload.{phase_name}.processes[{index}]",
            )
    exact_keys(platform["os_release"], {"ID", "VERSION_ID", "VERSION_CODENAME", "PRETTY_NAME"}, "$.platform.os_release")
    exact_keys(platform["cpu"], {"vendor", "model"}, "$.platform.cpu")
    exact_keys(test["provider_image"], {"slug", "id"}, "$.test.provider_image")
    podman = exact_keys(runtime["podman"], {"version", "rootless", "seccomp_enabled", "apparmor_enabled", "oci_runtime", "network_backend", "rootless_network_command", "cgroup_version"}, "$.runtime.podman")
    uidmap = exact_keys(
        runtime["uidmap"],
        {"newuidmap", "newgidmap", "subuid", "subgid", "mapping_effective"},
        "$.runtime.uidmap",
    )
    for name in ("subuid", "subgid"):
        exact_keys(
            uidmap[name],
            {"start", "count", "entry_count", "overlap"},
            f"$.runtime.uidmap.{name}",
        )
    exact_keys(runtime["apparmor_host"], {"kernel_enabled", "loaded_profiles", "enforcing_profiles"}, "$.runtime.apparmor_host")
    exact_keys(
        runtime["systemd_user"],
        {
            "manager_available",
            "starts_at_boot",
            "linger_enabled",
            "dbus_session_available",
            "runtime_directory",
            "runtime_directory_uid",
            "runtime_directory_gid",
            "runtime_directory_mode",
        },
        "$.runtime.systemd_user",
    )
    exact_keys(
        runtime["quadlet"],
        {
            "generator_path",
            "effective_search_paths",
            "definitions_uid",
            "definitions_gid",
            "definitions_mode",
            "tree_symlinks_present",
            "service_account_can_write",
        },
        "$.runtime.quadlet",
    )
    exact_keys(runtime["storage"], {"driver", "graphroot", "runroot"}, "$.runtime.storage")
    exact_keys(
        runtime["api"],
        {
            "system_service_active",
            "system_service_enabled",
            "system_socket_active",
            "system_socket_enabled",
            "user_service_active",
            "user_service_enabled",
            "user_socket_active",
            "user_socket_enabled",
            "tcp_listener",
            "unix_listener",
            "service_process",
            "process_scan_incomplete",
            "listener_scan_incomplete",
            "connection_scan_incomplete",
            "remote_connection",
        },
        "$.runtime.api",
    )
    exact_keys(
        runtime["updates"],
        {"auto_update_timer_enabled", "auto_update_timer_active"},
        "$.runtime.updates",
    )
    exact_keys(
        runtime["registries"],
        {"ghcr_insecure", "secpal_mirrors", "secpal_location_rewrite"},
        "$.runtime.registries",
    )
    exact_keys(
        host["kernel_package"],
        {
            "name",
            "version",
            "architecture",
            "origin",
            "suite",
            "owned",
            "status",
            "maintainer",
            "database_files_safe",
            "files_verified",
            "provenance_basis",
        },
        "$.host.kernel_package",
    )
    exact_keys(
        host["filesystem"],
        {"type", "read_only", "overlayfs_supported", "d_type"},
        "$.host.filesystem",
    )
    exact_keys(
        host["security_updates"],
        {
            "mechanism",
            "automatic",
            "timer_enabled",
            "security_suite",
            "normal_updates_automatic",
            "major_release_upgrades_automatic",
            "automatic_reboot",
            "runtime_packages_excluded",
        },
        "$.host.security_updates",
    )
    exact_keys(host["required_tools"], {"present", "missing"}, "$.host.required_tools")
    exact_keys(host["clock"], {"synchronized"}, "$.host.clock")
    exact_keys(host["ssh"], {"root_login_denied"}, "$.host.ssh")
    exact_keys(
        host["cloud_identity"],
        {"probe_supported", "probe_succeeded", "identity_present"},
        "$.host.cloud_identity",
    )
    if workflow["repository"] != "SecPal/deployment" or re.fullmatch(r"[0-9a-f]{40}", str(workflow["target_sha"])) is None:
        fail("workflow identity is invalid")
    if workload["instance"] != str(workflow["target_sha"])[:12]:
        fail("workload instance does not match the exact target SHA")
    provider_identity = (
        test["provider"],
        test["region"],
        test["profile"],
        test["machine_type"],
        test["provider_image"]["slug"],
    )
    allowed_identities = {
        (
            "digitalocean",
            "fra1",
            "intel",
            "s-4vcpu-8gb-intel",
            "debian-13-x64",
        ),
        (
            "digitalocean",
            "fra1",
            "amd",
            "s-4vcpu-8gb-amd",
            "debian-13-x64",
        ),
        (
            "gcp",
            "europe-west3-a",
            "axion",
            "c4a-standard-4",
            "debian-cloud/debian-13-arm64",
        ),
    }
    if provider_identity not in allowed_identities:
        fail("provider identity is outside the closed allowlist")
    provider_image_id = test["provider_image"]["id"]
    if not isinstance(provider_image_id, str) or (
        test["provider"] == "digitalocean"
        and re.fullmatch(r"[1-9][0-9]{0,19}", provider_image_id) is None
    ) or (
        test["provider"] == "gcp"
        and re.fullmatch(
            r"https://www\.googleapis\.com/compute/v1/projects/debian-cloud/"
            r"global/images/debian-13-trixie-arm64-v[0-9]{8}",
            provider_image_id,
        )
        is None
    ):
        fail("provider image identity is inconsistent with the provider")
    for name in ("started_at", "ended_at"):
        try:
            datetime.fromisoformat(str(test[name]).replace("Z", "+00:00"))
        except ValueError:
            fail(f"{name} is not an RFC 3339 timestamp")
    failures = test["failed_admission_invariants"]
    if (
        not isinstance(failures, list)
        or len(failures) != len(set(str(item) for item in failures))
        or not all(re.fullmatch(r"[A-Z0-9_]+", str(item)) for item in failures)
    ):
        fail("failed admission invariants are malformed")
    for value in [*phase_statuses.values(), *collection_statuses.values()]:
        if type(value) is not int or not 0 <= value <= 255:
            fail("phase status is malformed")
    for field, expected_names in (
        ("runtime_packages", RUNTIME_PACKAGE_NAMES),
        ("bootstrap_packages", BOOTSTRAP_PACKAGE_NAMES),
    ):
        package_facts = apt[field]
        if not isinstance(package_facts, dict) or set(package_facts) != expected_names:
            fail(f"{field.replace('_', ' ')} provenance is incomplete")
        for name, package in package_facts.items():
            exact_keys(
                package,
                {"version", "architecture", "origin", "suite"},
                f"$.apt.{field}.{name}",
            )
    host_failures, workload_failures, overall_failures = recompute_admission(root)
    if host_admission["failed_admission_invariants"] != host_failures or (
        host_admission["result"] != ("passed" if not host_failures else "failed")
    ):
        fail("host admission failures do not match effective facts for D.1")
    if workload["failed_admission_invariants"] != workload_failures or (
        workload["result"] != ("passed" if not workload_failures else "failed")
    ):
        fail("workload admission failures do not match independent D.1a observations")
    expected_result = "passed" if not overall_failures else "failed"
    if test["result"] != expected_result:
        fail("result contradicts phase status or admission failures")
    if [str(item) for item in failures] != overall_failures:
        fail("result or admission failures contradicts effective facts")
    validate_declared_schema(root)
    if podman["apparmor_enabled"] is not None and not isinstance(podman["apparmor_enabled"], bool):
        fail("Podman AppArmor capability must remain distinct boolean evidence")
    return root


def write_summary(document: dict[str, object], path: Path) -> None:
    workflow = document["workflow"]
    test = document["test"]
    platform = document["platform"]
    runtime = document["runtime"]
    apt = document["apt"]
    host = document["host"]
    host_admission = document["host_admission"]
    workload = document["workload"]
    assert isinstance(workflow, dict) and isinstance(test, dict)
    assert isinstance(platform, dict) and isinstance(runtime, dict)
    assert isinstance(apt, dict) and isinstance(host, dict)
    assert isinstance(host_admission, dict) and isinstance(workload, dict)
    podman = runtime["podman"]
    apparmor = runtime["apparmor_host"]
    provider_image = test["provider_image"]
    cloud_identity = host["cloud_identity"]
    kernel_package = host["kernel_package"]
    assert isinstance(podman, dict) and isinstance(apparmor, dict)
    assert isinstance(provider_image, dict) and isinstance(cloud_identity, dict)
    assert isinstance(kernel_package, dict)
    kernel_source = (
        f"{kernel_package['origin']}/{kernel_package['suite']}"
        if kernel_package["provenance_basis"] == "active-apt-policy"
        else "unavailable from authenticated APT policy"
    )
    failures = test["failed_admission_invariants"]
    assert isinstance(failures, list)
    lines = [
        "# Debian 13 cloud conformance evidence",
        "",
        f"- Result: `{test['result']}`",
        f"- D.1 production-host admission: `{host_admission['result']}`",
        f"- D.1a workload admission: `{workload['result']}`",
        f"- Target SHA: `{workflow['target_sha']}`",
        f"- Provider/profile: `{test['provider']}/{test['profile']}` in `{test['region']}`",
        f"- Machine type: `{test['machine_type']}`",
        f"- Provider image: `{provider_image['slug']}` resolved to `{provider_image['id']}`",
        f"- Platform: `{platform['architecture']}` / `{platform['kernel']}`",
        f"- Kernel package: `{kernel_package['name']}` via `{kernel_package['provenance_basis']}` from `{kernel_source}`; files verified `{kernel_package['files_verified']}`",
        f"- APT releases: `{', '.join(apt['verified_release_suites'])}`; signatures `{apt['release_signatures_verified']}`",
        f"- Security updates: `{host['security_updates']['mechanism']}`; automatic `{host['security_updates']['automatic']}`; reboot `{host['security_updates']['automatic_reboot']}`",
        f"- CPU: `{platform['cpu']['vendor']} {platform['cpu']['model']}`",
        f"- Podman: `{podman['version']}`; rootless `{podman['rootless']}`",
        f"- OCI/network: `{podman['oci_runtime']}` / `{podman['network_backend']}` / `{podman['rootless_network_command']}`",
        f"- Host AppArmor: kernel `{apparmor['kernel_enabled']}`, enforcing profiles `{apparmor['enforcing_profiles']}`",
        f"- Rootless Podman AppArmor capability: `{podman['apparmor_enabled']}`",
        f"- Podman seccomp: `{podman['seccomp_enabled']}`",
        f"- Root SSH denied: `{host['ssh']['root_login_denied']}`",
        f"- VM cloud identity present: `{cloud_identity['identity_present']}`",
        f"- Lifecycle phase statuses: `{json.dumps(test['phase_exit_statuses'], sort_keys=True, separators=(',', ':'))}`",
        f"- Collector phase statuses: `{json.dumps(test['collection_exit_statuses'], sort_keys=True, separators=(',', ':'))}`",
        f"- Trusted Quadlet normalization diagnostics: `{json.dumps(test['normalization_diagnostics'], sort_keys=True, separators=(',', ':'))}`",
        f"- Workload instance: `{workload['instance']}`; baseline containers `{len(workload['baseline']['containers'])}`; live containers `{len(workload['live']['containers'])}`; post-cleanup containers `{len(workload['post_cleanup']['containers'])}`",
        f"- Failed admission invariants: `{', '.join(str(item) for item in failures) if failures else 'none'}`",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    parser.add_argument("summary", type=Path)
    parser.add_argument("--require-passed", action="store_true")
    arguments = parser.parse_args()
    try:
        payload = arguments.evidence.read_bytes()
        if not payload or len(payload) > MAX_EVIDENCE_BYTES:
            fail("evidence is empty or exceeds 256 KiB")
        document = validate_document(exact_json_loads(payload))
        write_summary(document, arguments.summary)
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        DuplicateJSONKey,
        ValueError,
    ) as error:
        print(f"ERROR: evidence validation failed closed: {error}", file=sys.stderr)
        return 1
    test = document["test"]
    assert isinstance(test, dict)
    print(f"Cloud evidence is complete and reports result={test['result']}.")
    return 1 if arguments.require_passed and test["result"] != "passed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
