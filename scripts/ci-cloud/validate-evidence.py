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
from pathlib import Path
from typing import NoReturn

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError


MAX_EVIDENCE_BYTES = 262_144
WORKLOAD_COLLECTOR_PATH = Path(__file__).with_name("collect-workload-evidence.py")
WORKLOAD_ADMISSION_PATH = Path(__file__).with_name("workload-admission.py")
WORKLOAD_PURITY_PATH = Path(__file__).with_name("workload-purity.py")
_PURITY_MODULE = None
SCHEMA_PATH = Path(__file__).resolve().parents[2] / "schemas" / "ci-cloud-evidence.schema.json"
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
    if path in {WORKLOAD_COLLECTOR_PATH, WORKLOAD_ADMISSION_PATH}:
        load_workload_purity().check_files(path.parent)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        fail("trusted admission implementation is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_workload_purity():
    global _PURITY_MODULE
    if _PURITY_MODULE is not None:
        return _PURITY_MODULE
    spec = importlib.util.spec_from_file_location(
        "trusted_workload_purity", WORKLOAD_PURITY_PATH
    )
    if spec is None or spec.loader is None:
        fail("PURITY_SOURCE_INVALID")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _PURITY_MODULE = module
    return module


def recompute_admission(
    document: dict[str, object],
) -> list[str]:
    test = document["test"]
    assert isinstance(test, dict)
    workload_module = load_trusted_module(
        WORKLOAD_ADMISSION_PATH, "ci_cloud_workload_admission"
    )
    try:
        workload_failures = load_workload_purity().guarded_decision(
            workload_module, document["workload"]
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
    workload_failures.extend(
        invariant for value, invariant in workload_status_invariants if value != 0
    )
    workload_failures = list(dict.fromkeys(workload_failures))
    return workload_failures


def validate_document(document: object) -> dict[str, object]:
    reject_sensitive(document)
    root = exact_keys(
        document,
        {
            "schema_version", "workflow", "test", "workload",
        },
        "$",
    )
    if root["schema_version"] != 5:
        fail("unsupported evidence schema version")
    workflow = exact_keys(root["workflow"], {"repository", "run_id", "run_attempt", "target_sha"}, "$.workflow")
    test = exact_keys(
        root["test"],
        {
            "normalization_diagnostics",
            "phase_exit_statuses",
            "collection_exit_statuses",
            "result",
            "failed_admission_invariants",
        },
        "$.test",
    )
    phase_statuses = exact_keys(
        test["phase_exit_statuses"],
        {
            "workload_prepare_start", "workload_cleanup",
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
            not in workload_module.NORMALIZATION_STAGES
            or diagnostic["failure_reason"]
            not in workload_module.NORMALIZATION_FAILURE_REASONS
            or (diagnostic["failure_reason"] == "command-exit")
            != (command_status is not None)
        ):
            fail("failed normalization diagnostic is inconsistent")
    workload = exact_keys(
        root["workload"],
        {
            "protocol_version", "claim_scope", "database_scope",
            "target_sha", "instance", "result",
            "failed_admission_invariants", "baseline", "live", "post_cleanup",
        },
        "$.workload",
    )
    if (
        workload["claim_scope"]
        != "disposable-rootless-application-integration"
        or workload["database_scope"]
        != "disposable-postgresql-18-fixture"
    ):
        fail("workload evidence overstates its integration-only authority")
    baseline = exact_keys(
        workload["baseline"],
        {
            "phase", "target_sha", "target_admitted", "collector_uid", "collector_gid",
            "complete", "containers", "networks", "volumes",
            "migration_invocation_count", "podman_api", "user_work",
            "processes", "control_resources",
        },
        "$.workload.baseline",
    )
    live = exact_keys(
        workload["live"],
        {
            "phase", "target_sha", "target_admitted", "collector_uid", "collector_gid",
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
            "phase", "target_sha", "target_admitted", "collector_uid", "collector_gid",
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
                {"container_id", "timer", "service", "interval_usec"},
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
            unit, {"name", "path", "uid", "gid", "mode", "sha256", "image"},
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
                "effective_caps", "bounding_caps", "selinux_process_label",
                "selinux_mount_label", "effective_process_label",
                "effective_seccomp_mode", "devices_present",
                "mounts", "tmpfs", "remote_api_environment", "security_opt",
                "lifecycle_events", "networks", "published_ports", "auto_update", "systemd_unit",
                "container_cgroup", "lifecycle_service_invocation", "image",
                "image_id", "image_digest",
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
    if workflow["repository"] != "SecPal/deployment" or re.fullmatch(r"[0-9a-f]{40}", str(workflow["target_sha"])) is None:
        fail("workflow identity is invalid")
    if workload["instance"] != str(workflow["target_sha"])[:12]:
        fail("workload instance does not match the exact target SHA")
    if (
        workload["target_sha"] != workflow["target_sha"]
        or any(
            observation["target_sha"] != workflow["target_sha"]
            for observation in (baseline, live, post_cleanup)
        )
    ):
        fail("workload observations do not match the exact target SHA")
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
    workload_failures = recompute_admission(root)
    if workload["failed_admission_invariants"] != workload_failures or (
        workload["result"] != ("passed" if not workload_failures else "failed")
    ):
        fail("workload admission failures do not match independent observations")
    expected_result = "passed" if not workload_failures else "failed"
    if test["result"] != expected_result:
        fail("result contradicts phase status or admission failures")
    if [str(item) for item in failures] != workload_failures:
        fail("result or admission failures contradicts effective facts")
    validate_declared_schema(root)
    return root


def write_summary(document: dict[str, object], path: Path) -> None:
    workflow = document["workflow"]
    test = document["test"]
    workload = document["workload"]
    failures = test["failed_admission_invariants"]
    lines = [
        "# Disposable rootless application-workload evidence",
        "",
        f"- Result: `{test['result']}`",
        f"- Target SHA: `{workflow['target_sha']}`",
        "- Scope: disposable integration; independent Rocky host qualification is required separately.",
        f"- Workload phase statuses: `{json.dumps(test['phase_exit_statuses'], sort_keys=True, separators=(',', ':'))}`",
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
