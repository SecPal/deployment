#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Trusted controller-side admission of current normalized workload facts.

The target-streamed collector exports only the closed contract below. Importing
it defines functions and constants; admission never calls its collection surface.
"""

from __future__ import annotations

import importlib.util
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any


COLLECTOR_PATH = Path(__file__).with_name("collect-workload-evidence.py")


def load_contract() -> Mapping[str, object]:
    spec = importlib.util.spec_from_file_location("ci_cloud_workload_contract", COLLECTOR_PATH)
    if spec is None or spec.loader is None:
        raise ValueError("workload contract is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.ADMISSION_CONTRACT


_CONTRACT = load_contract()
API_DIGEST = _CONTRACT["API_DIGEST"]
BASELINE_OBSERVATION_FIELDS = _CONTRACT["BASELINE_OBSERVATION_FIELDS"]
CI_GID = _CONTRACT["CI_GID"]
CI_UID = _CONTRACT["CI_UID"]
CLEANUP_OBSERVATION_FIELDS = _CONTRACT["CLEANUP_OBSERVATION_FIELDS"]
CONTROL_NETWORK = _CONTRACT["CONTROL_NETWORK"]
CONTROL_VOLUME = _CONTRACT["CONTROL_VOLUME"]
FRONTEND_DIGEST = _CONTRACT["FRONTEND_DIGEST"]
GENERATED_LOGICAL_NAMES = _CONTRACT["GENERATED_LOGICAL_NAMES"]
GENERATOR_ROOT = _CONTRACT["GENERATOR_ROOT"]
HEALTHY_ROLES = _CONTRACT["HEALTHY_ROLES"]
HEALTH_INTERVAL_USEC = _CONTRACT["HEALTH_INTERVAL_USEC"]
LIVE_OBSERVATION_FIELDS = _CONTRACT["LIVE_OBSERVATION_FIELDS"]
NETWORK_KINDS = _CONTRACT["NETWORK_KINDS"]
OPAQUE_PROCESS_EXECUTABLE = _CONTRACT["OPAQUE_PROCESS_EXECUTABLE"]
PODMAN_54_HEALTH_TIMER_SUFFIX = _CONTRACT["PODMAN_54_HEALTH_TIMER_SUFFIX"]
PODMAN_NETWORK_ONLINE_UNIT = _CONTRACT["PODMAN_NETWORK_ONLINE_UNIT"]
QUADLET_ROOT = _CONTRACT["QUADLET_ROOT"]
READY_ROLES = _CONTRACT["READY_ROLES"]
ROLES = _CONTRACT["ROLES"]
ROLE_CONTRACTS = _CONTRACT["ROLE_CONTRACTS"]
SYSTEMD_ROOT = _CONTRACT["SYSTEMD_ROOT"]
TRUSTED_CONTAINER_SERVICE_ENVIRONMENT_NAMES = _CONTRACT["TRUSTED_CONTAINER_SERVICE_ENVIRONMENT_NAMES"]
TRUSTED_SERVICE_CONFIG_ENVIRONMENT = _CONTRACT["TRUSTED_SERVICE_CONFIG_ENVIRONMENT"]
VOLUME_KINDS = _CONTRACT["VOLUME_KINDS"]
allowed_service_process_groups = _CONTRACT["allowed_service_process_groups"]
compose_id_maps = _CONTRACT["compose_id_maps"]
id_map_is_bounded = _CONTRACT["id_map_is_bounded"]
container_pid_matches_state = _CONTRACT["container_pid_matches_state"]
expected_gateway_port = _CONTRACT["expected_gateway_port"]
expected_generated_source = _CONTRACT["expected_generated_source"]
expected_image_identity = _CONTRACT["expected_image_identity"]
expected_role_mounts = _CONTRACT["expected_role_mounts"]
expected_role_tmpfs = _CONTRACT["expected_role_tmpfs"]
expected_unit_names = _CONTRACT["expected_unit_names"]
service_state_matches_role = _CONTRACT["service_state_matches_role"]
tmpfs_contract_matches = _CONTRACT["tmpfs_contract_matches"]

def exact_keys(value: object, expected: set[str]) -> dict[str, Any] | None:
    return value if isinstance(value, dict) and set(value) == expected else None


def exact_string_set(value: object) -> set[str] | None:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        return None
    names = set(value)
    return names if len(names) == len(value) else None


def exact_process_map(
    value: object,
) -> dict[tuple[str, str, int, int], int] | None:
    if not isinstance(value, list) or len(value) > 256:
        return None
    facts: dict[tuple[str, str, int, int], int] = {}
    for item in value:
        if not isinstance(item, dict) or set(item) != {
            "executable", "control_group", "uid", "gid", "count"
        }:
            return None
        executable = item.get("executable")
        control_group = item.get("control_group")
        uid = item.get("uid")
        gid = item.get("gid")
        count = item.get("count")
        reviewed_opaque = (
            executable == OPAQUE_PROCESS_EXECUTABLE
            and isinstance(control_group, str)
            and control_group in {
                "/user.slice/user-20000.slice/user@20000.service/init.scope",
                (
                    "/user.slice/user-20000.slice/user@20000.service/app.slice/"
                    "ssh-agent.service"
                ),
            }
            and (uid, gid) == (CI_UID, CI_GID)
        )
        if (
            not isinstance(executable, str)
            or (not executable.startswith("/") and not reviewed_opaque)
            or len(executable) > 512
            or "\x00" in executable
            or not isinstance(control_group, str)
            or not control_group.startswith("/user.slice/user-20000.slice/")
            or len(control_group) > 512
            or type(uid) is not int
            or not 0 <= uid <= 4_294_967_295
            or type(gid) is not int
            or not 0 <= gid <= 4_294_967_295
            or type(count) is not int
            or not 1 <= count <= 256
        ):
            return None
        key = (executable, control_group, uid, gid)
        if key in facts:
            return None
        facts[key] = count
    return facts


def reviewed_podman_auxiliary_units(
    active_units: set[str], health_timer_facts: object, containers: object
) -> tuple[set[str], str, str] | None:
    if (
        not isinstance(containers, list)
        or not isinstance(health_timer_facts, list)
        or len(health_timer_facts) > len(HEALTHY_ROLES)
    ):
        return None
    healthy_ids: set[str] = set()
    for container in containers:
        if not isinstance(container, dict):
            return None
        if container.get("role") not in HEALTHY_ROLES:
            continue
        container_id = container.get("id")
        if not isinstance(container_id, str) or re.fullmatch(
            r"[0-9a-f]{64}", container_id
        ) is None:
            return None
        if container_id in healthy_ids:
            return None
        healthy_ids.add(container_id)
    health_timer_candidates = {
        unit
        for unit in active_units
        if re.fullmatch(
            rf"[0-9a-f]{{64}}-{PODMAN_54_HEALTH_TIMER_SUFFIX}\.timer",
            unit,
        )
    }
    health_timers: set[str] = set()
    observed_health_ids: set[str] = set()
    previous_timer = ""
    for fact in health_timer_facts:
        if not isinstance(fact, dict) or set(fact) != {
            "container_id", "timer", "service", "interval_usec"
        }:
            return None
        container_id = fact.get("container_id")
        timer = fact.get("timer")
        service = fact.get("service")
        interval_usec = fact.get("interval_usec")
        role = next(
            (
                container.get("role")
                for container in containers
                if isinstance(container, dict)
                and container.get("id") == container_id
            ),
            None,
        )
        if (
            not isinstance(container_id, str)
            or not isinstance(timer, str)
            or not isinstance(service, str)
            or container_id in observed_health_ids
            or timer in health_timers
            or timer <= previous_timer
            or re.fullmatch(
                rf"{re.escape(container_id)}-"
                rf"{PODMAN_54_HEALTH_TIMER_SUFFIX}\.timer",
                timer,
            )
            is None
            or service != timer.removesuffix(".timer") + ".service"
            or interval_usec != HEALTH_INTERVAL_USEC.get(str(role))
        ):
            return None
        observed_health_ids.add(container_id)
        health_timers.add(timer)
        previous_timer = timer
    if observed_health_ids != healthy_ids:
        return None
    for container_id in healthy_ids:
        matches = {
            unit
            for unit in health_timers
            if unit.startswith(f"{container_id}-")
        }
        if len(matches) != 1:
            return None
    if health_timers != health_timer_candidates:
        return None
    rootless_scopes = {
        unit
        for unit in active_units
        if re.fullmatch(r"rootless-netns-[0-9a-f]{8}\.scope", unit)
    }
    dns_scopes = {
        unit
        for unit in active_units
        if re.fullmatch(r"run-p[1-9][0-9]{0,9}-i[1-9][0-9]{0,9}\.scope", unit)
    }
    if (
        len(rootless_scopes) != 1
        or len(dns_scopes) != 1
        or PODMAN_NETWORK_ONLINE_UNIT not in active_units
    ):
        return None
    rootless_scope = next(iter(rootless_scopes))
    dns_scope = next(iter(dns_scopes))
    return (
        health_timers
        | rootless_scopes
        | dns_scopes
        | {PODMAN_NETWORK_ONLINE_UNIT},
        rootless_scope,
        dns_scope,
    )


def reviewed_podman_helper_process(
    key: tuple[str, str, int, int], count: int,
    rootless_scope: str, dns_scope: str,
) -> str | None:
    executable, control_group, uid, gid = key
    if count != 1 or (uid, gid) != (CI_UID, CI_GID):
        return None
    if (
        executable in {"/usr/bin/pasta", "/usr/bin/pasta.avx2"}
        and control_group
        == (
            "/user.slice/user-20000.slice/user@20000.service/"
            f"user.slice/{rootless_scope}"
        )
    ):
        return "rootless-network"
    if (
        executable == "/usr/lib/podman/aardvark-dns"
        and control_group
        == (
            "/user.slice/user-20000.slice/user@20000.service/"
            f"app.slice/{dns_scope}"
        )
    ):
        return "dns"
    return None


def id_map_covers(value: list[dict[str, int]], identity: int) -> bool:
    return sum(
        item["container_id"] <= identity < item["container_id"] + item["size"]
        for item in value
    ) == 1


def id_map_is_within_collector(
    value: list[dict[str, int]], collector_map: list[dict[str, int]]
) -> bool:
    return all(
        sum(
            outer["container_id"] <= item["host_id"]
            and item["host_id"] + item["size"]
            <= outer["container_id"] + outer["size"]
            for outer in collector_map
        )
        == 1
        for item in value
    )


def user_namespace_contract_matches(
    container: dict[str, object], expected_uid: int, expected_gid: int
) -> bool:
    value = container.get("user_namespace")
    expected_fields = {
        "compat_mode", "create_options", "process_identity",
        "collector_identity", "uid_map", "gid_map", "collector_uid_map",
        "collector_gid_map", "configured_uid_map", "configured_gid_map",
        "podman_uid_map", "podman_gid_map",
    }
    if not isinstance(value, dict) or set(value) != expected_fields:
        return False
    compat_mode = value["compat_mode"]
    create_options = value["create_options"]
    if compat_mode not in {"", "private"} or not isinstance(
        create_options, list
    ) or len(create_options) > 1 or any(
        not isinstance(option, str)
        or re.fullmatch(
            r"(?:private|nomap|auto(?::[a-z0-9=,@:+-]{1,256})?|"
            r"keep-id(?::[a-z0-9=,@:+-]{1,256})?)",
            option,
        )
        is None
        for option in create_options
    ):
        return False
    if compat_mode == "private" and create_options not in ([], ["private"]):
        return False

    configured_user = container.get("configured_user")
    if not isinstance(configured_user, str) or re.fullmatch(
        r"[0-9]{1,10}:[0-9]{1,10}", configured_user
    ) is None:
        return False
    configured_uid, configured_gid = (
        int(identity) for identity in configured_user.split(":", 1)
    )
    if (configured_uid, configured_gid) != (expected_uid, expected_gid):
        return False

    configured_uid_map = value["configured_uid_map"]
    configured_gid_map = value["configured_gid_map"]
    podman_uid_map = value["podman_uid_map"]
    podman_gid_map = value["podman_gid_map"]
    if (
        not id_map_is_bounded(configured_uid_map, allow_empty=True)
        or not id_map_is_bounded(configured_gid_map, allow_empty=True)
        or bool(configured_uid_map) != bool(configured_gid_map)
        or not id_map_is_bounded(podman_uid_map, allow_empty=False)
        or not id_map_is_bounded(podman_gid_map, allow_empty=False)
        or (
            bool(configured_uid_map)
            and (
                not id_map_covers(configured_uid_map, configured_uid)
                or not id_map_covers(configured_gid_map, configured_gid)
            )
        )
    ):
        return False

    collector_identity = value["collector_identity"]
    collector_uid_map = value["collector_uid_map"]
    collector_gid_map = value["collector_gid_map"]
    if (
        not isinstance(collector_identity, str)
        or re.fullmatch(r"user:\[[0-9]{1,20}\]", collector_identity) is None
        or not id_map_is_bounded(collector_uid_map, allow_empty=False)
        or not id_map_is_bounded(collector_gid_map, allow_empty=False)
    ):
        return False

    if container.get("state") == "running":
        process_identity = value["process_identity"]
        uid_map = value["uid_map"]
        gid_map = value["gid_map"]
        effective_uid = container.get("effective_uid")
        effective_gid = container.get("effective_gid")
        effective_groups = container.get("effective_supplementary_gids")
        expected_uid_map = compose_id_maps(
            configured_uid_map, podman_uid_map
        ) if configured_uid_map else None
        expected_gid_map = compose_id_maps(
            configured_gid_map, podman_gid_map
        ) if configured_gid_map else None
        default_mode = create_options == [] and not configured_uid_map
        return bool(
            isinstance(process_identity, str)
            and re.fullmatch(r"user:\[[0-9]{1,20}\]", process_identity)
            and process_identity != collector_identity
            and id_map_is_bounded(uid_map, allow_empty=False)
            and id_map_is_bounded(gid_map, allow_empty=False)
            and uid_map != collector_uid_map
            and gid_map != collector_gid_map
            and id_map_is_within_collector(uid_map, collector_uid_map)
            and id_map_is_within_collector(gid_map, collector_gid_map)
            and (
                (default_mode and uid_map == podman_uid_map)
                or (
                    bool(configured_uid_map)
                    and uid_map == expected_uid_map
                )
                or (
                    not default_mode
                    and not configured_uid_map
                    and uid_map != podman_uid_map
                )
            )
            and (
                (default_mode and gid_map == podman_gid_map)
                or (
                    bool(configured_gid_map)
                    and gid_map == expected_gid_map
                )
                or (
                    not default_mode
                    and not configured_gid_map
                    and gid_map != podman_gid_map
                )
            )
            and type(effective_uid) is int
            and type(effective_gid) is int
            and (effective_uid, effective_gid) == (expected_uid, expected_gid)
            and id_map_covers(uid_map, configured_uid)
            and id_map_covers(gid_map, configured_gid)
            and id_map_covers(uid_map, effective_uid)
            and id_map_covers(gid_map, effective_gid)
            and isinstance(effective_groups, list)
            and all(id_map_covers(gid_map, gid) for gid in effective_groups)
        )

    expected_uid_map = compose_id_maps(
        configured_uid_map, podman_uid_map
    ) if configured_uid_map else podman_uid_map
    expected_gid_map = compose_id_maps(
        configured_gid_map, podman_gid_map
    ) if configured_gid_map else podman_gid_map
    return bool(
        container.get("state") == "exited"
        and value["process_identity"] == ""
        and value["uid_map"] == []
        and value["gid_map"] == []
        and create_options == []
        and expected_uid_map is not None
        and expected_gid_map is not None
        and id_map_is_within_collector(expected_uid_map, collector_uid_map)
        and id_map_is_within_collector(expected_gid_map, collector_gid_map)
        and (
            id_map_covers(expected_uid_map, configured_uid)
            and id_map_covers(expected_gid_map, configured_gid)
        )
        and re.fullmatch(
            r"[0-9a-f]{32}",
            str(container.get("lifecycle_service_invocation", "")),
        )
        is not None
    )


def generated_source_matches(instance: str, service: dict[str, object]) -> bool:
    try:
        expected = expected_generated_source(
            instance, str(service.get("logical_name", ""))
        )
    except ValueError:
        return False
    return service.get("source_path") == str(expected)


def service_environment_names_are_trusted(service: object) -> bool:
    if not isinstance(service, dict):
        return False
    environment = service.get("environment")
    logical_name = service.get("logical_name")
    if logical_name in ROLES:
        expected = sorted(TRUSTED_CONTAINER_SERVICE_ENVIRONMENT_NAMES)
    elif logical_name in GENERATED_LOGICAL_NAMES:
        expected = sorted(TRUSTED_SERVICE_CONFIG_ENVIRONMENT)
    else:
        return False
    return environment == expected


def selinux_labels_match(container: dict[str, object]) -> bool:
    process_label = container.get("selinux_process_label")
    mount_label = container.get("selinux_mount_label")
    if not isinstance(process_label, str) or not isinstance(mount_label, str):
        return False
    process_pattern = (
        r"[^:]{1,64}:[^:]{1,64}:container_t:"
        r"s0:c[0-9]{1,4},c[0-9]{1,4}"
    )
    mount_pattern = (
        r"[^:]{1,64}:[^:]{1,64}:container_file_t:"
        r"s0:c[0-9]{1,4},c[0-9]{1,4}"
    )
    if (
        re.fullmatch(process_pattern, process_label) is None
        or re.fullmatch(mount_pattern, mount_label) is None
        or process_label.split(":", 3)[3] != mount_label.split(":", 3)[3]
    ):
        return False
    if container.get("state") == "running":
        return container.get("effective_process_label") == process_label
    return container.get("effective_process_label") == ""


def workload_admission_failures(observations: object) -> list[str]:
    failures: list[str] = []
    if not isinstance(observations, dict):
        return ["WORKLOAD_OBSERVATION_SCHEMA"]
    baseline_value = observations.get("baseline")
    live_value = observations.get("live")
    cleanup_value = observations.get("post_cleanup")
    baseline = exact_keys(baseline_value, set(BASELINE_OBSERVATION_FIELDS))
    live = exact_keys(live_value, set(LIVE_OBSERVATION_FIELDS))
    cleanup = exact_keys(cleanup_value, set(CLEANUP_OBSERVATION_FIELDS))
    if baseline is None:
        failures.append("WORKLOAD_BASELINE_OBSERVATION")
    if live is None:
        failures.append("WORKLOAD_LIVE_OBSERVATION")
    if cleanup is None:
        failures.append("WORKLOAD_POST_CLEANUP_OBSERVATION")
    if baseline is None or live is None or cleanup is None:
        return failures
    if any(
        observation.get("target_admitted") is not True
        or observation.get("collector_uid") != CI_UID
        or observation.get("collector_gid") != CI_GID
        or observation.get("complete") is not True
        for observation in (baseline, live, cleanup)
    ):
        failures.append("WORKLOAD_OBSERVATION_INCOMPLETE")
    if (
        baseline["phase"] != "baseline"
        or live["phase"] != "live"
        or cleanup["phase"] != "post-cleanup"
    ):
        failures.append("WORKLOAD_PHASE_CONSISTENCY")
    if baseline.get("migration_invocation_count") != 0:
        failures.append("WORKLOAD_BASELINE_MIGRATION")
    if baseline.get("podman_api") is not False:
        failures.append("WORKLOAD_PODMAN_API_DISABLED")
    instance = observations.get("instance")
    target_sha = observations.get("target_sha")
    if (
        not isinstance(target_sha, str)
        or re.fullmatch(r"[0-9a-f]{40}", target_sha) is None
        or instance != target_sha[:12]
        or any(
            observation.get("target_sha") != target_sha
            for observation in (baseline, live, cleanup)
        )
    ):
        failures.append("WORKLOAD_TARGET_BINDING")
    try:
        names = expected_unit_names(str(instance))
        gateway_port = expected_gateway_port(str(instance))
    except ValueError:
        names = ()
        gateway_port = None
        failures.append("WORKLOAD_OBSERVATION_SCHEMA")
    units = live.get("installed_units")
    if not isinstance(units, list) or len(units) != len(names) or {
        unit.get("name") for unit in units if isinstance(unit, dict)
    } != set(names) or any(
        not isinstance(unit, dict)
        or set(unit) != {
            "name", "path", "uid", "gid", "mode", "sha256", "image",
        }
        or unit["uid"] != 0 or unit["gid"] != 0 or unit["mode"] != "0644"
        or re.fullmatch(r"[0-9a-f]{64}", str(unit["sha256"])) is None
        or unit["path"] != str(
            (SYSTEMD_ROOT if str(unit["name"]).endswith(".target") else QUADLET_ROOT)
            / str(unit["name"])
        )
        for unit in units if isinstance(unit, dict)
    ):
        failures.append("WORKLOAD_QUADLET_SNAPSHOT")
    if live.get("quadlet_search_paths") != [str(QUADLET_ROOT)]:
        failures.append("WORKLOAD_QUADLET_SEARCH_PATH")
    if live.get("podman_rootless") is not True:
        failures.append("WORKLOAD_ROOTLESS")
    if live.get("oci_runtime") != "crun":
        failures.append("WORKLOAD_OCI_RUNTIME")
    services = live.get("generated_services")
    if not isinstance(services, list) or len(services) != len(GENERATED_LOGICAL_NAMES) or {
        service.get("logical_name") for service in services if isinstance(service, dict)
    } != set(GENERATED_LOGICAL_NAMES) or any(
        not isinstance(service, dict)
        or set(service) != {
            "logical_name", "unit", "fragment_path", "fragment_uid", "fragment_gid",
            "fragment_mode", "drop_in_paths", "drop_in_owners", "active_state",
            "sub_state", "result", "exec_main_status", "main_pid", "control_group",
            "invocation_id", "source_path", "fragment_sha256",
            "drop_in_sha256", "environment",
        }
        or not str(service["fragment_path"]).startswith(f"{GENERATOR_ROOT}/")
        or service["fragment_uid"] != CI_UID
        or service["fragment_gid"] != CI_GID
        or service["fragment_mode"] != "0644"
        or re.fullmatch(r"[0-9a-f]{32}", str(service["invocation_id"])) is None
        or any(not str(path).startswith(f"{GENERATOR_ROOT}/") for path in service["drop_in_paths"])
        or len(service["drop_in_paths"]) != len(service["drop_in_owners"])
        or any(
            not isinstance(owner, dict)
            or owner != {"uid": CI_UID, "gid": CI_GID, "mode": "0644"}
            for owner in service["drop_in_owners"]
        )
        for service in services if isinstance(service, dict)
    ):
        failures.append("WORKLOAD_GENERATED_UNITS")
    if isinstance(services, list) and any(
        not isinstance(service, dict)
        or not generated_source_matches(str(instance), service)
        or re.fullmatch(
            r"[0-9a-f]{64}", str(service.get("fragment_sha256", ""))
        )
        is None
        or not isinstance(service.get("drop_in_sha256"), list)
        or len(service.get("drop_in_sha256", []))
        != len(service.get("drop_in_paths", []))
        or any(
            re.fullmatch(r"[0-9a-f]{64}", str(digest)) is None
            for digest in service.get("drop_in_sha256", [])
        )
        for service in services
    ):
        failures.append("WORKLOAD_GENERATED_PROVENANCE")
    if isinstance(services, list) and any(
        not service_environment_names_are_trusted(service)
        for service in services
    ):
        failures.append("WORKLOAD_HOST_NAMESPACES")
    if isinstance(services, list):
        for service in services:
            if not isinstance(service, dict):
                continue
            if not service_state_matches_role(
                service, str(service.get("logical_name", ""))
            ):
                failures.append("WORKLOAD_SERVICE_STATE")
    containers = live.get("containers")
    installed_images = {
        str(unit.get("name")): unit.get("image")
        for unit in units
        if isinstance(unit, dict)
    } if isinstance(units, list) else {}
    container_roles = [
        item.get("role") for item in containers if isinstance(item, dict)
    ] if isinstance(containers, list) else []
    if len(container_roles) != len(ROLES) or set(container_roles) != set(ROLES):
        failures.append("WORKLOAD_CONTAINER_SET")
    if isinstance(containers, list):
        services_by_role = {
            str(service.get("logical_name")): service
            for service in services
            if isinstance(service, dict)
        } if isinstance(services, list) else {}
        for item in containers:
            if not isinstance(item, dict):
                continue
            if item.get("rootless") is not True:
                failures.append("WORKLOAD_ROOTLESS")
            if item.get("oci_runtime") != "crun":
                failures.append("WORKLOAD_OCI_RUNTIME")
            role_contract = ROLE_CONTRACTS.get(str(item.get("role")))
            expected_caps = (
                list(role_contract.capabilities) if role_contract is not None else []
            )
            if (
                item.get("privileged") is not False
                or item.get("cap_add") not in ([], expected_caps)
                or item.get("group_add") != []
                or item.get("effective_caps") != expected_caps
                or item.get("bounding_caps") != expected_caps
            ):
                failures.append("WORKLOAD_PRIVILEGE_BOUNDARY")
            if role_contract is None:
                failures.append("WORKLOAD_RUNTIME_IDENTITY")
            else:
                expected_uid, expected_gid = role_contract.identity
                running = item.get("state") == "running"
                if (
                    item.get("configured_user")
                    != f"{expected_uid}:{expected_gid}"
                    or item.get("effective_uid")
                    != (expected_uid if running else -1)
                    or item.get("effective_gid")
                    != (expected_gid if running else -1)
                ):
                    failures.append("WORKLOAD_RUNTIME_IDENTITY")
                effective_groups = item.get("effective_supplementary_gids")
                groups_valid = isinstance(effective_groups, list) and (
                    effective_groups in ([], [expected_gid])
                    if running
                    else effective_groups == []
                )
                if not groups_valid:
                    failures.append("WORKLOAD_PRIVILEGE_BOUNDARY")
            if item.get("read_only_rootfs") is not True:
                failures.append("WORKLOAD_READ_ONLY_ROOTFS")
            if role_contract is not None and any(
                expected is not None and item.get(field) != list(expected)
                for field, expected in (
                    ("entrypoint", role_contract.entrypoint),
                    ("command", role_contract.command),
                    ("healthcheck_command", role_contract.healthcheck),
                )
            ):
                failures.append("WORKLOAD_EXECUTION_CONTRACT")
            if str(item.get("role")) != "migrate" and any(
                "migrat" in argument.casefold()
                for field in ("entrypoint", "command", "healthcheck_command")
                for argument in (
                    item.get(field) if isinstance(item.get(field), list) else []
                )
                if isinstance(argument, str)
            ):
                failures.append("WORKLOAD_EXECUTION_CONTRACT")
            if item.get("devices_present") is not False:
                failures.append("WORKLOAD_PRIVILEGE_BOUNDARY")
            mounts = item.get("mounts")
            if (
                not isinstance(mounts, list)
                or any(not isinstance(mount, dict) for mount in mounts)
                or any(
                    any(
                        marker in str(mount.get(field, ""))
                        for marker in (
                            "/run/podman", "/run/user/20000/podman",
                            "podman.sock",
                        )
                        for field in ("source", "destination")
                    )
                    for mount in mounts
                    if isinstance(mount, dict)
                )
                or item.get("remote_api_environment") is not False
            ):
                failures.append("WORKLOAD_PODMAN_API_DISABLED")
            if any(
                item.get(field) != "private"
                for field in ("pid_mode", "ipc_mode", "uts_mode")
            ) or (
                role_contract is None
                or not user_namespace_contract_matches(
                    item, *role_contract.identity
                )
            ):
                failures.append("WORKLOAD_HOST_NAMESPACES")
            network_mode = str(item.get("network_mode", ""))
            if re.match(r"^(?:host$|container(?::|$)|ns:)", network_mode):
                failures.append("WORKLOAD_HOST_NETWORK")
            if item.get("auto_update") is not False:
                failures.append("WORKLOAD_AUTO_UPDATE_DISABLED")
            security_options = item.get("security_opt", [])
            if security_options != ["no-new-privileges"]:
                failures.append("WORKLOAD_SECURITY_OPTIONS")
            if not selinux_labels_match(item):
                failures.append("WORKLOAD_SELINUX_ISOLATION")
            if (
                item.get("effective_seccomp_mode")
                != (2 if item.get("state") == "running" else -1)
            ):
                failures.append("WORKLOAD_SECCOMP_ISOLATION")
            if not expected_image_identity(
                str(instance),
                str(item.get("role")),
                item,
                installed_images.get(
                    f"secpal-int-{instance}-{item.get('role')}.container"
                ),
            ):
                failures.append("WORKLOAD_IMAGE_PROVENANCE")
            if any(network == "host" for network in item.get("networks", [])):
                failures.append("WORKLOAD_HOST_NETWORK")
            role = str(item.get("role"))
            expected_service = f"secpal-int-{instance}-{role}.service"
            expected_service_fact = services_by_role.get(role, {})
            expected_control_group = expected_service_fact.get("control_group")
            container_control_group = item.get("container_cgroup")
            lifecycle_invocation = item.get("lifecycle_service_invocation")
            if role in READY_ROLES:
                service_binding_matches = (
                    isinstance(expected_control_group, str)
                    and expected_control_group
                    and isinstance(container_control_group, str)
                    and (
                        container_control_group == expected_control_group
                        or container_control_group.startswith(
                            f"{expected_control_group}/"
                        )
                    )
                    and lifecycle_invocation == ""
                )
            else:
                service_binding_matches = (
                    container_control_group == ""
                    and lifecycle_invocation
                    == expected_service_fact.get("invocation_id")
                )
            if (
                re.fullmatch(r"[0-9a-f]{64}", str(item.get("id", ""))) is None
                or item.get("systemd_unit") != expected_service
                or not service_binding_matches
                or not container_pid_matches_state(item)
            ):
                failures.append("WORKLOAD_SERVICE_BINDING")
            expected_networks = [
                f"secpal-int-{instance}-{kind}"
                for kind in (
                    ROLE_CONTRACTS[role].networks if role in ROLE_CONTRACTS else ()
                )
            ]
            reviewed_exited_network_omission = (
                role == "migrate"
                and item.get("state") == "exited"
                and network_mode == "bridge"
                and item.get("networks") == []
                and container_control_group == ""
                and lifecycle_invocation
                == expected_service_fact.get("invocation_id")
                and [
                    event.get("status")
                    for event in item.get("lifecycle_events", [])
                    if isinstance(event, dict)
                ] == ["create", "start", "died"]
            )
            if (
                item.get("networks") != expected_networks
                and not reviewed_exited_network_omission
            ):
                failures.append("WORKLOAD_CONTAINER_NETWORKS")
            if mounts != expected_role_mounts(instance, role):
                failures.append("WORKLOAD_VOLUME_TOPOLOGY")
            tmpfs = item.get("tmpfs")
            expected_tmpfs = expected_role_tmpfs(role)
            if not tmpfs_contract_matches(tmpfs, expected_tmpfs):
                failures.append("WORKLOAD_TMPFS_TOPOLOGY")
            lifecycle_events = item.get("lifecycle_events")
            expected_lifecycle = (
                ["create", "start"]
                if role in READY_ROLES
                else ["create", "start", "died"]
            )
            if (
                not isinstance(lifecycle_events, list)
                or [
                    event.get("status")
                    for event in lifecycle_events
                    if isinstance(event, dict)
                ] != expected_lifecycle
                or len(lifecycle_events) != len(expected_lifecycle)
            ):
                failures.append("WORKLOAD_CONTAINER_LIFECYCLE")
            published_ports = item.get("published_ports")
            if role == "gateway":
                valid_ports = published_ports == [
                    f"127.0.0.1:{gateway_port}:8443/tcp"
                ]
            else:
                valid_ports = published_ports == []
            if not valid_ports:
                failures.append("WORKLOAD_PUBLISHED_PORTS")
        images_by_role = {
            str(item.get("role")): item.get("image_digest")
            for item in containers
            if isinstance(item, dict)
        }
        api_identity = images_by_role.get("api")
        frontend_identity = images_by_role.get("frontend")
        if (
            api_identity != API_DIGEST
            or frontend_identity != FRONTEND_DIGEST
            or api_identity == frontend_identity
        ):
            failures.append("WORKLOAD_IMAGE_ROLE_SEPARATION")
        api_family = {
            role: images_by_role.get(role)
            for role in (
                "secrets-init", "migrate", "api", "worker-general",
                "worker-hash-chain", "scheduler",
            )
        }
        if (
            set(api_family.values()) != {API_DIGEST}
        ):
            failures.append("WORKLOAD_EXECUTION_CONTRACT")
    if isinstance(containers, list) and any(
        sum(
            isinstance(item, dict) and item.get("role") == role
            for item in containers
        ) != 1
        for role in ("scheduler", "worker-hash-chain")
    ):
        failures.append("WORKLOAD_SINGLETON_ROLES")
    if live.get("podman_api") is not False:
        failures.append("WORKLOAD_PODMAN_API_DISABLED")
    if cleanup.get("podman_api") is not False:
        failures.append("WORKLOAD_PODMAN_API_DISABLED")
    baseline_user_work = exact_keys(
        baseline.get("user_work"),
        {"active_units", "jobs", "podman_health_timers"},
    )
    cleanup_user_work = exact_keys(
        cleanup.get("user_work"),
        {"active_units", "jobs", "podman_health_timers"},
    )
    baseline_units = (
        exact_string_set(baseline_user_work.get("active_units"))
        if baseline_user_work is not None
        else None
    )
    cleanup_units = (
        exact_string_set(cleanup_user_work.get("active_units"))
        if cleanup_user_work is not None
        else None
    )
    if (
        baseline_user_work is None
        or cleanup_user_work is None
        or baseline_units is None
        or exact_string_set(baseline_user_work.get("jobs")) is None
        or cleanup_units is None
        or exact_string_set(cleanup_user_work.get("jobs")) is None
        or baseline_user_work.get("podman_health_timers") != []
        or cleanup_user_work.get("podman_health_timers") != []
        or PODMAN_NETWORK_ONLINE_UNIT in baseline_units
        or PODMAN_NETWORK_ONLINE_UNIT not in cleanup_units
        or cleanup_units - {PODMAN_NETWORK_ONLINE_UNIT} != baseline_units
        or cleanup_user_work.get("jobs") != baseline_user_work.get("jobs")
    ):
        failures.append("WORKLOAD_PENDING_USER_WORK")
    live_user_work = exact_keys(
        live.get("user_work"),
        {"active_units", "jobs", "podman_health_timers"},
    )
    live_units = (
        exact_string_set(live_user_work.get("active_units"))
        if live_user_work is not None
        else None
    )
    generated_units = {
        str(service.get("unit"))
        for service in services
        if isinstance(service, dict)
    } if isinstance(services, list) else set()
    fixture_target = (
        {f"secpal-int-{instance}.target"}
        if re.fullmatch(r"[0-9a-f]{12}", str(instance)) is not None
        else set()
    )
    auxiliary = (
        reviewed_podman_auxiliary_units(
            live_units, live_user_work.get("podman_health_timers"), containers
        )
        if live_units is not None
        and live_user_work is not None
        else None
    )
    auxiliary_units = auxiliary[0] if auxiliary is not None else set()
    if (
        live_user_work is None
        or live_units is None
        or baseline_units is None
        or auxiliary is None
        or live_units
        != (
            baseline_units - {PODMAN_NETWORK_ONLINE_UNIT}
        ) | generated_units | fixture_target | auxiliary_units
        or live_user_work.get("jobs")
        != (baseline_user_work.get("jobs") if baseline_user_work else None)
    ):
        failures.append("WORKLOAD_LIVE_USER_WORK")
    baseline_processes = exact_process_map(baseline.get("processes"))
    live_processes = exact_process_map(live.get("processes"))
    cleanup_processes = exact_process_map(cleanup.get("processes"))
    allowed_groups = allowed_service_process_groups(services, containers)
    helper_kinds: list[str] = []
    process_delta_valid = True
    if live_processes is not None and baseline_processes is not None:
        for key, count in live_processes.items():
            delta = count - baseline_processes.get(key, 0)
            if delta <= 0:
                continue
            service_process = any(
                (key[1] == group or key[1].startswith(f"{group}/"))
                and (key[2], key[3]) in identities
                for group, identities in allowed_groups.items()
            )
            helper_kind = (
                reviewed_podman_helper_process(
                    key, delta, auxiliary[1], auxiliary[2]
                )
                if auxiliary is not None
                else None
            )
            if helper_kind is not None:
                helper_kinds.append(helper_kind)
            elif not service_process:
                process_delta_valid = False
    if (
        baseline_processes is None
        or live_processes is None
        or cleanup_processes != baseline_processes
        or any(
            live_processes.get(key, 0) < count
            for key, count in baseline_processes.items()
        )
        or not process_delta_valid
        or sorted(helper_kinds) != ["dns", "rootless-network"]
    ):
        failures.append("WORKLOAD_PROCESS_DELTA")
    migrate = next(
        (
            item for item in containers
            if isinstance(item, dict) and item.get("role") == "migrate"
        ),
        {},
    ) if isinstance(containers, list) else {}
    if (
        migrate.get("state") != "exited"
        or migrate.get("exit_code") != 0
        or cleanup.get("migration_invocation_count") != 1
    ):
        failures.append("WORKLOAD_MIGRATION")
    if cleanup.get("migration_invocation_count") != 1:
        failures.append("WORKLOAD_CLEANUP_MIGRATION")
    secrets_init = next(
        (
            item for item in containers
            if isinstance(item, dict) and item.get("role") == "secrets-init"
        ),
        {},
    ) if isinstance(containers, list) else {}
    if secrets_init.get("state") != "exited" or secrets_init.get("exit_code") != 0:
        failures.append("WORKLOAD_LIFECYCLE")
    by_role = {
        str(item.get("role")): item
        for item in containers
        if isinstance(item, dict)
    } if isinstance(containers, list) else {}
    if any(
        by_role.get(role, {}).get("state") != "running"
        or (
            by_role.get(role, {}).get("health") != "healthy"
            if role in HEALTHY_ROLES
            else by_role.get(role, {}).get("health") != "none"
        )
        for role in READY_ROLES
    ):
        failures.append("WORKLOAD_READINESS")
    prefix = f"secpal-int-{instance}-"
    if len(live.get("networks", [])) != len(NETWORK_KINDS) or set(
        live.get("networks", [])
    ) != {f"{prefix}{kind}" for kind in NETWORK_KINDS}:
        failures.append("WORKLOAD_NETWORK_SET")
    if len(live.get("volumes", [])) != len(VOLUME_KINDS) or set(
        live.get("volumes", [])
    ) != {f"{prefix}{kind}" for kind in VOLUME_KINDS}:
        failures.append("WORKLOAD_VOLUME_SET")
    if any(cleanup.get(name) for name in (
        "owned_units", "generated_services", "containers", "networks", "volumes"
    )):
        failures.append("WORKLOAD_CLEANUP_ABSENCE")
    baseline_inventory = {
        kind: exact_string_set(baseline.get(kind))
        for kind in ("containers", "networks", "volumes")
    }
    live_inventory = {
        kind: exact_string_set(live.get(f"all_{kind}"))
        for kind in ("containers", "networks", "volumes")
    }
    cleanup_inventory = {
        kind: exact_string_set(cleanup.get(f"all_{kind}"))
        for kind in ("containers", "networks", "volumes")
    }
    expected_live_additions = {
        "containers": {f"secpal-int-{instance}-{role}" for role in ROLES},
        "networks": {f"secpal-int-{instance}-{kind}" for kind in NETWORK_KINDS},
        "volumes": {f"secpal-int-{instance}-{kind}" for kind in VOLUME_KINDS},
    }
    fixture_prefix = f"secpal-int-{instance}"
    if (
        any(
            baseline_inventory[kind] is None
            or any(
                name.startswith(fixture_prefix)
                for name in baseline_inventory[kind]
            )
            for kind in ("containers", "networks", "volumes")
        )
        or baseline_inventory["networks"] is not None
        and CONTROL_NETWORK not in baseline_inventory["networks"]
        or baseline_inventory["volumes"] is not None
        and CONTROL_VOLUME not in baseline_inventory["volumes"]
    ):
        failures.append("WORKLOAD_BASELINE_INVENTORY")
    if any(
        baseline_inventory[kind] is None
        or live_inventory[kind] != baseline_inventory[kind] | expected_live_additions[kind]
        or cleanup_inventory[kind] != baseline_inventory[kind]
        for kind in ("containers", "networks", "volumes")
    ):
        failures.append("WORKLOAD_RESOURCE_INVENTORY")
    baseline_controls = baseline.get("control_resources")
    if (
        not isinstance(baseline_controls, dict)
        or set(baseline_controls) != {
            "network_present", "volume_present", "network_id",
            "volume_created_at",
        }
        or baseline_controls.get("network_present") is not True
        or baseline_controls.get("volume_present") is not True
        or re.fullmatch(
            r"[0-9a-f]{64}", str(baseline_controls.get("network_id", ""))
        ) is None
        or re.fullmatch(
            r"[0-9T:+.Z-]{1,64}",
            str(baseline_controls.get("volume_created_at", "")),
        ) is None
        or live.get("control_resources") != baseline_controls
        or cleanup.get("control_resources") != baseline_controls
    ):
        failures.append("WORKLOAD_CONTROL_RESOURCES_PRESERVED")
    return list(dict.fromkeys(failures))
