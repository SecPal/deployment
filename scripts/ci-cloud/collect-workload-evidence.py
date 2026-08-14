#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Collect bounded, independent rootless Quadlet workload observations."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any


CI_UID = 20000
CI_GID = 20000
PROTOCOL_VERSION = 1
MAX_OUTPUT = 256 * 1024
CHECKOUT = Path("/home/secpal-ci/deployment-target")
QUADLET_ROOT = Path("/etc/containers/systemd/users/20000")
SYSTEMD_ROOT = Path("/etc/systemd/user")
GENERATOR_ROOT = Path("/run/user/20000/systemd/generator")
CONTROL_NETWORK = "secpal-ci-unrelated-control-network"
CONTROL_VOLUME = "secpal-ci-unrelated-control-volume"
ROLES = (
    "secrets-init", "postgres", "valkey", "migrate", "api",
    "worker-general", "worker-hash-chain", "scheduler", "frontend", "gateway",
)
NETWORK_KINDS = ("application", "edge")
VOLUME_KINDS = ("secrets", "private-storage", "postgres")
GENERATED_LOGICAL_NAMES = (
    *ROLES,
    *(f"{kind}-network" for kind in NETWORK_KINDS),
    *(f"{kind}-volume" for kind in VOLUME_KINDS),
)
READY_ROLES = frozenset(ROLES) - {"secrets-init", "migrate"}
HEALTHY_ROLES = frozenset({"postgres", "valkey", "api", "frontend", "gateway"})
ROLE_NETWORK_KINDS = {
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


def command_environment() -> dict[str, str]:
    return {
        "HOME": "/home/secpal-ci",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "XDG_RUNTIME_DIR": "/run/user/20000",
        "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/20000/bus",
        "QUADLET_UNIT_DIRS": "/etc/containers/systemd/users/20000",
    }


def command_result(arguments: list[str], timeout: int = 20) -> tuple[int, str, bool]:
    try:
        completed = subprocess.run(
            arguments,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            env=command_environment(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return 255, "", False
    complete = len(completed.stdout) <= MAX_OUTPUT
    return (
        completed.returncode,
        completed.stdout[:MAX_OUTPUT].decode("utf-8", errors="replace").strip(),
        complete,
    )


def checked_output(arguments: list[str], timeout: int = 20) -> str:
    status_code, value, complete = command_result(arguments, timeout)
    return value if status_code == 0 and complete else ""


def json_array(arguments: list[str], timeout: int = 30) -> tuple[list[object], bool]:
    status_code, value, complete = command_result(arguments, timeout)
    if status_code != 0 or not complete:
        return [], False
    try:
        document = json.loads(value)
    except json.JSONDecodeError:
        return [], False
    return (document, True) if isinstance(document, list) else ([], False)


def expected_unit_names(instance: str) -> tuple[str, ...]:
    if re.fullmatch(r"[0-9a-f]{12}", instance) is None:
        raise ValueError("fixture instance is outside the closed contract")
    prefix = f"secpal-int-{instance}"
    names = [f"{prefix}-{role}.container" for role in ROLES]
    names.extend(f"{prefix}-{kind}.network" for kind in NETWORK_KINDS)
    names.extend(f"{prefix}-{kind}.volume" for kind in VOLUME_KINDS)
    names.append(f"{prefix}.target")
    return tuple(sorted(names))


def admit_collection_context(
    phase: str, target_sha: str, instance: str, checkout: Path
) -> None:
    if phase not in {"live", "post-cleanup"}:
        raise ValueError("collection phase is outside the closed contract")
    if os.getuid() != CI_UID or os.getgid() != CI_GID:
        raise ValueError("collector must run as UID/GID 20000")
    if re.fullmatch(r"[0-9a-f]{40}", target_sha) is None:
        raise ValueError("target SHA is not a full lowercase commit")
    if instance != target_sha[:12]:
        raise ValueError("fixture instance is not derived from the target SHA")
    if checkout != CHECKOUT:
        raise ValueError("target checkout path is outside the closed contract")
    actual_sha = checked_output(
        ["git", "-C", str(checkout), "rev-parse", "--verify", "HEAD^{commit}"]
    )
    if actual_sha != target_sha:
        raise ValueError("collector did not admit the exact target SHA")


def file_fact(path: Path, name: str) -> dict[str, object] | None:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None
    try:
        before = os.fstat(descriptor)
        content = os.read(descriptor, 64 * 1024 + 1)
        after = os.fstat(descriptor)
    except OSError:
        return None
    finally:
        os.close(descriptor)
    identity = lambda value: (
        value.st_dev, value.st_ino, value.st_uid, value.st_gid, value.st_mode,
        value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns,
    )
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or len(content) > 64 * 1024
        or identity(before) != identity(after)
    ):
        return None
    return {
        "name": name,
        "path": str(path),
        "uid": before.st_uid,
        "gid": before.st_gid,
        "mode": f"0{stat.S_IMODE(before.st_mode):03o}",
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def installed_unit_facts(instance: str) -> tuple[list[dict[str, object]], bool]:
    facts: list[dict[str, object]] = []
    complete = True
    for name in expected_unit_names(instance):
        path = (SYSTEMD_ROOT if name.endswith(".target") else QUADLET_ROOT) / name
        fact = file_fact(path, name)
        if fact is None:
            complete = False
        else:
            facts.append(fact)
    prefix = f"secpal-int-{instance}"
    expected_paths = {
        str((SYSTEMD_ROOT if name.endswith(".target") else QUADLET_ROOT) / name)
        for name in expected_unit_names(instance)
    }
    try:
        observed_paths = {
            str(path)
            for root in (QUADLET_ROOT, SYSTEMD_ROOT)
            for path in root.iterdir()
            if path.name.startswith(prefix)
        }
        complete = complete and observed_paths == expected_paths
    except OSError:
        complete = False
    return facts, complete


def metadata_fact(path: Path) -> tuple[int, int, str] | None:
    try:
        metadata = path.lstat()
    except OSError:
        return None
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        return None
    return metadata.st_uid, metadata.st_gid, f"0{stat.S_IMODE(metadata.st_mode):03o}"


def generated_service_facts(instance: str) -> tuple[list[dict[str, object]], bool]:
    facts: list[dict[str, object]] = []
    complete = True
    prefix = f"secpal-int-{instance}"
    for logical_name in GENERATED_LOGICAL_NAMES:
        unit = f"{prefix}-{logical_name}.service"
        status_code, value, bounded = command_result(
            [
                "systemctl", "--user", "show", unit,
                "--property=FragmentPath", "--property=DropInPaths",
            ]
        )
        properties: dict[str, str] = {}
        for line in value.splitlines():
            if "=" in line:
                key, item = line.split("=", 1)
                properties[key] = item
        fragment = Path(properties.get("FragmentPath", ""))
        drop_ins = [Path(item) for item in properties.get("DropInPaths", "").split()]
        fragment_metadata = metadata_fact(fragment) if str(fragment) != "." else None
        drop_in_metadata = [metadata_fact(path) for path in drop_ins]
        if status_code != 0 or not bounded or fragment_metadata is None or any(
            item is None for item in drop_in_metadata
        ):
            complete = False
            continue
        facts.append(
            {
                "logical_name": logical_name,
                "unit": unit,
                "fragment_path": str(fragment),
                "fragment_uid": fragment_metadata[0],
                "fragment_gid": fragment_metadata[1],
                "fragment_mode": fragment_metadata[2],
                "drop_in_paths": [str(path) for path in drop_ins],
                "drop_in_owners": [
                    {"uid": item[0], "gid": item[1], "mode": item[2]}
                    for item in drop_in_metadata
                    if item is not None
                ],
            }
        )
    return facts, complete


def names_from_listing(
    arguments: list[str], prefix: str
) -> tuple[list[str], bool]:
    rows, complete = json_array(arguments)
    names: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            complete = False
            continue
        raw_names = row.get("Names", row.get("Name", []))
        candidates = raw_names if isinstance(raw_names, list) else [raw_names]
        for name in candidates:
            if isinstance(name, str) and name.startswith(prefix):
                names.append(name)
    return sorted(names), complete and len(names) == len(set(names))


def container_facts(instance: str) -> tuple[list[dict[str, object]], bool]:
    prefix = f"secpal-int-{instance}-"
    names, complete = names_from_listing(
        ["podman", "ps", "--all", "--format", "json"], prefix
    )
    if not names:
        return [], complete
    inspections, inspection_complete = json_array(
        ["podman", "container", "inspect", *names], timeout=60
    )
    complete = complete and inspection_complete and len(inspections) == len(names)
    facts: list[dict[str, object]] = []
    for item in inspections:
        if not isinstance(item, dict):
            complete = False
            continue
        name = str(item.get("Name", "")).lstrip("/")
        role = name.removeprefix(prefix)
        state = item.get("State", {})
        config = item.get("Config", {})
        host_config = item.get("HostConfig", {})
        network_settings = item.get("NetworkSettings", {})
        if not all(isinstance(value, dict) for value in (state, config, host_config, network_settings)):
            complete = False
            continue
        required_item = {"Name", "State", "Config", "HostConfig", "NetworkSettings", "Mounts", "OCIRuntime", "Rootless"}
        required_state = {"Status", "ExitCode"}
        required_config = {"Labels", "Env", "Image"}
        required_host_config = {
            "Privileged", "PidMode", "UsernsMode", "NetworkMode",
            "SecurityOpt", "CapAdd", "Devices",
        }
        required_network_settings = {"Networks", "Ports"}
        if (
            not required_item.issubset(item)
            or not required_state.issubset(state)
            or not required_config.issubset(config)
            or not required_host_config.issubset(host_config)
            or not required_network_settings.issubset(network_settings)
            or not isinstance(item["Rootless"], bool)
            or not isinstance(item["Mounts"], list)
            or not isinstance(config["Labels"], dict)
            or not isinstance(config["Env"], list)
            or not isinstance(host_config["Privileged"], bool)
            or not isinstance(host_config["SecurityOpt"], list)
            or not isinstance(host_config["CapAdd"], list)
            or not isinstance(host_config["Devices"], list)
            or not isinstance(network_settings["Networks"], dict)
            or not isinstance(network_settings["Ports"], dict)
        ):
            complete = False
            continue
        health_value = state.get("Health", {})
        health = (
            str(health_value.get("Status", "none"))
            if isinstance(health_value, dict)
            else "none"
        )
        labels = config["Labels"]
        network_map = network_settings["Networks"]
        port_map = network_settings["Ports"]
        published: list[str] = []
        port_fact_complete = True
        for container_port, bindings in port_map.items():
            if bindings is None:
                continue
            if not isinstance(container_port, str) or not isinstance(bindings, list):
                port_fact_complete = False
                continue
            for binding in bindings:
                if not isinstance(binding, dict) or set(binding) != {"HostIp", "HostPort"} or not all(
                    isinstance(binding[field], str) and binding[field]
                    for field in ("HostIp", "HostPort")
                ):
                    port_fact_complete = False
                    continue
                published.append(
                    f"{binding['HostIp']}:{binding['HostPort']}:{container_port}"
                )
        if not port_fact_complete:
            complete = False
        security_opt = host_config["SecurityOpt"]
        cap_add = host_config["CapAdd"]
        devices = host_config["Devices"]
        mounts = item["Mounts"]
        environment = config["Env"]
        if any(not isinstance(value, str) for value in environment) or any(
            not isinstance(value, dict) for value in mounts
        ):
            complete = False
        socket_paths = ("/run/podman", "/run/user/20000/podman", "podman.sock")
        podman_socket_mount = any(
            isinstance(mount, dict)
            and any(
                marker in str(mount.get(field, ""))
                for marker in socket_paths
                for field in ("Source", "Destination")
            )
            for mount in mounts
        )
        remote_api_environment = any(
            isinstance(value, str)
            and value.split("=", 1)[0] in {"CONTAINER_HOST", "DOCKER_HOST"}
            for value in environment
        )
        facts.append(
            {
                "role": role,
                "name": name,
                "state": str(state.get("Status", "")),
                "exit_code": int(state.get("ExitCode", -1)),
                "health": health,
                "oci_runtime": str(item["OCIRuntime"]),
                "rootless": item["Rootless"],
                "privileged": host_config["Privileged"],
                "pid_mode": str(host_config["PidMode"] or "private"),
                "userns_mode": str(host_config["UsernsMode"] or "private"),
                "network_mode": str(host_config["NetworkMode"] or "private"),
                "cap_add": sorted(str(value) for value in cap_add),
                "devices_present": bool(devices),
                "podman_socket_mount": podman_socket_mount,
                "remote_api_environment": remote_api_environment,
                "security_opt": sorted(str(value) for value in security_opt),
                "networks": sorted(str(value) for value in network_map),
                "published_ports": sorted(published),
                "auto_update": "io.containers.autoupdate" in labels,
                "image": str(item.get("ImageName", config.get("Image", ""))),
            }
        )
    return sorted(facts, key=lambda fact: str(fact["role"])), complete


def quadlet_search_paths() -> list[str]:
    environment = checked_output(["systemctl", "--user", "show-environment"])
    for line in environment.splitlines():
        if line.startswith("QUADLET_UNIT_DIRS="):
            return [value for value in line.split("=", 1)[1].split(":") if value]
    return []


def podman_runtime_facts() -> tuple[bool, str, bool]:
    status_code, value, complete = command_result(
        ["podman", "info", "--format", "json"], timeout=30
    )
    if status_code != 0 or not complete:
        return False, "", False
    try:
        document = json.loads(value)
    except json.JSONDecodeError:
        return False, "", False
    host = document.get("host", {}) if isinstance(document, dict) else {}
    security = host.get("security", {}) if isinstance(host, dict) else {}
    runtime = host.get("ociRuntime", {}) if isinstance(host, dict) else {}
    if not isinstance(security, dict) or not isinstance(runtime, dict):
        return False, "", False
    return security.get("rootless") is True, str(runtime.get("name", "")), True


def control_resource_facts() -> dict[str, bool]:
    networks, networks_complete = names_from_listing(
        ["podman", "network", "ls", "--format", "json"], CONTROL_NETWORK
    )
    volumes, volumes_complete = names_from_listing(
        ["podman", "volume", "ls", "--format", "json"], CONTROL_VOLUME
    )
    return {
        "network_present": networks_complete and networks == [CONTROL_NETWORK],
        "volume_present": volumes_complete and volumes == [CONTROL_VOLUME],
    }


def podman_api_facts() -> tuple[bool, bool]:
    for scope in ([], ["--user"]):
        for kind in ("service", "socket"):
            status_code, _, complete = command_result(
                ["systemctl", *scope, "is-active", f"podman.{kind}"]
            )
            if not complete or status_code not in {0, 3, 4}:
                return True, False
            if status_code == 0:
                return True, True
    connections, complete = json_array(
        ["podman", "system", "connection", "list", "--format", "json"]
    )
    if not complete or bool(connections):
        return True, complete
    socket_status, sockets, socket_complete = command_result(["ss", "-lxnp"])
    if socket_status != 0 or not socket_complete:
        return True, False
    if re.search(
        r"/(?:run/podman|run/user/20000/podman)/(?!nv-proxy\.sock)\S+",
        sockets,
    ):
        return True, True
    try:
        processes = tuple(Path("/proc").iterdir())
    except OSError:
        return True, False
    for process in processes:
        if not process.name.isdigit():
            continue
        try:
            with (process / "cmdline").open("rb") as stream:
                arguments = stream.read(8193)
        except FileNotFoundError:
            continue
        except OSError:
            return True, False
        if len(arguments) > 8192:
            return True, False
        fields = [value for value in arguments.split(b"\0") if value]
        if fields and Path(fields[0].decode(errors="replace")).name == "podman" and any(
            fields[index:index + 2] == [b"system", b"service"]
            for index in range(1, len(fields) - 1)
        ):
            return True, True
    return False, True


def collect_live(instance: str) -> dict[str, object]:
    units, units_complete = installed_unit_facts(instance)
    services, services_complete = generated_service_facts(instance)
    containers, containers_complete = container_facts(instance)
    prefix = f"secpal-int-{instance}-"
    networks, networks_complete = names_from_listing(
        ["podman", "network", "ls", "--format", "json"], prefix
    )
    volumes, volumes_complete = names_from_listing(
        ["podman", "volume", "ls", "--format", "json"], prefix
    )
    podman_rootless, oci_runtime, runtime_complete = podman_runtime_facts()
    podman_api, podman_api_complete = podman_api_facts()
    by_role = {str(item.get("role")): item for item in containers}
    migrate = by_role.get("migrate", {})
    ready_roles = sorted(
        role
        for role in READY_ROLES
        if by_role.get(role, {}).get("state") == "running"
        and (
            by_role.get(role, {}).get("health") == "healthy"
            if role in HEALTHY_ROLES
            else by_role.get(role, {}).get("health") == "none"
        )
    )
    return {
        "phase": "live",
        "target_admitted": True,
        "collector_uid": os.getuid(),
        "collector_gid": os.getgid(),
        "complete": all(
            (
                units_complete, services_complete, containers_complete,
                networks_complete, volumes_complete, runtime_complete,
                podman_api_complete,
            )
        ),
        "quadlet_search_paths": quadlet_search_paths(),
        "installed_units": units,
        "generated_services": services,
        "containers": containers,
        "podman_rootless": podman_rootless,
        "oci_runtime": oci_runtime,
        "singleton_roles": {
            role: sum(item.get("role") == role for item in containers)
            for role in ("scheduler", "worker-hash-chain")
        },
        "networks": networks,
        "volumes": volumes,
        "migration": {
            "observed": bool(migrate),
            "exit_code": int(migrate.get("exit_code", -1)),
        },
        "readiness": {
            "observed": set(ready_roles) == READY_ROLES,
            "ready_roles": ready_roles,
        },
        "podman_api": podman_api,
        "control_resources": control_resource_facts(),
    }


def collect_post_cleanup(instance: str) -> dict[str, object]:
    prefix = f"secpal-int-{instance}"
    owned_units = []
    for root in (QUADLET_ROOT, SYSTEMD_ROOT):
        try:
            owned_units.extend(path.name for path in root.iterdir() if path.name.startswith(prefix))
        except OSError:
            return {
                "phase": "post-cleanup", "target_admitted": True,
                "collector_uid": os.getuid(), "collector_gid": os.getgid(),
                "complete": False, "owned_units": [], "generated_services": [],
                "containers": [], "networks": [], "volumes": [],
                "control_resources": control_resource_facts(),
            }
    generated = []
    try:
        generated = [path.name for path in GENERATOR_ROOT.glob(f"{prefix}*.service")]
    except OSError:
        pass
    containers, containers_complete = names_from_listing(
        ["podman", "ps", "--all", "--format", "json"], f"{prefix}-"
    )
    networks, networks_complete = names_from_listing(
        ["podman", "network", "ls", "--format", "json"], f"{prefix}-"
    )
    volumes, volumes_complete = names_from_listing(
        ["podman", "volume", "ls", "--format", "json"], f"{prefix}-"
    )
    return {
        "phase": "post-cleanup",
        "target_admitted": True,
        "collector_uid": os.getuid(),
        "collector_gid": os.getgid(),
        "complete": containers_complete and networks_complete and volumes_complete,
        "owned_units": sorted(owned_units),
        "generated_services": sorted(generated),
        "containers": containers,
        "networks": networks,
        "volumes": volumes,
        "control_resources": control_resource_facts(),
    }


def exact_keys(value: object, expected: set[str]) -> dict[str, Any] | None:
    return value if isinstance(value, dict) and set(value) == expected else None


def workload_admission_failures(observations: object) -> list[str]:
    failures: list[str] = []
    if not isinstance(observations, dict):
        return ["D1A_OBSERVATION_SCHEMA"]
    live_value = observations.get("live")
    cleanup_value = observations.get("post_cleanup")
    live_expected = {
        "phase", "target_admitted", "collector_uid", "collector_gid", "complete",
        "quadlet_search_paths", "installed_units", "generated_services", "containers",
        "singleton_roles", "networks", "volumes", "migration", "readiness",
        "podman_rootless", "oci_runtime", "podman_api", "control_resources",
    }
    cleanup_expected = {
        "phase", "target_admitted", "collector_uid", "collector_gid", "complete",
        "owned_units", "generated_services", "containers", "networks", "volumes",
        "control_resources",
    }
    live = exact_keys(live_value, live_expected)
    cleanup = exact_keys(cleanup_value, cleanup_expected)
    if live is None:
        failures.append("D1A_LIVE_OBSERVATION")
    if cleanup is None:
        failures.append("D1A_POST_CLEANUP_OBSERVATION")
    if live is None or cleanup is None:
        return failures
    if any(
        observation.get("target_admitted") is not True
        or observation.get("collector_uid") != CI_UID
        or observation.get("collector_gid") != CI_GID
        or observation.get("complete") is not True
        for observation in (live, cleanup)
    ):
        failures.append("D1A_OBSERVATION_INCOMPLETE")
    if live["phase"] != "live" or cleanup["phase"] != "post-cleanup":
        failures.append("D1A_PHASE_CONSISTENCY")
    instance = observations.get("instance")
    try:
        names = expected_unit_names(str(instance))
    except ValueError:
        names = ()
        failures.append("D1A_OBSERVATION_SCHEMA")
    units = live.get("installed_units")
    if not isinstance(units, list) or len(units) != 16 or {
        unit.get("name") for unit in units if isinstance(unit, dict)
    } != set(names) or any(
        not isinstance(unit, dict)
        or set(unit) != {"name", "path", "uid", "gid", "mode", "sha256"}
        or unit["uid"] != 0 or unit["gid"] != 0 or unit["mode"] != "0644"
        or re.fullmatch(r"[0-9a-f]{64}", str(unit["sha256"])) is None
        or unit["path"] != str(
            (SYSTEMD_ROOT if str(unit["name"]).endswith(".target") else QUADLET_ROOT)
            / str(unit["name"])
        )
        for unit in units if isinstance(unit, dict)
    ):
        failures.append("D1A_QUADLET_SNAPSHOT")
    if live.get("quadlet_search_paths") != [str(QUADLET_ROOT)]:
        failures.append("D1A_QUADLET_SEARCH_PATH")
    if live.get("podman_rootless") is not True:
        failures.append("D1A_ROOTLESS")
    if live.get("oci_runtime") != "crun":
        failures.append("D1A_OCI_RUNTIME")
    services = live.get("generated_services")
    if not isinstance(services, list) or len(services) != len(GENERATED_LOGICAL_NAMES) or {
        service.get("logical_name") for service in services if isinstance(service, dict)
    } != set(GENERATED_LOGICAL_NAMES) or any(
        not isinstance(service, dict)
        or set(service) != {
            "logical_name", "unit", "fragment_path", "fragment_uid", "fragment_gid",
            "fragment_mode", "drop_in_paths", "drop_in_owners",
        }
        or not str(service["fragment_path"]).startswith(f"{GENERATOR_ROOT}/")
        or service["fragment_uid"] != CI_UID
        or service["fragment_gid"] != CI_GID
        or service["fragment_mode"] != "0644"
        or any(not str(path).startswith(f"{GENERATOR_ROOT}/") for path in service["drop_in_paths"])
        or len(service["drop_in_paths"]) != len(service["drop_in_owners"])
        for service in services if isinstance(service, dict)
    ):
        failures.append("D1A_GENERATED_UNITS")
    containers = live.get("containers")
    container_roles = [
        item.get("role") for item in containers if isinstance(item, dict)
    ] if isinstance(containers, list) else []
    if len(container_roles) != len(ROLES) or set(container_roles) != set(ROLES):
        failures.append("D1A_CONTAINER_SET")
    if isinstance(containers, list):
        for item in containers:
            if not isinstance(item, dict):
                continue
            if item.get("rootless") is not True:
                failures.append("D1A_ROOTLESS")
            if item.get("oci_runtime") != "crun":
                failures.append("D1A_OCI_RUNTIME")
            if item.get("privileged") is not False or item.get("cap_add"):
                failures.append("D1A_PRIVILEGE_BOUNDARY")
            if item.get("devices_present") is not False:
                failures.append("D1A_PRIVILEGE_BOUNDARY")
            if item.get("podman_socket_mount") is not False or item.get(
                "remote_api_environment"
            ) is not False:
                failures.append("D1A_PODMAN_API_DISABLED")
            if item.get("pid_mode") != "private" or item.get("userns_mode") != "private":
                failures.append("D1A_HOST_NAMESPACES")
            if item.get("network_mode") in {"host", "container"}:
                failures.append("D1A_HOST_NETWORK")
            if item.get("auto_update") is not False:
                failures.append("D1A_AUTO_UPDATE_DISABLED")
            security_options = item.get("security_opt", [])
            if not isinstance(security_options, list) or not any(
                "no-new-privileges" in str(option) for option in security_options
            ) or any(
                "unconfined" in str(option) or str(option).endswith("=disable")
                for option in security_options
            ):
                failures.append("D1A_SECURITY_OPTIONS")
            if re.fullmatch(r"localhost/secpal-ci-[a-z0-9-]+@sha256:[0-9a-f]{64}", str(item.get("image"))) is None:
                failures.append("D1A_IMAGE_PROVENANCE")
            if any(network == "host" for network in item.get("networks", [])):
                failures.append("D1A_HOST_NETWORK")
            role = str(item.get("role"))
            expected_networks = [
                f"secpal-int-{instance}-{kind}"
                for kind in ROLE_NETWORK_KINDS.get(role, ())
            ]
            if item.get("networks") != expected_networks:
                failures.append("D1A_CONTAINER_NETWORKS")
            published_ports = item.get("published_ports")
            if role == "gateway":
                valid_ports = (
                    isinstance(published_ports, list)
                    and len(published_ports) == 1
                    and re.fullmatch(
                        r"127\.0\.0\.1:([1-9][0-9]{0,4}):8443/tcp",
                        str(published_ports[0]),
                    ) is not None
                    and int(str(published_ports[0]).split(":", 2)[1]) <= 65535
                )
            else:
                valid_ports = published_ports == []
            if not valid_ports:
                failures.append("D1A_PUBLISHED_PORTS")
    if live.get("singleton_roles") != {"scheduler": 1, "worker-hash-chain": 1}:
        failures.append("D1A_SINGLETON_ROLES")
    if live.get("podman_api") is not False:
        failures.append("D1A_PODMAN_API_DISABLED")
    migration = live.get("migration")
    if migration != {"observed": True, "exit_code": 0}:
        failures.append("D1A_MIGRATION")
    secrets_init = next(
        (
            item for item in containers
            if isinstance(item, dict) and item.get("role") == "secrets-init"
        ),
        {},
    ) if isinstance(containers, list) else {}
    if secrets_init.get("state") != "exited" or secrets_init.get("exit_code") != 0:
        failures.append("D1A_LIFECYCLE")
    readiness = live.get("readiness")
    if not isinstance(readiness, dict) or readiness.get("observed") is not True or set(
        readiness.get("ready_roles", [])
    ) != READY_ROLES:
        failures.append("D1A_READINESS")
    elif any(
        not isinstance(item, dict)
        or item.get("state") != "running"
        or (
            item.get("health") != "healthy"
            if item.get("role") in HEALTHY_ROLES
            else item.get("health") != "none"
        )
        for item in containers
        if isinstance(item, dict) and item.get("role") in READY_ROLES
    ):
        failures.append("D1A_READINESS")
    prefix = f"secpal-int-{instance}-"
    if len(live.get("networks", [])) != len(NETWORK_KINDS) or set(
        live.get("networks", [])
    ) != {f"{prefix}{kind}" for kind in NETWORK_KINDS}:
        failures.append("D1A_NETWORK_SET")
    if len(live.get("volumes", [])) != len(VOLUME_KINDS) or set(
        live.get("volumes", [])
    ) != {f"{prefix}{kind}" for kind in VOLUME_KINDS}:
        failures.append("D1A_VOLUME_SET")
    if any(cleanup.get(name) for name in (
        "owned_units", "generated_services", "containers", "networks", "volumes"
    )):
        failures.append("D1A_CLEANUP_ABSENCE")
    for observation in (live, cleanup):
        if observation.get("control_resources") != {
            "network_present": True, "volume_present": True
        }:
            failures.append("D1A_CONTROL_RESOURCES_PRESERVED")
            break
    return list(dict.fromkeys(failures))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=["live", "post-cleanup"])
    parser.add_argument("target_sha")
    parser.add_argument("instance")
    arguments = parser.parse_args()
    try:
        admit_collection_context(arguments.phase, arguments.target_sha, arguments.instance, CHECKOUT)
        observation = (
            collect_live(arguments.instance)
            if arguments.phase == "live"
            else collect_post_cleanup(arguments.instance)
        )
    except ValueError as error:
        print(f"ERROR: workload collection refused: {error}", file=sys.stderr)
        return 1
    json.dump(observation, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
