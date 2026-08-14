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
import selectors
import shlex
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, NamedTuple


CI_UID = 20000
CI_GID = 20000
PROTOCOL_VERSION = 1
MAX_OUTPUT = 256 * 1024
CHECKOUT = Path("/home/secpal-ci/deployment-target")
QUADLET_ROOT = Path("/etc/containers/systemd/users/20000")
SYSTEMD_ROOT = Path("/etc/systemd/user")
GENERATOR_BASE = Path("/run/user/20000/systemd")
GENERATOR_ROOT = GENERATOR_BASE / "generator"
GENERATOR_ROOTS = tuple(
    GENERATOR_BASE / name
    for name in ("generator.early", "generator", "generator.late")
)
PODMAN_EXECUTABLE = Path("/usr/bin/podman")
DBUS_SOCKET_FRAGMENTS = frozenset(
    {Path("/usr/lib/systemd/user/dbus.socket"), Path("/lib/systemd/user/dbus.socket")}
)
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
class RoleContract(NamedTuple):
    identity: tuple[int, int]
    networks: tuple[str, ...] = ()
    volumes: tuple[tuple[str, str, bool], ...] = ()
    binds: tuple[tuple[str, str], ...] = ()
    tmpfs: tuple[tuple[str, int, str, bool], ...] = ()
    capabilities: tuple[str, ...] = ()
    entrypoint: tuple[str, ...] | None = None
    command: tuple[str, ...] | None = None
    healthcheck: tuple[str, ...] | None = None


API_VOLUMES = (
    ("secrets", "/run/secpal-secrets", False),
    ("private-storage", "/app/storage/app/private", True),
)
API_BINDS = (
    ("container-entrypoint.sh", "/run/secpal/container-entrypoint.sh"),
    ("phase-b-runtime-probe.php", "/run/secpal/phase-b-runtime-probe.php"),
)
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
ROLE_CONTRACTS = {
    "secrets-init": RoleContract(
        (0, 0),
        networks=(),
        volumes=(
            ("secrets", "/run/secpal-secrets", True),
            ("postgres", "/var/lib/postgresql/data", True),
            ("private-storage", "/mnt/secpal-private-storage", True),
        ),
        binds=(
            ("init-local-secrets.sh", "/run/secpal/init-local-secrets.sh"),
            (
                "quadlet-oneshot-entrypoint.sh",
                "/run/secpal/quadlet-oneshot-entrypoint.sh",
            ),
        ),
        tmpfs=(("/tmp", 16, "0700", True),),
        capabilities=("CAP_CHOWN", "CAP_FOWNER"),
        entrypoint=("/bin/bash", "/run/secpal/init-local-secrets.sh"),
        command=(),
        healthcheck=(),
    ),
    "postgres": RoleContract(
        (999, 999),
        networks=("application",),
        volumes=(
            ("secrets", "/run/secpal-secrets", False),
            ("postgres", "/var/lib/postgresql/data", True),
        ),
        tmpfs=(("/tmp", 32, "0700", True), ("/run/postgresql", 16, "0750", True)),
    ),
    "valkey": RoleContract(
        (10002, 10002),
        networks=("application",),
        volumes=(("secrets", "/run/secpal-secrets", False),),
        binds=(("valkey-entrypoint.sh", "/run/secpal/valkey-entrypoint.sh"),),
        tmpfs=(("/tmp", 16, "0700", True), ("/data", 32, "0700", True)),
    ),
    "migrate": RoleContract(
        (10001, 10001),
        networks=("application",),
        volumes=API_VOLUMES,
        binds=API_BINDS
        + (("quadlet-oneshot-entrypoint.sh", "/run/secpal/quadlet-oneshot-entrypoint.sh"),),
        tmpfs=API_TMPFS,
        entrypoint=("/bin/bash", "/run/secpal/container-entrypoint.sh"),
        command=("php", "artisan", "migrate", "--force"),
        healthcheck=(),
    ),
    "api": RoleContract(
        (10001, 10001),
        networks=("application", "edge"),
        volumes=API_VOLUMES,
        binds=API_BINDS,
        tmpfs=API_TMPFS,
        entrypoint=("/bin/bash", "/run/secpal/container-entrypoint.sh"),
        command=("frankenphp", "run", "--config", "/etc/frankenphp/Caddyfile"),
        healthcheck=("CMD", "/usr/local/bin/secpal-http-live"),
    ),
    "worker-general": RoleContract(
        (10001, 10001), networks=("application",), volumes=API_VOLUMES,
        binds=API_BINDS, tmpfs=API_TMPFS,
        entrypoint=("/bin/bash", "/run/secpal/container-entrypoint.sh"),
        command=(
            "php", "artisan", "queue:work",
            "--queue=merkle,opentimestamp,default", "--sleep=1", "--tries=3",
            "--timeout=90",
        ),
        healthcheck=(),
    ),
    "worker-hash-chain": RoleContract(
        (10001, 10001), networks=("application",), volumes=API_VOLUMES,
        binds=API_BINDS, tmpfs=API_TMPFS,
        entrypoint=("/bin/bash", "/run/secpal/container-entrypoint.sh"),
        command=(
            "php", "artisan", "queue:work", "--queue=activity-hash-chain",
            "--sleep=1", "--tries=3", "--timeout=90",
        ),
        healthcheck=(),
    ),
    "scheduler": RoleContract(
        (10001, 10001), networks=("application",), volumes=API_VOLUMES,
        binds=API_BINDS, tmpfs=API_TMPFS,
        entrypoint=("/bin/bash", "/run/secpal/container-entrypoint.sh"),
        command=("php", "artisan", "schedule:work"),
        healthcheck=(),
    ),
    "frontend": RoleContract(
        (101, 101), networks=("edge",), tmpfs=(("/tmp", 32, "0700", True),)
    ),
    "gateway": RoleContract(
        (10003, 10003),
        networks=("edge",),
        binds=(("Caddyfile", "/etc/caddy/Caddyfile"),),
        tmpfs=(
            ("/tmp", 16, "0700", True),
            ("/config", 16, "0700", True),
            ("/data", 32, "0700", True),
        ),
    ),
}
BASELINE_OBSERVATION_FIELDS = frozenset(
    {
        "phase", "target_admitted", "collector_uid", "collector_gid", "complete",
        "containers", "networks", "volumes", "migration_invocation_count",
        "podman_api", "user_work", "processes", "control_resources",
    }
)
LIVE_OBSERVATION_FIELDS = frozenset(
    {
        "phase", "target_admitted", "collector_uid", "collector_gid", "complete",
        "quadlet_search_paths", "installed_units", "generated_services",
        "containers", "networks", "volumes", "all_containers",
        "all_networks", "all_volumes",
        "podman_rootless", "oci_runtime", "podman_api", "user_work",
        "processes", "control_resources",
    }
)
CLEANUP_OBSERVATION_FIELDS = frozenset(
    {
        "phase", "target_admitted", "collector_uid", "collector_gid", "complete",
        "owned_units", "generated_services", "containers", "networks", "volumes",
        "all_containers", "all_networks", "all_volumes",
        "migration_invocation_count", "podman_api", "user_work",
        "processes", "control_resources",
    }
)
TRUSTED_MANAGER_ENVIRONMENT = (
    "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/20000/bus",
    "HOME=/home/secpal-ci",
    "LANG=C.UTF-8",
    "LC_ALL=C.UTF-8",
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    f"QUADLET_UNIT_DIRS={QUADLET_ROOT}",
    "XDG_RUNTIME_DIR=/run/user/20000",
)


def incomplete_observation(phase: str) -> dict[str, object]:
    common: dict[str, object] = {
        "phase": phase,
        "target_admitted": False,
        "collector_uid": CI_UID,
        "collector_gid": CI_GID,
        "complete": False,
        "containers": [],
        "networks": [],
        "volumes": [],
        "control_resources": {
            "network_present": False,
            "volume_present": False,
            "network_id": "",
            "volume_created_at": "",
        },
    }
    if phase == "baseline":
        common["migration_invocation_count"] = 0
        common["podman_api"] = True
        common["user_work"] = {"active_units": [], "jobs": []}
        common["processes"] = []
        return common
    common.update(
        {
            "all_containers": [],
            "all_networks": [],
            "all_volumes": [],
            "generated_services": [],
        }
    )
    if phase == "post-cleanup":
        common["owned_units"] = []
        common["migration_invocation_count"] = 0
        common["podman_api"] = True
        common["user_work"] = {"active_units": [], "jobs": []}
        common["processes"] = []
        return common
    if phase != "live":
        raise ValueError("observation phase is outside the closed contract")
    common.update(
        {
            "quadlet_search_paths": [],
            "installed_units": [],
            "podman_rootless": False,
            "oci_runtime": "",
            "podman_api": True,
            "user_work": {"active_units": [], "jobs": []},
            "processes": [],
        }
    )
    return common


def command_environment() -> dict[str, str]:
    return {
        "HOME": "/home/secpal-ci",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "XDG_RUNTIME_DIR": "/run/user/20000",
        "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/20000/bus",
        "QUADLET_UNIT_DIRS": "/etc/containers/systemd/users/20000",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
    }


def command_result(arguments: list[str], timeout: int = 20) -> tuple[int, str, bool]:
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            arguments,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=command_environment(),
            start_new_session=True,
        )
        if process.stdout is None:
            raise OSError("subprocess stdout pipe is unavailable")
        deadline = time.monotonic() + timeout
        output = bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(arguments, timeout)
                events = selector.select(remaining)
                if not events:
                    raise subprocess.TimeoutExpired(arguments, timeout)
                chunk = os.read(
                    process.stdout.fileno(),
                    min(65_536, MAX_OUTPUT + 1 - len(output)),
                )
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > MAX_OUTPUT:
                    raise OverflowError("subprocess output exceeded the bound")
        status_code = process.wait(timeout=max(0.1, deadline - time.monotonic()))
        process.stdout.close()
    except (OSError, OverflowError, subprocess.TimeoutExpired):
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (OSError, ProcessLookupError):
                pass
            try:
                process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                pass
            if process.stdout is not None:
                process.stdout.close()
        return 255, "", False
    return (
        status_code,
        bytes(output).decode("utf-8", errors="replace").strip(),
        True,
    )


def checked_output(arguments: list[str], timeout: int = 20) -> str:
    status_code, value, complete = command_result(arguments, timeout)
    return value if status_code == 0 and complete else ""


def checkout_tree_clean(checkout: Path, target_sha: str) -> bool:
    git = [
        "git",
        f"--git-dir={checkout / '.git'}",
        f"--work-tree={checkout}",
        "-c", "core.fsmonitor=false",
        "-c", "core.hooksPath=/dev/null",
    ]
    index_status, _, index_complete = command_result(
        [*git, "read-tree", "--reset", target_sha]
    )
    diff_status, _, diff_complete = command_result(
        [*git, "diff-index", "--quiet", "--no-ext-diff", target_sha, "--"]
    )
    untracked_status, untracked, untracked_complete = command_result(
        [*git, "ls-files", "--others"]
    )
    return (
        index_status == 0
        and index_complete
        and diff_status == 0
        and diff_complete
        and untracked_status == 0
        and untracked_complete
        and untracked == ""
    )


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


def expected_generated_source(instance: str, logical_name: str) -> Path:
    if re.fullmatch(r"[0-9a-f]{12}", instance) is None:
        raise ValueError("fixture instance is outside the closed contract")
    prefix = f"secpal-int-{instance}"
    if logical_name in ROLES:
        return QUADLET_ROOT / f"{prefix}-{logical_name}.container"
    if logical_name.endswith("-network"):
        kind = logical_name.removesuffix("-network")
        if kind in NETWORK_KINDS:
            return QUADLET_ROOT / f"{prefix}-{kind}.network"
    if logical_name.endswith("-volume"):
        kind = logical_name.removesuffix("-volume")
        if kind in VOLUME_KINDS:
            return QUADLET_ROOT / f"{prefix}-{kind}.volume"
    raise ValueError("generated logical name is outside the closed contract")


def admit_collection_context(
    phase: str, target_sha: str, instance: str, checkout: Path
) -> None:
    if phase not in {"baseline", "normalize", "live", "post-cleanup"}:
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
    if not checkout_tree_clean(checkout, target_sha):
        raise ValueError("collector did not admit a clean target tree")


def manager_environment() -> dict[str, str] | None:
    status, output, complete = command_result(
        ["systemctl", "--user", "show-environment"]
    )
    if status != 0 or not complete or len(output.encode("utf-8")) > 16_384:
        return None
    environment: dict[str, str] = {}
    for line in output.splitlines():
        if len(line) > 2048 or "=" not in line or "\x00" in line:
            return None
        name, value = line.split("=", 1)
        if (
            re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", name) is None
            or name in environment
        ):
            return None
        environment[name] = value
        if len(environment) > 128:
            return None
    return environment


def normalize_quadlet_runtime(instance: str, *, activate: bool) -> bool:
    if re.fullmatch(r"[0-9a-f]{12}", instance) is None:
        return False
    existing = manager_environment()
    if existing is None:
        return False
    names = sorted(existing)
    if names:
        unset_status, _, unset_complete = command_result(
            ["systemctl", "--user", "unset-environment", *names]
        )
        if unset_status != 0 or not unset_complete:
            return False
    set_status, _, set_complete = command_result(
        ["systemctl", "--user", "set-environment", *TRUSTED_MANAGER_ENVIRONMENT]
    )
    if set_status != 0 or not set_complete:
        return False
    reload_status, _, reload_complete = command_result(
        ["systemctl", "--user", "daemon-reload"], timeout=60
    )
    if reload_status != 0 or not reload_complete:
        return False
    if activate:
        prefix = f"secpal-int-{instance}"
        target = f"{prefix}.target"
        services = [
            f"{prefix}-{logical_name}.service"
            for logical_name in GENERATED_LOGICAL_NAMES
        ]
        stop_status, _, stop_complete = command_result(
            ["systemctl", "--user", "stop", target, *services], timeout=120
        )
        if stop_status != 0 or not stop_complete:
            return False
        start_status, _, start_complete = command_result(
            ["systemctl", "--user", "start", target], timeout=600
        )
        if start_status != 0 or not start_complete:
            return False
    observed = manager_environment()
    expected = dict(item.split("=", 1) for item in TRUSTED_MANAGER_ENVIRONMENT)
    return (
        observed == expected
        and quadlet_search_paths() == [str(QUADLET_ROOT)]
    )


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


def generated_file_fact(path: Path) -> tuple[int, int, str, str] | None:
    fact = file_fact(path, path.name)
    if fact is None:
        return None
    return (
        int(fact["uid"]),
        int(fact["gid"]),
        str(fact["mode"]),
        str(fact["sha256"]),
    )


def generated_service_facts(instance: str) -> tuple[list[dict[str, object]], bool]:
    facts: list[dict[str, object]] = []
    complete = True
    prefix = f"secpal-int-{instance}"
    expected_properties = {
        "FragmentPath", "DropInPaths", "ActiveState", "SubState", "Result",
        "ExecMainStatus", "MainPID", "ControlGroup", "InvocationID",
        "SourcePath",
    }
    for logical_name in GENERATED_LOGICAL_NAMES:
        unit = f"{prefix}-{logical_name}.service"
        status_code, value, bounded = command_result(
            [
                "systemctl", "--user", "show", unit,
                "--property=FragmentPath", "--property=DropInPaths",
                "--property=ActiveState", "--property=SubState",
                "--property=Result", "--property=ExecMainStatus",
                "--property=MainPID", "--property=ControlGroup",
                "--property=InvocationID", "--property=SourcePath",
            ]
        )
        properties: dict[str, str] = {}
        for line in value.splitlines():
            if "=" not in line:
                properties = {}
                break
            key, item = line.split("=", 1)
            if key not in expected_properties or key in properties:
                properties = {}
                break
            properties[key] = item
        fragment = Path(properties.get("FragmentPath", ""))
        drop_ins = [Path(item) for item in properties.get("DropInPaths", "").split()]
        fragment_metadata = (
            generated_file_fact(fragment) if str(fragment) != "." else None
        )
        drop_in_metadata = [generated_file_fact(path) for path in drop_ins]
        source_path = properties.get("SourcePath", "")
        active_state = properties.get("ActiveState", "")
        sub_state = properties.get("SubState", "")
        result = properties.get("Result", "")
        exec_main_status = properties.get("ExecMainStatus", "")
        main_pid = properties.get("MainPID", "")
        control_group = properties.get("ControlGroup", "")
        invocation_id = properties.get("InvocationID", "")
        if (
            status_code != 0
            or not bounded
            or set(properties) != expected_properties
            or fragment_metadata is None
            or any(item is None for item in drop_in_metadata)
            or re.fullmatch(r"[a-z][a-z0-9-]{0,31}", active_state) is None
            or re.fullmatch(r"[a-z][a-z0-9-]{0,31}", sub_state) is None
            or re.fullmatch(r"[a-z][a-z0-9-]{0,31}", result) is None
            or re.fullmatch(r"[0-9]{1,3}", exec_main_status) is None
            or int(exec_main_status) > 255
            or re.fullmatch(r"[0-9]{1,10}", main_pid) is None
            or int(main_pid) > 4_194_304
            or len(control_group) > 256
            or control_group != "" and not control_group.startswith("/")
            or len(source_path) > 256
            or not source_path.startswith("/")
            or "\x00" in source_path
            or re.fullmatch(r"[0-9a-f]{32}", invocation_id) is None
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
                "fragment_sha256": fragment_metadata[3],
                "source_path": source_path,
                "drop_in_paths": [str(path) for path in drop_ins],
                "drop_in_owners": [
                    {"uid": item[0], "gid": item[1], "mode": item[2]}
                    for item in drop_in_metadata
                    if item is not None
                ],
                "drop_in_sha256": [
                    item[3] for item in drop_in_metadata if item is not None
                ],
                "active_state": active_state,
                "sub_state": sub_state,
                "result": result,
                "exec_main_status": int(exec_main_status),
                "main_pid": int(main_pid),
                "control_group": control_group,
                "invocation_id": invocation_id,
            }
        )
    return facts, complete


def names_from_listing(
    arguments: list[str], prefix: str | None = None
) -> tuple[list[str], bool]:
    rows, complete = json_array(arguments)
    names: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            complete = False
            continue
        name_key = next(
            (key for key in ("Names", "Name", "name") if key in row), None
        )
        if name_key is None:
            complete = False
            continue
        raw_names = row[name_key]
        candidates = raw_names if isinstance(raw_names, list) else [raw_names]
        for name in candidates:
            if not isinstance(name, str) or not name:
                complete = False
            elif prefix is None or name.startswith(prefix):
                names.append(name)
    sorted_names = sorted(names)
    return (
        sorted_names[:128],
        complete and len(names) <= 128 and len(names) == len(set(names)),
    )


def container_lifecycle_events(
    container_id: str,
) -> tuple[list[dict[str, object]], bool]:
    if re.fullmatch(r"[0-9a-f]{64}", container_id) is None:
        return [], False
    status_code, output, complete = command_result(
        [
            "podman", "events", "--stream=false", "--format=json",
            "--since=4h",
            "--filter", f"container={container_id}",
        ],
        timeout=30,
    )
    if status_code != 0 or not complete:
        return [], False
    relevant = {"create", "start", "died"}
    events: list[dict[str, object]] = []
    try:
        for line in output.splitlines():
            if not line:
                continue
            record = json.loads(line)
            if not isinstance(record, dict):
                return [], False
            status = record.get("Status", record.get("status"))
            event_type = record.get("Type", record.get("type"))
            event_id = record.get("ID", record.get("id"))
            time_nano = record.get("TimeNano", record.get("timeNano"))
            if status not in relevant:
                if status in {"exec", "exec_died"}:
                    return [], False
                continue
            if (
                event_type != "container"
                or event_id != container_id
                or type(time_nano) is not int
                or not 0 < time_nano < 10**21
            ):
                return [], False
            events.append({"status": status, "time_nano": time_nano})
    except json.JSONDecodeError:
        return [], False
    return (
        events,
        len(events) <= 4
        and all(
            int(events[index - 1]["time_nano"])
            < int(events[index]["time_nano"])
            for index in range(1, len(events))
        ),
    )


def normalized_mounts(
    mounts: list[object],
) -> tuple[list[dict[str, object]], bool]:
    normalized: list[dict[str, object]] = []
    for mount in mounts:
        if (
            not isinstance(mount, dict)
            or not {"Type", "Destination", "RW"}.issubset(mount)
            or not isinstance(mount["Type"], str)
            or not isinstance(mount["Destination"], str)
            or not isinstance(mount["RW"], bool)
        ):
            return [], False
        mount_type = mount["Type"].lower()
        if mount_type == "tmpfs":
            continue
        source_field = "Name" if mount_type == "volume" else "Source"
        if (
            mount_type not in {"bind", "volume"}
            or not isinstance(mount.get(source_field), str)
            or not mount[source_field]
            or not mount["Destination"].startswith("/")
        ):
            return [], False
        normalized.append(
            {
                "type": mount_type,
                "source": mount[source_field],
                "destination": mount["Destination"],
                "rw": mount["RW"],
            }
        )
    normalized.sort(key=lambda item: str(item["destination"]))
    destinations = [str(item["destination"]) for item in normalized]
    return (
        normalized[:16],
        len(normalized) <= 16 and len(destinations) == len(set(destinations)),
    )


def parsed_tmpfs_size(value: str) -> int | None:
    match = re.fullmatch(r"([1-9][0-9]*)([kmg]?)", value.lower())
    if match is None:
        return None
    multipliers = {
        "": 1,
        "k": 1024,
        "m": 1024 * 1024,
        "g": 1024 * 1024 * 1024,
    }
    return int(match.group(1)) * multipliers[match.group(2)]


def normalized_tmpfs(
    tmpfs: dict[object, object],
) -> tuple[list[dict[str, object]], bool]:
    facts: list[dict[str, object]] = []
    allowed_flags = {"rprivate", "tmpcopyup", "nosuid", "nodev", "noexec", "rw"}
    for destination, raw_options in tmpfs.items():
        if (
            not isinstance(destination, str)
            or not destination.startswith("/")
            or not isinstance(raw_options, str)
        ):
            return [], False
        flags: set[str] = set()
        values: dict[str, str] = {}
        for raw_option in raw_options.split(","):
            option = raw_option.strip().lower()
            if not option:
                return [], False
            if "=" in option:
                name, value = option.split("=", 1)
                if name in values or name not in {"size", "mode", "uid", "gid"}:
                    return [], False
                values[name] = value
            elif option in flags or option not in allowed_flags:
                return [], False
            else:
                flags.add(option)
        size = parsed_tmpfs_size(values.get("size", ""))
        try:
            mode = f"{int(values.get('mode', ''), 8):04o}"
            uid = int(values.get("uid", ""), 10)
            gid = int(values.get("gid", ""), 10)
        except ValueError:
            return [], False
        if (
            size is None
            or set(values) != {"size", "mode", "uid", "gid"}
            or not 0 <= uid <= 2**32 - 1
            or not 0 <= gid <= 2**32 - 1
        ):
            return [], False
        facts.append(
            {
                "destination": destination,
                "size_bytes": size,
                "mode": mode,
                "uid": uid,
                "gid": gid,
                "flags": sorted(flags),
            }
        )
    facts.sort(key=lambda item: str(item["destination"]))
    destinations = [str(item["destination"]) for item in facts]
    return (
        facts[:16],
        len(facts) <= 16 and len(destinations) == len(set(destinations)),
    )


def normalized_command(value: object) -> tuple[list[str], bool]:
    if value is None:
        return [], True
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, list):
        values = value
    else:
        return [], False
    if (
        len(values) > 32
        or any(
            not isinstance(item, str)
            or not item
            or len(item) > 1024
            or "\x00" in item
            for item in values
        )
        or sum(len(item) for item in values) > 8192
    ):
        return [], False
    return list(values), True


def container_identity_from_host(value: int) -> int:
    if value == CI_UID:
        return 0
    if 200_000 <= value <= 265_535:
        return value - 199_999
    return -1


def container_identity_on_host(value: int) -> int:
    return CI_UID if value == 0 else 199_999 + value


def process_status_facts(
    pid: int, *, require_all_ids_equal: bool
) -> tuple[int, int, list[int], bool]:
    if pid <= 0 or pid > 4_194_304:
        return -1, -1, [], False
    try:
        with Path(f"/proc/{pid}/status").open("rb") as stream:
            content = stream.read(16_385)
    except OSError:
        return -1, -1, [], False
    if len(content) > 16_384:
        return -1, -1, [], False
    try:
        lines = content.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return -1, -1, [], False
    values: dict[str, int] = {}
    for field in ("Uid", "Gid"):
        matching = [line for line in lines if line.startswith(f"{field}:\t")]
        if len(matching) != 1:
            return -1, -1, [], False
        fields = matching[0].split()
        if len(fields) != 5 or any(not item.isdigit() for item in fields[1:]):
            return -1, -1, [], False
        effective = int(fields[2])
        if require_all_ids_equal and any(
            int(item) != effective for item in fields[1:]
        ):
            return -1, -1, [], False
        values[field] = effective
    matching_groups = [line for line in lines if line.startswith("Groups:\t")]
    if len(matching_groups) != 1:
        return -1, -1, [], False
    group_fields = matching_groups[0].split()[1:]
    if (
        len(group_fields) > 64
        or any(not item.isdigit() for item in group_fields)
    ):
        return -1, -1, [], False
    groups = [int(item) for item in group_fields]
    if len(groups) != len(set(groups)):
        return -1, -1, [], False
    return values["Uid"], values["Gid"], sorted(groups), True


def process_status_identity(
    pid: int, *, require_all_ids_equal: bool
) -> tuple[int, int, bool]:
    uid, gid, _, complete = process_status_facts(
        pid, require_all_ids_equal=require_all_ids_equal
    )
    return uid, gid, complete


def effective_process_identity(pid: int) -> tuple[int, int, list[int], bool]:
    uid, gid, supplementary_groups, complete = process_status_facts(
        pid, require_all_ids_equal=True
    )
    if not complete:
        return -1, -1, [], False
    container_uid = container_identity_from_host(uid)
    container_gid = container_identity_from_host(gid)
    container_groups = [
        container_identity_from_host(value) for value in supplementary_groups
    ]
    if (
        container_uid < 0
        or container_gid < 0
        or any(value < 0 for value in container_groups)
    ):
        return -1, -1, [], False
    return container_uid, container_gid, sorted(container_groups), True


def container_facts(
    instance: str, *, rootless: bool
) -> tuple[list[dict[str, object]], bool]:
    prefix = f"secpal-int-{instance}-"
    all_names, complete = names_from_listing(
        ["podman", "ps", "--all", "--format", "json"]
    )
    names = [name for name in all_names if name.startswith(prefix)]
    if len(names) > len(ROLES):
        names = names[:len(ROLES)]
        complete = False
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
        required_item = {
            "Id", "Name", "State", "Config", "HostConfig", "NetworkSettings",
            "Mounts", "OCIRuntime", "EffectiveCaps", "BoundingCaps",
        }
        required_state = {"Status", "ExitCode", "Pid"}
        required_config = {
            "Labels", "Env", "Image", "User", "Entrypoint", "Cmd",
            "Healthcheck",
        }
        required_host_config = {
            "Privileged", "PidMode", "UsernsMode", "IpcMode", "UTSMode",
            "NetworkMode",
            "SecurityOpt", "CapAdd", "GroupAdd", "Devices", "Tmpfs",
            "ReadonlyRootfs",
        }
        required_network_settings = {"Networks", "Ports"}
        if (
            not required_item.issubset(item)
            or not required_state.issubset(state)
            or not required_config.issubset(config)
            or not required_host_config.issubset(host_config)
            or not required_network_settings.issubset(network_settings)
            or not isinstance(item["Id"], str)
            or re.fullmatch(r"[0-9a-f]{64}", item["Id"]) is None
            or not isinstance(item["Mounts"], list)
            or not isinstance(item["EffectiveCaps"], list)
            or not isinstance(item["BoundingCaps"], list)
            or not isinstance(config["Labels"], dict)
            or not isinstance(config["Env"], list)
            or not isinstance(config["User"], str)
            or re.fullmatch(r"[0-9]{1,10}:[0-9]{1,10}", config["User"])
            is None
            or not isinstance(state["Pid"], int)
            or isinstance(state["Pid"], bool)
            or not 0 <= state["Pid"] <= 4_194_304
            or not isinstance(host_config["Privileged"], bool)
            or not isinstance(host_config["SecurityOpt"], list)
            or not isinstance(host_config["CapAdd"], list)
            or not isinstance(host_config["GroupAdd"], list)
            or not isinstance(host_config["Devices"], list)
            or not isinstance(host_config["Tmpfs"], dict)
            or not isinstance(host_config["ReadonlyRootfs"], bool)
            or not isinstance(network_settings["Networks"], dict)
            or not isinstance(network_settings["Ports"], dict)
        ):
            complete = False
            continue
        health_value = state.get("Healthcheck", {})
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
        group_add = host_config["GroupAdd"]
        effective_caps = item["EffectiveCaps"]
        bounding_caps = item["BoundingCaps"]
        devices = host_config["Devices"]
        mounts = item["Mounts"]
        environment = config["Env"]
        entrypoint, entrypoint_complete = normalized_command(config["Entrypoint"])
        command, command_complete = normalized_command(config["Cmd"])
        configured_healthcheck = config["Healthcheck"]
        if configured_healthcheck is None:
            healthcheck_command, healthcheck_complete = [], True
        elif isinstance(configured_healthcheck, dict) and set(
            configured_healthcheck
        ).issuperset({"Test"}):
            healthcheck_command, healthcheck_complete = normalized_command(
                configured_healthcheck["Test"]
            )
        else:
            healthcheck_command, healthcheck_complete = [], False
        effective_uid, effective_gid, effective_groups, identity_complete = (
            effective_process_identity(state["Pid"])
            if str(state.get("Status", "")) == "running"
            else (-1, -1, [], True)
        )
        if any(not isinstance(value, str) for value in environment) or any(
            not isinstance(value, str)
            for values in (cap_add, group_add, effective_caps, bounding_caps)
            for value in values
        ):
            complete = False
        mount_facts, mounts_complete = normalized_mounts(mounts)
        tmpfs_facts, tmpfs_complete = normalized_tmpfs(host_config["Tmpfs"])
        lifecycle_events, events_complete = container_lifecycle_events(item["Id"])
        complete = complete and all(
            (
                mounts_complete, tmpfs_complete, events_complete,
                entrypoint_complete, command_complete, healthcheck_complete,
                identity_complete,
            )
        )
        remote_api_environment = any(
            isinstance(value, str)
            and value.split("=", 1)[0] in {"CONTAINER_HOST", "DOCKER_HOST"}
            for value in environment
        )
        facts.append(
            {
                "id": item["Id"],
                "role": role,
                "name": name,
                "state": str(state.get("Status", "")),
                "pid": state["Pid"],
                "exit_code": int(state.get("ExitCode", -1)),
                "health": health,
                "oci_runtime": str(item["OCIRuntime"]),
                "rootless": rootless,
                "privileged": host_config["Privileged"],
                "configured_user": config["User"],
                "effective_uid": effective_uid,
                "effective_gid": effective_gid,
                "effective_supplementary_gids": effective_groups,
                "read_only_rootfs": host_config["ReadonlyRootfs"],
                "entrypoint": entrypoint,
                "command": command,
                "healthcheck_command": healthcheck_command,
                "pid_mode": str(host_config["PidMode"] or "private"),
                "userns_mode": str(host_config["UsernsMode"] or "host"),
                "ipc_mode": str(host_config["IpcMode"] or "private"),
                "uts_mode": str(host_config["UTSMode"] or "private"),
                "network_mode": str(host_config["NetworkMode"] or "private"),
                "cap_add": sorted(
                    f"CAP_{str(value).upper().removeprefix('CAP_')}"
                    for value in cap_add
                ),
                "group_add": sorted(str(value) for value in group_add),
                "effective_caps": sorted(
                    f"CAP_{str(value).upper().removeprefix('CAP_')}"
                    for value in effective_caps
                ),
                "bounding_caps": sorted(
                    f"CAP_{str(value).upper().removeprefix('CAP_')}"
                    for value in bounding_caps
                ),
                "devices_present": bool(devices),
                "mounts": mount_facts,
                "tmpfs": tmpfs_facts,
                "remote_api_environment": remote_api_environment,
                "security_opt": sorted(str(value) for value in security_opt),
                "lifecycle_events": lifecycle_events,
                "networks": sorted(str(value) for value in network_map),
                "published_ports": sorted(published),
                "auto_update": "io.containers.autoupdate" in labels,
                "systemd_unit": str(labels.get("PODMAN_SYSTEMD_UNIT", "")),
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


def control_resource_facts() -> tuple[dict[str, object], bool]:
    networks, networks_complete = json_array(
        ["podman", "network", "inspect", CONTROL_NETWORK]
    )
    volumes, volumes_complete = json_array(
        ["podman", "volume", "inspect", CONTROL_VOLUME]
    )
    network = (
        networks[0]
        if len(networks) == 1 and isinstance(networks[0], dict)
        else {}
    )
    volume = (
        volumes[0]
        if len(volumes) == 1 and isinstance(volumes[0], dict)
        else {}
    )
    network_name = network.get("name", network.get("Name", ""))
    volume_name = volume.get("Name", volume.get("name", ""))
    network_id_value = network.get("id", network.get("ID", ""))
    volume_created_at_value = volume.get("CreatedAt", volume.get("createdAt", ""))
    network_id = network_id_value if isinstance(network_id_value, str) else ""
    volume_created_at = (
        volume_created_at_value if isinstance(volume_created_at_value, str) else ""
    )
    valid_network_id = re.fullmatch(r"[0-9a-f]{64}", network_id) is not None
    valid_created_at = re.fullmatch(
        r"[0-9T:+.Z-]{1,64}", volume_created_at
    ) is not None
    complete = (
        networks_complete
        and network_name == CONTROL_NETWORK
        and valid_network_id
        and volumes_complete
        and volume_name == CONTROL_VOLUME
        and valid_created_at
    )
    return (
        {
            "network_present": (
                networks_complete and network_name == CONTROL_NETWORK
            ),
            "volume_present": volumes_complete and volume_name == CONTROL_VOLUME,
            "network_id": network_id if valid_network_id else "",
            "volume_created_at": volume_created_at if valid_created_at else "",
        },
        complete,
    )


def resource_inventory() -> tuple[dict[str, list[str]], bool]:
    containers, containers_complete = names_from_listing(
        ["podman", "ps", "--all", "--format", "json"]
    )
    networks, networks_complete = names_from_listing(
        ["podman", "network", "ls", "--format", "json"]
    )
    volumes, volumes_complete = names_from_listing(
        ["podman", "volume", "ls", "--format", "json"]
    )
    return (
        {
            "containers": containers,
            "networks": networks,
            "volumes": volumes,
        },
        containers_complete and networks_complete and volumes_complete,
    )


def user_socket_activation_facts() -> tuple[bool, bool]:
    status_code, output, complete = command_result(
        [
            "systemctl", "--user", "list-units", "--type=socket",
            "--state=active", "--no-legend", "--plain", "--no-pager",
        ]
    )
    if status_code != 0 or not complete:
        return True, False
    units: list[str] = []
    for line in output.splitlines():
        fields = line.split()
        if not fields or re.fullmatch(r"[A-Za-z0-9:_.@-]+\.socket", fields[0]) is None:
            return True, False
        units.append(fields[0])
    if len(units) != len(set(units)) or len(units) > 16:
        return True, False
    if units != ["dbus.socket"]:
        return True, True
    status_code, output, complete = command_result(
        [
            "systemctl", "--user", "show", "dbus.socket",
            "--property=FragmentPath", "--property=DropInPaths",
            "--property=Triggers",
        ]
    )
    if status_code != 0 or not complete:
        return True, False
    properties: dict[str, str] = {}
    for line in output.splitlines():
        if "=" not in line:
            return True, False
        key, value = line.split("=", 1)
        if key in properties:
            return True, False
        properties[key] = value
    if set(properties) != {"FragmentPath", "DropInPaths", "Triggers"}:
        return True, False
    trusted = (
        Path(properties["FragmentPath"]) in DBUS_SOCKET_FRAGMENTS
        and properties["DropInPaths"] == ""
        and properties["Triggers"] == "dbus.service"
    )
    return not trusted, True


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
    unsafe_socket_activation, socket_activation_complete = (
        user_socket_activation_facts()
    )
    if not socket_activation_complete or unsafe_socket_activation:
        return True, socket_activation_complete
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
        if not any(
            fields[index:index + 2] == [b"system", b"service"]
            for index in range(0, len(fields) - 1)
        ):
            continue
        try:
            trusted = PODMAN_EXECUTABLE.stat()
            executable = (process / "exe").stat()
        except FileNotFoundError:
            continue
        except OSError:
            return True, False
        if (trusted.st_dev, trusted.st_ino) == (executable.st_dev, executable.st_ino):
            return True, True
        return True, False
    return False, True


def migration_invocation_facts(instance: str) -> tuple[int, bool]:
    unit = f"secpal-int-{instance}-migrate.service"
    status_code, output, complete = command_result(
        [
            "journalctl",
            f"--user-unit={unit}",
            "--output=json",
            "--output-fields=_SYSTEMD_INVOCATION_ID",
            "--no-pager",
        ],
        timeout=30,
    )
    if status_code != 0 or not complete:
        return 0, False
    invocation_ids: set[str] = set()
    try:
        for line in output.splitlines():
            if not line:
                continue
            record = json.loads(line)
            if not isinstance(record, dict):
                return 0, False
            invocation_id = record.get("_SYSTEMD_INVOCATION_ID")
            if invocation_id is None:
                continue
            if not isinstance(invocation_id, str) or re.fullmatch(
                r"[0-9a-f]{32}", invocation_id
            ) is None:
                return 0, False
            invocation_ids.add(invocation_id)
    except json.JSONDecodeError:
        return 0, False
    return len(invocation_ids), True


def lifecycle_guard_facts(instance: str) -> tuple[dict[str, object], bool]:
    migration_invocations, migration_complete = migration_invocation_facts(instance)
    podman_api, podman_api_complete = podman_api_facts()
    return (
        {
            "migration_invocation_count": migration_invocations,
            "podman_api": podman_api,
        },
        migration_complete and podman_api_complete,
    )


def user_work_facts() -> tuple[dict[str, list[str]], bool]:
    units_status, units_output, units_complete = command_result(
        [
            "systemctl", "--user", "list-units", "--all",
            "--state=active,activating,reloading", "--plain", "--no-legend",
            "--no-pager",
        ]
    )
    jobs_status, jobs_output, jobs_complete = command_result(
        [
            "systemctl", "--user", "list-jobs", "--all", "--plain",
            "--no-legend", "--no-pager",
        ]
    )
    active_units: list[str] = []
    jobs: list[str] = []
    complete = (
        units_status == 0
        and units_complete
        and jobs_status == 0
        and jobs_complete
    )
    for line in units_output.splitlines():
        fields = line.split()
        if not fields or re.fullmatch(r"[A-Za-z0-9_.@:-]{1,128}", fields[0]) is None:
            complete = False
            continue
        active_units.append(fields[0])
    for line in jobs_output.splitlines():
        fields = line.split()
        if (
            len(fields) < 2
            or re.fullmatch(r"[1-9][0-9]{0,9}", fields[0]) is None
            or re.fullmatch(r"[A-Za-z0-9_.@:-]{1,128}", fields[1]) is None
        ):
            complete = False
            continue
        jobs.append(fields[1])
    return (
        {
            "active_units": sorted(set(active_units))[:128],
            "jobs": sorted(set(jobs))[:128],
        },
        complete
        and len(active_units) <= 128
        and len(jobs) <= 128
        and len(active_units) == len(set(active_units))
        and len(jobs) == len(set(jobs)),
    )


def process_control_group(pid: int) -> tuple[str, bool]:
    if pid <= 0 or pid > 4_194_304:
        return "", False
    try:
        with Path(f"/proc/{pid}/cgroup").open("rb") as stream:
            content = stream.read(8193)
    except OSError:
        return "", False
    if len(content) > 8192:
        return "", False
    try:
        lines = content.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return "", False
    if len(lines) != 1 or not lines[0].startswith("0::/"):
        return "", False
    control_group = lines[0][3:]
    if len(control_group) > 256 or "\x00" in control_group:
        return "", False
    return control_group, True


def process_host_identity(pid: int) -> tuple[int, int, bool]:
    return process_status_identity(pid, require_all_ids_equal=False)


def user_process_facts() -> tuple[list[dict[str, object]], bool]:
    user_slice_prefix = "/user.slice/user-20000.slice/"
    own_group, own_group_complete = process_control_group(os.getpid())
    if not own_group_complete:
        return [], False
    try:
        processes = tuple(Path("/proc").iterdir())
    except OSError:
        return [], False
    facts: dict[tuple[str, str, int, int], int] = {}
    complete = True
    visited = 0
    for process in processes:
        if not process.name.isdigit():
            continue
        visited += 1
        if visited > 8192:
            return [], False
        pid = int(process.name)
        control_group, group_complete = process_control_group(pid)
        if not group_complete:
            if process.exists():
                complete = False
            continue
        if not control_group.startswith(user_slice_prefix) or control_group == own_group:
            continue
        uid, gid, identity_complete = process_host_identity(pid)
        try:
            executable = os.readlink(process / "exe")
        except OSError:
            if process.exists():
                complete = False
            continue
        if (
            not identity_complete
            or not executable.startswith("/")
            or len(executable) > 512
            or "\x00" in executable
            or executable.endswith(" (deleted)")
        ):
            complete = False
            continue
        key = (executable, control_group, uid, gid)
        facts[key] = facts.get(key, 0) + 1
        if facts[key] > 256 or len(facts) > 256:
            return [], False
    return (
        [
            {
                "executable": executable,
                "control_group": control_group,
                "uid": uid,
                "gid": gid,
                "count": count,
            }
            for (executable, control_group, uid, gid), count in sorted(facts.items())
        ],
        complete,
    )


def service_state_matches_role(
    service: dict[str, object], logical_name: str
) -> bool:
    unit = service.get("unit")
    common_state = (
        logical_name in GENERATED_LOGICAL_NAMES
        and isinstance(unit, str)
        and service.get("active_state") == "active"
        and service.get("result") == "success"
        and type(service.get("exec_main_status")) is int
        and service["exec_main_status"] == 0
        and type(service.get("main_pid")) is int
    )
    if logical_name in READY_ROLES:
        return (
            common_state
            and service.get("sub_state") == "running"
            and service["main_pid"] > 0
            and isinstance(service.get("control_group"), str)
            and service["control_group"].endswith(f"/{unit}")
        )
    return (
        common_state
        and service.get("sub_state") == "exited"
        and service["main_pid"] == 0
        and service.get("control_group") == ""
    )


def container_pid_matches_state(container: dict[str, object]) -> bool:
    pid = container.get("pid")
    state = container.get("state")
    return type(pid) is int and (
        (state == "running" and pid > 0)
        or (state == "exited" and pid == 0)
    )


def expected_role_mounts(instance: str, role: str) -> list[dict[str, object]]:
    prefix = f"secpal-int-{instance}-"
    asset_root = Path("/home/secpal-ci/quadlet-fixture") / instance / "assets"
    contract = ROLE_CONTRACTS.get(role)
    if contract is None:
        return []
    facts = [
        {
            "type": "volume",
            "source": f"{prefix}{kind}",
            "destination": destination,
            "rw": writable,
        }
        for kind, destination, writable in contract.volumes
    ]
    facts.extend(
        {
            "type": "bind",
            "source": str(asset_root / asset_name),
            "destination": destination,
            "rw": False,
        }
        for asset_name, destination in contract.binds
    )
    return sorted(facts, key=lambda item: str(item["destination"]))


def expected_role_tmpfs(role: str) -> list[dict[str, object]]:
    contract = ROLE_CONTRACTS.get(role)
    if contract is None:
        return []
    uid, gid = contract.identity
    return sorted(
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
            for destination, size_mib, mode, noexec in contract.tmpfs
        ],
        key=lambda item: str(item["destination"]),
    )


def tmpfs_contract_matches(
    observed: object, expected: list[dict[str, object]]
) -> bool:
    if not isinstance(observed, list) or len(observed) != len(expected):
        return False
    for fact, contract in zip(observed, expected, strict=True):
        if not isinstance(fact, dict) or set(fact) != set(contract):
            return False
        flags = fact.get("flags")
        expected_flags = contract["flags"]
        if (
            not isinstance(flags, list)
            or len(flags) != len(set(flags))
            or set(flags) not in (set(expected_flags), set(expected_flags) | {"rw"})
        ):
            return False
        normalized = dict(fact)
        normalized["flags"] = [flag for flag in flags if flag != "rw"]
        if normalized != contract:
            return False
    return True


def exited_container_execution_matches(
    service: dict[str, object], container: dict[str, object]
) -> tuple[bool, bool]:
    unit = service.get("unit")
    invocation_id = service.get("invocation_id")
    container_id = container.get("id")
    container_name = container.get("name")
    lifecycle_events = container.get("lifecycle_events")
    if (
        not isinstance(unit, str)
        or re.fullmatch(r"secpal-int-[0-9a-f]{12}-[a-z0-9-]+\.service", unit)
        is None
        or not isinstance(invocation_id, str)
        or re.fullmatch(r"[0-9a-f]{32}", invocation_id) is None
        or not isinstance(container_id, str)
        or re.fullmatch(r"[0-9a-f]{64}", container_id) is None
        or not isinstance(container_name, str)
        or re.fullmatch(r"secpal-int-[0-9a-f]{12}-[a-z0-9-]+", container_name)
        is None
        or not isinstance(lifecycle_events, list)
        or [event.get("status") for event in lifecycle_events if isinstance(event, dict)]
        != ["create", "start", "died"]
    ):
        return False, False
    status_code, output, complete = command_result(
        [
            "journalctl",
            f"--user-unit={unit}",
            "--output=json",
            "--output-fields=_SYSTEMD_INVOCATION_ID,_EXE,_CMDLINE,MESSAGE",
            "--no-pager",
        ],
        timeout=30,
    )
    if status_code != 0 or not complete:
        return False, False
    matches = 0
    try:
        for line in output.splitlines():
            if not line:
                continue
            record = json.loads(line)
            if not isinstance(record, dict):
                return False, False
            command_line = record.get("_CMDLINE")
            try:
                command = shlex.split(command_line) if isinstance(command_line, str) else []
            except ValueError:
                return False, False
            names = [
                value.split("=", 1)[1]
                for value in command
                if value.startswith("--name=")
            ]
            names.extend(
                command[index + 1]
                for index, value in enumerate(command[:-1])
                if value == "--name"
            )
            if (
                record.get("_SYSTEMD_INVOCATION_ID") == invocation_id
                and record.get("_EXE") == str(PODMAN_EXECUTABLE)
                and record.get("MESSAGE") == container_id
                and len(command) >= 2
                and command[0] == str(PODMAN_EXECUTABLE)
                and command[1] == "run"
                and names == [container_name]
            ):
                matches += 1
    except json.JSONDecodeError:
        return False, False
    return matches == 1, True


def bind_container_services(
    services: list[dict[str, object]],
    containers: list[dict[str, object]],
) -> tuple[list[dict[str, object]], bool]:
    services_by_role = {
        str(service.get("logical_name")): service
        for service in services
        if isinstance(service, dict)
    }
    complete = len(services_by_role) == len(services)
    bound: list[dict[str, object]] = []
    for container in containers:
        fact = dict(container)
        role = str(fact.get("role", ""))
        expected_unit = f"{fact.get('name', '')}.service"
        service = services_by_role.get(role)
        if not isinstance(service, dict):
            fact["container_cgroup"] = ""
            fact["lifecycle_service_invocation"] = ""
            bound.append(fact)
            complete = False
            continue
        common_binding = (
            fact.get("systemd_unit") == expected_unit
            and service.get("unit") == expected_unit
            and service_state_matches_role(service, role)
            and container_pid_matches_state(fact)
        )
        if fact.get("state") == "running":
            pid = fact.get("pid")
            observed_group, observed_complete = (
                process_control_group(pid)
                if type(pid) is int
                else ("", False)
            )
            complete = complete and observed_complete
            fact["container_cgroup"] = observed_group
            fact["lifecycle_service_invocation"] = ""
        else:
            execution_matches, execution_complete = (
                exited_container_execution_matches(service, fact)
                if common_binding and fact.get("state") == "exited"
                else (False, True)
            )
            complete = complete and execution_complete
            fact["container_cgroup"] = ""
            fact["lifecycle_service_invocation"] = (
                str(service.get("invocation_id", ""))
                if common_binding and execution_matches
                else ""
            )
        bound.append(fact)
    return bound, complete


def collect_baseline(instance: str) -> dict[str, object]:
    inventory, complete = resource_inventory()
    controls, controls_complete = control_resource_facts()
    lifecycle, lifecycle_complete = lifecycle_guard_facts(instance)
    user_work, user_work_complete = user_work_facts()
    processes, processes_complete = user_process_facts()
    return {
        "phase": "baseline",
        "target_admitted": True,
        "collector_uid": os.getuid(),
        "collector_gid": os.getgid(),
        "complete": all(
            (
                complete, controls_complete, lifecycle_complete,
                user_work_complete, processes_complete,
            )
        ),
        **inventory,
        **lifecycle,
        "user_work": user_work,
        "processes": processes,
        "control_resources": controls,
    }


def collect_live(instance: str) -> dict[str, object]:
    user_work_before, user_work_before_complete = user_work_facts()
    processes_before, processes_before_complete = user_process_facts()
    units, units_complete = installed_unit_facts(instance)
    services, services_complete = generated_service_facts(instance)
    podman_rootless, oci_runtime, runtime_complete = podman_runtime_facts()
    containers, containers_complete = container_facts(
        instance, rootless=podman_rootless
    )
    containers, bindings_complete = bind_container_services(services, containers)
    inventory, inventory_complete = resource_inventory()
    prefix = f"secpal-int-{instance}-"
    networks = [name for name in inventory["networks"] if name.startswith(prefix)]
    volumes = [name for name in inventory["volumes"] if name.startswith(prefix)]
    lifecycle, lifecycle_complete = lifecycle_guard_facts(instance)
    controls, controls_complete = control_resource_facts()
    user_work_after, user_work_after_complete = user_work_facts()
    processes_after, processes_after_complete = user_process_facts()
    return {
        "phase": "live",
        "target_admitted": True,
        "collector_uid": os.getuid(),
        "collector_gid": os.getgid(),
        "complete": all(
            (
                units_complete, services_complete, containers_complete,
                bindings_complete, inventory_complete, runtime_complete,
                lifecycle_complete, controls_complete,
                user_work_before_complete, user_work_after_complete,
                user_work_before == user_work_after,
                processes_before_complete, processes_after_complete,
                processes_before == processes_after,
            )
        ),
        "quadlet_search_paths": quadlet_search_paths(),
        "installed_units": units,
        "generated_services": services,
        "containers": containers,
        "podman_rootless": podman_rootless,
        "oci_runtime": oci_runtime,
        "networks": networks,
        "volumes": volumes,
        "all_containers": inventory["containers"],
        "all_networks": inventory["networks"],
        "all_volumes": inventory["volumes"],
        "podman_api": lifecycle["podman_api"],
        "user_work": user_work_after,
        "processes": processes_after,
        "control_resources": controls,
    }


def generated_cleanup_artifacts(instance: str) -> tuple[list[str], bool]:
    prefix = f"secpal-int-{instance}"
    artifacts: list[str] = []
    maximum_artifacts = 128
    maximum_entries = 1024
    visited_entries = 0
    pending = [(root, False) for root in GENERATOR_ROOTS]
    while pending:
        directory, fixture_parent = pending.pop()
        try:
            entries = directory.iterdir()
            for entry in entries:
                visited_entries += 1
                if visited_entries > maximum_entries:
                    return sorted(artifacts), False
                relative = entry.relative_to(GENERATOR_BASE)
                fixture_owned = fixture_parent or entry.name.startswith(prefix)
                if fixture_owned:
                    artifacts.append(str(relative))
                    if len(artifacts) > maximum_artifacts:
                        return sorted(artifacts[:maximum_artifacts]), False
                descend = entry.is_dir() and not entry.is_symlink()
                if descend:
                    pending.append((entry, fixture_owned))
        except OSError:
            return sorted(artifacts), False
    return sorted(artifacts), True


def collect_post_cleanup(instance: str) -> dict[str, object]:
    prefix = f"secpal-int-{instance}"
    owned_units = []
    user_work_before, user_work_before_complete = user_work_facts()
    controls, controls_complete = control_resource_facts()
    lifecycle, lifecycle_complete = lifecycle_guard_facts(instance)
    processes_before, processes_before_complete = user_process_facts()
    for root in (QUADLET_ROOT, SYSTEMD_ROOT):
        try:
            owned_units.extend(path.name for path in root.iterdir() if path.name.startswith(prefix))
        except OSError:
            return {
                "phase": "post-cleanup", "target_admitted": True,
                "collector_uid": os.getuid(), "collector_gid": os.getgid(),
                "complete": False, "owned_units": [], "generated_services": [],
                "containers": [], "networks": [], "volumes": [],
                "all_containers": [], "all_networks": [], "all_volumes": [],
                **lifecycle,
                "user_work": user_work_before,
                "processes": processes_before,
                "control_resources": controls,
            }
    generated, generated_complete = generated_cleanup_artifacts(instance)
    inventory, inventory_complete = resource_inventory()
    containers = [
        name for name in inventory["containers"] if name.startswith(f"{prefix}-")
    ]
    networks = [
        name for name in inventory["networks"] if name.startswith(f"{prefix}-")
    ]
    volumes = [
        name for name in inventory["volumes"] if name.startswith(f"{prefix}-")
    ]
    user_work_after, user_work_after_complete = user_work_facts()
    processes_after, processes_after_complete = user_process_facts()
    return {
        "phase": "post-cleanup",
        "target_admitted": True,
        "collector_uid": os.getuid(),
        "collector_gid": os.getgid(),
        "complete": all(
            (
                inventory_complete, generated_complete, controls_complete,
                lifecycle_complete, user_work_before_complete,
                user_work_after_complete, user_work_before == user_work_after,
                processes_before_complete, processes_after_complete,
                processes_before == processes_after,
            )
        ),
        "owned_units": sorted(owned_units),
        "generated_services": sorted(generated),
        "containers": containers,
        "networks": networks,
        "volumes": volumes,
        "all_containers": inventory["containers"],
        "all_networks": inventory["networks"],
        "all_volumes": inventory["volumes"],
        **lifecycle,
        "user_work": user_work_after,
        "processes": processes_after,
        "control_resources": controls,
    }


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
        if (
            not isinstance(executable, str)
            or not executable.startswith("/")
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


def generated_source_matches(instance: str, service: dict[str, object]) -> bool:
    try:
        expected = expected_generated_source(
            instance, str(service.get("logical_name", ""))
        )
    except ValueError:
        return False
    return service.get("source_path") == str(expected)


def workload_admission_failures(observations: object) -> list[str]:
    failures: list[str] = []
    if not isinstance(observations, dict):
        return ["D1A_OBSERVATION_SCHEMA"]
    baseline_value = observations.get("baseline")
    live_value = observations.get("live")
    cleanup_value = observations.get("post_cleanup")
    baseline = exact_keys(baseline_value, set(BASELINE_OBSERVATION_FIELDS))
    live = exact_keys(live_value, set(LIVE_OBSERVATION_FIELDS))
    cleanup = exact_keys(cleanup_value, set(CLEANUP_OBSERVATION_FIELDS))
    if baseline is None:
        failures.append("D1A_BASELINE_OBSERVATION")
    if live is None:
        failures.append("D1A_LIVE_OBSERVATION")
    if cleanup is None:
        failures.append("D1A_POST_CLEANUP_OBSERVATION")
    if baseline is None or live is None or cleanup is None:
        return failures
    if any(
        observation.get("target_admitted") is not True
        or observation.get("collector_uid") != CI_UID
        or observation.get("collector_gid") != CI_GID
        or observation.get("complete") is not True
        for observation in (baseline, live, cleanup)
    ):
        failures.append("D1A_OBSERVATION_INCOMPLETE")
    if (
        baseline["phase"] != "baseline"
        or live["phase"] != "live"
        or cleanup["phase"] != "post-cleanup"
    ):
        failures.append("D1A_PHASE_CONSISTENCY")
    if baseline.get("migration_invocation_count") != 0:
        failures.append("D1A_BASELINE_MIGRATION")
    if baseline.get("podman_api") is not False:
        failures.append("D1A_PODMAN_API_DISABLED")
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
            "fragment_mode", "drop_in_paths", "drop_in_owners", "active_state",
            "sub_state", "result", "exec_main_status", "main_pid", "control_group",
            "invocation_id", "source_path", "fragment_sha256",
            "drop_in_sha256",
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
        failures.append("D1A_GENERATED_UNITS")
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
        failures.append("D1A_GENERATED_PROVENANCE")
    if isinstance(services, list):
        for service in services:
            if not isinstance(service, dict):
                continue
            if not service_state_matches_role(
                service, str(service.get("logical_name", ""))
            ):
                failures.append("D1A_SERVICE_STATE")
    containers = live.get("containers")
    container_roles = [
        item.get("role") for item in containers if isinstance(item, dict)
    ] if isinstance(containers, list) else []
    if len(container_roles) != len(ROLES) or set(container_roles) != set(ROLES):
        failures.append("D1A_CONTAINER_SET")
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
                failures.append("D1A_ROOTLESS")
            if item.get("oci_runtime") != "crun":
                failures.append("D1A_OCI_RUNTIME")
            role_contract = ROLE_CONTRACTS.get(str(item.get("role")))
            expected_caps = (
                list(role_contract.capabilities) if role_contract is not None else []
            )
            if (
                item.get("privileged") is not False
                or item.get("cap_add") != expected_caps
                or item.get("group_add") != []
                or item.get("effective_caps") != expected_caps
                or item.get("bounding_caps") != expected_caps
            ):
                failures.append("D1A_PRIVILEGE_BOUNDARY")
            if role_contract is None:
                failures.append("D1A_RUNTIME_IDENTITY")
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
                    failures.append("D1A_RUNTIME_IDENTITY")
                effective_groups = item.get("effective_supplementary_gids")
                groups_valid = isinstance(effective_groups, list) and (
                    effective_groups in ([], [expected_gid])
                    if running
                    else effective_groups == []
                )
                if not groups_valid:
                    failures.append("D1A_PRIVILEGE_BOUNDARY")
            if item.get("read_only_rootfs") is not True:
                failures.append("D1A_READ_ONLY_ROOTFS")
            if role_contract is not None and any(
                expected is not None and item.get(field) != list(expected)
                for field, expected in (
                    ("entrypoint", role_contract.entrypoint),
                    ("command", role_contract.command),
                    ("healthcheck_command", role_contract.healthcheck),
                )
            ):
                failures.append("D1A_EXECUTION_CONTRACT")
            if str(item.get("role")) != "migrate" and any(
                "migrat" in argument.casefold()
                for field in ("entrypoint", "command", "healthcheck_command")
                for argument in (
                    item.get(field) if isinstance(item.get(field), list) else []
                )
                if isinstance(argument, str)
            ):
                failures.append("D1A_EXECUTION_CONTRACT")
            if item.get("devices_present") is not False:
                failures.append("D1A_PRIVILEGE_BOUNDARY")
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
                failures.append("D1A_PODMAN_API_DISABLED")
            if any(
                item.get(field) != "private"
                for field in ("pid_mode", "userns_mode", "ipc_mode", "uts_mode")
            ):
                failures.append("D1A_HOST_NAMESPACES")
            network_mode = str(item.get("network_mode", ""))
            if re.match(r"^(?:host$|container(?::|$)|ns:)", network_mode):
                failures.append("D1A_HOST_NETWORK")
            if item.get("auto_update") is not False:
                failures.append("D1A_AUTO_UPDATE_DISABLED")
            security_options = item.get("security_opt", [])
            if security_options != ["no-new-privileges"]:
                failures.append("D1A_SECURITY_OPTIONS")
            if re.fullmatch(r"localhost/secpal-ci-[a-z0-9-]+@sha256:[0-9a-f]{64}", str(item.get("image"))) is None:
                failures.append("D1A_IMAGE_PROVENANCE")
            if any(network == "host" for network in item.get("networks", [])):
                failures.append("D1A_HOST_NETWORK")
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
                failures.append("D1A_SERVICE_BINDING")
            expected_networks = [
                f"secpal-int-{instance}-{kind}"
                for kind in (
                    ROLE_CONTRACTS[role].networks if role in ROLE_CONTRACTS else ()
                )
            ]
            if item.get("networks") != expected_networks:
                failures.append("D1A_CONTAINER_NETWORKS")
            if mounts != expected_role_mounts(instance, role):
                failures.append("D1A_VOLUME_TOPOLOGY")
            tmpfs = item.get("tmpfs")
            expected_tmpfs = expected_role_tmpfs(role)
            if not tmpfs_contract_matches(tmpfs, expected_tmpfs):
                failures.append("D1A_TMPFS_TOPOLOGY")
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
                failures.append("D1A_CONTAINER_LIFECYCLE")
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
        images_by_role = {
            str(item.get("role")): item.get("image")
            for item in containers
            if isinstance(item, dict)
        }
        api_identity = str(images_by_role.get("api", "")).rsplit("@sha256:", 1)
        frontend_identity = str(images_by_role.get("frontend", "")).rsplit(
            "@sha256:", 1
        )
        if (
            len(api_identity) != 2
            or len(frontend_identity) != 2
            or api_identity[1] == frontend_identity[1]
        ):
            failures.append("D1A_IMAGE_ROLE_SEPARATION")
        api_family = {
            role: str(images_by_role.get(role, "")).rsplit("@sha256:", 1)
            for role in (
                "secrets-init", "migrate", "api", "worker-general",
                "worker-hash-chain", "scheduler",
            )
        }
        if (
            any(len(identity) != 2 for identity in api_family.values())
            or len({identity[1] for identity in api_family.values()}) != 1
        ):
            failures.append("D1A_EXECUTION_CONTRACT")
    if isinstance(containers, list) and any(
        sum(
            isinstance(item, dict) and item.get("role") == role
            for item in containers
        ) != 1
        for role in ("scheduler", "worker-hash-chain")
    ):
        failures.append("D1A_SINGLETON_ROLES")
    if live.get("podman_api") is not False:
        failures.append("D1A_PODMAN_API_DISABLED")
    if cleanup.get("podman_api") is not False:
        failures.append("D1A_PODMAN_API_DISABLED")
    baseline_user_work = exact_keys(
        baseline.get("user_work"), {"active_units", "jobs"}
    )
    cleanup_user_work = exact_keys(
        cleanup.get("user_work"), {"active_units", "jobs"}
    )
    if (
        baseline_user_work is None
        or cleanup_user_work is None
        or exact_string_set(baseline_user_work.get("active_units")) is None
        or exact_string_set(baseline_user_work.get("jobs")) is None
        or exact_string_set(cleanup_user_work.get("active_units")) is None
        or exact_string_set(cleanup_user_work.get("jobs")) is None
        or cleanup_user_work != baseline_user_work
    ):
        failures.append("D1A_PENDING_USER_WORK")
    live_user_work = exact_keys(live.get("user_work"), {"active_units", "jobs"})
    expected_live_units = (
        exact_string_set(baseline_user_work.get("active_units"))
        if baseline_user_work is not None
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
    if (
        live_user_work is None
        or expected_live_units is None
        or exact_string_set(live_user_work.get("active_units"))
        != expected_live_units | generated_units | fixture_target
        or live_user_work.get("jobs")
        != (baseline_user_work.get("jobs") if baseline_user_work else None)
    ):
        failures.append("D1A_LIVE_USER_WORK")
    baseline_processes = exact_process_map(baseline.get("processes"))
    live_processes = exact_process_map(live.get("processes"))
    cleanup_processes = exact_process_map(cleanup.get("processes"))
    allowed_groups = {
        str(service.get("control_group")): {
            (CI_UID, CI_GID),
            (
                container_identity_on_host(
                    ROLE_CONTRACTS[str(service.get("logical_name"))].identity[0]
                ),
                container_identity_on_host(
                    ROLE_CONTRACTS[str(service.get("logical_name"))].identity[1]
                ),
            ),
        }
        for service in services
        if (
            isinstance(service, dict)
            and service.get("control_group")
            and str(service.get("logical_name")) in ROLE_CONTRACTS
        )
    } if isinstance(services, list) else {}
    if (
        baseline_processes is None
        or live_processes is None
        or cleanup_processes != baseline_processes
        or any(
            live_processes.get(key, 0) < count
            for key, count in baseline_processes.items()
        )
        or any(
            not any(
                (key[1] == group or key[1].startswith(f"{group}/"))
                and (key[2], key[3]) in identities
                for group, identities in allowed_groups.items()
            )
            for key, count in live_processes.items()
            if count > baseline_processes.get(key, 0)
        )
    ):
        failures.append("D1A_PROCESS_DELTA")
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
        failures.append("D1A_MIGRATION")
    if cleanup.get("migration_invocation_count") != 1:
        failures.append("D1A_CLEANUP_MIGRATION")
    secrets_init = next(
        (
            item for item in containers
            if isinstance(item, dict) and item.get("role") == "secrets-init"
        ),
        {},
    ) if isinstance(containers, list) else {}
    if secrets_init.get("state") != "exited" or secrets_init.get("exit_code") != 0:
        failures.append("D1A_LIFECYCLE")
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
        failures.append("D1A_BASELINE_INVENTORY")
    if any(
        baseline_inventory[kind] is None
        or live_inventory[kind] != baseline_inventory[kind] | expected_live_additions[kind]
        or cleanup_inventory[kind] != baseline_inventory[kind]
        for kind in ("containers", "networks", "volumes")
    ):
        failures.append("D1A_RESOURCE_INVENTORY")
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
        failures.append("D1A_CONTROL_RESOURCES_PRESERVED")
    return list(dict.fromkeys(failures))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "phase", choices=["baseline", "normalize", "live", "post-cleanup"]
    )
    parser.add_argument("target_sha")
    parser.add_argument("instance")
    parser.add_argument(
        "normalization_mode", nargs="?", choices=["live", "cleanup"]
    )
    arguments = parser.parse_args()
    try:
        if (arguments.phase == "normalize") != (
            arguments.normalization_mode is not None
        ):
            raise ValueError("normalization mode does not match collection phase")
        admit_collection_context(arguments.phase, arguments.target_sha, arguments.instance, CHECKOUT)
        if arguments.phase == "baseline":
            observation = collect_baseline(arguments.instance)
        elif arguments.phase == "normalize":
            return 0 if normalize_quadlet_runtime(
                arguments.instance,
                activate=arguments.normalization_mode == "live",
            ) else 1
        elif arguments.phase == "live":
            observation = collect_live(arguments.instance)
        else:
            observation = collect_post_cleanup(arguments.instance)
    except ValueError as error:
        print(f"ERROR: workload collection refused: {error}", file=sys.stderr)
        return 1
    json.dump(observation, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
