#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Run the disposable SecPal integration on rootless Podman and Quadlet."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import secrets
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
from typing import Mapping, Protocol, Sequence

sys.dont_write_bytecode = True
SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if os.fspath(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, os.fspath(SCRIPT_DIRECTORY))

from integration_runtime_contract import (
    API_DIGEST,
    API_IMAGE,
    API_SOURCE_COMMIT,
    CADDY_IMAGE,
    CONTAINER_LOG_DRIVER,
    CONTAINER_PIDS_LIMIT,
    CONTAINER_ROLES,
    CONTAINER_STOP_TIMEOUT,
    ExecutionSpec,
    FRONTEND_DIGEST,
    FRONTEND_IMAGE,
    FRONTEND_SOURCE_COMMIT,
    GATEWAY_HEALTH_FAILURE_SPEC,
    HealthSpec,
    INTERNAL_NETWORKS,
    POSTGRES_IMAGE,
    PRIVATE_STORAGE_MODE,
    PROXY_ENVIRONMENT_NAMES,
    REQUIRED_CONTAINER_GIDS,
    REQUIRED_CONTAINER_UIDS,
    TARGET_REQUIRED_ROLES,
    TmpfsSpec,
    VALKEY_IMAGE,
    VOLUME_NAMES,
    podman_version_supported,
    podman_versions_compatible,
    role_execution_spec,
    role_spec,
)

ONESHOT_SYSTEMD_PROPERTIES = (
    "ActiveState",
    "SubState",
    "Result",
    "ExecMainStatus",
    "NRestarts",
    "InvocationID",
    "ExecMainStartTimestampMonotonic",
)
EXPECTED_GH_VERSION = "2.97.0"
INSTANCE_PATTERN = re.compile(r"[a-z0-9]{8,24}\Z")
SAFE_PATH_PATTERN = re.compile(r"/[A-Za-z0-9._@+/-]*\Z")
QUADLET_USER_GENERATOR = Path(
    "/usr/lib/systemd/user-generators/podman-user-generator"
)
HANDLED_SIGNALS = (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)
FORBIDDEN_RUNTIME_ENVIRONMENT = (
    "CONTAINER_HOST",
    "CONTAINER_CONNECTION",
    "DOCKER_HOST",
    "CONTAINERS_CONF",
    "CONTAINERS_CONF_OVERRIDE",
    "CONTAINERS_CONF_MODULES",
    "CONTAINERS_REGISTRIES_CONF",
    "CONTAINERS_REGISTRIES_CONF_DIR",
    "CONTAINERS_STORAGE_CONF",
    "CONTAINERS_POLICY",
)
CLOUD_FIXTURE_CLIENT = Path("/usr/local/bin/secpal-ci-quadlet-fixture")
CLOUD_FIXTURE_BASE = Path("/home/secpal-ci/quadlet-fixture")
CLOUD_OPERATOR_UID = 20_000
CLOUD_OPERATOR_GID = 20_000
CLOUD_IMAGE_TAGS = {
    "api": "localhost/secpal-ci-api:verified",
    "frontend": "localhost/secpal-ci-frontend:verified",
    "postgres": "localhost/secpal-ci-postgres:verified",
    "valkey": "localhost/secpal-ci-valkey:verified",
}
CLOUD_GH_RELEASES = {
    "x86_64": (
        "amd64",
        "a2c9b8497e1f85b1ad0dfcb78b5a622e098801b8e461e459e88e1ee12f018112",
    ),
    "aarch64": (
        "arm64",
        "73ea440ecad9c9e284429997ee6f93577bc6f7bc6fba357ef62c53ad8fb641a5",
    ),
}


class IntegrationError(RuntimeError):
    """A fail-closed integration admission or lifecycle failure."""


class PortCollisionError(IntegrationError):
    """A verified loopback bind collision eligible for bounded automatic retry."""


class IntegrationInterrupted(BaseException):
    """A handled signal that must unwind into the normal cleanup path."""

    def __init__(self, signal_number: int) -> None:
        super().__init__(f"integration interrupted by signal {signal_number}")
        self.signal_number = signal_number


class CommandRunner(Protocol):
    def run(self, command: Sequence[str], **kwargs):
        """Run one argv-only command."""


class Runner:
    """Subprocess boundary that never invokes a shell."""

    def __init__(self) -> None:
        self.active: subprocess.Popen[str] | None = None
        self.active_process_group = False

    def run(self, command: Sequence[str], **kwargs) -> subprocess.CompletedProcess[str]:
        defaults = {"check": True, "text": True}
        defaults.update(kwargs)
        check = defaults.pop("check")
        capture_output = defaults.pop("capture_output", False)
        start_new_session = defaults.pop("start_new_session", True)
        if capture_output:
            defaults["stdout"] = subprocess.PIPE
            defaults["stderr"] = subprocess.PIPE
        process = subprocess.Popen(
            list(command), start_new_session=start_new_session, **defaults
        )
        self.active = process
        self.active_process_group = start_new_session
        try:
            stdout, stderr = process.communicate()
        finally:
            if process.poll() is not None:
                self.active = None
                self.active_process_group = False
        completed = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
        if check and process.returncode:
            raise subprocess.CalledProcessError(process.returncode, command, stdout, stderr)
        return completed

    def terminate_active(self) -> None:
        process = self.active
        if process is None or process.poll() is not None:
            return
        try:
            if self.active_process_group:
                os.killpg(process.pid, signal.SIGTERM)
            else:
                process.terminate()
        except ProcessLookupError:
            return

    def reap_active(self) -> None:
        process = self.active
        if process is None:
            return
        try:
            process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            try:
                if self.active_process_group:
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
            except ProcessLookupError:
                pass
            process.communicate()
        finally:
            self.active = None
            self.active_process_group = False


@dataclass(frozen=True)
class Resources:
    instance: str
    uid: int
    active_root: Path
    prefix: str
    target: str
    containers: tuple[str, ...]
    networks: tuple[str, ...]
    volumes: tuple[str, ...]
    gateway_image: str
    unit_files: tuple[Path, ...]
    systemd_target_file: Path

    @classmethod
    def for_instance(
        cls, instance: str, uid: int, active_root: Path, cloud_mode: bool = False
    ) -> "Resources":
        prefix = f"secpal-int-{instance}"
        unit_names = [f"{prefix}-{role}.container" for role in CONTAINER_ROLES]
        unit_names.extend(f"{prefix}-{name}.network" for name in INTERNAL_NETWORKS)
        unit_names.extend(f"{prefix}-{name}.volume" for name in VOLUME_NAMES)
        if not cloud_mode:
            unit_names.append(f"{prefix}.target")
        return cls(
            instance=instance,
            uid=uid,
            active_root=active_root,
            prefix=prefix,
            target=f"{prefix}.target",
            containers=tuple(f"{prefix}-{role}" for role in CONTAINER_ROLES),
            networks=tuple(f"{prefix}-{name}" for name in INTERNAL_NETWORKS),
            volumes=tuple(f"{prefix}-{name}" for name in VOLUME_NAMES),
            gateway_image=(
                f"localhost/secpal-ci-gateway-{instance}:2.10.2"
                if cloud_mode
                else f"localhost/secpal-integration-gateway-{instance}:2.10.2"
            ),
            unit_files=tuple(active_root / name for name in sorted(unit_names)),
            systemd_target_file=Path("/etc/systemd/user") / f"{prefix}.target",
        )


def nested(mapping: Mapping, *path: str):
    current = mapping
    for key in path:
        if not isinstance(current, Mapping) or key not in current:
            raise IntegrationError(f"Podman runtime fact is missing: {'.'.join(path)}")
        current = current[key]
    return current


def required_first_line(output: str, source: str) -> str:
    lines = output.splitlines()
    if not lines:
        raise IntegrationError(f"{source} returned no output")
    return lines[0]


def validate_gh_version_line(line: str) -> None:
    if not re.fullmatch(rf"gh version {re.escape(EXPECTED_GH_VERSION)}(?: .*)?", line):
        raise IntegrationError(f"GitHub CLI {EXPECTED_GH_VERSION} is required")


def playwright_admission_command() -> tuple[str, str, str]:
    return (
        "node",
        "-e",
        "const fs=require('node:fs');const {chromium}=require('@playwright/test');"
        "fs.accessSync(chromium.executablePath(),fs.constants.X_OK)",
    )


def parse_json_mapping(output: str, source: str) -> Mapping:
    try:
        payload = json.loads(output)
    except (json.JSONDecodeError, TypeError) as error:
        raise IntegrationError(f"{source} returned malformed JSON") from error
    if not isinstance(payload, Mapping):
        raise IntegrationError(f"{source} returned an unexpected JSON document")
    return payload


def parse_json_objects(output: str, source: str) -> list[Mapping]:
    try:
        payload = json.loads(output)
    except (json.JSONDecodeError, TypeError) as error:
        raise IntegrationError(f"{source} returned malformed JSON") from error
    if not isinstance(payload, list) or not all(
        isinstance(item, Mapping) for item in payload
    ):
        raise IntegrationError(f"{source} returned an unexpected JSON document")
    return payload


def parse_single_json_object(output: str, source: str) -> Mapping:
    payload = parse_json_objects(output, source)
    if len(payload) != 1:
        raise IntegrationError(f"{source} returned an ambiguous JSON document")
    return payload[0]


def has_injected_health_failure(details: Mapping) -> bool:
    """Recognize the closed health-failure fixture from Podman's own state."""

    test = nested(details, "Config", "Healthcheck", "Test")
    if test != ["CMD-SHELL", "/bin/false"]:
        raise IntegrationError("gateway does not use the injected health check")
    health = nested(details, "State", "Health")
    status = nested(health, "Status")
    if status in {"", "starting"}:
        return False
    if status != "unhealthy":
        raise IntegrationError("injected gateway health check did not become unhealthy")
    failing_streak = nested(health, "FailingStreak")
    if (
        isinstance(failing_streak, bool)
        or not isinstance(failing_streak, int)
        or failing_streak < 1
    ):
        raise IntegrationError("injected gateway health check has no failing streak")
    log = nested(health, "Log")
    if not isinstance(log, list) or not log or not isinstance(log[-1], Mapping):
        raise IntegrationError("injected gateway health check has no failure log")
    exit_code = log[-1].get("ExitCode")
    if isinstance(exit_code, bool) or not isinstance(exit_code, int) or exit_code == 0:
        raise IntegrationError("injected gateway health check did not record a failure")
    return True


def runtime_probe_contract(instance: str) -> dict[str, object]:
    """Map a bounded instance to the immutable Phase B probe namespace."""

    if not INSTANCE_PATTERN.fullmatch(instance):
        raise IntegrationError("invalid integration instance for runtime probes")
    return {
        "cache_key": f"phase-b-cache-{instance}",
        "cache_value": f"phase-b-cache-value-{instance}",
        "worker-general": (f"phase-b-queue-general-{instance}", "default"),
        "worker-hash-chain": (
            f"phase-b-queue-hash-chain-{instance}",
            "activity-hash-chain",
        ),
    }


def failure_blocked_roles(failure_case: str) -> tuple[str, ...]:
    application_roles = (
        "api",
        "worker-general",
        "worker-hash-chain",
        "scheduler",
        "gateway",
    )
    if failure_case == "migration":
        return application_roles
    if failure_case == "dependency":
        return ("migrate", *application_roles)
    raise IntegrationError("failure case has no reviewed dependency descendants")


def parse_systemd_resource_properties(properties: str) -> dict[str, int]:
    allowed = {"CPUUsageNSec", "MemoryCurrent", "MemoryPeak"}
    observations: dict[str, int] = {}
    for line in properties.splitlines():
        if "=" not in line:
            continue
        name, value = line.split("=", 1)
        if name in allowed and value.isascii() and value.isdecimal():
            observations[name] = int(value)
    return dict(sorted(observations.items()))


def parse_du_size(output: str) -> int | None:
    fields = output.split(None, 1)
    first = fields[0] if fields else ""
    if not first.isascii() or not first.isdecimal():
        return None
    return int(first)


def validate_runtime_info(
    info: Mapping, uid: int, environment: Mapping[str, str]
) -> tuple[Path, Path]:
    if uid == 0:
        raise IntegrationError("rootful Podman is forbidden")
    for variable in FORBIDDEN_RUNTIME_ENVIRONMENT:
        if environment.get(variable):
            raise IntegrationError(f"runtime override is forbidden: {variable}")
    if not podman_version_supported(nested(info, "version", "Version")):
        raise IntegrationError("Podman >=5.4.2,<6.0.0 is required")
    if nested(info, "host", "serviceIsRemote") is not False:
        raise IntegrationError("the Podman service must be local and daemonless")
    if nested(info, "host", "security", "rootless") is not True:
        raise IntegrationError("effective Podman must be rootless")
    if nested(info, "host", "ociRuntime", "name") != "crun":
        raise IntegrationError("effective OCI runtime must be crun")
    if nested(info, "host", "cgroupVersion") != "v2":
        raise IntegrationError("unified cgroup v2 is required")
    if nested(info, "host", "networkBackend") != "netavark":
        raise IntegrationError("effective Podman network backend must be Netavark")
    network = nested(info, "host", "networkBackendInfo")
    if not isinstance(network, Mapping) or network.get("backend") != "netavark":
        raise IntegrationError("effective Netavark runtime information is required")
    netavark_version = network.get("version")
    if (
        not isinstance(netavark_version, str)
        or re.fullmatch(
            r"netavark [1-9][0-9]*\.[0-9]+\.[0-9]+(?:[-+~][0-9A-Za-z.+~-]+)?",
            netavark_version,
        )
        is None
    ):
        raise IntegrationError("effective Netavark runtime information is required")
    dns = network.get("dns")
    if not isinstance(dns, Mapping):
        raise IntegrationError("effective Aardvark DNS is required")
    aardvark_path = Path(str(dns.get("path", "")))
    aardvark_version = dns.get("version")
    if (
        not aardvark_path.is_absolute()
        or not isinstance(aardvark_version, str)
        or re.fullmatch(
            r"aardvark-dns [1-9][0-9]*\.[0-9]+\.[0-9]+(?:[-+~][0-9A-Za-z.+~-]+)?",
            aardvark_version,
        )
        is None
    ):
        raise IntegrationError("effective Aardvark DNS is required")
    if nested(info, "host", "rootlessNetworkCmd") != "pasta":
        raise IntegrationError("effective rootless network transport must be pasta")
    runtime_component_paths(info)
    if nested(info, "host", "security", "seccompEnabled") is not True:
        raise IntegrationError("seccomp must be effective for Podman")
    mappings = nested(info, "host", "idMappings")
    validate_id_mapping(
        nested(mappings, "uidmap"), REQUIRED_CONTAINER_UIDS, "uid"
    )
    validate_id_mapping(
        nested(mappings, "gidmap"), REQUIRED_CONTAINER_GIDS, "gid"
    )
    graph_root = Path(str(nested(info, "store", "graphRoot")))
    run_root = Path(str(nested(info, "store", "runRoot")))
    if not graph_root.is_absolute() or not run_root.is_absolute():
        raise IntegrationError("Podman storage roots must be absolute")
    return graph_root, run_root


def runtime_component_paths(info: Mapping) -> tuple[tuple[Path, str], ...]:
    components = (
        (
            nested(info, "host", "ociRuntime", "path"),
            "effective crun executable",
        ),
        (
            nested(info, "host", "networkBackendInfo", "path"),
            "effective Netavark executable",
        ),
        (
            nested(info, "host", "networkBackendInfo", "dns", "path"),
            "effective Aardvark DNS executable",
        ),
        (
            nested(info, "host", "pasta", "executable"),
            "effective pasta executable",
        ),
    )
    paths = tuple((Path(str(value)), description) for value, description in components)
    if any(not path.is_absolute() for path, _description in paths):
        raise IntegrationError("effective runtime executable path is not absolute")
    return paths


def validate_id_mapping(
    entries: object, required_ids: frozenset[int], mapping_name: str
) -> None:
    if not isinstance(entries, list) or not entries:
        raise IntegrationError(f"usable subordinate {mapping_name} mapping is required")
    ranges: list[tuple[int, int]] = []
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise IntegrationError(
                f"usable subordinate {mapping_name} mapping is required"
            )
        start = entry.get("container_id")
        host = entry.get("host_id")
        size = entry.get("size")
        if (
            not isinstance(start, int)
            or isinstance(start, bool)
            or not isinstance(host, int)
            or isinstance(host, bool)
            or not isinstance(size, int)
            or isinstance(size, bool)
            or start < 0
            or host < 0
            or size <= 0
        ):
            raise IntegrationError(
                f"usable subordinate {mapping_name} mapping is required"
            )
        ranges.append((start, start + size))
    if any(not any(start <= identity < end for start, end in ranges) for identity in required_ids):
        raise IntegrationError(f"usable subordinate {mapping_name} mapping is required")


def parse_tmpfs_size(value: str) -> int:
    match = re.fullmatch(r"([1-9][0-9]*)([kmg]?)", value.lower())
    if not match:
        raise IntegrationError("effective runtime tmpfs options are malformed")
    multipliers = {"": 1, "k": 1024, "m": 1024 * 1024, "g": 1024 * 1024 * 1024}
    return int(match.group(1)) * multipliers[match.group(2)]


def validate_tmpfs_options(
    options: object,
    expected: TmpfsSpec,
    expected_identity: tuple[int, int],
) -> None:
    if not isinstance(options, str):
        raise IntegrationError("effective runtime tmpfs options are malformed")
    flags: set[str] = set()
    values: dict[str, str] = {}
    for raw_option in options.split(","):
        option = raw_option.strip()
        if not option:
            raise IntegrationError("effective runtime tmpfs options are malformed")
        if "=" in option:
            name, value = option.split("=", 1)
            name = name.lower()
            if (
                name in values
                or name not in {"size", "mode", "uid", "gid"}
                or not value
            ):
                raise IntegrationError("effective runtime tmpfs options are malformed")
            values[name] = value
        else:
            flag = option.lower()
            if flag in flags:
                raise IntegrationError("effective runtime tmpfs options are malformed")
            flags.add(flag)
    required_flags = {"rprivate", "tmpcopyup", "nosuid", "nodev"}
    if expected.noexec:
        required_flags.add("noexec")
    # Podman 5.4 materializes the implicit read-write default; 5.7 omits it.
    if flags not in (required_flags, required_flags | {"rw"}) or set(values) != {
        "size",
        "mode",
        "uid",
        "gid",
    }:
        raise IntegrationError("effective runtime tmpfs options differ from the reviewed contract")
    try:
        mode = int(values["mode"], 8)
        uid = int(values["uid"], 10)
        gid = int(values["gid"], 10)
    except ValueError as error:
        raise IntegrationError("effective runtime tmpfs options are malformed") from error
    if (
        parse_tmpfs_size(values["size"]) != expected.size
        or mode != expected.mode
        or (uid, gid) != expected_identity
    ):
        raise IntegrationError("effective runtime tmpfs options differ from the reviewed contract")


def validate_container_security(
    inspect: Mapping,
    apparmor_available: bool,
    allowed_capabilities: frozenset[str] = frozenset(),
    expected_mounts: Mapping[str, tuple[str, str, bool]] | None = None,
    expected_tmpfs: Mapping[str, TmpfsSpec] | None = None,
    expected_tmpfs_identity: tuple[int, int] | None = None,
) -> None:
    host = nested(inspect, "HostConfig")
    if host.get("Privileged") is not False:
        raise IntegrationError("a runtime container is privileged")
    if host.get("ReadonlyRootfs") is not True:
        raise IntegrationError("a runtime container root filesystem is writable")
    if host.get("PidsLimit") != CONTAINER_PIDS_LIMIT:
        raise IntegrationError(
            "effective runtime process limit differs from the reviewed contract"
        )
    if host.get("Init") is not True:
        raise IntegrationError("effective runtime init differs from the reviewed contract")
    log_config = host.get("LogConfig")
    if (
        not isinstance(log_config, Mapping)
        or log_config.get("Type") != CONTAINER_LOG_DRIVER
    ):
        raise IntegrationError(
            "effective runtime log driver differs from the reviewed contract"
        )
    if nested(inspect, "Config", "StopTimeout") != CONTAINER_STOP_TIMEOUT:
        raise IntegrationError(
            "effective runtime stop timeout differs from the reviewed contract"
        )
    if str(host.get("NetworkMode", "")).lower() == "host":
        raise IntegrationError("a runtime container uses host networking")
    if any(
        str(host.get(name) or "private").lower() != "private"
        for name in ("PidMode", "IpcMode", "UTSMode")
    ):
        raise IntegrationError("a runtime container shares a host namespace")
    bindings = host.get("Binds") or []
    if any("podman.sock" in str(binding) or "docker.sock" in str(binding) for binding in bindings):
        raise IntegrationError("a runtime socket is mounted into a container")
    added = {str(value).upper().removeprefix("CAP_") for value in host.get("CapAdd") or []}
    if not added <= allowed_capabilities:
        raise IntegrationError("a runtime container has unexpected added capabilities")
    effective = {
        str(value).upper().removeprefix("CAP_") for value in inspect.get("EffectiveCaps") or []
    }
    bounding = {
        str(value).upper().removeprefix("CAP_") for value in inspect.get("BoundingCaps") or []
    }
    if effective != allowed_capabilities or bounding != allowed_capabilities:
        raise IntegrationError("effective runtime capabilities differ from the reviewed contract")
    security_options = host.get("SecurityOpt")
    if security_options != ["no-new-privileges"]:
        raise IntegrationError(
            "effective runtime security options differ from the reviewed contract"
        )
    if apparmor_available and inspect.get("AppArmorProfile") in (None, "", "unconfined"):
        raise IntegrationError("AppArmor is available but the container is unconfined")
    if expected_mounts is not None:
        observed_mounts: dict[str, tuple[str, str, bool]] = {}
        for mount in inspect.get("Mounts") or []:
            if not isinstance(mount, Mapping):
                raise IntegrationError("a runtime container reported an invalid mount")
            mount_type = str(mount.get("Type", "")).lower()
            if mount_type == "tmpfs":
                continue
            destination = str(mount.get("Destination", ""))
            source = str(mount.get("Name") if mount_type == "volume" else mount.get("Source", ""))
            if not destination or destination in observed_mounts:
                raise IntegrationError("a runtime container reported an ambiguous mount")
            observed_mounts[destination] = (mount_type, source, mount.get("RW") is True)
        if observed_mounts != dict(expected_mounts):
            raise IntegrationError("effective runtime mounts differ from the reviewed contract")
    if expected_tmpfs is not None:
        if expected_tmpfs_identity is None:
            raise IntegrationError("effective runtime tmpfs identity contract is missing")
        tmpfs = host.get("Tmpfs") or {}
        if not isinstance(tmpfs, Mapping) or set(tmpfs) != set(expected_tmpfs):
            observed_tmpfs = sorted(tmpfs) if isinstance(tmpfs, Mapping) else ["<invalid>"]
            raise IntegrationError(
                "effective runtime tmpfs paths differ from the reviewed contract: "
                f"expected {sorted(expected_tmpfs)}, observed {observed_tmpfs}"
            )
        for destination, expected in expected_tmpfs.items():
            validate_tmpfs_options(
                tmpfs[destination], expected, expected_tmpfs_identity
            )


def validate_container_environment(inspect: Mapping) -> None:
    config = inspect.get("Config")
    environment = config.get("Env") if isinstance(config, Mapping) else None
    if not isinstance(environment, list):
        raise IntegrationError("effective runtime environment is malformed")
    names: set[str] = set()
    for entry in environment:
        if not isinstance(entry, str) or "=" not in entry:
            raise IntegrationError("effective runtime environment is malformed")
        name, _value = entry.split("=", 1)
        if (
            re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) is None
            or name in names
        ):
            raise IntegrationError("effective runtime environment is malformed")
        names.add(name)
    if names & PROXY_ENVIRONMENT_NAMES:
        raise IntegrationError("automatic proxy environment inheritance is forbidden")


def validate_container_execution(inspect: Mapping, expected: ExecutionSpec) -> None:
    config = inspect.get("Config")
    if (
        not isinstance(config, Mapping)
        or (
            expected.entrypoint is not None
            and config.get("Entrypoint") != list(expected.entrypoint)
        )
        or (
            expected.command is not None
            and config.get("Cmd") != list(expected.command)
        )
    ):
        raise IntegrationError(
            "effective execution contract differs from the reviewed contract"
        )


def validate_container_health(inspect: Mapping, expected: HealthSpec) -> None:
    config = inspect.get("Config")
    if not isinstance(config, Mapping):
        raise IntegrationError("effective health contract is missing")
    health = config.get("Healthcheck")
    expected_health = {
        "Test": ["CMD-SHELL", expected.command],
        "Interval": expected.interval_seconds * 1_000_000_000,
        "Timeout": expected.timeout_seconds * 1_000_000_000,
        "Retries": expected.retries,
        "StartPeriod": expected.start_period_seconds * 1_000_000_000,
    }
    if (
        not isinstance(health, Mapping)
        or dict(health) != expected_health
        or any(
            type(health.get(name)) is not int
            for name in ("Interval", "Timeout", "Retries", "StartPeriod")
        )
        or config.get("HealthcheckOnFailureAction") != "kill"
        or config.get("sdNotifyMode") != "healthy"
    ):
        raise IntegrationError(
            "effective health contract differs from the reviewed contract"
        )


def validate_oneshot_state(properties: str) -> tuple[str, str]:
    values = dict(
        line.split("=", 1)
        for line in properties.splitlines()
        if "=" in line
    )
    expected = {
        "ActiveState": "active",
        "SubState": "exited",
        "Result": "success",
        "ExecMainStatus": "0",
        "NRestarts": "0",
    }
    if any(values.get(name) != value for name, value in expected.items()):
        raise IntegrationError("one-shot systemd service did not complete exactly once")
    invocation = values.get("InvocationID", "")
    started = values.get("ExecMainStartTimestampMonotonic", "")
    if not re.fullmatch(r"[a-f0-9]{32}", invocation) or not started.isdecimal() or int(started) <= 0:
        raise IntegrationError("one-shot systemd invocation identity is missing")
    return invocation, started


def validate_removed_systemd_unit_state(properties: str) -> None:
    values: dict[str, str] = {}
    for line in properties.splitlines():
        if "=" not in line:
            raise IntegrationError("removed systemd unit state is malformed")
        name, value = line.split("=", 1)
        if name in values:
            raise IntegrationError("removed systemd unit state is malformed")
        values[name] = value
    if values != {"LoadState": "not-found", "ActiveState": "inactive"}:
        raise IntegrationError("removed systemd unit remains loaded or active")


def validate_effective_systemd_unit(properties: str, expected_fragment: Path) -> None:
    values: dict[str, str] = {}
    for line in properties.splitlines():
        if "=" not in line:
            raise IntegrationError("effective systemd unit identity is malformed")
        name, value = line.split("=", 1)
        if name in values:
            raise IntegrationError("effective systemd unit identity is malformed")
        values[name] = value
    expected = {
        "FragmentPath": os.fspath(expected_fragment),
        "DropInPaths": "",
    }
    if values != expected:
        raise IntegrationError("effective systemd unit is overridden or has drop-ins")


def validate_effective_systemd_target(
    properties: str,
    expected_fragment: Path,
    expected_requires: set[str],
) -> None:
    values: dict[str, str] = {}
    for line in properties.splitlines():
        if "=" not in line:
            raise IntegrationError("effective systemd target identity is malformed")
        name, value = line.split("=", 1)
        if name in values:
            raise IntegrationError("effective systemd target identity is malformed")
        values[name] = value
    if set(values) != {"FragmentPath", "DropInPaths", "Wants", "Requires"}:
        raise IntegrationError("effective systemd target identity is malformed")
    wants = set(values["Wants"].split())
    requires = set(values["Requires"].split())
    if (
        values["FragmentPath"] != os.fspath(expected_fragment)
        or values["DropInPaths"]
        or wants
        or requires != expected_requires
    ):
        raise IntegrationError(
            "effective systemd target dependencies differ from the reviewed contract"
        )


def validate_effective_health_service(properties: str) -> None:
    values: dict[str, str] = {}
    for line in properties.splitlines():
        if "=" not in line:
            raise IntegrationError("effective systemd health readiness is malformed")
        name, value = line.split("=", 1)
        if name in values:
            raise IntegrationError("effective systemd health readiness is malformed")
        values[name] = value
    if values != {"Type": "notify", "NotifyAccess": "all"}:
        raise IntegrationError(
            "effective systemd health readiness differs from the reviewed contract"
        )


def validate_registry_documents(documents: Sequence[Mapping]) -> None:
    for document in documents:
        credential_helpers = document.get("credential-helpers")
        if credential_helpers not in (None, [], ["containers-auth.json"]):
            raise IntegrationError("external registry credential helpers are forbidden")
        if document.get("additional-layer-store-auth-helper"):
            raise IntegrationError("additional-layer-store credential helpers are forbidden")
        entries = document.get("registry") or []
        if isinstance(entries, Mapping):
            entries = [entries]
        if not isinstance(entries, list):
            raise IntegrationError("registry configuration has an invalid registry table")
        for entry in entries:
            if not isinstance(entry, Mapping):
                raise IntegrationError("registry configuration has an invalid entry")
            prefix = str(entry.get("prefix") or entry.get("location") or "")
            location = str(entry.get("location") or prefix).lower().rstrip("/")
            if (
                location != prefix.lower().rstrip("/")
                or entry.get("mirror")
                or entry.get("insecure") is True
                or entry.get("blocked") is True
            ):
                raise IntegrationError("registry rewrite, mirror, fallback, or insecure transport is forbidden")


def load_registry_document(path: Path) -> Mapping:
    try:
        with path.open("rb") as stream:
            return tomllib.load(stream)
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise IntegrationError(
            "system registry configuration could not be parsed safely"
        ) from error


def validate_trusted_directory(path: Path, description: str) -> None:
    if not path.is_absolute():
        raise IntegrationError(f"{description} directory must be absolute")
    try:
        current = path
        while True:
            metadata = current.lstat()
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != 0
                or metadata.st_gid != 0
                or metadata.st_mode & 0o022
            ):
                raise IntegrationError(
                    f"{description} directory or ancestry is not trusted"
                )
            if current == current.parent:
                return
            current = current.parent
    except IntegrationError:
        raise
    except OSError as error:
        raise IntegrationError(
            f"{description} directory or ancestry could not be inspected safely"
        ) from error


def validate_trusted_regular_file(path: Path, description: str) -> None:
    validate_trusted_directory(path.parent, description)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise IntegrationError(
            f"{description} could not be inspected safely"
        ) from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or metadata.st_mode & 0o022
    ):
        raise IntegrationError(f"{description} is not a trusted regular file")


def validate_trusted_executable(path: Path, description: str) -> None:
    validate_trusted_regular_file(path, description)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise IntegrationError(f"{description} is unavailable") from error
    if metadata.st_mode & stat.S_IXOTH == 0:
        raise IntegrationError(f"{description} is not executable")


def validate_quadlet_generator(path: Path) -> Path:
    validate_trusted_directory(path.parent, "native Quadlet user generator")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise IntegrationError(
            "native Quadlet user generator is unavailable"
        ) from error
    validate_trusted_executable(resolved, "native Quadlet user generator")
    return resolved


def validate_quadlet_search_path_policy(path: Path, expected: str) -> None:
    try:
        validate_trusted_regular_file(path, "root-owned Quadlet search-path policy")
        metadata = path.lstat()
        if (
            path.read_text(encoding="utf-8") != expected
            or (metadata.st_mode & 0o7777) != 0o644
        ):
            raise IntegrationError(
                "root-owned Quadlet search-path policy is not installed"
            )
    except IntegrationError:
        raise
    except (OSError, UnicodeError) as error:
        raise IntegrationError(
            "root-owned Quadlet search-path policy could not be inspected safely"
        ) from error


def validate_api_origin_root(body: str) -> None:
    if "<!doctype html" in body.lower():
        raise IntegrationError("API origin returned the frontend SPA shell")


def transfer_timeout_seconds(deadline: float, current: float) -> int:
    remaining = deadline - current
    if remaining <= 0:
        raise IntegrationError("external readiness deadline expired")
    return min(10, max(1, math.ceil(remaining)))


def validate_dns_isolation_result(returncode: int, service: str) -> None:
    if returncode == 0:
        raise IntegrationError(f"frontend unexpectedly resolved data service {service}")
    if returncode != 2:
        raise IntegrationError(f"unable to verify frontend DNS isolation for {service}")


def validate_port_publication(
    role: str, bindings: object, port: int | None
) -> None:
    if not isinstance(bindings, Mapping):
        raise IntegrationError(f"invalid host port publication for {role}")
    if role != "gateway":
        if bindings:
            raise IntegrationError(f"unexpected host port publication for {role}")
        return
    expected = {
        "8443/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(port)}]
    }
    if bindings != expected:
        raise IntegrationError("gateway loopback publication is not exact")


def user_container_configuration_root(
    home: Path, environment: Mapping[str, str]
) -> Path:
    configured = environment.get("XDG_CONFIG_HOME")
    if configured:
        root = Path(configured)
        if not root.is_absolute():
            raise IntegrationError("XDG_CONFIG_HOME must be absolute")
        return root / "containers"
    return home / ".config" / "containers"


def validate_user_container_configuration(
    home: Path, environment: Mapping[str, str] | None = None
) -> None:
    root = user_container_configuration_root(home, environment or {})
    paths = [
        root / "containers.conf",
        root / "mounts.conf",
        root / "policy.json",
        root / "storage.conf",
        root / "containers.conf.d",
        root / "registries.conf.d",
        *(root / "containers.conf.d").glob("*.conf"),
    ]
    if any(path.exists() or path.is_symlink() for path in paths):
        raise IntegrationError("user-writable Podman runtime configuration is forbidden")


def _inspect_resource(runner: CommandRunner, kind: str, name: str) -> Mapping | None:
    exists = runner.run(
        ["podman", kind, "exists", name],
        check=False,
        capture_output=True,
    )
    if exists.returncode == 1:
        return None
    if exists.returncode != 0:
        raise IntegrationError(f"unable to verify same-named {kind}: {name}")
    result = runner.run(
        ["podman", kind, "inspect", name],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        raise IntegrationError(f"unable to inspect same-named {kind}: {name}")
    return parse_single_json_object(
        result.stdout or "", "Podman resource ownership inspection"
    )


def _ownership_labels(details: Mapping, kind: str) -> Mapping:
    if kind == "container":
        return nested(details, "Config", "Labels")
    labels = details.get("Labels") or details.get("labels")
    if isinstance(labels, Mapping):
        return labels
    config = details.get("Config")
    if isinstance(config, Mapping) and isinstance(config.get("Labels"), Mapping):
        return config["Labels"]
    return {}


def _owned_by_instance(details: Mapping, kind: str, instance: str, role: str | None = None) -> bool:
    labels = _ownership_labels(details, kind)
    if (
        labels.get("org.secpal.integration") != "true"
        or labels.get("org.secpal.integration.instance") != instance
    ):
        return False
    return role is None or labels.get("org.secpal.role") == role


def _owned_unit_file(path: Path, resources: Resources) -> bool:
    if not (path.exists() or path.is_symlink()):
        return False
    metadata = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o644
    ):
        raise IntegrationError(f"same-named active unit is not safely owned: {path.name}")
    content = path.read_text(encoding="utf-8")
    if path.name.endswith(".target"):
        marker = f"Description=SecPal rootless Podman integration fixture ({resources.instance})"
    else:
        marker = f"Label=org.secpal.integration.instance={resources.instance}"
    if marker not in content:
        raise IntegrationError(f"same-named active unit lacks fixture ownership: {path.name}")
    return True


def cleanup_resources(
    runner: CommandRunner, resources: Resources, *, cloud_mode: bool = False
) -> None:
    """Best-effort exact cleanup after a read-only ownership admission."""

    owned_units = [path for path in resources.unit_files if _owned_unit_file(path, resources)]
    owned_unit_names = {path.name for path in owned_units}
    owned_target = _owned_unit_file(resources.systemd_target_file, resources)

    owned_containers: list[str] = []
    for role, name in zip(CONTAINER_ROLES, resources.containers, strict=True):
        details = _inspect_resource(runner, "container", name)
        if details is None:
            continue
        unit_name = f"{resources.prefix}-{role}.container"
        if (
            not _owned_by_instance(details, "container", resources.instance, role)
            and unit_name not in owned_unit_names
        ):
            raise IntegrationError(f"refusing to remove same-named unowned container: {name}")
        owned_containers.append(name)
    owned_networks: list[str] = []
    for name in resources.networks:
        details = _inspect_resource(runner, "network", name)
        if details is None:
            continue
        unit_name = f"{name}.network"
        if (
            not _owned_by_instance(details, "network", resources.instance)
            and unit_name not in owned_unit_names
        ):
            raise IntegrationError(f"refusing to remove same-named unowned network: {name}")
        owned_networks.append(name)
    owned_volumes: list[str] = []
    for name in resources.volumes:
        details = _inspect_resource(runner, "volume", name)
        if details is None:
            continue
        unit_name = f"{name}.volume"
        if (
            not _owned_by_instance(details, "volume", resources.instance)
            and unit_name not in owned_unit_names
        ):
            raise IntegrationError(f"refusing to remove same-named unowned volume: {name}")
        owned_volumes.append(name)
    gateway = _inspect_resource(runner, "image", resources.gateway_image)
    gateway_unit = f"{resources.prefix}-gateway.container"
    if (
        gateway is not None
        and not _owned_by_instance(gateway, "image", resources.instance)
        and gateway_unit not in owned_unit_names
    ):
        raise IntegrationError(
            f"refusing to remove same-named unowned image: {resources.gateway_image}"
        )

    commands: list[list[str]] = []
    if owned_target or owned_units or owned_containers or owned_networks or owned_volumes:
        commands.append(["systemctl", "--user", "stop", resources.target])
    resource_services: list[str] = []
    for name in resources.networks:
        if name in owned_networks or f"{name}.network" in owned_unit_names:
            resource_services.append(f"{name}-network.service")
    for name in resources.volumes:
        if name in owned_volumes or f"{name}.volume" in owned_unit_names:
            resource_services.append(f"{name}-volume.service")
    if resource_services:
        commands.append(["systemctl", "--user", "stop", *resource_services])
    commands.extend(["podman", "rm", "--force", name] for name in reversed(owned_containers))
    commands.extend(["podman", "network", "rm", name] for name in owned_networks)
    commands.extend(["podman", "volume", "rm", name] for name in owned_volumes)
    if gateway is not None:
        commands.append(["podman", "image", "rm", resources.gateway_image])
    fixture_remove_command = None
    if cloud_mode and (owned_target or owned_units):
        fixture_remove_command = [
            os.fspath(CLOUD_FIXTURE_CLIENT),
            "remove",
            resources.instance,
        ]
        commands.append(fixture_remove_command)
    else:
        commands.extend(
            ["sudo", "-n", "rm", "-f", "--", os.fspath(path)]
            for path in owned_units
        )
        if owned_target:
            commands.append(
                [
                    "sudo",
                    "-n",
                    "rm",
                    "-f",
                    "--",
                    os.fspath(resources.systemd_target_file),
                ]
            )
    commands.append(["systemctl", "--user", "daemon-reload"])
    generated_services = generated_service_names(resources)
    commands.append(
        ["systemctl", "--user", "reset-failed", resources.target, *generated_services]
    )
    reload_failed = False
    fixture_remove_failed = False
    reload_command = ["systemctl", "--user", "daemon-reload"]
    for command in commands:
        try:
            result = runner.run(
                command,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=command[0] != "sudo",
            )
        except OSError:
            if command == reload_command:
                reload_failed = True
            if command == fixture_remove_command:
                fixture_remove_failed = True
            continue
        if command == reload_command and result.returncode != 0:
            reload_failed = True
        if command == fixture_remove_command and result.returncode != 0:
            fixture_remove_failed = True
    if reload_failed:
        raise IntegrationError("systemd user daemon reload failed during cleanup")
    if fixture_remove_failed:
        raise IntegrationError("trusted Quadlet fixture removal failed")


def render_and_start_with_port_retries(lifecycle, start, port_allocator=None) -> None:
    automatic_port = getattr(lifecycle, "port", 1) is None
    allocator = port_allocator or allocate_port
    previous_port: int | None = None
    for attempt in range(3):
        if automatic_port:
            selected = allocate_distinct_port(allocator, previous_port)
            lifecycle.select_port(selected)
            previous_port = selected
        lifecycle.render_validate_and_install_units()
        try:
            start()
            return
        except PortCollisionError as error:
            if not automatic_port:
                raise
            if attempt == 2:
                raise IntegrationError(
                    "an isolated loopback port could not be allocated after three attempts"
                ) from error
            lifecycle.prepare_port_retry()
    raise IntegrationError("unreachable port retry state")


def execute_lifecycle(lifecycle, port_allocator=None) -> None:
    failure: BaseException | None = None
    try:
        lifecycle.validate_repository_and_runtime()
        lifecycle.retrieve_verify_and_stage_images()
        render_and_start_with_port_retries(
            lifecycle, lifecycle.start_target, port_allocator
        )
        lifecycle.prove_runtime()
        lifecycle.collect_resource_evidence()
    except BaseException as error:
        failure = error
    try:
        lifecycle.cleanup()
    except BaseException as cleanup_error:
        if failure is not None:
            raise IntegrationError(
                f"lifecycle failed ({failure}); cleanup also failed ({cleanup_error})"
            ) from cleanup_error
        raise
    if failure is not None:
        raise failure


def execute_expected_failure_lifecycle(lifecycle, port_allocator=None) -> None:
    failure: BaseException | None = None
    try:
        lifecycle.validate_repository_and_runtime()
        lifecycle.retrieve_verify_and_stage_images()
        render_and_start_with_port_retries(
            lifecycle, lifecycle.start_expected_failure, port_allocator
        )
        lifecycle.prove_expected_failure()
    except BaseException as error:
        failure = error
    try:
        lifecycle.cleanup()
    except BaseException as cleanup_error:
        if failure is not None:
            raise IntegrationError(
                f"failure-evidence lifecycle failed ({failure}); cleanup also failed ({cleanup_error})"
            ) from cleanup_error
        raise
    if failure is not None:
        raise failure


def execute_cloud_prepare(lifecycle) -> None:
    """Verify, stage, render, and publish without activating target units."""

    lifecycle.validate_repository_and_runtime()
    lifecycle.retrieve_verify_and_stage_images()
    lifecycle.render_validate_and_install_units()


def execute_cloud_cleanup(lifecycle) -> None:
    """Reconstruct the fixed fixture and remove only its owned resources."""

    lifecycle.validate_cloud_cleanup_runtime()
    lifecycle.cleanup()


def allocate_distinct_port(port_allocator, previous_port: int | None) -> int:
    for _attempt in range(10):
        port = port_allocator()
        if isinstance(port, bool) or not isinstance(port, int) or not 1024 <= port <= 65535:
            raise IntegrationError("automatic loopback port allocator returned an invalid port")
        if port != previous_port:
            return port
    raise IntegrationError("a new isolated loopback port could not be selected")


def cloud_fixture_root(instance: str) -> Path:
    if re.fullmatch(r"[0-9a-f]{12}", instance) is None:
        raise IntegrationError("cloud fixture instance is outside the closed contract")
    return CLOUD_FIXTURE_BASE / instance


def cloud_fixture_port(instance: str) -> int:
    if re.fullmatch(r"[0-9a-f]{12}", instance) is None:
        raise IntegrationError("cloud fixture instance is outside the closed contract")
    return 20_000 + int(instance[:8], 16) % 40_000


def is_port_collision_log(output: str) -> bool:
    return bool(
        re.search(
            r"address already in use|port is already allocated|"
            r"failed to bind host port|bind for .* failed",
            output,
            flags=re.IGNORECASE,
        )
    )


def handle_signal(lifecycle, signal_number: int) -> None:
    # A second termination request must not re-enter exact cleanup halfway
    # through resource removal.
    for handled_signal in HANDLED_SIGNALS:
        signal.signal(handled_signal, signal.SIG_IGN)
    lifecycle.signal_number = signal_number
    if getattr(lifecycle, "cleanup_active", False):
        return
    terminate = getattr(getattr(lifecycle, "runner", None), "terminate_active", None)
    if terminate is not None:
        terminate()
    raise IntegrationInterrupted(signal_number)


class IntegrationLifecycle:
    def __init__(
        self,
        *,
        root: Path,
        instance: str,
        port: int | None,
        fixture_root: Path,
        output: Path,
        failure_case: str | None = None,
        runner: Runner | None = None,
        cloud_mode: bool = False,
    ) -> None:
        self.root = root
        self.instance = instance
        self.port = port
        self.fixture_root = fixture_root
        self.output = output
        self.failure_case = failure_case
        self.runner = runner or Runner()
        self.cloud_mode = cloud_mode
        self.uid = os.getuid()
        self.active_root = Path(f"/etc/containers/systemd/users/{self.uid}")
        self.resources = Resources.for_instance(
            instance, self.uid, self.active_root, cloud_mode
        )
        self.assets = fixture_root / "assets"
        self.gh_config = fixture_root / "anonymous-gh-config"
        self.cleaned = False
        self.cleanup_active = False
        self.signal_number: int | None = None
        self.runtime_admitted = False
        self.graph_root: Path | None = None
        self.run_root: Path | None = None
        self.apparmor_available = False
        self.cloud_gateway_digest: str | None = None
        self.gh_executable = "gh"
        self.migration_invocation: tuple[str, str] | None = None
        self.inspected_oneshots: set[str] = set()
        self.preexisting_resources: dict[str, set[str]] = {}
        self.expected_failure_observed = False
        self.injected_health_failure_observed = False

    def select_port(self, port: int) -> None:
        if isinstance(port, bool) or not isinstance(port, int) or not 1024 <= port <= 65535:
            raise IntegrationError("integration port must be from 1024 through 65535")
        self.port = port

    def command(
        self,
        argv: Sequence[str],
        *,
        capture: bool = False,
        check: bool = True,
        environment: Mapping[str, str] | None = None,
        cwd: Path | None = None,
        start_new_session: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        try:
            return self.runner.run(
                argv,
                check=check,
                capture_output=capture,
                env=dict(environment) if environment is not None else None,
                cwd=os.fspath(cwd) if cwd is not None else None,
                start_new_session=start_new_session,
            )
        except subprocess.CalledProcessError as error:
            detail = ""
            if capture and error.stderr:
                detail = f": {str(error.stderr).strip()[:400]}"
            raise IntegrationError(f"command failed ({argv[0]}){detail}") from error
        except OSError as error:
            raise IntegrationError(f"unable to execute required command: {argv[0]}") from error

    def captured(self, argv: Sequence[str], **kwargs) -> str:
        return (self.command(argv, capture=True, **kwargs).stdout or "").strip()

    def sudo(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return self.command(
            ["sudo", *arguments],
            start_new_session=False,
        )

    def validate_repository_and_runtime(self) -> None:
        required = [
            "catatonit",
            "curl",
            "du",
            "journalctl",
            "podman",
            "python3",
            "systemctl",
        ]
        if not self.cloud_mode:
            required.extend(("gh", "node", "npm", "sudo"))
        missing = [name for name in required if shutil.which(name) is None]
        if missing:
            raise IntegrationError(f"required command(s) missing: {' '.join(missing)}")
        if not INSTANCE_PATTERN.fullmatch(self.instance):
            raise IntegrationError("invalid integration instance identifier")
        if self.port is not None and not 1024 <= self.port <= 65535:
            raise IntegrationError("integration port must be from 1024 through 65535")
        if self.fixture_root.is_symlink() or self.fixture_root.resolve() != self.fixture_root:
            raise IntegrationError("fixture root must be canonical and contain no symlink component")
        if stat_mode(self.fixture_root) != 0o700:
            raise IntegrationError("fixture root must have mode 0700")

        if self.cloud_mode:
            if (
                self.uid != CLOUD_OPERATOR_UID
                or os.getgid() != CLOUD_OPERATOR_GID
                or self.fixture_root != cloud_fixture_root(self.instance)
                or self.port != cloud_fixture_port(self.instance)
            ):
                raise IntegrationError("cloud fixture identity or derived paths differ")
            validate_trusted_executable(
                CLOUD_FIXTURE_CLIENT, "trusted Quadlet fixture client"
            )

        if not self.cloud_mode:
            version_line = required_first_line(
                self.captured(["gh", "version"]), "GitHub CLI"
            )
            validate_gh_version_line(version_line)
            self.command(["gh", "attestation", "verify", "--help"], capture=True)
            self.command(playwright_admission_command(), capture=True)
            # Authenticate once while the operator is present. Every later install
            # and cleanup command remains non-interactive so failure paths cannot
            # hang on a password prompt.
            self.sudo("-S", "-v")

        info = parse_json_mapping(
            self.captured(["podman", "info", "--format", "json"]),
            "Podman runtime information",
        )
        self.graph_root, self.run_root = validate_runtime_info(
            info, self.uid, os.environ
        )
        for path, description in runtime_component_paths(info):
            validate_trusted_executable(path, description)
        generator = validate_quadlet_generator(QUADLET_USER_GENERATOR)
        generator_version = required_first_line(
            self.captured([os.fspath(generator), "--version"]),
            "native Quadlet user generator",
        )
        if not podman_versions_compatible(
            generator_version, nested(info, "version", "Version")
        ):
            raise IntegrationError("native Quadlet user generator does not match Podman")
        self.apparmor_available = bool(
            nested(info, "host", "security", "apparmorEnabled")
        )
        self._validate_disabled_user_unit("podman.socket")
        self._validate_disabled_user_unit("podman-auto-update.timer")
        connections_text = self.captured(
            ["podman", "system", "connection", "list", "--format", "json"]
        )
        connections = parse_json_objects(
            connections_text, "Podman connection information"
        )
        if any(str(item.get("URI", "")).startswith(("ssh://", "tcp://")) for item in connections):
            raise IntegrationError("remote Podman connections are forbidden")
        validate_user_container_configuration(Path.home(), os.environ)
        self._validate_registry_files()
        policy = Path("/etc/environment.d/90-secpal-quadlet.conf")
        expected_policy = f"QUADLET_UNIT_DIRS={self.active_root}\n"
        validate_quadlet_search_path_policy(policy, expected_policy)
        environment = self.captured(["systemctl", "--user", "show-environment"])
        values = [line for line in environment.splitlines() if line.startswith("QUADLET_UNIT_DIRS=")]
        if values != [expected_policy.strip()]:
            raise IntegrationError("effective Quadlet search path is not the reviewed root-owned path")
        self.command(["systemctl", "--user", "is-active", "default.target"], capture=True)
        self.snapshot_unrelated_resources()
        self.runtime_admitted = True
        cleanup_resources(
            self.runner, self.resources, cloud_mode=self.cloud_mode
        )
        stale = self._owned_resource_errors()
        if stale:
            raise IntegrationError("stale integration resources could not be removed: " + "; ".join(stale))

    def validate_cloud_cleanup_runtime(self) -> None:
        if not self.cloud_mode:
            raise IntegrationError("cloud cleanup requires the fixed cloud mode")
        try:
            identity_or_path_differs = (
                self.uid != CLOUD_OPERATOR_UID
                or os.getgid() != CLOUD_OPERATOR_GID
                or self.fixture_root != cloud_fixture_root(self.instance)
                or CLOUD_FIXTURE_BASE.resolve() != CLOUD_FIXTURE_BASE
                or self.fixture_root.resolve() != self.fixture_root
            )
        except OSError:
            identity_or_path_differs = True
        if identity_or_path_differs:
            raise IntegrationError("cloud cleanup identity or fixture path differs")
        validate_trusted_executable(
            CLOUD_FIXTURE_CLIENT, "trusted Quadlet fixture client"
        )
        info = parse_json_mapping(
            self.captured(["podman", "info", "--format", "json"]),
            "Podman runtime information",
        )
        self.graph_root, self.run_root = validate_runtime_info(
            info, self.uid, os.environ
        )
        validate_user_container_configuration(Path.home(), os.environ)
        self.runtime_admitted = True

    def _validate_registry_files(self) -> None:
        user_root = user_container_configuration_root(Path.home(), os.environ)
        user_paths = [
            user_root / "registries.conf",
            user_root / "registries.conf.d",
            *(user_root / "registries.conf.d").glob("*.conf"),
        ]
        if any(path.exists() or path.is_symlink() for path in user_paths):
            raise IntegrationError("user-writable registry configuration is forbidden")
        system_root = Path("/etc/containers")
        dropin_root = system_root / "registries.conf.d"
        try:
            if system_root.exists() or system_root.is_symlink():
                validate_trusted_directory(
                    system_root, "system registry configuration"
                )
            if dropin_root.exists() or dropin_root.is_symlink():
                validate_trusted_directory(
                    dropin_root, "system registry configuration"
                )
        except IntegrationError:
            raise
        except OSError as error:
            raise IntegrationError(
                "system registry configuration could not be inspected safely"
            ) from error
        system_paths = [
            system_root / "registries.conf",
            *dropin_root.glob("*.conf"),
        ]
        documents = []
        for path in system_paths:
            if not (path.exists() or path.is_symlink()):
                continue
            try:
                validate_trusted_regular_file(path, "system registry configuration")
                documents.append(load_registry_document(path))
            except IntegrationError:
                raise
            except (OSError, UnicodeError) as error:
                raise IntegrationError(
                    "system registry configuration could not be parsed safely"
                ) from error
        validate_registry_documents(documents)

    def _validate_disabled_user_unit(self, name: str) -> None:
        result = self.command(
            [
                "systemctl",
                "--user",
                "show",
                name,
                "--property=LoadState",
                "--property=UnitFileState",
                "--property=ActiveState",
            ],
            capture=True,
            check=False,
        )
        if result.returncode != 0:
            raise IntegrationError(f"unable to verify forbidden user unit: {name}")
        properties: dict[str, str] = {}
        for line in (result.stdout or "").splitlines():
            if "=" not in line:
                raise IntegrationError(f"unable to verify forbidden user unit: {name}")
            key, value = line.split("=", 1)
            if key in properties:
                raise IntegrationError(f"unable to verify forbidden user unit: {name}")
            properties[key] = value
        if set(properties) != {"LoadState", "UnitFileState", "ActiveState"}:
            raise IntegrationError(f"unable to verify forbidden user unit: {name}")
        safe_state = (
            properties["ActiveState"] == "inactive"
            and (
                (
                    properties["LoadState"] == "loaded"
                    and properties["UnitFileState"] == "disabled"
                )
                or (
                    properties["LoadState"] == "masked"
                    and properties["UnitFileState"] in {"masked", "masked-runtime"}
                )
                or (
                    properties["LoadState"] == "not-found"
                    and properties["UnitFileState"] in {"", "not-found"}
                )
            )
        )
        if not safe_state:
            raise IntegrationError(f"forbidden user unit is enabled or active: {name}")

    def snapshot_unrelated_resources(self) -> None:
        self.preexisting_resources = {
            "containers": {
                name
                for name in self._podman_names(
                    ["podman", "ps", "--all", "--format", "{{.Names}}"]
                )
                if not is_integration_resource_name("container", name)
            },
            "networks": {
                name
                for name in self._podman_names(
                    ["podman", "network", "ls", "--format", "{{.Name}}"]
                )
                if not is_integration_resource_name("network", name)
            },
            "volumes": {
                name
                for name in self._podman_names(
                    ["podman", "volume", "ls", "--format", "{{.Name}}"]
                )
                if not is_integration_resource_name("volume", name)
            },
        }

    def _podman_names(self, command: Sequence[str]) -> list[str]:
        output = self.captured(command)
        return [line for line in output.splitlines() if line]

    def anonymous_environment(
        self,
        auth_file: Path | None = None,
        *,
        credential_root: Path | None = None,
    ) -> dict[str, str]:
        environment = dict(os.environ)
        storage_data_home = environment.get("XDG_DATA_HOME") or os.fspath(
            Path(environment.get("HOME", os.fspath(Path.home()))) / ".local" / "share"
        )
        for name in (
            *FORBIDDEN_RUNTIME_ENVIRONMENT,
            "DOCKER_CONFIG",
            "DOCKER_AUTH_CONFIG",
            "REGISTRY_AUTH_FILE",
            "GH_TOKEN",
            "GITHUB_TOKEN",
            "GH_ENTERPRISE_TOKEN",
            "GITHUB_ENTERPRISE_TOKEN",
            "GH_HOST",
        ):
            environment.pop(name, None)
        if auth_file is not None:
            if credential_root is None:
                raise IntegrationError("anonymous registry isolation root is missing")
            isolated = {
                "HOME": credential_root / "home",
                "XDG_CONFIG_HOME": credential_root / "xdg-config",
                "DOCKER_CONFIG": credential_root / "docker-config",
            }
            for path in (*isolated.values(), credential_root / "certs"):
                path.mkdir(mode=0o700)
            environment.update(
                {name: os.fspath(path) for name, path in isolated.items()}
            )
            environment["XDG_DATA_HOME"] = storage_data_home
            environment["REGISTRY_AUTH_FILE"] = os.fspath(auth_file)
        return environment

    def stage_cloud_gh_cli(self) -> None:
        if not self.cloud_mode:
            return
        release = CLOUD_GH_RELEASES.get(os.uname().machine)
        if release is None:
            raise IntegrationError("cloud GitHub CLI architecture is unsupported")
        release_arch, expected_sha256 = release
        archive_name = f"gh_{EXPECTED_GH_VERSION}_linux_{release_arch}.tar.gz"
        archive = self.fixture_root / archive_name
        executable = self.fixture_root / "tools" / "gh"
        executable.parent.mkdir(mode=0o700)
        self.command(
            [
                "curl",
                "--disable",
                "--proto",
                "=https",
                "--tlsv1.2",
                "--fail",
                "--location",
                "--silent",
                "--show-error",
                "--max-time",
                "180",
                "--max-filesize",
                "67108864",
                "--output",
                os.fspath(archive),
                (
                    "https://github.com/cli/cli/releases/download/"
                    f"v{EXPECTED_GH_VERSION}/{archive_name}"
                ),
            ],
            environment=self.anonymous_environment(),
        )
        try:
            if hashlib.sha256(archive.read_bytes()).hexdigest() != expected_sha256:
                raise IntegrationError("cloud GitHub CLI archive digest differs")
            member_name = (
                f"gh_{EXPECTED_GH_VERSION}_linux_{release_arch}/bin/gh"
            )
            with tarfile.open(archive, mode="r:gz") as bundle:
                member = bundle.getmember(member_name)
                if not member.isfile() or not 0 < member.size <= 64 * 1024 * 1024:
                    raise IntegrationError("cloud GitHub CLI archive member is invalid")
                source = bundle.extractfile(member)
                if source is None:
                    raise IntegrationError("cloud GitHub CLI archive member is missing")
                content = source.read(64 * 1024 * 1024 + 1)
                if len(content) != member.size:
                    raise IntegrationError("cloud GitHub CLI archive member is truncated")
            executable.write_bytes(content)
            executable.chmod(0o700)
        except (KeyError, OSError, tarfile.TarError) as error:
            raise IntegrationError("cloud GitHub CLI staging failed") from error
        finally:
            archive.unlink(missing_ok=True)
        self.gh_executable = os.fspath(executable)
        version_line = required_first_line(
            self.captured([self.gh_executable, "version"]), "GitHub CLI"
        )
        validate_gh_version_line(version_line)
        self.command(
            [self.gh_executable, "attestation", "verify", "--help"],
            capture=True,
        )

    def retrieve_verify_and_stage_images(self) -> None:
        self.stage_cloud_gh_cli()
        self.gh_config.mkdir(mode=0o700)
        products = (
            (
                "api",
                API_IMAGE,
                API_DIGEST,
                "SecPal/api",
                "SecPal/api/.github/workflows/publish-container.yml",
                API_SOURCE_COMMIT,
                "secpal/api",
            ),
            (
                "frontend",
                FRONTEND_IMAGE,
                FRONTEND_DIGEST,
                "SecPal/frontend",
                "SecPal/frontend/.github/workflows/publish-container.yml",
                FRONTEND_SOURCE_COMMIT,
                "secpal/frontend",
            ),
        )
        for values in products:
            self.verify_and_stage_product(*values)
        for label, image in (
            ("postgres", POSTGRES_IMAGE),
            ("valkey", VALKEY_IMAGE),
            ("caddy", CADDY_IMAGE),
        ):
            self.anonymous_pull(label, image)
            self.verify_staged_image(image, image.rsplit("@", 1)[1])
            if self.cloud_mode and label != "caddy":
                self.stage_cloud_image_alias(
                    label, image, image.rsplit("@", 1)[1]
                )
        self.command(
            [
                "podman",
                "build",
                "--pull=never",
                "--force-rm=true",
                "--label",
                "org.secpal.integration=true",
                "--label",
                f"org.secpal.integration.instance={self.instance}",
                "--build-arg",
                f"CADDY_IMAGE={CADDY_IMAGE}",
                "--tag",
                self.resources.gateway_image,
                os.fspath(self.root / "containers" / "phase-b-gateway"),
            ],
            environment=self.anonymous_environment(),
            cwd=self.root,
        )
        if self.cloud_mode:
            self.cloud_gateway_digest = self.local_image_digest(
                self.resources.gateway_image
            )

    def verify_and_stage_product(
        self,
        label: str,
        image: str,
        digest: str,
        repository: str,
        workflow: str,
        source_commit: str,
        registry_path: str,
    ) -> None:
        canonical_name = image.split("@", 1)[0]
        if image != f"{canonical_name}@{digest}" or canonical_name != f"ghcr.io/{registry_path}":
            raise IntegrationError(f"unreviewed {label} image identity")
        subject = self.fixture_root / f"{label}-image-index.json"
        bundle = self.fixture_root / f"{label}-attestation.json"
        self.command(
            [
                "python3",
                os.fspath(self.root / "scripts" / "fetch-oci-attestation.py"),
                os.fspath(subject),
                os.fspath(bundle),
                canonical_name,
                digest,
                registry_path,
            ],
            environment=self.anonymous_environment(),
        )
        gh_environment = self.anonymous_environment()
        gh_environment.update(
            {
                "GH_CONFIG_DIR": os.fspath(self.gh_config),
                "GH_PROMPT_DISABLED": "1",
                "GH_NO_UPDATE_NOTIFIER": "1",
                "GH_NO_EXTENSION_UPDATE_NOTIFIER": "1",
                "GH_TELEMETRY": "false",
            }
        )
        self.command(
            [
                self.gh_executable,
                "attestation",
                "verify",
                os.fspath(subject),
                "--bundle",
                os.fspath(bundle),
                "--repo",
                repository,
                "--signer-workflow",
                workflow,
                "--signer-digest",
                source_commit,
                "--source-ref",
                "refs/heads/main",
                "--source-digest",
                source_commit,
                "--deny-self-hosted-runners",
                "--hostname",
                "github.com",
            ],
            environment=gh_environment,
        )
        self.anonymous_pull(label, image)
        self.verify_staged_image(image, digest)
        if self.cloud_mode:
            self.stage_cloud_image_alias(label, image, digest)
        subject.unlink(missing_ok=True)
        bundle.unlink(missing_ok=True)
        print(f"Verified and staged {label} image: {image}")

    def anonymous_pull(self, label: str, image: str) -> None:
        if self.graph_root is None or self.run_root is None:
            raise IntegrationError("admitted rootless storage paths are missing")
        auth_directory = Path(tempfile.mkdtemp(prefix=f"anon-{label}.", dir=self.fixture_root))
        auth_directory.chmod(0o700)
        auth_file = auth_directory / "auth.json"
        auth_file.write_text("{}\n", encoding="utf-8")
        auth_file.chmod(0o600)
        try:
            self.command(
                [
                    "podman",
                    "--root",
                    os.fspath(self.graph_root),
                    "--runroot",
                    os.fspath(self.run_root),
                    "pull",
                    "--authfile",
                    os.fspath(auth_file),
                    "--cert-dir",
                    os.fspath(auth_directory / "certs"),
                    image,
                ],
                environment=self.anonymous_environment(
                    auth_file,
                    credential_root=auth_directory,
                ),
            )
        finally:
            try:
                shutil.rmtree(auth_directory)
            except OSError as error:
                raise IntegrationError(
                    f"anonymous {label} pull credential isolation could not be removed"
                ) from error

    def verify_staged_image(self, image: str, digest: str) -> None:
        observed = parse_single_json_object(
            self.captured(
                ["podman", "image", "inspect", image, "--format", "json"]
            ),
            "staged image inspection",
        )
        repo_digests = observed.get("RepoDigests") or []
        if image not in repo_digests and observed.get("Digest") != digest:
            raise IntegrationError("staged image does not retain the reviewed digest")

    def stage_cloud_image_alias(
        self, label: str, source: str, digest: str
    ) -> None:
        tag = CLOUD_IMAGE_TAGS.get(label)
        if tag is None or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
            raise IntegrationError("cloud image alias is outside the closed contract")
        repository = tag.rsplit(":", 1)[0]
        exact_reference = f"{repository}@{digest}"
        self.command(["podman", "tag", source, tag])
        observed = parse_single_json_object(
            self.captured(
                ["podman", "image", "inspect", exact_reference, "--format", "json"]
            ),
            "cloud image alias inspection",
        )
        repo_digests = observed.get("RepoDigests")
        if (
            observed.get("Digest") != digest
            or not isinstance(repo_digests, list)
            or not all(isinstance(item, str) for item in repo_digests)
            or exact_reference not in repo_digests
        ):
            raise IntegrationError("cloud image alias lost the verified digest")

    def local_image_digest(self, image: str) -> str:
        observed = parse_single_json_object(
            self.captured(
                ["podman", "image", "inspect", image, "--format", "json"]
            ),
            "local gateway image inspection",
        )
        digest = observed.get("Digest")
        exact_reference = f"{image.rsplit(':', 1)[0]}@{digest}"
        repo_digests = observed.get("RepoDigests")
        if (
            not isinstance(digest, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
            or not isinstance(repo_digests, list)
            or not all(isinstance(item, str) for item in repo_digests)
            or exact_reference not in repo_digests
        ):
            raise IntegrationError("local gateway image has no immutable digest")
        return digest

    def render_validate_and_install_units(self) -> None:
        if self.port is None:
            raise IntegrationError("integration port was not selected before rendering")
        self.assets.mkdir(mode=0o700, exist_ok=True)
        if self.assets.is_symlink() or stat_mode(self.assets) != 0o700:
            raise IntegrationError("integration asset directory is not private")
        for source, name, mode in (
            (self.root / "scripts" / "container-entrypoint.sh", "container-entrypoint.sh", 0o755),
            (self.root / "scripts" / "init-local-secrets.sh", "init-local-secrets.sh", 0o755),
            (self.root / "scripts" / "valkey-entrypoint.sh", "valkey-entrypoint.sh", 0o755),
            (
                self.root / "scripts" / "quadlet-oneshot-entrypoint.sh",
                "quadlet-oneshot-entrypoint.sh",
                0o755,
            ),
            (self.root / "scripts" / "phase-b-runtime-probe.php", "phase-b-runtime-probe.php", 0o644),
            (self.root / "config" / "quadlet" / "Caddyfile", "Caddyfile", 0o644),
        ):
            destination = self.assets / name
            shutil.copyfile(source, destination)
            destination.chmod(mode)
        renderer = self.root / "scripts" / "render-integration-quadlets.py"
        base = [
            "--instance",
            self.instance,
            "--port",
            str(self.port),
            "--fixture-root",
            os.fspath(self.fixture_root),
        ]
        if self.failure_case is not None:
            base.extend(("--failure-case", self.failure_case))
        if self.cloud_mode:
            if self.cloud_gateway_digest is None:
                raise IntegrationError("cloud gateway digest is missing before rendering")
            base.extend(("--cloud-gateway-digest", self.cloud_gateway_digest))
        self.command(["python3", os.fspath(renderer), "render", *base, "--output", os.fspath(self.output)])
        self.command(["python3", os.fspath(renderer), "validate", *base, "--input", os.fspath(self.output)])
        self.publish_rendered_units()
        validate_active_root(self.active_root)
        validate_active_root(self.resources.systemd_target_file.parent)
        validate_active_quadlet_inputs(self.active_root)
        for source in sorted(self.output.iterdir()):
            destination = (
                self.resources.systemd_target_file
                if source.name == self.resources.target
                else self.active_root / source.name
            )
            metadata = destination.lstat()
            if (
                not destination.is_file()
                or destination.is_symlink()
                or metadata.st_uid != 0
                or metadata.st_gid != 0
                or stat_mode(destination) != 0o644
                or destination.read_text(encoding="utf-8")
                != source.read_text(encoding="utf-8")
            ):
                raise IntegrationError(
                    f"active unit differs from the reviewed contract: {source.name}"
                )
        if self.cloud_mode:
            return
        self.command(
            [
                "python3",
                os.fspath(renderer),
                "validate",
                *base,
                "--input",
                os.fspath(self.active_root),
                "--require-root-owned",
                "--allow-unrelated",
            ]
        )
        self.command(["systemctl", "--user", "daemon-reload"])
        generator_root = Path(f"/run/user/{self.uid}/systemd/generator")
        target_properties = self.captured(
            [
                "systemctl",
                "--user",
                "show",
                self.resources.target,
                "--property=FragmentPath",
                "--property=DropInPaths",
                "--property=Wants",
                "--property=Requires",
            ]
        )
        validate_effective_systemd_target(
            target_properties,
            self.resources.systemd_target_file,
            {
                f"{self.resources.prefix}-{role}.service"
                for role in TARGET_REQUIRED_ROLES
            },
        )
        for unit in generated_service_names(self.resources):
            properties = self.captured(
                [
                    "systemctl",
                    "--user",
                    "show",
                    unit,
                    "--property=FragmentPath",
                    "--property=DropInPaths",
                ]
            )
            validate_effective_systemd_unit(properties, generator_root / unit)
        for role in (
            item for item in CONTAINER_ROLES if role_spec(item).health is not None
        ):
            properties = self.captured(
                [
                    "systemctl",
                    "--user",
                    "show",
                    f"{self.resources.prefix}-{role}.service",
                    "--property=Type",
                    "--property=NotifyAccess",
                ]
            )
            validate_effective_health_service(properties)

    def publish_rendered_units(self) -> None:
        if self.cloud_mode:
            self.command(
                [
                    os.fspath(CLOUD_FIXTURE_CLIENT),
                    "install",
                    self.instance,
                    os.fspath(self.output),
                ]
            )
            return
        self.sudo(
            "-n",
            "install",
            "-d",
            "-o",
            "root",
            "-g",
            "root",
            "-m",
            "0755",
            os.fspath(self.active_root),
        )
        for source in sorted(self.output.iterdir()):
            self.sudo(
                "-n",
                "install",
                "-o",
                "root",
                "-g",
                "root",
                "-m",
                "0644",
                os.fspath(source),
                os.fspath(self.active_root / source.name),
            )
        target_source = self.output / self.resources.target
        self.sudo(
            "-n",
            "install",
            "-o",
            "root",
            "-g",
            "root",
            "-m",
            "0644",
            os.fspath(target_source),
            os.fspath(self.resources.systemd_target_file),
        )

    def start_target(self) -> None:
        if not self.inspected_oneshots:
            queued = self.command(
                ["systemctl", "--user", "start", "--no-block", self.resources.target],
                capture=True,
                check=False,
            )
            if queued.returncode != 0:
                raise IntegrationError("systemd-user target could not be queued")
            for role in ("secrets-init", "migrate"):
                details = self._wait_for_oneshot_container(role)
                self._validate_effective_container(role, details)
                self.inspected_oneshots.add(role)
                self.command(
                    [
                        "podman",
                        "exec",
                        f"{self.resources.prefix}-{role}",
                        "/bin/sh",
                        "-c",
                        ": > /tmp/secpal-inspection-release",
                    ]
                )
        result = self.command(
            ["systemctl", "--user", "start", self.resources.target],
            capture=True,
            check=False,
        )
        if result.returncode != 0:
            if self._gateway_port_collision():
                raise PortCollisionError("gateway loopback port is already allocated")
            states = []
            for role in CONTAINER_ROLES:
                unit = f"{self.resources.prefix}-{role}.service"
                state = self.command(
                    ["systemctl", "--user", "show", unit, "--property=ActiveState", "--property=Result"],
                    capture=True,
                    check=False,
                )
                states.append(f"{unit}: {(state.stdout or '').strip()}")
            raise IntegrationError("systemd-user target failed closed; " + "; ".join(states))

    def _gateway_port_collision(self) -> bool:
        service = f"{self.resources.prefix}-gateway.service"
        invocation = self.command(
            [
                "systemctl",
                "--user",
                "show",
                service,
                "--property=InvocationID",
                "--value",
            ],
            capture=True,
            check=False,
        )
        invocation_id = (invocation.stdout or "").strip()
        if invocation.returncode != 0 or not re.fullmatch(r"[a-f0-9]{32}", invocation_id):
            return False
        journal = self.command(
            [
                "journalctl",
                "--user",
                "--unit",
                service,
                f"_SYSTEMD_INVOCATION_ID={invocation_id}",
                "--lines",
                "80",
                "--no-pager",
                "--output=cat",
            ],
            capture=True,
            check=False,
        )
        return journal.returncode == 0 and is_port_collision_log(
            (journal.stdout or "") + "\n" + (journal.stderr or "")
        )

    def prepare_port_retry(self) -> None:
        if self.port is None or self.inspected_oneshots != {"secrets-init", "migrate"}:
            raise IntegrationError("port retry was requested before one-shot completion")
        migration_invocation = self.oneshot_invocation("migrate")
        if self.migration_invocation is not None and self.migration_invocation != migration_invocation:
            raise IntegrationError("migration executed more than once before port retry")
        self.migration_invocation = migration_invocation
        retry_roles = (
            "api",
            "worker-general",
            "worker-hash-chain",
            "scheduler",
            "frontend",
            "gateway",
        )
        services = [f"{self.resources.prefix}-{role}.service" for role in retry_roles]
        self.command(["systemctl", "--user", "stop", *services])
        for role in reversed(retry_roles):
            name = f"{self.resources.prefix}-{role}"
            details = _inspect_resource(self.runner, "container", name)
            if details is None:
                continue
            if not _owned_by_instance(details, "container", self.instance, role):
                raise IntegrationError(
                    f"refusing to reset same-named unowned container: {name}"
                )
            self.command(["podman", "rm", "--force", name])
        self.command(
            ["systemctl", "--user", "reset-failed", self.resources.target, *services],
        )
        if self.output.exists():
            try:
                shutil.rmtree(self.output)
            except OSError as error:
                raise IntegrationError(
                    "previous Quadlet attempt could not be removed"
                ) from error
        self.expected_failure_observed = False
        self.injected_health_failure_observed = False
        self.port = None

    def start_expected_failure(self) -> None:
        if self.failure_case not in {"migration", "dependency", "health"}:
            raise IntegrationError("expected-failure lifecycle lacks a reviewed failure case")
        queued = self.command(
            ["systemctl", "--user", "start", "--no-block", self.resources.target],
            capture=True,
            check=False,
        )
        if queued.returncode != 0:
            raise IntegrationError("expected-failure systemd target could not be queued")
        release_roles = [] if self.inspected_oneshots else ["secrets-init"]
        if release_roles and self.failure_case != "dependency":
            release_roles.append("migrate")
        for role in release_roles:
            details = self._wait_for_oneshot_container(role)
            self._validate_effective_container(role, details)
            self.inspected_oneshots.add(role)
            self.command(
                [
                    "podman",
                    "exec",
                    f"{self.resources.prefix}-{role}",
                    "/bin/sh",
                    "-c",
                    ": > /tmp/secpal-inspection-release",
                ]
            )
        if self.failure_case == "health":
            migration_invocation = self._wait_for_oneshot_success("migrate")
            if (
                self.migration_invocation is not None
                and self.migration_invocation != migration_invocation
            ):
                raise IntegrationError("migration executed more than once")
            self.migration_invocation = migration_invocation
            self._wait_for_injected_health_failure()
        result = self.command(
            ["systemctl", "--user", "start", self.resources.target],
            capture=True,
            check=False,
        )
        if result.returncode == 0:
            raise IntegrationError(f"{self.failure_case} failure profile returned a green target")
        self.expected_failure_observed = True

    def _wait_for_injected_health_failure(self) -> None:
        role = "gateway"
        name = f"{self.resources.prefix}-{role}"
        service = f"{name}.service"
        deadline = time.monotonic() + 180
        container_id: str | None = None
        while time.monotonic() < deadline:
            inspected = self.command(
                ["podman", "container", "inspect", name], capture=True, check=False
            )
            if inspected.returncode == 0:
                details = parse_single_json_object(
                    inspected.stdout or "", "injected gateway health inspection"
                )
                running = nested(details, "State", "Running")
                if running is True:
                    self._validate_effective_container(role, details)
                    candidate_id = details.get("Id")
                    if not isinstance(candidate_id, str) or not re.fullmatch(
                        r"[0-9a-f]{64}", candidate_id
                    ):
                        raise IntegrationError(
                            "gateway inspection has no exact container identity"
                        )
                    if container_id is not None and candidate_id != container_id:
                        raise IntegrationError(
                            "gateway container identity changed during health proof"
                        )
                    container_id = candidate_id
                state = details.get("State")
                health = state.get("Health") if isinstance(state, Mapping) else None
                if isinstance(health, Mapping):
                    if has_injected_health_failure(details):
                        if running is not True:
                            self._validate_effective_container(role, details)
                        self.injected_health_failure_observed = True
                        return
            state = self.command(
                [
                    "systemctl",
                    "--user",
                    "show",
                    service,
                    "--property=ActiveState",
                    "--property=Result",
                ],
                capture=True,
                check=False,
            )
            values = dict(
                line.split("=", 1)
                for line in (state.stdout or "").splitlines()
                if "=" in line
            )
            if values.get("ActiveState") == "failed" or values.get("Result") not in {
                None,
                "",
                "success",
            }:
                if container_id is not None and self._has_injected_unhealthy_event(
                    container_id
                ):
                    self.injected_health_failure_observed = True
                    return
                if self._gateway_port_collision():
                    raise PortCollisionError("gateway loopback port is already allocated")
                raise IntegrationError(
                    "gateway failed before the injected health check was observed"
                )
            time.sleep(0.1)
        raise IntegrationError("injected gateway health check was not observed")

    def _has_injected_unhealthy_event(self, container_id: str) -> bool:
        if not re.fullmatch(r"[0-9a-f]{64}", container_id):
            raise IntegrationError("invalid gateway container identity for health evidence")
        events = self.command(
            [
                "podman",
                "events",
                "--stream=false",
                "--since=10m",
                "--filter=type=container",
                f"--filter=container={container_id}",
                "--filter=event=health_status",
                "--format={{.HealthStatus}}",
            ],
            capture=True,
            check=False,
        )
        if events.returncode != 0:
            raise IntegrationError("unable to query retained Podman health evidence")
        statuses = [line.strip() for line in (events.stdout or "").splitlines() if line.strip()]
        if any(status not in {"starting", "healthy", "unhealthy"} for status in statuses):
            raise IntegrationError("retained Podman health evidence was unexpected")
        return "unhealthy" in statuses

    def _wait_for_oneshot_success(self, role: str) -> tuple[str, str]:
        deadline = time.monotonic() + 180
        last = ""
        while time.monotonic() < deadline:
            result = self.command(
                [
                    "systemctl",
                    "--user",
                    "show",
                    f"{self.resources.prefix}-{role}.service",
                    *(f"--property={name}" for name in ONESHOT_SYSTEMD_PROPERTIES),
                ],
                capture=True,
                check=False,
            )
            last = result.stdout or ""
            try:
                return validate_oneshot_state(last)
            except IntegrationError:
                time.sleep(0.1)
        raise IntegrationError(f"one-shot did not complete before the expected failure: {role}")

    def prove_expected_failure(self) -> None:
        if not self.expected_failure_observed or self.failure_case is None:
            raise IntegrationError("the reviewed failure did not reach systemd")
        failed_role = {
            "migration": "migrate",
            "dependency": "postgres",
            "health": "gateway",
        }[self.failure_case]
        failed = self.captured(
            [
                "systemctl",
                "--user",
                "show",
                f"{self.resources.prefix}-{failed_role}.service",
                "--property=ActiveState",
                "--property=Result",
                "--property=ExecMainStatus",
            ]
        )
        properties = dict(
            line.split("=", 1) for line in failed.splitlines() if "=" in line
        )
        if (
            properties.get("ActiveState") not in {"failed", "inactive"}
            or properties.get("Result") in {None, "", "success"}
            or (
                self.failure_case in {"migration", "dependency"}
                and (
                    properties.get("Result") != "exit-code"
                    or properties.get("ExecMainStatus") != "1"
                )
            )
            or (
                self.failure_case == "health"
                and (
                    properties.get("Result") != "exit-code"
                    or properties.get("ExecMainStatus") != "137"
                )
            )
        ):
            raise IntegrationError(f"{self.failure_case} failure profile was not fail-closed")
        target_state = self.captured(
            [
                "systemctl",
                "--user",
                "show",
                self.resources.target,
                "--property=ActiveState",
            ]
        )
        if target_state.strip() == "ActiveState=active":
            raise IntegrationError(f"{self.failure_case} failure left a false-green target")
        if self.failure_case in {"migration", "dependency"}:
            for role in failure_blocked_roles(self.failure_case):
                exists = self.command(
                    ["podman", "container", "exists", f"{self.resources.prefix}-{role}"],
                    check=False,
                    capture=True,
                )
                if exists.returncode == 0:
                    raise IntegrationError(
                        f"{self.failure_case} failure allowed dependent role to execute: {role}"
                    )
                if exists.returncode != 1:
                    raise IntegrationError(
                        f"unable to verify blocked role absence: {role}"
                    )
        if self.failure_case == "health":
            if self.migration_invocation is None:
                raise IntegrationError("health failure occurred without one successful migration")
            if not self.injected_health_failure_observed:
                raise IntegrationError(
                    "health failure occurred without observing the injected health check"
                )

    def _wait_for_oneshot_container(self, role: str) -> Mapping:
        name = f"{self.resources.prefix}-{role}"
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            result = self.command(
                ["podman", "container", "inspect", name], capture=True, check=False
            )
            if result.returncode == 0:
                details = parse_single_json_object(
                    result.stdout or "", f"one-shot container inspection for {role}"
                )
                if nested(details, "State", "Running") is True:
                    return details
            state = self.command(
                [
                    "systemctl",
                    "--user",
                    "show",
                    f"{self.resources.prefix}-{role}.service",
                    "--property=ActiveState",
                    "--property=Result",
                ],
                capture=True,
                check=False,
            )
            values = dict(
                line.split("=", 1)
                for line in (state.stdout or "").splitlines()
                if "=" in line
            )
            if values.get("ActiveState") == "failed" or values.get("Result") not in {
                None,
                "",
                "success",
            }:
                raise IntegrationError(f"one-shot container failed before inspection: {role}")
            time.sleep(0.1)
        raise IntegrationError(f"one-shot container did not become inspectable: {role}")

    def prove_runtime(self) -> None:
        for role in ("secrets-init", "migrate"):
            if role not in self.inspected_oneshots:
                raise IntegrationError(f"one-shot effective security was not inspected: {role}")
            invocation = self.oneshot_invocation(role)
            if role == "migrate":
                if (
                    self.migration_invocation is not None
                    and self.migration_invocation != invocation
                ):
                    raise IntegrationError("migration executed more than once")
                self.migration_invocation = invocation
        for role in (item for item in CONTAINER_ROLES if item not in {"secrets-init", "migrate"}):
            name = f"{self.resources.prefix}-{role}"
            details = parse_single_json_object(
                self.captured(["podman", "container", "inspect", name]),
                f"container inspection for {role}",
            )
            contract = role_spec(role)
            self._validate_effective_container(
                role, details, f"{contract.uid}:{contract.gid}"
            )
        self._validate_network_boundary()
        self._validate_external_behavior()
        self._validate_runtime_probes_and_restart()
        self._validate_long_running_roles()

    def _validate_long_running_roles(self) -> None:
        for role in (
            item for item in CONTAINER_ROLES if item not in {"secrets-init", "migrate"}
        ):
            service = self.command(
                [
                    "systemctl",
                    "--user",
                    "is-active",
                    f"{self.resources.prefix}-{role}.service",
                ],
                check=False,
                capture=True,
            )
            if service.returncode != 0 or (service.stdout or "").strip() != "active":
                raise IntegrationError(f"{role} is not systemd-active after runtime probes")
            inspected = self.command(
                [
                    "podman",
                    "container",
                    "inspect",
                    f"{self.resources.prefix}-{role}",
                ],
                check=False,
                capture=True,
            )
            if inspected.returncode != 0:
                raise IntegrationError(f"unable to verify final container state for {role}")
            details = parse_single_json_object(
                inspected.stdout or "", f"final container inspection for {role}"
            )
            if nested(details, "State", "Running") is not True:
                raise IntegrationError(f"{role} container is not running after runtime probes")

    def _validate_effective_container(
        self, role: str, details: Mapping, expected_user: str | None = None
    ) -> None:
        contract = role_spec(role)
        allowed = frozenset({"CHOWN", "FOWNER"}) if role == "secrets-init" else frozenset()
        validate_container_environment(details)
        execution = role_execution_spec(role, self.failure_case)
        if execution is not None:
            validate_container_execution(details, execution)
        validate_container_security(
            details,
            self.apparmor_available,
            allowed,
            self._expected_mounts(role),
            self._expected_tmpfs(role),
            (contract.uid, contract.gid),
        )
        expected_health = (
            GATEWAY_HEALTH_FAILURE_SPEC
            if role == "gateway" and self.failure_case == "health"
            else contract.health
        )
        if expected_health is not None:
            validate_container_health(details, expected_health)
        user = str(nested(details, "Config", "User"))
        if user != (expected_user or f"{contract.uid}:{contract.gid}"):
            raise IntegrationError(f"unexpected container identity for {role}")
        labels = nested(details, "Config", "Labels")
        if (
            labels.get("org.secpal.integration") != "true"
            or labels.get("org.secpal.integration.instance") != self.instance
            or labels.get("org.secpal.role") != role
        ):
            raise IntegrationError(f"unexpected ownership labels for {role}")
        observed_networks = set(
            (nested(details, "NetworkSettings", "Networks") or {}).keys()
        )
        if observed_networks != self._expected_networks(role):
            raise IntegrationError(f"network isolation mismatch for {role}")
        bindings = (details.get("HostConfig") or {}).get("PortBindings") or {}
        validate_port_publication(role, bindings, self.port)

    def _expected_networks(self, role: str) -> set[str]:
        # Podman inspect preserves disabled networking as the special "none"
        # entry; only named Quadlet networks receive the instance prefix.
        return {
            "none" if name == "none" else f"{self.resources.prefix}-{name}"
            for name in role_spec(role).networks
        }

    def _expected_mounts(self, role: str) -> dict[str, tuple[str, str, bool]]:
        prefix = self.resources.prefix
        asset = lambda name: os.fspath(self.assets / name)
        api_mounts = {
            "/run/secpal/container-entrypoint.sh": (
                "bind",
                asset("container-entrypoint.sh"),
                False,
            ),
            "/run/secpal/phase-b-runtime-probe.php": (
                "bind",
                asset("phase-b-runtime-probe.php"),
                False,
            ),
            "/run/secpal-secrets": ("volume", f"{prefix}-secrets", False),
            "/app/storage/app/private": (
                "volume",
                f"{prefix}-private-storage",
                True,
            ),
        }
        if role in {"api", "worker-general", "worker-hash-chain", "scheduler"}:
            return api_mounts
        if role == "migrate":
            return {
                **api_mounts,
                "/run/secpal/quadlet-oneshot-entrypoint.sh": (
                    "bind",
                    asset("quadlet-oneshot-entrypoint.sh"),
                    False,
                ),
            }
        if role == "secrets-init":
            return {
                "/run/secpal/init-local-secrets.sh": (
                    "bind",
                    asset("init-local-secrets.sh"),
                    False,
                ),
                "/run/secpal/quadlet-oneshot-entrypoint.sh": (
                    "bind",
                    asset("quadlet-oneshot-entrypoint.sh"),
                    False,
                ),
                "/run/secpal-secrets": ("volume", f"{prefix}-secrets", True),
                "/var/lib/postgresql/data": ("volume", f"{prefix}-postgres", True),
                "/mnt/secpal-private-storage": (
                    "volume",
                    f"{prefix}-private-storage",
                    True,
                ),
            }
        if role == "postgres":
            return {
                "/run/secpal-secrets": ("volume", f"{prefix}-secrets", False),
                "/var/lib/postgresql/data": ("volume", f"{prefix}-postgres", True),
            }
        if role == "valkey":
            return {
                "/run/secpal/valkey-entrypoint.sh": (
                    "bind",
                    asset("valkey-entrypoint.sh"),
                    False,
                ),
                "/run/secpal-secrets": ("volume", f"{prefix}-secrets", False),
            }
        if role == "gateway":
            return {
                "/etc/caddy/Caddyfile": ("bind", asset("Caddyfile"), False),
            }
        if role == "frontend":
            return {}
        raise IntegrationError(f"missing reviewed mount contract for role: {role}")

    def _expected_tmpfs(self, role: str) -> Mapping[str, TmpfsSpec]:
        return role_spec(role).tmpfs

    def oneshot_invocation(self, role: str) -> tuple[str, str]:
        properties = self.captured(
            [
                "systemctl",
                "--user",
                "show",
                f"{self.resources.prefix}-{role}.service",
                *(f"--property={name}" for name in ONESHOT_SYSTEMD_PROPERTIES),
            ]
        )
        return validate_oneshot_state(properties)

    def _validate_network_boundary(self) -> None:
        for network in INTERNAL_NETWORKS:
            name = f"{self.resources.prefix}-{network}"
            internal = self.captured(
                [
                    "podman",
                    "network",
                    "inspect",
                    "--format",
                    "{{.Internal}}",
                    name,
                ]
            )
            if internal != "true":
                raise IntegrationError(f"network is not internal: {name}")
        resolver = self.command(
            [
                "podman",
                "exec",
                f"{self.resources.prefix}-frontend",
                "/bin/sh",
                "-c",
                "command -v getent >/dev/null 2>&1",
            ],
            check=False,
            capture=True,
        )
        if resolver.returncode != 0:
            raise IntegrationError("frontend DNS isolation probe is unavailable")
        for forbidden in ("postgres", "valkey"):
            probe = self.command(
                [
                    "podman",
                    "exec",
                    f"{self.resources.prefix}-frontend",
                    "/bin/sh",
                    "-c",
                    f"getent hosts {forbidden} >/dev/null 2>&1",
                ],
                check=False,
                capture=True,
            )
            validate_dns_isolation_result(probe.returncode, forbidden)

    def curl(
        self,
        origin: str,
        path: str,
        *extra: str,
        check: bool = True,
        timeout_seconds: int = 10,
        allow_http_error: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 10:
            raise IntegrationError("curl transfer timeout is outside the closed contract")
        if type(allow_http_error) is not bool:
            raise IntegrationError("curl HTTP-error policy is outside the closed contract")
        host = "app.secpal.example.invalid" if origin == "app" else "api.secpal.example.invalid"
        failure_option = "--fail-with-body" if allow_http_error else "--fail"
        result = self.command(
            [
                "curl",
                failure_option,
                "--silent",
                "--show-error",
                "--max-time",
                str(timeout_seconds),
                "--insecure",
                "--noproxy",
                host,
                "--resolve",
                f"{host}:{self.port}:127.0.0.1",
                *extra,
                f"https://{host}:{self.port}{path}",
            ],
            capture=True,
            check=False if allow_http_error else check,
        )
        if allow_http_error and result.returncode not in {0, 22}:
            raise IntegrationError("curl HTTP probe had a transport failure")
        return result

    def browser_environment(self) -> dict[str, str]:
        if self.port is None:
            raise IntegrationError("integration port was not selected before browser testing")
        environment = dict(os.environ)
        environment.pop("PLAYWRIGHT_LAST_RUN_OUTPUT_FILE", None)
        environment.update(
            {
                "APP_ORIGIN": f"https://app.secpal.example.invalid:{self.port}",
                "API_ORIGIN": f"https://api.secpal.example.invalid:{self.port}",
                "SECPAL_INTEGRATION_INSTANCE": self.instance,
            }
        )
        return environment

    def _validate_external_behavior(self) -> None:
        deadline = time.monotonic() + 90
        api = frontend = ""
        while time.monotonic() < deadline:
            api_result = self.curl(
                "api",
                "/health/live",
                check=False,
                timeout_seconds=transfer_timeout_seconds(
                    deadline, time.monotonic()
                ),
            )
            api = api_result.stdout or ""
            if time.monotonic() >= deadline:
                break
            frontend_result = self.curl(
                "app",
                "/health/live",
                check=False,
                timeout_seconds=transfer_timeout_seconds(
                    deadline, time.monotonic()
                ),
            )
            frontend = frontend_result.stdout or ""
            if api_result.returncode == 0 and frontend_result.returncode == 0:
                break
            time.sleep(1)
        if '"status":"alive"' not in api or not frontend:
            raise IntegrationError("real API/frontend health evidence did not become ready")
        api_root_result = self.curl(
            "api",
            "/",
            "--header",
            "Accept: application/json",
            allow_http_error=True,
        )
        api_root = api_root_result.stdout or ""
        validate_api_origin_root(api_root)
        page = self.curl("app", "/").stdout or ""
        runtime_config = self.curl("app", "/runtime-config.js").stdout or ""
        if "<!doctype html" not in page.lower() or f'https://api.secpal.example.invalid:{self.port}' not in runtime_config:
            raise IntegrationError("frontend origin or runtime API configuration is invalid")
        app_origin = f"https://app.secpal.example.invalid:{self.port}"
        cors = self.curl(
            "api",
            "/v1/auth/login",
            "--dump-header",
            "-",
            "--output",
            "/dev/null",
            "--request",
            "OPTIONS",
            "--header",
            f"Origin: {app_origin}",
            "--header",
            "Access-Control-Request-Method: POST",
            "--header",
            "Access-Control-Request-Headers: Content-Type,X-XSRF-TOKEN",
        ).stdout or ""
        lowered = cors.replace("\r", "").lower()
        if (
            f"access-control-allow-origin: {app_origin}".lower() not in lowered
            or "access-control-allow-credentials: true" not in lowered
            or "access-control-allow-origin: *" in lowered
        ):
            raise IntegrationError("credentialed CORS did not preserve the exact frontend origin")
        foreign_result = self.curl(
            "api",
            "/v1/auth/login",
            "--dump-header",
            "-",
            "--output",
            "/dev/null",
            "--request",
            "OPTIONS",
            "--header",
            "Origin: https://foreign.example.org",
            "--header",
            "Access-Control-Request-Method: POST",
            allow_http_error=True,
        )
        foreign = foreign_result.stdout or ""
        if "access-control-allow-credentials: true" in foreign.lower():
            raise IntegrationError("a foreign origin received credentialed CORS approval")
        for path in ("/v1/quadlet-not-an-api-route", "/sanctum/csrf-cookie", "/health/ready"):
            status = self.curl(
                "app",
                path,
                "--output",
                "/dev/null",
                "--write-out",
                "%{http_code}",
                allow_http_error=True,
            )
            if (status.stdout or "").strip() != "404":
                raise IntegrationError(f"frontend origin exposed forbidden route {path}")
        self.command(
            ["npm", "run", "test:integration:browser"],
            environment=self.browser_environment(),
            cwd=self.root,
        )

    def podman_exec(self, role: str, *arguments: str, capture: bool = False) -> subprocess.CompletedProcess[str]:
        return self.command(
            ["podman", "exec", f"{self.resources.prefix}-{role}", *arguments],
            capture=capture,
        )

    def restart_application(self) -> None:
        # A normal restart stop-job propagates through the target's fail-closed
        # Requires graph. Dependencies were already inspected and must neither
        # be stopped nor re-run for this single-role parity probe.
        self.command(
            [
                "systemctl",
                "--user",
                "restart",
                "--job-mode=ignore-dependencies",
                f"{self.resources.prefix}-api.service",
            ]
        )

    def _validate_runtime_probes_and_restart(self) -> None:
        probes = runtime_probe_contract(self.instance)
        probe = "/run/secpal/phase-b-runtime-probe.php"
        cache_key = str(probes["cache_key"])
        cache_value = str(probes["cache_value"])
        entrypoint = ["/bin/bash", "/run/secpal/container-entrypoint.sh", "php", probe]
        self.podman_exec("api", *entrypoint, "cache-put", cache_key, cache_value)
        observed = self.podman_exec("api", *entrypoint, "cache-get", cache_key, capture=True).stdout
        if (observed or "").strip() != cache_value:
            raise IntegrationError("Valkey cache round trip failed")
        for role in ("worker-general", "worker-hash-chain"):
            queue_key, queue = probes[role]
            hostname = (self.podman_exec(role, "hostname", capture=True).stdout or "").strip()
            self.podman_exec("api", *entrypoint, "queue-dispatch", queue_key, queue)
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                value = self.command(
                    [
                        "podman",
                        "exec",
                        f"{self.resources.prefix}-api",
                        *entrypoint,
                        "cache-get",
                        queue_key,
                    ],
                    capture=True,
                    check=False,
                )
                if value.returncode == 0 and (value.stdout or "").strip() == hostname:
                    break
                time.sleep(1)
            else:
                raise IntegrationError(f"{role} did not process its isolated queue probe")
            self.podman_exec("api", *entrypoint, "cache-forget", queue_key)
        self.podman_exec("api", *entrypoint, "cache-forget", cache_key)
        self._validate_private_storage_and_restart()

    def _validate_private_storage_and_restart(self) -> None:
        storage_name = f"quadlet-storage-{self.instance}"
        storage_path = f"/app/storage/app/private/{storage_name}"
        self.podman_exec(
            "api",
            "/bin/sh",
            "-eu",
            "-c",
            f'umask 027; printf "%s" "$2" >"$1"; chmod {PRIVATE_STORAGE_MODE:04o} "$1"',
            "sh",
            storage_path,
            storage_name,
        )
        observed_storage = self.podman_exec("worker-general", "cat", storage_path, capture=True).stdout
        if (observed_storage or "").strip() != storage_name:
            raise IntegrationError("private-storage fixture is not shared")
        metadata = self.podman_exec(
            "worker-hash-chain",
            "stat",
            "-c",
            "%u:%g:%a",
            storage_path,
            capture=True,
        ).stdout
        api = role_spec("api")
        expected_metadata = f"{api.uid}:{api.gid}:{PRIVATE_STORAGE_MODE:o}"
        if (metadata or "").strip() != expected_metadata:
            raise IntegrationError("private-storage fixture has unexpected metadata")
        if self.migration_invocation is None:
            raise IntegrationError("migration invocation identity was not recorded")
        self.restart_application()
        if self.oneshot_invocation("migrate") != self.migration_invocation:
            raise IntegrationError("application restart executed migration again")
        if (self.podman_exec("api", "cat", storage_path, capture=True).stdout or "").strip() != storage_name:
            raise IntegrationError("private-storage fixture did not survive application restart")
        self.podman_exec("api", "rm", "-f", "--", storage_path)

    def collect_resource_evidence(self) -> None:
        observations: dict[str, object] = {"instance": self.instance}
        running_containers = tuple(
            name
            for role, name in zip(CONTAINER_ROLES, self.resources.containers, strict=True)
            if role not in {"secrets-init", "migrate"}
        )
        stats = self.command(
            ["podman", "stats", "--no-stream", "--format", "json", *running_containers],
            capture=True,
            check=False,
        )
        if stats.returncode == 0:
            try:
                observations["container_stats"] = json.loads(stats.stdout or "[]")
            except json.JSONDecodeError:
                observations["container_stats"] = "unavailable"
        systemd_resources: dict[str, dict[str, int]] = {}
        for role in (item for item in CONTAINER_ROLES if item not in {"secrets-init", "migrate"}):
            result = self.command(
                [
                    "systemctl",
                    "--user",
                    "show",
                    f"{self.resources.prefix}-{role}.service",
                    "--property=CPUUsageNSec",
                    "--property=MemoryCurrent",
                    "--property=MemoryPeak",
                ],
                capture=True,
                check=False,
            )
            if result.returncode == 0:
                values = parse_systemd_resource_properties(result.stdout or "")
                if values:
                    systemd_resources[role] = values
        observations["systemd_user_resources"] = systemd_resources
        storage = self.command(
            ["podman", "system", "df", "--format", "json"],
            capture=True,
            check=False,
        )
        if storage.returncode == 0:
            try:
                observations["podman_storage"] = json.loads(storage.stdout or "[]")
            except json.JSONDecodeError:
                observations["podman_storage"] = "unavailable"
        observations["fixture_bytes"] = directory_size(self.fixture_root)
        volume_sizes: dict[str, int | str] = {}
        for name in self.resources.volumes:
            label = name.removeprefix(f"{self.resources.prefix}-")
            result = self.command(
                ["podman", "volume", "inspect", name, "--format", "{{.Mountpoint}}"],
                capture=True,
                check=False,
            )
            mountpoint = Path((result.stdout or "").strip())
            if result.returncode == 0 and mountpoint.is_absolute() and mountpoint.is_dir():
                size = self.command(
                    [
                        "podman",
                        "unshare",
                        "du",
                        "--summarize",
                        "--bytes",
                        "--",
                        os.fspath(mountpoint),
                    ],
                    capture=True,
                    check=False,
                )
                parsed = parse_du_size(size.stdout or "") if size.returncode == 0 else None
                volume_sizes[label] = (
                    parsed if parsed is not None else "unavailable"
                )
            else:
                volume_sizes[label] = "unavailable"
        observations["volume_bytes"] = volume_sizes
        image_sizes = {}
        for label, image in (("api", API_IMAGE), ("frontend", FRONTEND_IMAGE), ("postgres", POSTGRES_IMAGE), ("valkey", VALKEY_IMAGE)):
            result = self.command(["podman", "image", "inspect", image, "--format", "{{.Size}}"], capture=True, check=False)
            if result.returncode == 0 and (result.stdout or "").strip().isdigit():
                image_sizes[label] = int((result.stdout or "").strip())
        observations["image_bytes"] = image_sizes
        evidence = self.fixture_root / "resource-observations.json"
        evidence.write_text(json.dumps(observations, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        evidence.chmod(0o600)
        print("Resource observations: " + json.dumps(observations, sort_keys=True))

    def cleanup(self) -> None:
        if self.cleaned:
            return
        self.cleanup_active = True
        try:
            reap = getattr(self.runner, "reap_active", None)
            if reap is not None:
                reap()
            errors: list[str] = []
            if self.runtime_admitted:
                try:
                    cleanup_resources(
                        self.runner, self.resources, cloud_mode=self.cloud_mode
                    )
                except Exception:
                    errors.append("resource cleanup failed")
                try:
                    errors.extend(self._owned_resource_errors())
                except Exception:
                    errors.append("owned-resource verification failed")
                try:
                    self._verify_unrelated_resources(errors)
                except Exception:
                    errors.append("unrelated-resource verification failed")
            if self.fixture_root.exists():
                try:
                    shutil.rmtree(self.fixture_root)
                except OSError:
                    errors.append("fixture root could not be removed")
            if self.cloud_mode and CLOUD_FIXTURE_BASE.exists():
                try:
                    if not any(CLOUD_FIXTURE_BASE.iterdir()):
                        CLOUD_FIXTURE_BASE.rmdir()
                except OSError:
                    errors.append("cloud fixture parent could not be removed")
            if errors:
                raise IntegrationError("incomplete exact cleanup: " + "; ".join(errors))
            self.cleaned = True
        finally:
            self.cleanup_active = False

    def _owned_resource_errors(self) -> list[str]:
        errors: list[str] = []
        for name in self.resources.containers:
            result = self.command(["podman", "container", "exists", name], check=False)
            if result.returncode == 0:
                errors.append(f"container remained: {name}")
            elif result.returncode != 1:
                errors.append(f"unable to verify container absence: {name}")
        for kind, names in (("network", self.resources.networks), ("volume", self.resources.volumes)):
            for name in names:
                result = self.command(["podman", kind, "exists", name], check=False)
                if result.returncode == 0:
                    errors.append(f"{kind} remained: {name}")
                elif result.returncode != 1:
                    errors.append(f"unable to verify {kind} absence: {name}")
        image = self.command(
            ["podman", "image", "exists", self.resources.gateway_image],
            check=False,
        )
        if image.returncode == 0:
            errors.append(f"gateway image remained: {self.resources.gateway_image}")
        elif image.returncode != 1:
            errors.append(
                f"unable to verify gateway image absence: {self.resources.gateway_image}"
            )
        for path in self.resources.unit_files:
            if path.exists() or path.is_symlink():
                errors.append(f"active unit remained: {path.name}")
        if self.resources.systemd_target_file.exists() or self.resources.systemd_target_file.is_symlink():
            errors.append(f"active systemd target remained: {self.resources.target}")
        units = [("target", self.resources.target)]
        units.extend(
            ("generated service", service)
            for service in generated_service_names(self.resources)
        )
        for description, unit in units:
            result = self.command(
                [
                    "systemctl",
                    "--user",
                    "show",
                    unit,
                    "--property=LoadState",
                    "--property=ActiveState",
                ],
                capture=True,
                check=False,
            )
            if result.returncode != 0:
                errors.append(f"unable to verify {description} unload state: {unit}")
                continue
            try:
                validate_removed_systemd_unit_state(result.stdout or "")
            except IntegrationError:
                errors.append(f"{description} remained loaded or active: {unit}")
        return errors

    def _verify_unrelated_resources(self, errors: list[str]) -> None:
        if not self.preexisting_resources:
            return
        current = {
            "containers": set(self._podman_names(["podman", "ps", "--all", "--format", "{{.Names}}"])),
            "networks": set(self._podman_names(["podman", "network", "ls", "--format", "{{.Name}}"])),
            "volumes": set(self._podman_names(["podman", "volume", "ls", "--format", "{{.Name}}"])),
        }
        for kind, before in self.preexisting_resources.items():
            missing = before - current[kind]
            if missing:
                errors.append(f"unrelated {kind} were removed: {','.join(sorted(missing))}")


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o7777


def validate_active_root(path: Path) -> None:
    try:
        validate_trusted_directory(path, "active Quadlet path")
    except IntegrationError as error:
        raise IntegrationError("active Quadlet root is not a trusted real directory") from error


def validate_active_quadlet_inputs(path: Path) -> None:
    def raise_walk_error(error: OSError) -> None:
        raise error

    try:
        for root, directories, files in os.walk(
            path, topdown=True, followlinks=False, onerror=raise_walk_error
        ):
            root_path = Path(root)
            for name in directories + files:
                metadata = (root_path / name).lstat()
                expected_directory = name in directories
                expected_type = (
                    stat.S_ISDIR(metadata.st_mode)
                    if expected_directory
                    else stat.S_ISREG(metadata.st_mode)
                )
                if (
                    not expected_type
                    or metadata.st_uid != 0
                    or metadata.st_gid != 0
                    or metadata.st_mode & 0o022
                ):
                    raise IntegrationError(
                        "active Quadlet input is writable, non-root-owned, or not a regular path"
                    )
    except IntegrationError:
        raise
    except OSError as error:
        raise IntegrationError("active Quadlet inputs could not be inspected safely") from error


def directory_size(path: Path) -> int:
    total = 0
    def raise_walk_error(error: OSError) -> None:
        raise error

    for root, directories, files in os.walk(path, topdown=True, onerror=raise_walk_error):
        root_path = Path(root)
        directories[:] = [
            name for name in directories if not (root_path / name).is_symlink()
        ]
        for name in files:
            entry = root_path / name
            metadata = entry.lstat()
            if stat.S_ISREG(metadata.st_mode):
                total += metadata.st_size
    return total


def is_integration_resource_name(kind: str, name: str) -> bool:
    suffixes = {
        "container": CONTAINER_ROLES,
        "network": INTERNAL_NETWORKS,
        "volume": VOLUME_NAMES,
    }.get(kind)
    if suffixes is None or not name.startswith("secpal-int-"):
        return False
    for suffix in suffixes:
        marker = f"-{suffix}"
        if not name.endswith(marker):
            continue
        instance = name[len("secpal-int-") : -len(marker)]
        if INSTANCE_PATTERN.fullmatch(instance):
            return True
    return False


def generated_service_names(resources: Resources) -> list[str]:
    services = [f"{resources.prefix}-{role}.service" for role in CONTAINER_ROLES]
    services.extend(
        f"{resources.prefix}-{name}-network.service" for name in INTERNAL_NETWORKS
    )
    services.extend(f"{resources.prefix}-{name}-volume.service" for name in VOLUME_NAMES)
    return services


def allocate_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def parse_arguments(argv: Sequence[str] | None = None):
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--instance")
    parser.add_argument("--port", type=int)
    parser.add_argument("--fixture-root", type=Path)
    parser.add_argument("--failure-case", choices=("migration", "dependency", "health"))
    parser.add_argument("--cloud-phase", choices=("prepare", "cleanup"))
    arguments = parser.parse_args(argv)
    if arguments.cloud_phase is not None and any(
        value is not None
        for value in (
            arguments.instance,
            arguments.port,
            arguments.fixture_root,
            arguments.failure_case,
        )
    ):
        parser.error("cloud phases accept no runtime override arguments")
    return arguments


def prepare_cloud_fixture_directory(fixture_root: Path) -> None:
    if fixture_root.parent != CLOUD_FIXTURE_BASE:
        raise IntegrationError("cloud fixture root is outside the fixed base")
    try:
        if (
            CLOUD_FIXTURE_BASE.resolve() != CLOUD_FIXTURE_BASE
            or fixture_root.resolve() != fixture_root
        ):
            raise IntegrationError(
                "cloud fixture path is stale or has unsafe metadata"
            )
    except OSError as error:
        raise IntegrationError(
            "cloud fixture path is stale or has unsafe metadata"
        ) from error
    if not CLOUD_FIXTURE_BASE.exists():
        CLOUD_FIXTURE_BASE.mkdir(mode=0o700)
    parent_metadata = CLOUD_FIXTURE_BASE.lstat()
    if (
        not stat.S_ISDIR(parent_metadata.st_mode)
        or CLOUD_FIXTURE_BASE.is_symlink()
        or parent_metadata.st_uid != os.getuid()
        or parent_metadata.st_gid != os.getgid()
        or stat.S_IMODE(parent_metadata.st_mode) != 0o700
        or fixture_root.exists()
        or fixture_root.is_symlink()
    ):
        raise IntegrationError("cloud fixture path is stale or has unsafe metadata")
    fixture_root.mkdir(mode=0o700)


def main() -> int:
    arguments = parse_arguments()
    root = Path(__file__).resolve().parents[1]
    if arguments.cloud_phase is not None:
        instance = os.environ.get("SECPAL_FIXTURE_INSTANCE", "")
        try:
            fixture_root = cloud_fixture_root(instance)
            if arguments.cloud_phase == "prepare":
                prepare_cloud_fixture_directory(fixture_root)
            port = cloud_fixture_port(instance)
        except (IntegrationError, OSError) as error:
            print(f"ERROR: {error}", file=sys.stderr)
            return 1
        lifecycle = IntegrationLifecycle(
            root=root,
            instance=instance,
            port=port,
            fixture_root=fixture_root,
            output=fixture_root / "quadlets",
            cloud_mode=True,
        )
        for signal_number in HANDLED_SIGNALS:
            signal.signal(
                signal_number,
                lambda _signum, _frame, number=signal_number: handle_signal(
                    lifecycle, number
                ),
            )
        try:
            if arguments.cloud_phase == "prepare":
                execute_cloud_prepare(lifecycle)
            else:
                execute_cloud_cleanup(lifecycle)
        except IntegrationInterrupted as interruption:
            return 128 + interruption.signal_number
        except IntegrationError as error:
            print(f"ERROR: {error}", file=sys.stderr)
            return 1
        if lifecycle.signal_number is not None:
            return 128 + lifecycle.signal_number
        print(f"Cloud Quadlet fixture {arguments.cloud_phase} passed.")
        return 0
    instance = (
        secrets.token_hex(6) if arguments.instance is None else arguments.instance
    )
    if not INSTANCE_PATTERN.fullmatch(instance):
        print("ERROR: invalid integration instance identifier.", file=sys.stderr)
        return 1
    port = arguments.port
    if port is not None and not 1024 <= port <= 65535:
        print("ERROR: integration port must be from 1024 through 65535.", file=sys.stderr)
        return 1
    if arguments.fixture_root is None:
        fixture_root = Path(tempfile.mkdtemp(prefix="secpal-quadlet."))
        if (
            not SAFE_PATH_PATTERN.fullmatch(os.fspath(fixture_root))
            or not fixture_root.is_absolute()
        ):
            try:
                shutil.rmtree(fixture_root)
            except OSError:
                print(
                    "ERROR: unable to remove invalid generated fixture root.",
                    file=sys.stderr,
                )
                return 1
            print(
                "ERROR: fixture root must be a new safe ASCII path without whitespace or Quadlet delimiters.",
                file=sys.stderr,
            )
            return 1
        fixture_root.chmod(0o700)
    else:
        fixture_root = arguments.fixture_root
        if (
            not SAFE_PATH_PATTERN.fullmatch(os.fspath(fixture_root))
            or not fixture_root.is_absolute()
            or fixture_root.exists()
        ):
            print(
                "ERROR: fixture root must be a new safe ASCII path without whitespace or Quadlet delimiters.",
                file=sys.stderr,
            )
            return 1
        try:
            fixture_root.mkdir(mode=0o700, parents=False)
        except OSError:
            print("ERROR: unable to create private fixture root.", file=sys.stderr)
            return 1
    output = fixture_root / "quadlets"
    lifecycle = IntegrationLifecycle(
        root=root,
        instance=instance,
        port=port,
        fixture_root=fixture_root,
        output=output,
        failure_case=arguments.failure_case,
    )
    for signal_number in HANDLED_SIGNALS:
        signal.signal(signal_number, lambda _signum, _frame, number=signal_number: handle_signal(lifecycle, number))
    try:
        if arguments.failure_case is None:
            execute_lifecycle(lifecycle)
        else:
            execute_expected_failure_lifecycle(lifecycle)
    except IntegrationInterrupted as interruption:
        return 128 + interruption.signal_number
    except IntegrationError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    if lifecycle.signal_number is not None:
        return 128 + lifecycle.signal_number
    if arguments.failure_case is None:
        print("Rootless Podman/Quadlet integration passed.")
    else:
        print(f"Rootless Podman/Quadlet {arguments.failure_case} failure evidence passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
