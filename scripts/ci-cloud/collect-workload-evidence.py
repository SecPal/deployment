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
USER_ENVIRONMENT_GENERATOR_ROOTS = tuple(
    Path(root)
    for root in (
        "/run/systemd/user-environment-generators",
        "/etc/systemd/user-environment-generators",
        "/usr/local/lib/systemd/user-environment-generators",
        "/usr/lib/systemd/user-environment-generators",
    )
)
TRUSTED_USER_ENVIRONMENT_GENERATOR_PATH = (
    USER_ENVIRONMENT_GENERATOR_ROOTS[1]
    / "30-systemd-environment-d-generator"
)
TRUSTED_USER_ENVIRONMENT_GENERATOR = b"""#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

[[ "$(/usr/bin/id -u)" == 20000 ]] || exit 0
printf '%s\\n' \\
  'CONTAINERS_CONF=/dev/null' \\
  'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/20000/bus' \\
  'HOME=/home/secpal-ci' \\
  'LANG=C.UTF-8' \\
  'LC_ALL=C.UTF-8' \\
  'LOGNAME=secpal-ci' \\
  'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' \\
  'QUADLET_UNIT_DIRS=/etc/containers/systemd/users/20000' \\
  'SHELL=/bin/bash' \\
  'USER=secpal-ci' \\
  'XDG_RUNTIME_DIR=/run/user/20000'
"""
PODMAN_EXECUTABLE = Path("/usr/bin/podman")
PODMAN_NETWORK_ONLINE_UNIT = "podman-user-wait-network-online.service"
PODMAN_NETWORK_ONLINE_FRAGMENT = (
    Path("/usr/lib/systemd/user") / PODMAN_NETWORK_ONLINE_UNIT
)
TRUSTED_USER_SOCKET_UNITS = {
    name: (
        frozenset(
            {
                Path("/usr/lib/systemd/user") / name,
                Path("/lib/systemd/user") / name,
            }
        ),
        service,
    )
    for name, service in {
        "dbus.socket": "dbus.service",
        "dirmngr.socket": "dirmngr.service",
        "gpg-agent-browser.socket": "gpg-agent.service",
        "gpg-agent-extra.socket": "gpg-agent.service",
        "gpg-agent-ssh.socket": "gpg-agent.service",
        "gpg-agent.socket": "gpg-agent.service",
        "keyboxd.socket": "keyboxd.service",
        "ssh-agent.socket": "ssh-agent.service",
    }.items()
}
TRUSTED_USER_SERVICE_UNITS = {
    name: frozenset(
        {
            Path("/usr/lib/systemd/user") / name,
            Path("/lib/systemd/user") / name,
        }
    )
    for name in {
        "dbus.service",
        "dirmngr.service",
        "gpg-agent.service",
        "keyboxd.service",
        "ssh-agent.service",
    }
}
TRUSTED_USER_UNIT_PACKAGES = {
    "dbus.socket": "dbus-user-session",
    "dbus.service": "dbus-user-session",
    "dirmngr.socket": "dirmngr",
    "dirmngr.service": "dirmngr",
    "gpg-agent-browser.socket": "gpg-agent",
    "gpg-agent-extra.socket": "gpg-agent",
    "gpg-agent-ssh.socket": "gpg-agent",
    "gpg-agent.socket": "gpg-agent",
    "gpg-agent.service": "gpg-agent",
    # Debian 13 (trixie) ships Keyboxd and both user units in binary package gpg.
    "keyboxd.socket": "gpg",
    "keyboxd.service": "gpg",
    "ssh-agent.socket": "openssh-client",
    "ssh-agent.service": "openssh-client",
}
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
ROLE_PREDECESSORS = {
    "postgres": ("secrets-init",),
    "valkey": ("secrets-init",),
    "migrate": ("postgres", "valkey"),
    "api": ("migrate",),
    "worker-general": ("migrate",),
    "worker-hash-chain": ("migrate",),
    "scheduler": ("migrate",),
    "gateway": ("api", "frontend"),
}
TARGET_REQUIRED_ROLES = (
    "gateway", "worker-general", "worker-hash-chain", "scheduler",
)
AUXILIARY_EXEC_PROPERTIES = frozenset(
    {
        "ExecCondition",
        "ExecStartPre",
        "ExecStartPost",
        "ExecReload",
        "ExecStop",
        "ExecStopPost",
    }
)
SYSTEMD_OMITTED_EMPTY_SERVICE_PROPERTIES = frozenset(
    {"EnvironmentFiles", *AUXILIARY_EXEC_PROPERTIES}
)
SERVICE_ACTIVATION_PROPERTIES = (
    "FragmentPath",
    "DropInPaths",
    "Environment",
    "EnvironmentFiles",
    "PassEnvironment",
    "UnsetEnvironment",
    "ExecCondition",
    "ExecStartPre",
    "ExecStart",
    "ExecStartPost",
    "ExecReload",
    "ExecStop",
    "ExecStopPost",
    "Requires",
    "After",
)
READY_ROLES = frozenset(ROLES) - {"secrets-init", "migrate"}
HEALTHY_ROLES = frozenset({"postgres", "valkey", "api", "frontend", "gateway"})
# Podman 5.4 formats a non-negative 64-bit rand.Int() with "%x" for this
# suffix: no leading zeroes, at most 16 hex digits, and a 16th digit <= 7.
PODMAN_54_HEALTH_TIMER_SUFFIX = (
    r"(?:0|[1-9a-f][0-9a-f]{0,14}|[1-7][0-9a-f]{15})"
)
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
    "CONTAINERS_CONF=/dev/null",
    "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/20000/bus",
    "HOME=/home/secpal-ci",
    "LANG=C.UTF-8",
    "LC_ALL=C.UTF-8",
    "LOGNAME=secpal-ci",
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    f"QUADLET_UNIT_DIRS={QUADLET_ROOT}",
    "SHELL=/bin/bash",
    "USER=secpal-ci",
    "XDG_RUNTIME_DIR=/run/user/20000",
)
TRUSTED_SERVICE_CONFIG_ENVIRONMENT = {
    "CONTAINERS_CONF": "/dev/null",
    "CONTAINERS_CONF_OVERRIDE": "/dev/null",
    "CONTAINERS_CONF_MODULES": "",
    "PODMAN_USERNS": "",
}
TRUSTED_CONTAINER_SERVICE_ENVIRONMENT_NAMES = frozenset(
    {*TRUSTED_SERVICE_CONFIG_ENVIRONMENT, "PODMAN_SYSTEMD_UNIT"}
)
NORMALIZATION_DIAGNOSTIC_PREFIX = "Trusted Quadlet normalization diagnostic: "
NORMALIZATION_MODES = frozenset({"live", "cleanup"})
NORMALIZATION_STAGES = frozenset(
    {
        "instance-admission",
        "stop-existing-units",
        "manager-environment-read",
        "manager-environment-unset",
        "manager-environment-set",
        "pre-reload-manager-environment-read",
        "pre-reload-manager-environment-admission",
        "user-environment-generator-inventory-read",
        "user-environment-generator-inventory-admission",
        "user-environment-generator-presence-admission",
        "user-environment-generator-file-read",
        "user-environment-generator-file-admission",
        "user-environment-generator-content-admission",
        "user-environment-generator-metadata-admission",
        "daemon-reload",
        "post-reload-manager-environment-read",
        "post-reload-manager-environment-admission",
        "target-unit-admission",
        "generated-unit-admission",
        "target-start",
        "post-activation-manager-environment-read",
        "post-activation-manager-environment-admission",
        "quadlet-search-path-admission",
        "unreported",
    }
)
LEGACY_NORMALIZATION_STAGES = frozenset(
    {
        "manager-environment-admission",
        "post-manager-environment-read",
        "user-environment-generator-admission",
    }
)
NORMALIZATION_EVIDENCE_STAGES = NORMALIZATION_STAGES | LEGACY_NORMALIZATION_STAGES
NORMALIZATION_FAILURE_REASONS = frozenset(
    {"command-exit", "contract-rejected", "unexpected-error"}
)


class NormalizationOutcome(NamedTuple):
    mode: str
    status: int
    stage: str
    failure_reason: str | None
    command_status: int | None

    def __bool__(self) -> bool:
        return self.status == 0

    def document(self) -> dict[str, object]:
        return self._asdict()


class NormalizationAdmissionFailure(NamedTuple):
    stage: str
    failure_reason: str


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
        "CONTAINERS_CONF": "/dev/null",
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


def expected_gateway_port(instance: str) -> int:
    if re.fullmatch(r"[0-9a-f]{12}", instance) is None:
        raise ValueError("fixture instance is outside the closed contract")
    return 20_000 + int(instance[:8], 16) % 40_000


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


def parsed_manager_environment(output: str) -> dict[str, str] | None:
    if len(output.encode("utf-8")) > 16_384:
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


def normalization_failure(
    mode: str,
    stage: str,
    failure_reason: str,
    command_status: int | None = None,
) -> NormalizationOutcome:
    if (
        mode not in NORMALIZATION_MODES
        or stage not in NORMALIZATION_STAGES
        or failure_reason not in NORMALIZATION_FAILURE_REASONS
        or (failure_reason == "command-exit") != (command_status is not None)
        or (
            command_status is not None
            and not 0 < command_status <= 255
        )
    ):
        raise ValueError("normalization diagnostic is outside the closed contract")
    outcome = NormalizationOutcome(
        mode, 1, stage, failure_reason, command_status
    )
    print(
        NORMALIZATION_DIAGNOSTIC_PREFIX
        + json.dumps(
            outcome.document(), ensure_ascii=True, separators=(",", ":")
        ),
        file=sys.stderr,
    )
    return outcome


def normalization_command_failure(
    mode: str, stage: str, status: int, complete: bool
) -> NormalizationOutcome:
    return normalization_failure(
        mode,
        stage,
        "command-exit" if complete and status != 0 else "unexpected-error",
        status if complete and status != 0 else None,
    )


def normalize_quadlet_runtime(
    instance: str, *, activate: bool
) -> NormalizationOutcome:
    mode = "live" if activate else "cleanup"
    if re.fullmatch(r"[0-9a-f]{12}", instance) is None:
        return normalization_failure(
            mode, "instance-admission", "contract-rejected"
        )
    prefix = f"secpal-int-{instance}"
    target = f"{prefix}.target"
    services = [
        f"{prefix}-{logical_name}.service"
        for logical_name in GENERATED_LOGICAL_NAMES
    ]
    if activate:
        loaded_units: list[str] = []
        loaded_service_names: list[str] = []
        for unit in (target, *services):
            state_status, state_output, state_complete = command_result(
                [
                    "systemctl", "--user", "show", unit,
                    "--property=LoadState", "--property=ActiveState",
                ]
            )
            if state_status != 0 or not state_complete:
                return normalization_command_failure(
                    mode, "stop-existing-units", state_status, state_complete
                )
            properties = parsed_manager_environment(state_output)
            if properties == {
                "LoadState": "not-found", "ActiveState": "inactive"
            }:
                continue
            if (
                properties is None
                or set(properties) != {"LoadState", "ActiveState"}
                or properties["LoadState"] != "loaded"
                or properties["ActiveState"] not in {
                    "active", "activating", "deactivating", "failed",
                    "inactive", "reloading",
                }
            ):
                return normalization_failure(
                    mode, "stop-existing-units", "contract-rejected"
                )
            loaded_units.append(unit)
            if unit != target:
                loaded_service_names.append(
                    unit.removeprefix(f"{prefix}-").removesuffix(".service")
                )
        if target in loaded_units and not target_activation_is_trusted(instance):
            return normalization_failure(
                mode, "stop-existing-units", "contract-rejected"
            )
        for logical_name in loaded_service_names:
            if not generated_service_unit_activation_is_trusted(
                instance, logical_name
            ):
                return normalization_failure(
                    mode, "stop-existing-units", "contract-rejected"
                )
        if loaded_units:
            stop_status, _, stop_complete = command_result(
                ["systemctl", "--user", "stop", *loaded_units], timeout=120
            )
            if stop_status != 0 or not stop_complete:
                return normalization_command_failure(
                    mode, "stop-existing-units", stop_status, stop_complete
                )

    def read_manager_environment(
        stage: str,
    ) -> tuple[dict[str, str] | None, NormalizationOutcome | None]:
        environment_status, environment_output, environment_complete = command_result(
            ["systemctl", "--user", "show-environment"]
        )
        if environment_status != 0 or not environment_complete:
            return None, normalization_command_failure(
                mode, stage, environment_status, environment_complete
            )
        environment = parsed_manager_environment(environment_output)
        if environment is None:
            return None, normalization_failure(
                mode, stage, "contract-rejected"
            )
        return environment, None

    def replace_manager_environment(
        environment: dict[str, str],
    ) -> NormalizationOutcome | None:
        names = sorted(environment)
        if names:
            unset_status, _, unset_complete = command_result(
                ["systemctl", "--user", "unset-environment", *names]
            )
            if unset_status != 0 or not unset_complete:
                return normalization_command_failure(
                    mode,
                    "manager-environment-unset",
                    unset_status,
                    unset_complete,
                )
        set_status, _, set_complete = command_result(
            ["systemctl", "--user", "set-environment", *TRUSTED_MANAGER_ENVIRONMENT]
        )
        if set_status != 0 or not set_complete:
            return normalization_command_failure(
                mode, "manager-environment-set", set_status, set_complete
            )
        return None

    existing, environment_failure = read_manager_environment(
        "manager-environment-read"
    )
    if environment_failure is not None:
        return environment_failure
    if existing is None:
        return normalization_failure(
            mode, "manager-environment-read", "unexpected-error"
        )
    generator_failure = trusted_user_environment_generator_admission_failure()
    if generator_failure is not None:
        return normalization_failure(
            mode,
            generator_failure.stage,
            generator_failure.failure_reason,
        )
    environment_failure = replace_manager_environment(existing)
    if environment_failure is not None:
        return environment_failure
    expected = dict(item.split("=", 1) for item in TRUSTED_MANAGER_ENVIRONMENT)
    prepared, environment_failure = read_manager_environment(
        "pre-reload-manager-environment-read"
    )
    if environment_failure is not None:
        return environment_failure
    if prepared is None:
        return normalization_failure(
            mode, "pre-reload-manager-environment-read", "unexpected-error"
        )
    if prepared != expected:
        return normalization_failure(
            mode,
            "pre-reload-manager-environment-admission",
            "contract-rejected",
        )
    reload_status, _, reload_complete = command_result(
        ["systemctl", "--user", "daemon-reload"], timeout=60
    )
    if reload_status != 0 or not reload_complete:
        return normalization_command_failure(
            mode, "daemon-reload", reload_status, reload_complete
        )
    observed, environment_failure = read_manager_environment(
        "post-reload-manager-environment-read"
    )
    if environment_failure is not None:
        return environment_failure
    if observed is None:
        return normalization_failure(
            mode, "post-reload-manager-environment-read", "unexpected-error"
        )
    if observed != expected:
        return normalization_failure(
            mode,
            "post-reload-manager-environment-admission",
            "contract-rejected",
        )
    if activate:
        if not target_activation_is_trusted(instance):
            return normalization_failure(
                mode, "target-unit-admission", "contract-rejected"
            )
        if not generated_service_activation_is_trusted(instance):
            return normalization_failure(
                mode, "generated-unit-admission", "contract-rejected"
            )
        start_status, _, start_complete = command_result(
            ["systemctl", "--user", "start", target], timeout=600
        )
        if start_status != 0 or not start_complete:
            return normalization_command_failure(
                mode, "target-start", start_status, start_complete
            )
        observed, environment_failure = read_manager_environment(
            "post-activation-manager-environment-read"
        )
        if environment_failure is not None:
            return environment_failure
        if observed != expected:
            return normalization_failure(
                mode,
                "post-activation-manager-environment-admission",
                "contract-rejected",
            )
    if quadlet_search_paths() != [str(QUADLET_ROOT)]:
        return normalization_failure(
            mode, "quadlet-search-path-admission", "contract-rejected"
        )
    return NormalizationOutcome(mode, 0, "complete", None, None)


def bounded_regular_file(
    path: Path,
) -> tuple[bytes, os.stat_result] | None:
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
    return content, before


def file_fact(path: Path, name: str) -> dict[str, object] | None:
    observation = bounded_regular_file(path)
    if observation is None:
        return None
    content, metadata = observation
    return {
        "name": name,
        "path": str(path),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": f"0{stat.S_IMODE(metadata.st_mode):03o}",
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def trusted_user_environment_generator_metadata_is_admitted(
    metadata: os.stat_result,
) -> bool:
    return (
        metadata.st_uid == 0
        and metadata.st_gid == 0
        and stat.S_IMODE(metadata.st_mode) == 0o755
    )


def rejected_user_environment_generator_file(
    path: Path,
) -> NormalizationAdmissionFailure:
    try:
        metadata = path.lstat()
    except OSError:
        return NormalizationAdmissionFailure(
            "user-environment-generator-file-read", "unexpected-error"
        )
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > 64 * 1024
    ):
        return NormalizationAdmissionFailure(
            "user-environment-generator-file-admission", "contract-rejected"
        )
    if not trusted_user_environment_generator_metadata_is_admitted(metadata):
        return NormalizationAdmissionFailure(
            "user-environment-generator-metadata-admission",
            "contract-rejected",
        )
    return NormalizationAdmissionFailure(
        "user-environment-generator-file-read", "unexpected-error"
    )


def trusted_user_environment_generator_admission_failure(
) -> NormalizationAdmissionFailure | None:
    generator_name = TRUSTED_USER_ENVIRONMENT_GENERATOR_PATH.name
    vendor_path = USER_ENVIRONMENT_GENERATOR_ROOTS[-1] / generator_name
    allowed_paths = {TRUSTED_USER_ENVIRONMENT_GENERATOR_PATH, vendor_path}
    observed_paths: set[Path] = set()
    for root in USER_ENVIRONMENT_GENERATOR_ROOTS:
        try:
            entries = tuple(root.iterdir())
        except FileNotFoundError:
            continue
        except OSError:
            return NormalizationAdmissionFailure(
                "user-environment-generator-inventory-read", "unexpected-error"
            )
        if len(entries) > 16:
            return NormalizationAdmissionFailure(
                "user-environment-generator-inventory-admission",
                "contract-rejected",
            )
        for path in entries:
            if path not in allowed_paths or path in observed_paths:
                return NormalizationAdmissionFailure(
                    "user-environment-generator-inventory-admission",
                    "contract-rejected",
                )
            observed_paths.add(path)
    if TRUSTED_USER_ENVIRONMENT_GENERATOR_PATH not in observed_paths:
        return NormalizationAdmissionFailure(
            "user-environment-generator-presence-admission",
            "contract-rejected",
        )
    observation = bounded_regular_file(TRUSTED_USER_ENVIRONMENT_GENERATOR_PATH)
    if observation is None:
        return rejected_user_environment_generator_file(
            TRUSTED_USER_ENVIRONMENT_GENERATOR_PATH
        )
    content, metadata = observation
    if content != TRUSTED_USER_ENVIRONMENT_GENERATOR:
        return NormalizationAdmissionFailure(
            "user-environment-generator-content-admission",
            "contract-rejected",
        )
    if not trusted_user_environment_generator_metadata_is_admitted(metadata):
        return NormalizationAdmissionFailure(
            "user-environment-generator-metadata-admission",
            "contract-rejected",
        )
    return None


def trusted_user_environment_generator_is_admitted() -> bool:
    return trusted_user_environment_generator_admission_failure() is None


def quadlet_content_has_no_auxiliary_execution_directives(
    content: object,
) -> bool:
    if (
        not isinstance(content, bytes)
        or len(content) > 64 * 1024
        or b"\x00" in content
    ):
        return False
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return False
    directives = "|".join(sorted(AUXILIARY_EXEC_PROPERTIES))
    return re.search(
        rf"(?m)^[ \t]*(?:{directives})[ \t]*=", text
    ) is None


def quadlet_source_execution_controls_are_trusted(
    instance: str, logical_name: str
) -> bool:
    try:
        source = expected_generated_source(instance, logical_name)
    except ValueError:
        return False
    observation = bounded_regular_file(source)
    return bool(
        observation is not None
        and quadlet_content_has_no_auxiliary_execution_directives(
            observation[0]
        )
    )


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


def service_environment_controls_are_trusted(
    environment_files: object,
    pass_environment: object,
    unset_environment: object,
) -> bool:
    return all(
        isinstance(value, str) and value == ""
        for value in (environment_files, pass_environment, unset_environment)
    )


def exact_systemd_service_properties(
    output: object,
    expected_properties: set[str] | frozenset[str],
) -> dict[str, str] | None:
    if (
        not isinstance(output, str)
        or len(output) > MAX_OUTPUT
        or "\x00" in output
        or not expected_properties
    ):
        return None
    properties: dict[str, str] = {}
    for line in output.splitlines():
        if "=" not in line:
            return None
        name, value = line.split("=", 1)
        if name not in expected_properties or name in properties:
            return None
        properties[name] = value
    missing = expected_properties - properties.keys()
    if not missing <= SYSTEMD_OMITTED_EMPTY_SERVICE_PROPERTIES:
        return None
    for name in missing:
        properties[name] = ""
    return properties


def service_execution_controls_are_trusted(
    properties: object, logical_name: str
) -> bool:
    if (
        not isinstance(properties, dict)
        or set(properties) != AUXILIARY_EXEC_PROPERTIES
        or any(
            not isinstance(value, str) or len(value) > 65_536 or "\x00" in value
            for value in properties.values()
        )
        or any(
            properties[name] != ""
            for name in (
                "ExecCondition", "ExecStartPre", "ExecStartPost", "ExecReload"
            )
        )
    ):
        return False
    if logical_name in ROLES:
        operation = "rm"
        required = True
    elif logical_name in {f"{kind}-network" for kind in NETWORK_KINDS}:
        operation = "network rm"
        required = False
    elif logical_name in {f"{kind}-volume" for kind in VOLUME_KINDS}:
        operation = None
        required = False
    else:
        return False
    return all(
        podman_lifecycle_exec_is_trusted(
            properties[name], operation, required=required
        )
        for name in ("ExecStop", "ExecStopPost")
    )


def podman_lifecycle_exec_is_trusted(
    value: str, operation: str | None, *, required: bool
) -> bool:
    if value == "":
        return not required
    if operation is None:
        return False
    return bool(
        value.count("{ path=") == 1
        and value.count("argv[]=") == 1
        and value.count(" }") == 1
        and re.match(
            r"^\{ path=/usr/bin/podman ; argv\[\]=/usr/bin/podman "
            + re.escape(operation)
            + r"(?: | ;)",
            value,
        )
    )


def direct_podman_exec_start(value: object, logical_name: str) -> bool:
    if logical_name in ROLES:
        operation = "run"
    elif logical_name in {f"{kind}-network" for kind in NETWORK_KINDS}:
        operation = "network create"
    elif logical_name in {f"{kind}-volume" for kind in VOLUME_KINDS}:
        operation = "volume create"
    else:
        return False
    return bool(
        isinstance(value, str)
        and len(value) <= 65_536
        and "\x00" not in value
        and value.count("{ path=") == 1
        and re.match(
            r"^\{ path=/usr/bin/podman ; argv\[\]=/usr/bin/podman "
            + re.escape(operation)
            + r"(?: | ;)",
            value,
        )
    )


def service_runtime_controls_are_trusted(
    properties: object,
    logical_name: str,
    instance: str,
) -> bool:
    if not isinstance(properties, dict):
        return False
    generated_services = {
        f"secpal-int-{instance}-{name}.service"
        for name in GENERATED_LOGICAL_NAMES
    }
    expected_dependencies = expected_generated_service_dependencies(
        instance, logical_name
    )
    requires = (
        set(str(properties.get("Requires", "")).split()) & generated_services
    )
    after = set(str(properties.get("After", "")).split()) & generated_services
    return bool(
        set(properties) == set(SERVICE_ACTIVATION_PROPERTIES)
        and properties.get("FragmentPath")
        == str(
            GENERATOR_ROOT
            / f"secpal-int-{instance}-{logical_name}.service"
        )
        and properties.get("DropInPaths") == ""
        and requires == expected_dependencies
        and after == expected_dependencies
        and service_config_environment_is_trusted(
            properties.get("Environment"), logical_name, instance
        )
        and service_environment_controls_are_trusted(
            properties.get("EnvironmentFiles"),
            properties.get("PassEnvironment"),
            properties.get("UnsetEnvironment"),
        )
        and service_execution_controls_are_trusted(
            {
                name: properties.get(name)
                for name in AUXILIARY_EXEC_PROPERTIES
            },
            logical_name,
        )
        and direct_podman_exec_start(properties.get("ExecStart"), logical_name)
    )


def expected_generated_service_dependencies(
    instance: str,
    logical_name: str,
) -> set[str]:
    if (
        re.fullmatch(r"[0-9a-f]{12}", instance) is None
        or logical_name not in GENERATED_LOGICAL_NAMES
    ):
        return set()
    contract = ROLE_CONTRACTS.get(logical_name)
    if contract is None:
        return set()
    dependencies = set(ROLE_PREDECESSORS.get(logical_name, ()))
    dependencies.update(f"{network}-network" for network in contract.networks)
    dependencies.update(f"{volume[0]}-volume" for volume in contract.volumes)
    return {
        f"secpal-int-{instance}-{dependency}.service"
        for dependency in dependencies
    }


def generated_dependency_companions_are_absent(instance: str) -> bool:
    if re.fullmatch(r"[0-9a-f]{12}", instance) is None:
        return False
    status_code, output, bounded = command_result(
        ["systemctl", "--user", "show", "--property=UnitPath"]
    )
    if (
        status_code != 0
        or not bounded
        or not output.startswith("UnitPath=")
        or "\n" in output
        or len(output) > 65_536
    ):
        return False
    raw_paths = output.removeprefix("UnitPath=")
    path_values = raw_paths.split(" ") if raw_paths else []
    if (
        not path_values
        or len(path_values) > 64
        or " ".join(path_values) != raw_paths
    ):
        return False
    roots: list[Path] = []
    for value in path_values:
        if (
            len(value) > 4_096
            or "\x00" in value
            or re.fullmatch(r"/[A-Za-z0-9._@+/-]*", value) is None
            or os.path.normpath(value) != value
        ):
            return False
        root = Path(value)
        if root in roots:
            return False
        roots.append(root)
    prefix = f"secpal-int-{instance}"
    for root in roots:
        for logical_name in GENERATED_LOGICAL_NAMES:
            service_name = f"{prefix}-{logical_name}.service"
            for suffix in ("wants", "requires"):
                try:
                    (root / f"{service_name}.{suffix}").lstat()
                except FileNotFoundError:
                    continue
                except OSError:
                    return False
                return False
    return True


def podman_network_online_activation_is_trusted() -> bool:
    status_code, output, bounded = command_result(
        [
            "systemctl", "--user", "show", PODMAN_NETWORK_ONLINE_UNIT,
            "--property=FragmentPath", "--property=DropInPaths",
        ]
    )
    properties: dict[str, str] = {}
    for line in output.splitlines():
        if "=" not in line:
            return False
        name, value = line.split("=", 1)
        if name in properties:
            return False
        properties[name] = value
    return bool(
        status_code == 0
        and bounded
        and properties
        == {
            "FragmentPath": str(PODMAN_NETWORK_ONLINE_FRAGMENT),
            "DropInPaths": "",
        }
    )


def generated_service_unit_activation_is_trusted(
    instance: str, logical_name: str
) -> bool:
    if (
        re.fullmatch(r"[0-9a-f]{12}", instance) is None
        or logical_name not in GENERATED_LOGICAL_NAMES
        or not quadlet_source_execution_controls_are_trusted(
            instance, logical_name
        )
    ):
        return False
    status_code, output, bounded = command_result(
        [
            "systemctl", "--user", "show",
            f"secpal-int-{instance}-{logical_name}.service",
            *(f"--property={name}" for name in SERVICE_ACTIVATION_PROPERTIES),
        ]
    )
    properties = exact_systemd_service_properties(
        output, frozenset(SERVICE_ACTIVATION_PROPERTIES)
    )
    return bool(
        status_code == 0
        and bounded
        and properties is not None
        and service_runtime_controls_are_trusted(
            properties, logical_name, instance
        )
    )


def generated_service_activation_is_trusted(instance: str) -> bool:
    if (
        re.fullmatch(r"[0-9a-f]{12}", instance) is None
        or not podman_network_online_activation_is_trusted()
        or not generated_dependency_companions_are_absent(instance)
    ):
        return False
    for logical_name in GENERATED_LOGICAL_NAMES:
        if not generated_service_unit_activation_is_trusted(
            instance, logical_name
        ):
            return False
    return True


def target_activation_is_trusted(instance: str) -> bool:
    if re.fullmatch(r"[0-9a-f]{12}", instance) is None:
        return False
    prefix = f"secpal-int-{instance}"
    target = f"{prefix}.target"
    status_code, output, bounded = command_result(
        [
            "systemctl", "--user", "show", target,
            "--property=FragmentPath", "--property=DropInPaths",
            "--property=Wants", "--property=Requires",
        ]
    )
    properties: dict[str, str] = {}
    for line in output.splitlines():
        if "=" not in line:
            return False
        name, value = line.split("=", 1)
        if name in properties:
            return False
        properties[name] = value
    expected_requires = {
        f"{prefix}-{role}.service" for role in TARGET_REQUIRED_ROLES
    }
    return bool(
        status_code == 0
        and bounded
        and set(properties) == {
            "FragmentPath", "DropInPaths", "Wants", "Requires",
        }
        and properties["FragmentPath"] == str(SYSTEMD_ROOT / target)
        and properties["DropInPaths"] == ""
        and properties["Wants"] == ""
        and set(properties["Requires"].split()) == expected_requires
    )


def generated_service_facts(instance: str) -> tuple[list[dict[str, object]], bool]:
    facts: list[dict[str, object]] = []
    complete = True
    prefix = f"secpal-int-{instance}"
    expected_properties = {
        "FragmentPath", "DropInPaths", "ActiveState", "SubState", "Result",
        "ExecMainStatus", "MainPID", "ControlGroup", "InvocationID",
        "SourcePath", "Environment", "EnvironmentFiles", "PassEnvironment",
        "UnsetEnvironment", "ExecStart", *AUXILIARY_EXEC_PROPERTIES,
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
                "--property=Environment", "--property=EnvironmentFiles",
                "--property=PassEnvironment", "--property=UnsetEnvironment",
                "--property=ExecCondition", "--property=ExecStartPre",
                "--property=ExecStart", "--property=ExecStartPost",
                "--property=ExecReload", "--property=ExecStop",
                "--property=ExecStopPost",
            ]
        )
        properties = exact_systemd_service_properties(
            value, expected_properties
        )
        if properties is None:
            complete = False
            continue
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
        raw_environment = properties.get("Environment", "")
        environment, environment_complete = normalized_service_environment(
            raw_environment
        )
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
            or not environment_complete
            or not quadlet_source_execution_controls_are_trusted(
                instance, logical_name
            )
            or not service_config_environment_is_trusted(
                raw_environment, logical_name, instance
            )
            or not service_environment_controls_are_trusted(
                properties.get("EnvironmentFiles"),
                properties.get("PassEnvironment"),
                properties.get("UnsetEnvironment"),
            )
            or not service_execution_controls_are_trusted(
                {
                    name: properties.get(name)
                    for name in AUXILIARY_EXEC_PROPERTIES
                },
                logical_name,
            )
            or not direct_podman_exec_start(
                properties.get("ExecStart"), logical_name
            )
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
                "environment": environment,
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


def parse_id_map(content: bytes) -> tuple[list[dict[str, int]], bool]:
    if not content or len(content) > 4096:
        return [], False
    try:
        lines = content.decode("ascii").splitlines()
    except UnicodeDecodeError:
        return [], False
    if not 1 <= len(lines) <= 16:
        return [], False
    mappings: list[dict[str, int]] = []
    for line in lines:
        fields = line.split()
        if len(fields) != 3 or any(not field.isdigit() for field in fields):
            return [], False
        container_id, host_id, size = (int(field) for field in fields)
        if (
            size <= 0
            or container_id > 2**32 - 1
            or host_id > 2**32 - 1
            or container_id + size > 2**32
            or host_id + size > 2**32
        ):
            return [], False
        mappings.append(
            {"container_id": container_id, "host_id": host_id, "size": size}
        )
    mappings.sort(key=lambda item: (item["container_id"], item["host_id"]))
    if not id_map_is_bounded(mappings, allow_empty=False):
        return [], False
    return mappings, True


def configured_id_maps(value: object) -> tuple[
    list[dict[str, int]], list[dict[str, int]], bool
]:
    if value is None:
        return [], [], False
    if not isinstance(value, dict) or set(value) != {"UidMap", "GidMap"}:
        return [], [], False
    parsed: list[list[dict[str, int]]] = []
    for field in ("UidMap", "GidMap"):
        items = value[field]
        if not isinstance(items, list) or len(items) > 16 or any(
            not isinstance(item, str)
            or not item
            or len(item) > 64
            for item in items
        ):
            return [], [], False
        if not items:
            parsed.append([])
            continue
        try:
            content = (
                "\n".join(item.replace(":", " ") for item in items) + "\n"
            ).encode("ascii", errors="strict")
        except UnicodeEncodeError:
            return [], [], False
        mapping, complete = parse_id_map(content)
        if not complete:
            return [], [], False
        parsed.append(mapping)
    uid_map, gid_map = parsed
    if bool(uid_map) != bool(gid_map):
        return [], [], False
    return uid_map, gid_map, True


def configured_userns_options(value: object) -> tuple[list[str], bool]:
    if (
        not isinstance(value, list)
        or not 2 <= len(value) <= 256
        or any(
            not isinstance(item, str)
            or not item
            or len(item) > 4096
            or "\x00" in item
            for item in value
        )
        or sum(len(item) for item in value) > 65_536
    ):
        return [], False
    options: list[str] = []
    index = 0
    while index < len(value):
        argument = value[index]
        if argument == "--module" or argument.startswith("--module="):
            return [], False
        if argument == "--userns":
            if (
                index + 1 >= len(value)
                or value[index + 1].startswith("-")
                or len(value[index + 1]) > 256
            ):
                return [], False
            options.append(value[index + 1])
            index += 2
            continue
        if argument.startswith("--userns="):
            option = argument.split("=", 1)[1]
            if not option or len(option) > 256:
                return [], False
            options.append(option)
        index += 1
    return options, len(options) <= 1


def service_environment_assignments(
    value: object,
) -> tuple[dict[str, str], bool]:
    if not isinstance(value, str) or len(value) > 65_536 or "\x00" in value:
        return {}, False
    try:
        assignments = shlex.split(value, posix=True)
    except ValueError:
        return {}, False
    if len(assignments) > 64 or sum(len(item) for item in assignments) > 16_384:
        return {}, False
    parsed: dict[str, str] = {}
    for assignment in assignments:
        if (
            len(assignment) > 1024
            or "=" not in assignment
            or "\x00" in assignment
        ):
            return {}, False
        name, item = assignment.split("=", 1)
        if (
            re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", name) is None
            or name in parsed
            or any(ord(character) < 32 for character in item)
        ):
            return {}, False
        parsed[name] = item
    return parsed, True


def normalized_service_environment(value: object) -> tuple[list[str], bool]:
    assignments, complete = service_environment_assignments(value)
    return sorted(assignments), complete


def service_config_environment_is_trusted(
    value: object,
    logical_name: str,
    instance: str,
) -> bool:
    assignments, complete = service_environment_assignments(value)
    if logical_name in ROLES:
        if re.fullmatch(r"[0-9a-f]{12}", instance) is None:
            return False
        expected = {
            **TRUSTED_SERVICE_CONFIG_ENVIRONMENT,
            "PODMAN_SYSTEMD_UNIT": (
                f"secpal-int-{instance}-{logical_name}.service"
            ),
        }
    elif logical_name in GENERATED_LOGICAL_NAMES:
        expected = TRUSTED_SERVICE_CONFIG_ENVIRONMENT
    else:
        return False
    return complete and assignments == expected


def read_id_map(path: Path) -> tuple[list[dict[str, int]], bool]:
    try:
        with path.open("rb") as stream:
            content = stream.read(4097)
    except OSError:
        return [], False
    return parse_id_map(content)


def user_namespace_identity(path: Path) -> tuple[str, bool]:
    try:
        identity = os.readlink(path)
    except OSError:
        return "", False
    return (
        identity,
        re.fullmatch(r"user:\[[0-9]{1,20}\]", identity) is not None,
    )


def id_from_host(mapping: list[dict[str, int]], host_id: int) -> int:
    matches = [
        item["container_id"] + host_id - item["host_id"]
        for item in mapping
        if item["host_id"] <= host_id < item["host_id"] + item["size"]
    ]
    return matches[0] if len(matches) == 1 else -1


def id_to_host(mapping: list[dict[str, int]], container_id: int) -> int:
    matches = [
        item["host_id"] + container_id - item["container_id"]
        for item in mapping
        if item["container_id"] <= container_id < item["container_id"] + item["size"]
    ]
    return matches[0] if len(matches) == 1 else -1


def compose_id_maps(
    inner: list[dict[str, int]], outer: list[dict[str, int]]
) -> list[dict[str, int]] | None:
    composed: list[dict[str, int]] = []
    for item in inner:
        remaining = item["size"]
        container_id = item["container_id"]
        outer_id = item["host_id"]
        while remaining:
            match = next(
                (
                    candidate
                    for candidate in outer
                    if candidate["container_id"] <= outer_id
                    < candidate["container_id"] + candidate["size"]
                ),
                None,
            )
            if match is None:
                return None
            size = min(
                remaining,
                match["container_id"] + match["size"] - outer_id,
            )
            composed.append(
                {
                    "container_id": container_id,
                    "host_id": match["host_id"] + outer_id - match["container_id"],
                    "size": size,
                }
            )
            remaining -= size
            container_id += size
            outer_id += size
            if len(composed) > 16:
                return None
    composed.sort(key=lambda item: (item["container_id"], item["host_id"]))
    return composed if id_map_is_bounded(composed, allow_empty=False) else None


def podman_outer_id_maps() -> tuple[list[dict[str, int]], list[dict[str, int]], bool]:
    uid_status, uid_value, uid_complete = command_result(
        ["podman", "unshare", "cat", "/proc/self/uid_map"]
    )
    gid_status, gid_value, gid_complete = command_result(
        ["podman", "unshare", "cat", "/proc/self/gid_map"]
    )
    try:
        uid_map, uid_valid = parse_id_map(uid_value.encode("ascii"))
        gid_map, gid_valid = parse_id_map(gid_value.encode("ascii"))
    except UnicodeEncodeError:
        return [], [], False
    return (
        uid_map,
        gid_map,
        uid_status == 0 and gid_status == 0 and uid_complete and gid_complete
        and uid_valid and gid_valid,
    )


def effective_user_namespace_facts(
    pid: int,
) -> tuple[dict[str, object], int, int, list[int], bool]:
    empty = {
        "process_identity": "",
        "collector_identity": "",
        "uid_map": [],
        "gid_map": [],
        "collector_uid_map": [],
        "collector_gid_map": [],
    }
    if pid <= 0 or pid > 4_194_304:
        return empty, -1, -1, [], False
    collector_identity, collector_identity_complete = user_namespace_identity(
        Path("/proc/self/ns/user")
    )
    collector_uid_map, collector_uid_complete = read_id_map(
        Path("/proc/self/uid_map")
    )
    collector_gid_map, collector_gid_complete = read_id_map(
        Path("/proc/self/gid_map")
    )
    process_namespace_path = Path(f"/proc/{pid}/ns/user")
    process_identity_before, process_identity_before_complete = (
        user_namespace_identity(process_namespace_path)
    )
    uid_map, uid_complete = read_id_map(Path(f"/proc/{pid}/uid_map"))
    gid_map, gid_complete = read_id_map(Path(f"/proc/{pid}/gid_map"))
    host_uid, host_gid, host_groups, identity_complete = process_status_facts(
        pid, require_all_ids_equal=True
    )
    process_identity_after, process_identity_after_complete = (
        user_namespace_identity(process_namespace_path)
    )
    process_identity = (
        process_identity_before
        if process_identity_before == process_identity_after
        else ""
    )
    effective_uid = id_from_host(uid_map, host_uid)
    effective_gid = id_from_host(gid_map, host_gid)
    effective_groups = sorted(id_from_host(gid_map, value) for value in host_groups)
    complete = all(
        (
            collector_identity_complete,
            collector_uid_complete,
            collector_gid_complete,
            process_identity_before_complete,
            process_identity_after_complete,
            bool(process_identity),
            uid_complete,
            gid_complete,
            identity_complete,
            effective_uid >= 0,
            effective_gid >= 0,
            all(value >= 0 for value in effective_groups),
        )
    )
    facts = {
        "process_identity": process_identity,
        "collector_identity": collector_identity,
        "uid_map": uid_map,
        "gid_map": gid_map,
        "collector_uid_map": collector_uid_map,
        "collector_gid_map": collector_gid_map,
    }
    if not complete:
        return facts, -1, -1, [], False
    return facts, effective_uid, effective_gid, effective_groups, True


def collector_user_namespace_facts() -> tuple[dict[str, object], bool]:
    identity, identity_complete = user_namespace_identity(Path("/proc/self/ns/user"))
    uid_map, uid_complete = read_id_map(Path("/proc/self/uid_map"))
    gid_map, gid_complete = read_id_map(Path("/proc/self/gid_map"))
    return (
        {
            "process_identity": "",
            "collector_identity": identity,
            "uid_map": [],
            "gid_map": [],
            "collector_uid_map": uid_map,
            "collector_gid_map": gid_map,
        },
        identity_complete and uid_complete and gid_complete,
    )


def effective_host_identity(
    container: object, expected_uid: int, expected_gid: int
) -> tuple[int, int] | None:
    if not isinstance(container, dict):
        return None
    namespace = container.get("user_namespace")
    if not isinstance(namespace, dict):
        return None
    uid_map = namespace.get("uid_map")
    gid_map = namespace.get("gid_map")
    if (
        not id_map_is_bounded(uid_map, allow_empty=False)
        or not id_map_is_bounded(gid_map, allow_empty=False)
    ):
        return None
    host_uid = id_to_host(uid_map, expected_uid)
    host_gid = id_to_host(gid_map, expected_gid)
    return (host_uid, host_gid) if host_uid >= 0 and host_gid >= 0 else None


def allowed_service_process_groups(
    services: object, containers: object
) -> dict[str, set[tuple[int, int]]]:
    if not isinstance(services, list) or not isinstance(containers, list):
        return {}
    containers_by_role = {
        str(container.get("role")): container
        for container in containers
        if isinstance(container, dict)
    }
    allowed: dict[str, set[tuple[int, int]]] = {}
    for service in services:
        if not isinstance(service, dict):
            continue
        role = str(service.get("logical_name"))
        control_group = service.get("control_group")
        contract = ROLE_CONTRACTS.get(role)
        if not isinstance(control_group, str) or not control_group or contract is None:
            continue
        identities = {(CI_UID, CI_GID)}
        container_identity = effective_host_identity(
            containers_by_role.get(role), *contract.identity
        )
        if container_identity is not None:
            identities.add(container_identity)
        allowed[control_group] = identities
    return allowed


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


def container_facts(
    instance: str,
    *,
    rootless: bool,
    podman_uid_map: list[dict[str, int]],
    podman_gid_map: list[dict[str, int]],
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
            "CreateCommand",
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
            or (
                item["EffectiveCaps"] is not None
                and not isinstance(item["EffectiveCaps"], list)
            )
            or (
                item["BoundingCaps"] is not None
                and not isinstance(item["BoundingCaps"], list)
            )
            or not isinstance(config["Labels"], dict)
            or not isinstance(config["Env"], list)
            or not isinstance(config["CreateCommand"], list)
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
            or any(
                not isinstance(host_config[field], str)
                for field in (
                    "PidMode", "UsernsMode", "IpcMode", "UTSMode",
                    "NetworkMode",
                )
            )
            or not isinstance(network_settings["Networks"], dict)
            or not isinstance(network_settings["Ports"], dict)
        ):
            complete = False
            continue
        if "Health" not in state:
            health, health_complete = "none", True
        else:
            health_value = state["Health"]
            health_complete = (
                isinstance(health_value, dict)
                and isinstance(health_value.get("Status"), str)
                and bool(health_value["Status"])
            )
            health = (
                health_value["Status"] if health_complete else "none"
            )
        labels = config["Labels"]
        network_map = network_settings["Networks"]
        network_mode = host_config["NetworkMode"] or "private"
        network_names_complete = all(
            isinstance(value, str) and value
            for value in network_map
        )
        if network_mode == "none":
            networks = []
            network_names_complete = (
                network_names_complete
                and set(network_map) == {"none"}
                and isinstance(network_map["none"], dict)
            )
        else:
            networks = sorted(str(value) for value in network_map)
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
        effective_caps = (
            [] if item["EffectiveCaps"] is None else item["EffectiveCaps"]
        )
        bounding_caps = (
            [] if item["BoundingCaps"] is None else item["BoundingCaps"]
        )
        devices = host_config["Devices"]
        mounts = item["Mounts"]
        environment = config["Env"]
        entrypoint, entrypoint_complete = normalized_command(config["Entrypoint"])
        command, command_complete = normalized_command(config["Cmd"])
        if "Healthcheck" not in config:
            healthcheck_command, healthcheck_complete = [], True
        else:
            configured_healthcheck = config["Healthcheck"]
            if isinstance(configured_healthcheck, dict) and set(
                configured_healthcheck
            ).issuperset({"Test"}):
                healthcheck_command, healthcheck_complete = normalized_command(
                    configured_healthcheck["Test"]
                )
            else:
                healthcheck_command, healthcheck_complete = [], False
        create_options, create_options_complete = configured_userns_options(
            config["CreateCommand"]
        )
        if "IDMappings" not in host_config:
            configured_uid_map, configured_gid_map = [], []
            configured_maps_complete = True
        else:
            configured_uid_map, configured_gid_map, configured_maps_complete = (
                configured_id_maps(host_config["IDMappings"])
            )
        if str(state.get("Status", "")) == "running":
            (
                user_namespace,
                effective_uid,
                effective_gid,
                effective_groups,
                identity_complete,
            ) = effective_user_namespace_facts(state["Pid"])
        else:
            user_namespace, identity_complete = collector_user_namespace_facts()
            effective_uid, effective_gid, effective_groups = -1, -1, []
        user_namespace.update(
            {
                "compat_mode": host_config["UsernsMode"],
                "create_options": create_options,
                "configured_uid_map": configured_uid_map,
                "configured_gid_map": configured_gid_map,
                "podman_uid_map": podman_uid_map,
                "podman_gid_map": podman_gid_map,
            }
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
                entrypoint_complete, command_complete, health_complete,
                healthcheck_complete,
                identity_complete, create_options_complete,
                configured_maps_complete, network_names_complete,
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
                "user_namespace": user_namespace,
                "ipc_mode": str(host_config["IpcMode"] or "private"),
                "uts_mode": str(host_config["UTSMode"] or "private"),
                "network_mode": str(network_mode),
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
                "networks": networks,
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


def root_owned_systemd_unit(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == 0
        and metadata.st_gid == 0
        and stat.S_IMODE(metadata.st_mode) == 0o644
        and metadata.st_nlink == 1
    )


def systemd_unit_owned_by_package(path: Path, package: str) -> bool:
    if (
        path.parent not in {
            Path("/usr/lib/systemd/user"),
            Path("/lib/systemd/user"),
        }
        or re.fullmatch(r"[a-z0-9@_.-]+\.(?:service|socket)", path.name) is None
        or re.fullmatch(r"[a-z0-9][a-z0-9+.-]+", package) is None
    ):
        return False
    canonical = Path("/usr/lib/systemd/user") / path.name
    status_code, output, complete = command_result(
        ["dpkg-query", "-S", str(canonical)]
    )
    return (
        status_code == 0
        and complete
        and output == f"{package}: {canonical}"
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
    if (
        len(units) != len(set(units))
        or len(units) > 16
        or "dbus.socket" not in units
    ):
        return True, False
    if any(unit not in TRUSTED_USER_SOCKET_UNITS for unit in units):
        return True, True
    admitted_services: set[str] = set()
    for unit in units:
        status_code, output, complete = command_result(
            [
                "systemctl", "--user", "show", unit,
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
        fragments, trigger = TRUSTED_USER_SOCKET_UNITS[unit]
        fragment = Path(properties["FragmentPath"])
        package = TRUSTED_USER_UNIT_PACKAGES.get(unit)
        if (
            fragment not in fragments
            or not root_owned_systemd_unit(fragment)
            or package is None
            or not systemd_unit_owned_by_package(fragment, package)
            or properties["DropInPaths"] != ""
            or properties["Triggers"] != trigger
        ):
            return True, True
        if trigger in admitted_services:
            continue
        service_fragments = TRUSTED_USER_SERVICE_UNITS.get(trigger)
        if service_fragments is None:
            return True, True
        status_code, output, complete = command_result(
            [
                "systemctl", "--user", "show", trigger,
                "--property=FragmentPath", "--property=DropInPaths",
            ]
        )
        if status_code != 0 or not complete:
            return True, False
        service_properties: dict[str, str] = {}
        for line in output.splitlines():
            if "=" not in line:
                return True, False
            key, value = line.split("=", 1)
            if key in service_properties:
                return True, False
            service_properties[key] = value
        if set(service_properties) != {"FragmentPath", "DropInPaths"}:
            return True, False
        service_fragment = Path(service_properties["FragmentPath"])
        service_package = TRUSTED_USER_UNIT_PACKAGES.get(trigger)
        if (
            service_fragment not in service_fragments
            or not root_owned_systemd_unit(service_fragment)
            or service_package is None
            or not systemd_unit_owned_by_package(
                service_fragment, service_package
            )
            or service_properties["DropInPaths"] != ""
        ):
            return True, True
        admitted_services.add(trigger)
    return False, True


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

    def canonical_unit_name(value: str) -> bool:
        return bool(
            1 <= len(value) <= 128
            and re.fullmatch(
                r"(?:[A-Za-z0-9_.@:-]|\\x[0-9a-f]{2})+", value
            )
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
        if not fields or not canonical_unit_name(fields[0]):
            complete = False
            continue
        active_units.append(fields[0])
    for line in jobs_output.splitlines():
        fields = line.split()
        if (
            len(fields) < 2
            or re.fullmatch(r"[1-9][0-9]{0,9}", fields[0]) is None
            or not canonical_unit_name(fields[1])
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
        except OSError as error:
            trusted_opaque_group = control_group in {
                f"{user_slice_prefix}user@20000.service/init.scope",
                (
                    f"{user_slice_prefix}user@20000.service/app.slice/"
                    "ssh-agent.service"
                ),
            }
            if process.exists() and not (
                isinstance(error, PermissionError)
                and trusted_opaque_group
                and identity_complete
                and (uid, gid) == (CI_UID, CI_GID)
            ):
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
    one_shot_control_group = service.get("control_group")
    workload_one_shot_group_matches = (
        logical_name in {"secrets-init", "migrate"}
        and one_shot_control_group
        == (
            "/user.slice/user-20000.slice/user@20000.service/"
            f"app.slice/{unit}"
        )
    )
    return (
        common_state
        and service.get("sub_state") == "exited"
        and service["main_pid"] == 0
        and (
            one_shot_control_group == ""
            or workload_one_shot_group_matches
        )
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
    matched_statuses: list[str] = []
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
            message = record.get("MESSAGE")
            event = (
                re.fullmatch(
                    r"[0-9]{4}-[0-9]{2}-[0-9]{2} "
                    r"[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{1,9} "
                    r"[+-][0-9]{4} UTC m=\+[0-9]+\.[0-9]+ "
                    r"container (create|start|died) ([0-9a-f]{64}) "
                    r"\(([^()\n]{1,2048})\)",
                    message,
                )
                if isinstance(message, str) and len(message) <= 2304
                else None
            )
            metadata = event.group(3).split(", ") if event is not None else []
            if (
                record.get("_SYSTEMD_INVOCATION_ID") == invocation_id
                and record.get("_EXE") == str(PODMAN_EXECUTABLE)
                and len(command) >= 2
                and command[0] == str(PODMAN_EXECUTABLE)
                and command[1] == "run"
                and names == [container_name]
                and event is not None
                and event.group(2) == container_id
                and sum(
                    value == f"name={container_name}" for value in metadata
                ) == 1
                and sum(
                    value == f"PODMAN_SYSTEMD_UNIT={unit}"
                    for value in metadata
                ) == 1
                and sum(
                    value.startswith("image=") and len(value) > len("image=")
                    for value in metadata
                ) == 1
            ):
                matched_statuses.append(event.group(1))
    except json.JSONDecodeError:
        return False, False
    return matched_statuses == ["create", "start", "died"], True


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
    podman_uid_map, podman_gid_map, podman_maps_complete = podman_outer_id_maps()
    containers, containers_complete = container_facts(
        instance,
        rootless=podman_rootless,
        podman_uid_map=podman_uid_map,
        podman_gid_map=podman_gid_map,
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
                podman_maps_complete,
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


def reviewed_podman_auxiliary_units(
    active_units: set[str], containers: object
) -> tuple[set[str], str, str] | None:
    if not isinstance(containers, list):
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
    for container_id in healthy_ids:
        matches = {
            unit
            for unit in health_timer_candidates
            if unit.startswith(f"{container_id}-")
        }
        if len(matches) != 1:
            return None
        health_timers.update(matches)
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


def id_map_is_bounded(value: object, *, allow_empty: bool) -> bool:
    if (
        not isinstance(value, list)
        or len(value) > 16
        or (not allow_empty and not value)
    ):
        return False
    ranges: list[tuple[int, int, int]] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {
            "container_id", "host_id", "size"
        }:
            return False
        container_id = item["container_id"]
        host_id = item["host_id"]
        size = item["size"]
        if (
            type(container_id) is not int
            or type(host_id) is not int
            or type(size) is not int
            or not 0 <= container_id <= 2**32 - 1
            or not 0 <= host_id <= 2**32 - 1
            or not 1 <= size <= 2**32 - 1
            or container_id + size > 2**32
            or host_id + size > 2**32
        ):
            return False
        ranges.append((container_id, host_id, size))
    if ranges != sorted(ranges, key=lambda item: (item[0], item[1])):
        return False
    for index, (container_id, host_id, size) in enumerate(ranges):
        for other_container_id, other_host_id, other_size in ranges[index + 1:]:
            if (
                container_id < other_container_id + other_size
                and other_container_id < container_id + size
            ) or (
                host_id < other_host_id + other_size
                and other_host_id < host_id + size
            ):
                return False
    return True


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
        gateway_port = expected_gateway_port(str(instance))
    except ValueError:
        names = ()
        gateway_port = None
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
    if isinstance(services, list) and any(
        not service_environment_names_are_trusted(service)
        for service in services
    ):
        failures.append("D1A_HOST_NAMESPACES")
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
                or item.get("cap_add") not in ([], expected_caps)
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
                for field in ("pid_mode", "ipc_mode", "uts_mode")
            ) or (
                role_contract is None
                or not user_namespace_contract_matches(
                    item, *role_contract.identity
                )
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
                valid_ports = published_ports == [
                    f"127.0.0.1:{gateway_port}:8443/tcp"
                ]
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
        or PODMAN_NETWORK_ONLINE_UNIT in baseline_units
        or PODMAN_NETWORK_ONLINE_UNIT not in cleanup_units
        or cleanup_units - {PODMAN_NETWORK_ONLINE_UNIT} != baseline_units
        or cleanup_user_work.get("jobs") != baseline_user_work.get("jobs")
    ):
        failures.append("D1A_PENDING_USER_WORK")
    live_user_work = exact_keys(live.get("user_work"), {"active_units", "jobs"})
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
        reviewed_podman_auxiliary_units(live_units, containers)
        if live_units is not None
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
        failures.append("D1A_LIVE_USER_WORK")
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
            outcome = normalize_quadlet_runtime(
                arguments.instance,
                activate=arguments.normalization_mode == "live",
            )
            json.dump(
                outcome.document(),
                sys.stdout,
                sort_keys=True,
                separators=(",", ":"),
            )
            sys.stdout.write("\n")
            return outcome.status
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
