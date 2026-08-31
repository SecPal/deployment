#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Render the retained production rootless-Podman product-role Quadlets."""

from __future__ import annotations

import argparse
import importlib.util
import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if os.fspath(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, os.fspath(SCRIPT_DIRECTORY))

from integration_runtime_contract import (  # noqa: E402
    API_IMAGE,
    FRONTEND_IMAGE,
    role_execution_spec,
    role_spec,
    tmpfs_mounts,
)

# Production Valkey remains owned by the production state contract. The active
# disposable integration intentionally exports no Valkey image authority.
VALKEY_IMAGE = "docker.io/valkey/valkey@sha256:3acc0687f2a2e1091fae6450d7842dd658c941338cf0a873ddd9e14b9e4ea4dd"
VALKEY_UID = 10002
VALKEY_GID = 10002
VALKEY_TMPFS_MOUNTS = (
    "Mount=type=tmpfs,destination=/tmp,tmpfs-size=16m,tmpfs-mode=0700,"
    "U=true,nosuid=true,nodev=true,noexec=true",
    "Mount=type=tmpfs,destination=/data,tmpfs-size=32m,tmpfs-mode=0700,"
    "U=true,nosuid=true,nodev=true,noexec=true",
)


def _load_state_module():
    path = SCRIPT_DIRECTORY / "production-state.py"
    spec = importlib.util.spec_from_file_location("production_state", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load production state contract")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_STATE = _load_state_module()
DEFAULT_CONTRACT = _STATE.DEFAULT_CONTRACT
load_contract = _STATE.load_contract


API_ROLES = ("migrate", "api", "worker-general", "worker-hash-chain", "scheduler")
APPLICATION_ENVIRONMENT = (
    "Environment=APP_DEBUG=false",
    "Environment=APP_ENV=production",
    "Environment=APP_NAME=SecPal",
    "Environment=CACHE_STORE=redis",
    "Environment=DB_CONNECTION=pgsql",
    "Environment=DB_DATABASE=secpal",
    "Environment=DB_HOST=postgres",
    "Environment=DB_PORT=5432",
    "Environment=DB_USERNAME=secpal",
    "Environment=FILESYSTEM_DISK=local",
    "Environment=LOG_CHANNEL=stderr",
    "Environment=QUEUE_CONNECTION=redis",
    "Environment=REDIS_CLIENT=phpredis",
    "Environment=REDIS_CACHE_DB=1",
    "Environment=REDIS_DB=0",
    "Environment=REDIS_HOST=valkey",
    "Environment=REDIS_PORT=6379",
    "Environment=REDIS_QUEUE=default",
    "Environment=REDIS_QUEUE_CONNECTION=default",
    "Environment=SESSION_DRIVER=database",
)
COMMON_PODMAN_ARGS = (
    "PodmanArgs=--http-proxy=false",
    "PodmanArgs=--pid=private",
    "PodmanArgs=--ipc=private",
    "PodmanArgs=--uts=private",
)
SPDX_HEADER = (
    "# SPDX-FileCopyrightText: 2026 SecPal Contributors\n"
    + "# SPDX-License"
    + "-Identifier: CC0-1.0\n\n"
)
STATE_READY_COMMAND = (
    "/usr/bin/podman unshare /usr/local/libexec/secpal/production-state "
    "--contract /srv/secpal/config/state-contract.json "
    "--validate-namespace --require-secrets"
)


def section(name: str, lines: list[str] | tuple[str, ...]) -> str:
    return f"[{name}]\n" + "\n".join(lines) + "\n"


def unit(description: str, dependencies: tuple[str, ...] = (), *, oneshot: bool = False) -> str:
    lines = [f"Description={description}", "PartOf=secpal.target"]
    if dependencies:
        joined = " ".join(dependencies)
        lines.extend((f"Requires={joined}", f"After={joined}"))
    if not oneshot:
        lines.extend(("StartLimitIntervalSec=60", "StartLimitBurst=3"))
    return section("Unit", lines)


def common_container(
    contract: dict, role: str, image: str, *, instance: str | None = None
) -> list[str]:
    identity = role_spec(role) if role != "valkey" else None
    uid = VALKEY_UID if identity is None else identity.uid
    gid = VALKEY_GID if identity is None else identity.gid
    logs = contract["log_policy"]
    effective_role = instance or role
    container_name = f"secpal-{effective_role}"
    log_file = logs["file_name"].format(container_name=container_name)
    return [
        f"ContainerName={container_name}",
        f"Image={image}",
        "Pull=never",
        f"User={uid}",
        f"Group={gid}",
        "ReadOnly=true",
        "ReadOnlyTmpfs=false",
        "DropCapability=all",
        "NoNewPrivileges=true",
        "RunInit=true",
        "StopTimeout=30",
        f"LogDriver={logs['driver']}",
        f"LogOpt=path={logs['directory']}/{log_file}",
        f"LogOpt=max-size={logs['maximum_file_size']}",
        "PidsLimit=512",
        *COMMON_PODMAN_ARGS,
        "Label=org.secpal.production=true",
        f"Label=org.secpal.role={effective_role}",
    ]


def service(*, oneshot: bool = False) -> str:
    validation = f"ExecStartPre={STATE_READY_COMMAND}"
    if oneshot:
        return section(
            "Service",
            [
                "Type=oneshot",
                validation,
                "RemainAfterExit=yes",
                "Restart=no",
                "TimeoutStartSec=300",
            ],
        )
    return section(
        "Service",
        [validation, "Restart=on-failure", "RestartSec=2", "TimeoutStartSec=180"],
    )


def build_native_lifecycle_fixture_unit(
    contract: dict, fixture_root: Path, instance: str
) -> str:
    """Render a fixture-only probe from the production private-storage seam."""
    private = contract["objects"]["private_application_storage"]
    identity = role_spec("api")
    source = fixture_root / private["location"].lstrip("/")
    lines = common_container(contract, "api", FRONTEND_IMAGE, instance=instance)
    lines = [line for line in lines if not line.startswith(("LogDriver=", "LogOpt="))]
    lines.append("LogDriver=journald")
    lines.extend(
        (
            "Network=none",
            f"Mount=type=bind,source={source},target=/app/storage/app/private,rw=true",
            'Entrypoint=["/bin/sh"]',
            'Exec=-c "if [ ! -f /app/storage/app/private/proof ]; then '
            "printf persistence > /app/storage/app/private/proof; fi; exec sleep 300\"",
        )
    )
    # This fixture deliberately omits state-ready: host-side fixture admission is
    # separate, while the mounted path, target and API identity come from the
    # production contract and role registry.
    content = unit("SecPal D.2 native private-storage persistence proof")
    content += section("Container", lines)
    content += section("Service", ["Restart=no", "TimeoutStartSec=60"])
    if f"User={identity.uid}" not in content or f"Group={identity.gid}" not in content:
        raise ValueError("native lifecycle fixture identity drifted from API role")
    return SPDX_HEADER + content


def api_secret_mounts(contract: dict) -> list[str]:
    delivery = contract["secret_delivery"]["api"]
    return [
        "Mount=type=bind,source="
        f"{delivery['directory']}/{name},target=/run/secpal/secrets/api/{name},ro=true"
        for name in delivery["files"]
    ]


def api_container(contract: dict, role: str) -> str:
    private = contract["objects"]["private_application_storage"]["location"]
    public = contract["objects"]["public_application_storage"]["location"]
    execution = role_execution_spec(role)
    if execution is None or execution.command is None:
        raise ValueError(f"production role {role} has no reviewed execution contract")
    dependencies = (
        ("secpal-migrate.service",)
        if role != "migrate"
        else ("secpal-valkey.service",)
    )
    lines = common_container(contract, role, API_IMAGE)
    lines.extend(APPLICATION_ENVIRONMENT)
    execution_command = (
        ("php", "artisan", "migrate", "--force")
        if role == "migrate"
        else execution.command
    )
    role_tmpfs = tuple(
        mount
        for mount in tmpfs_mounts(role)
        if "destination=/app/storage/app/public," not in mount
    )
    lines.extend(
        (
            f"Exec={' '.join(execution_command)}",
            "Mount=type=bind,source=/srv/secpal/config/php/99-secpal-secrets.ini,"
            "target=/usr/local/etc/php/conf.d/99-secpal-secrets.ini,ro=true",
            "Mount=type=bind,source=/srv/secpal/config/runtime/production-secret-bootstrap.php,"
            "target=/run/secpal/bootstrap/production-secret-bootstrap.php,ro=true",
            *api_secret_mounts(contract),
            f"Mount=type=bind,source={private},target=/app/storage/app/private,rw=true",
            f"Mount=type=bind,source={public},target=/app/storage/app/public,rw=true",
            *role_tmpfs,
            "Network=secpal-application.network",
            *(("Network=secpal-edge.network",) if role == "api" else ()),
            f"NetworkAlias={role}",
        )
    )
    if role == "api":
        health = role_spec(role).health
        if health is None:
            raise ValueError("API health contract is missing")
        lines.extend(health.quadlet_lines())
    return unit(
        f"SecPal production {role}", dependencies, oneshot=role == "migrate"
    ) + section("Container", lines) + service(oneshot=role == "migrate")


def build_units(contract: dict) -> dict[str, str]:
    valkey_path = contract["objects"]["valkey_state"]["location"]
    valkey_secret = contract["secret_delivery"]["valkey"]["directory"]
    units: dict[str, str] = {}

    units["secpal-application.network"] = unit(
        "SecPal private production application network"
    ) + section(
        "Network",
        [
            "NetworkName=secpal-application",
            "Internal=true",
            "Label=org.secpal.production=true",
        ],
    )
    units["secpal-edge.network"] = unit(
        "SecPal private production edge network"
    ) + section(
        "Network",
        [
            "NetworkName=secpal-edge",
            "Internal=true",
            "Label=org.secpal.production=true",
        ],
    )

    valkey = common_container(contract, "valkey", VALKEY_IMAGE)
    valkey.extend(
        (
            'Entrypoint=["/bin/sh","/run/secpal/bootstrap/production-valkey-entrypoint.sh"]',
            "Mount=type=bind,source=/srv/secpal/config/runtime/production-valkey-entrypoint.sh,"
            "target=/run/secpal/bootstrap/production-valkey-entrypoint.sh,ro=true",
            f"Mount=type=bind,source={valkey_secret}/password,"
            "target=/run/secpal-secret/password,ro=true",
            f"Mount=type=bind,source={valkey_path},target=/data,rw=true",
            *(mount for mount in VALKEY_TMPFS_MOUNTS if "destination=/data," not in mount),
            "Network=secpal-application.network",
            "NetworkAlias=valkey",
            "HealthCmd=valkey-cli ping 2>&1 | grep -q 'NOAUTH Authentication required.'",
            "HealthInterval=5s",
            "HealthTimeout=3s",
            "HealthRetries=20",
            "HealthStartPeriod=5s",
            "HealthOnFailure=kill",
            "Notify=healthy",
        )
    )
    units["secpal-valkey.container"] = unit(
        "SecPal production Valkey", ("secpal-state-ready.service",)
    ) + section("Container", valkey) + service()

    for role in API_ROLES:
        units[f"secpal-{role}.container"] = api_container(contract, role)

    frontend = common_container(contract, "frontend", FRONTEND_IMAGE)
    frontend.extend(
        (
            *tmpfs_mounts("frontend"),
            "Network=secpal-edge.network",
            *role_spec("frontend").health.quadlet_lines(),
        )
    )
    units["secpal-frontend.container"] = unit(
        "SecPal production frontend", ("secpal-state-ready.service",)
    ) + section("Container", frontend) + service()

    units["secpal-state-ready.service"] = section(
        "Unit",
        [
            "Description=Validate SecPal production state before product startup",
            "Before=secpal-valkey.service secpal-migrate.service",
            "PartOf=secpal.target",
        ],
    ) + section(
        "Service",
        [
            "Type=oneshot",
            f"ExecStart={STATE_READY_COMMAND}",
            "RemainAfterExit=yes",
        ],
    )

    units["secpal.target"] = section(
        "Unit",
        [
            "Description=SecPal production role target",
            "Requires=secpal-api.service secpal-worker-general.service "
            "secpal-worker-hash-chain.service secpal-scheduler.service "
            "secpal-frontend.service",
            "After=secpal-migrate.service",
        ],
    ) + section("Install", ["WantedBy=default.target"])
    return dict(sorted((name, SPDX_HEADER + content) for name, content in units.items()))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--quadlet-output", type=Path, required=True)
    parser.add_argument("--systemd-output", type=Path, required=True)
    args = parser.parse_args()
    contract = load_contract(args.contract)
    quadlet_output = args.quadlet_output.resolve()
    systemd_output = args.systemd_output.resolve()
    quadlet_output.mkdir(parents=True, exist_ok=True)
    systemd_output.mkdir(parents=True, exist_ok=True)
    for name, content in build_units(contract).items():
        output = systemd_output if name.endswith((".service", ".target")) else quadlet_output
        destination = output / name
        destination.write_text(content, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
