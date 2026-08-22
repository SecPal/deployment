#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Render the production rootless-Podman Quadlet declarations from D.2."""

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
    POSTGRES_IMAGE,
    VALKEY_IMAGE,
    role_execution_spec,
    role_spec,
    tmpfs_mounts,
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
    "Environment=SECPAL_SECRET_ROOT=/run/secpal/secrets/api",
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
    identity = role_spec(role)
    logs = contract["log_policy"]
    effective_role = instance or role
    container_name = f"secpal-{effective_role}"
    log_file = logs["file_name"].format(container_name=container_name)
    return [
        f"ContainerName={container_name}",
        f"Image={image}",
        "Pull=never",
        f"User={identity.uid}",
        f"Group={identity.gid}",
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
    if oneshot:
        return section(
            "Service",
            ["Type=oneshot", "RemainAfterExit=yes", "Restart=no", "TimeoutStartSec=300"],
        )
    return section(
        "Service",
        ["Restart=on-failure", "RestartSec=2", "TimeoutStartSec=180"],
    )


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
    dependencies = ("secpal-migrate.service",) if role != "migrate" else (
        "secpal-postgres.service",
        "secpal-valkey.service",
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
            "Network=secpal-edge.network",
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
    postgres_path = contract["objects"]["postgresql_data"]["location"]
    valkey_path = contract["objects"]["valkey_state"]["location"]
    postgres_secret = contract["secret_delivery"]["postgres"]["directory"]
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

    postgres_init = common_container(
        contract, "postgres", POSTGRES_IMAGE, instance="postgres-init"
    )
    postgres_init.extend(
        (
            'Entrypoint=["/bin/sh","/run/secpal/bootstrap/production-postgres-entrypoint.sh"]',
            "Exec=initialize",
            "Mount=type=bind,source=/srv/secpal/config/runtime/production-postgres-entrypoint.sh,"
            "target=/run/secpal/bootstrap/production-postgres-entrypoint.sh,ro=true",
            f"Mount=type=bind,source={postgres_secret}/password,"
            "target=/run/secpal-secret/password,ro=true",
            f"Mount=type=bind,source={postgres_path},target=/var/lib/postgresql/data,rw=true",
            *tmpfs_mounts("postgres"),
            "Network=none",
        )
    )
    units["secpal-postgres-init.container"] = unit(
        "Initialize SecPal production PostgreSQL", ("secpal-state-ready.service",), oneshot=True
    ) + section("Container", postgres_init) + service(oneshot=True)

    postgres = common_container(contract, "postgres", POSTGRES_IMAGE)
    postgres.extend(
        (
            'Entrypoint=["/bin/sh","/run/secpal/bootstrap/production-postgres-entrypoint.sh"]',
            "Exec=run",
            "Mount=type=bind,source=/srv/secpal/config/runtime/production-postgres-entrypoint.sh,"
            "target=/run/secpal/bootstrap/production-postgres-entrypoint.sh,ro=true",
            f"Mount=type=bind,source={postgres_path},target=/var/lib/postgresql/data,rw=true",
            *tmpfs_mounts("postgres"),
            "Network=secpal-application.network",
            "NetworkAlias=postgres",
            "HealthCmd=pg_isready -U secpal -d secpal",
            "HealthInterval=5s",
            "HealthTimeout=3s",
            "HealthRetries=20",
            "HealthStartPeriod=10s",
            "HealthOnFailure=kill",
            "Notify=healthy",
        )
    )
    units["secpal-postgres.container"] = unit(
        "SecPal production PostgreSQL", ("secpal-postgres-init.service",)
    ) + section("Container", postgres) + service()

    valkey = common_container(contract, "valkey", VALKEY_IMAGE)
    valkey.extend(
        (
            'Entrypoint=["/bin/sh","/run/secpal/bootstrap/production-valkey-entrypoint.sh"]',
            "Mount=type=bind,source=/srv/secpal/config/runtime/production-valkey-entrypoint.sh,"
            "target=/run/secpal/bootstrap/production-valkey-entrypoint.sh,ro=true",
            f"Mount=type=bind,source={valkey_secret}/password,"
            "target=/run/secpal-secret/password,ro=true",
            f"Mount=type=bind,source={valkey_path},target=/data,rw=true",
            *(mount for mount in tmpfs_mounts("valkey") if "destination=/data," not in mount),
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
            "Before=secpal-postgres-init.service secpal-postgres.service "
            "secpal-valkey.service secpal-migrate.service",
            "PartOf=secpal.target",
        ],
    ) + section(
        "Service",
        [
            "Type=oneshot",
            "ExecStart=/usr/bin/podman unshare /usr/local/libexec/secpal/production-state "
            "--contract /srv/secpal/config/state-contract.yaml "
            "--validate-namespace --require-secrets",
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
