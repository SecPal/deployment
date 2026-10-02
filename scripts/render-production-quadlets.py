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
    FRONTEND_IMAGE,
    role_execution_spec,
    role_spec,
    tmpfs_mounts,
)

sys.path.insert(0, str(SCRIPT_DIRECTORY / 'ci-cloud'))
from postgresql_qualification_contract import APPLICATION_RUNTIME  # noqa: E402

API_IMAGE = APPLICATION_RUNTIME["image"]


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
    "Environment=CACHE_STORE=database",
    "Environment=DB_CONNECTION=pgsql",
    "Environment=DB_DATABASE=secpal",
    "Environment=DB_HOST=db.secpal.internal",
    "Environment=DB_PORT=5432",
    "Environment=DB_SSLMODE=verify-full",
    "Environment=DB_SSLROOTCERT=/run/secpal/secrets/database/postgres-ca.crt",
    "Environment=FILESYSTEM_DISK=local",
    "Environment=LOG_CHANNEL=stderr",
    "Environment=QUEUE_CONNECTION=database",
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
    identity = role_spec(role)
    uid = identity.uid
    gid = identity.gid
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


def api_secret_mounts(contract: dict, role: str) -> list[str]:
    delivery = contract["secret_delivery"]["api"]
    mounts = [
        "Mount=type=bind,source="
        f"{delivery['directory']}/{name},target=/run/secpal/secrets/api/{name},ro=true"
        for name in delivery["files"]
    ]
    database = contract['secret_delivery']['migration' if role == 'migrate' else 'runtime']
    mounts.extend(
        f"Mount=type=bind,source={database['directory']}/{name},"
        f"target=/run/secpal/secrets/database/{name},ro=true"
        for name in database['files']
    )
    return mounts


def api_container(contract: dict, role: str) -> str:
    private = contract["objects"]["private_application_storage"]["location"]
    public = contract["objects"]["public_application_storage"]["location"]
    execution = role_execution_spec(role)
    if execution is None or execution.command is None:
        raise ValueError(f"production role {role} has no reviewed execution contract")
    dependencies = (
        ("secpal-migrate.service",)
        if role != "migrate"
        else ("secpal-state-ready.service",)
    )
    lines = common_container(contract, role, API_IMAGE)
    lines.extend(APPLICATION_ENVIRONMENT)
    execution_command = (
        ("php", "/run/secpal/bootstrap/production-migrate.php")
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
            *api_secret_mounts(contract, role),
            *(("Mount=type=bind,source=/srv/secpal/config/runtime/production-migrate.php,"
               "target=/run/secpal/bootstrap/production-migrate.php,ro=true",)
              if role == "migrate" else ()),
            f"Mount=type=bind,source={private},target=/app/storage/app/private,rw=true",
            f"Mount=type=bind,source={public},target=/app/storage/app/public,rw=true",
            *role_tmpfs,
            "Network=pasta:--no-map-gw,--map-guest-addr,none,--map-host-loopback,169.254.81.1",
            "AddHost=db.secpal.internal:169.254.81.1",
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
    units: dict[str, str] = {}

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
            "Before=secpal-migrate.service",
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


def build_host_units(contract: dict) -> dict[str, str]:
    """Native firewall ownership; DB loss must not stop the user manager."""
    uid = contract['rootless_mapping']['service_uid']
    service = section('Unit', [
        'Description=SecPal rootless PostgreSQL loopback boundary',
        'After=nftables.service', f'Before=user@{uid}.service',
    ]) + section('Service', [
        'Type=oneshot', 'RemainAfterExit=yes',
        'ExecStartPre=/usr/sbin/nft --check -f /etc/nftables/secpal-postgresql.nft',
        'ExecStart=/usr/sbin/nft -f /etc/nftables/secpal-postgresql.nft',
        'ExecStop=/usr/sbin/nft delete table inet secpal_postgresql',
        'TimeoutStartSec=30', 'TimeoutStopSec=30', 'UMask=0077',
    ]) + section('Install', ['WantedBy=multi-user.target'])
    manager = section('Unit', [
        'Requires=secpal-postgresql-loopback.service',
        'BindsTo=secpal-postgresql-loopback.service',
        'After=secpal-postgresql-loopback.service postgresql.service',
        'Wants=postgresql.service',
    ])
    return {
        'secpal-postgresql-loopback.service': SPDX_HEADER + service,
        f'user@{uid}.service.d/secpal-postgresql.conf': SPDX_HEADER + manager,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--quadlet-output", type=Path, required=True)
    parser.add_argument("--systemd-output", type=Path, required=True)
    parser.add_argument("--host-systemd-output", type=Path)
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
    if args.host_systemd_output is not None:
        for name, content in build_host_units(contract).items():
            destination = args.host_systemd_output / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(content, encoding='utf-8')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
