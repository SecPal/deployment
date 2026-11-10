#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Render the retained production rootless-Podman product-role Quadlets."""

from __future__ import annotations

import argparse
import importlib.util
import os
import json
import shlex
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if os.fspath(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, os.fspath(SCRIPT_DIRECTORY))

from integration_runtime_contract import (  # noqa: E402
    FRONTEND_IMAGE, API_IMAGE as NGINX_IMAGE, PHP_FPM_IMAGE, FPM_SOCKET_VOLUME, FPM_SOCKET_DIRECTORY,
    role_execution_spec,
    role_spec, ROLE_STOP_SIGNALS,
    tmpfs_mounts,
)

sys.path.insert(0, str(SCRIPT_DIRECTORY / 'ci-cloud'))
from product_backend_contract import POLICY_CHECK_COMMAND, publish_lines  # noqa: E402

API_IMAGE = PHP_FPM_IMAGE


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


API_ROLES = ("migrate", "php-fpm", "worker-general", "worker-hash-chain", "scheduler")
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
    "Environment=APP_URL=https://api.secpal.dev",
    "Environment=FRONTEND_URL=https://app.secpal.dev",
    "Environment=SANCTUM_STATEFUL_DOMAINS=app.secpal.dev",
    "Environment=CORS_ALLOWED_ORIGINS=https://app.secpal.dev",
    "Environment=SESSION_DOMAIN=.secpal.dev",
    "Environment=SESSION_SECURE_COOKIE=true",
    "Environment=SESSION_HTTP_ONLY=true",
    "Environment=SESSION_SAME_SITE=lax",
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
        *([f"StopSignal={ROLE_STOP_SIGNALS[role]}"] if role in ROLE_STOP_SIGNALS else []),
        f"LogDriver={logs['driver']}",
        f"LogOpt=path={logs['directory']}/{log_file}",
        f"LogOpt=max-size={logs['maximum_file_size']}",
        "PidsLimit=512",
        *COMMON_PODMAN_ARGS,
        "Label=org.secpal.production=true",
        f"Label=org.secpal.role={effective_role}",
    ]


def service(*, oneshot: bool = False, backend: bool = False) -> str:
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
        [*((f"ExecStartPre={POLICY_CHECK_COMMAND}",) if backend else ()),
         validation, "Restart=on-failure", "RestartSec=2", "TimeoutStartSec=180"],
    )


def build_native_lifecycle_fixture_unit(
    contract: dict, fixture_root: Path, instance: str
) -> str:
    """Render disposable runtime evidence, independent of #99 Object Storage."""
    identity = role_spec("api")
    source = fixture_root / "state"
    lines = common_container(contract, "api", FRONTEND_IMAGE, instance=instance)
    lines = [
        line for line in lines
        if not line.startswith(("LogDriver=", "LogOpt="))
        and line != "Label=org.secpal.production=true"
    ]
    lines.append("LogDriver=journald")
    lines.extend(
        (
            "Network=none",
            # One fixture container owns this disposable source; private MCS
            # relabeling is appropriate. Production paths never use this probe.
            f"Mount=type=bind,source={source},target=/fixture-state,rw=true,relabel=private",
            'Entrypoint=["/bin/sh"]',
            'Exec=-c "set -eu; if [ ! -f /fixture-state/proof ]; then '
            "printf persistence > /fixture-state/proof; fi; exec sleep 300\"",
        )
    )
    # Only the reviewed non-root identity comes from the role registry. This
    # POSIX bind lifecycle does not qualify a Self-Hosted Object Storage adapter.
    content = unit("SecPal native rootless runtime lifecycle proof").replace(
        "PartOf=secpal.target\n", ""
    )
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
            *(("Entrypoint=" + json.dumps(execution.entrypoint, separators=(',', ':')),)
              if role == "php-fpm" else ()),
            f"Exec={shlex.join(execution_command)}",
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
    if role == "php-fpm":
        lines.append(f"Volume={FPM_SOCKET_VOLUME}.volume:{FPM_SOCKET_DIRECTORY}:rw,z")
        lines.append("Mount=type=bind,source=/srv/secpal/config/php/zz-fpm-session.conf,target=/usr/local/etc/php-fpm.d/zz-secpal-deployment.conf,ro=true")
        health = role_spec(role).health
        if health is None:
            raise ValueError("API health contract is missing")
        lines.extend(health.quadlet_lines())
    return unit(
        f"SecPal production {role}", dependencies, oneshot=role == "migrate"
    ) + section("Container", lines) + service(oneshot=role == "migrate", backend=False)


def nginx_container(contract: dict) -> str:
    lines = common_container(contract, "api", NGINX_IMAGE)
    public = contract["objects"]["public_application_storage"]["location"]
    lines.extend((
        f"Volume={FPM_SOCKET_VOLUME}.volume:{FPM_SOCKET_DIRECTORY}:ro,z",
        f"Mount=type=bind,source={public},target=/app/storage/app/public,ro=true",
        *tmpfs_mounts("api"),
        "Network=secpal-edge.network",
        *publish_lines("api"),
        *role_spec("api").health.quadlet_lines(),
    ))
    return unit("SecPal production API HTTP", ("secpal-php-fpm.service",)).replace("PartOf=secpal.target", "PartOf=secpal.target secpal-php-fpm.service") + section("Container", lines) + service(backend=True)


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

    units[f"{FPM_SOCKET_VOLUME}.volume"] = unit("SecPal private FastCGI socket") + section(
        "Volume", [f"VolumeName={FPM_SOCKET_VOLUME}", "Label=org.secpal.production=true"]
    )
    units["secpal-api.container"] = nginx_container(contract)

    for role in API_ROLES:
        units[f"secpal-{role}.container"] = api_container(contract, role)

    frontend = common_container(contract, "frontend", FRONTEND_IMAGE)
    frontend.extend(
        (
            *tmpfs_mounts("frontend"),
            "Network=secpal-edge.network",
            *publish_lines("frontend"),
            *role_spec("frontend").health.quadlet_lines(),
        )
    )
    units["secpal-frontend.container"] = unit(
        "SecPal production frontend", ("secpal-state-ready.service",)
    ) + section("Container", frontend) + service(backend=True)

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
        'Requires=nftables.service', 'After=nftables.service', 'PartOf=nftables.service',
        f'Before=user@{uid}.service',
    ]) + section('Service', [
        'Type=oneshot', 'RemainAfterExit=yes',
        'ExecStartPre=/usr/sbin/nft --check create table inet secpal_postgresql',
        'ExecStartPre=/usr/sbin/nft --check -f /etc/nftables/secpal-postgresql.nft',
        'ExecStart=/usr/sbin/nft -f /etc/nftables/secpal-postgresql.nft',
        'ExecStop=/usr/sbin/nft delete table inet secpal_postgresql',
        'TimeoutStartSec=30', 'TimeoutStopSec=30', 'UMask=0077',
    ]) + section('Install', ['WantedBy=multi-user.target'])
    manager = section('Unit', [
        'Requires=secpal-postgresql-loopback.service',
        'BindsTo=secpal-postgresql-loopback.service',
        'PartOf=secpal-postgresql-loopback.service',
        'After=secpal-postgresql-loopback.service postgresql.service',
        'Wants=postgresql.service',
    ])
    return {
        'secpal-postgresql-loopback.service': SPDX_HEADER + service,
        # The distribution reload flushes all tables without restarting dependents.
        # Reject reload; native stop/start ordering enforces the tested boundary.
        'nftables.service.d/secpal-postgresql.conf': SPDX_HEADER + section('Service', ['ExecReload=']),
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
    # Admit caller-supplied roots and ancestry before resolve() erases links.
    for supplied in (args.quadlet_output, args.systemd_output, args.host_systemd_output):
        if supplied is not None and any(path.is_symlink() for path in (supplied, *supplied.parents)):
            parser.error("unexpected production output; output roots and ancestors must not be symlinks")
    quadlet_output = args.quadlet_output.resolve()
    systemd_output = args.systemd_output.resolve()
    outputs: dict[Path, dict[str, str]] = {}
    for name, content in build_units(contract).items():
        output = systemd_output if name.endswith((".service", ".target")) else quadlet_output
        outputs.setdefault(output, {})[name] = content
    if args.host_systemd_output is not None:
        outputs.setdefault(args.host_systemd_output.resolve(), {}).update(build_host_units(contract))
    # Admit every complete staging inventory before the first mutation. The
    # host inventory has one declared drop-in directory; no other override or
    # retired service is allowed. Preserve unexpected entries, never prune.
    for output, declarations in outputs.items():
        files = {Path(name) for name in declarations}
        directories = {parent for name in files for parent in name.parents if parent != Path(".")}
        if (output.exists() and not output.is_dir()) or any(
            entry.is_symlink()
            or (entry.relative_to(output) not in directories if entry.is_dir()
                else entry.relative_to(output) not in files or not entry.is_file())
            for entry in output.rglob("*")
        ):
            parser.error(
                "unexpected production output; use a clean dedicated output "
                "directory or explicitly disposition existing entries"
            )
    for output, declarations in outputs.items():
        for name, content in declarations.items():
            destination = output / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(content, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
