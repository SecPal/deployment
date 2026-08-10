#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Render and validate the closed integration Quadlet contract."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile

sys.dont_write_bytecode = True

from integration_runtime_contract import (
    API_IMAGE,
    FRONTEND_IMAGE,
    GATEWAY_HEALTH_FAILURE_SPEC,
    INTERNAL_NETWORKS,
    POSTGRES_IMAGE,
    VALKEY_IMAGE,
    VOLUME_NAMES,
    health_lines,
    role_spec,
    tmpfs_mounts,
)

INSTANCE_PATTERN = re.compile(r"[a-z0-9]{8,24}\Z")
SAFE_PATH_PATTERN = re.compile(r"/[A-Za-z0-9._@+/-]*\Z")
FAILURE_CASES = ("migration", "dependency", "health")


class ContractError(ValueError):
    """Raised when a rendered Quadlet contract is unsafe or incomplete."""


def section(name: str, lines: list[str]) -> str:
    return f"[{name}]\n" + "\n".join(lines) + "\n"


def unit_description(
    description: str,
    dependencies: list[str] | None = None,
    part_of: str | None = None,
    start_limited: bool = False,
) -> str:
    lines = [f"Description={description}"]
    if part_of:
        lines.append(f"PartOf={part_of}")
    if dependencies:
        joined = " ".join(dependencies)
        lines.extend((f"Requires={joined}", f"After={joined}"))
    if start_limited:
        lines.extend(("StartLimitIntervalSec=60", "StartLimitBurst=3"))
    return section("Unit", lines)


def common_container(instance: str, role: str, image: str) -> list[str]:
    contract = role_spec(role)
    return [
        f"ContainerName=secpal-int-{instance}-{role}",
        f"Image={image}",
        "Pull=never",
        f"User={contract.uid}",
        f"Group={contract.gid}",
        "ReadOnly=true",
        "ReadOnlyTmpfs=false",
        "DropCapability=all",
        "NoNewPrivileges=true",
        "RunInit=true",
        "StopTimeout=30",
        "LogDriver=journald",
        "PidsLimit=512",
        "Label=org.secpal.integration=true",
        f"Label=org.secpal.integration.instance={instance}",
        f"Label=org.secpal.role={role}",
    ]


def service(restart: str = "on-failure") -> str:
    lines = [f"Restart={restart}", "TimeoutStartSec=180"]
    if restart != "no":
        lines.append("RestartSec=2")
    return section("Service", lines)


def network_lines(instance: str, role: str) -> list[str]:
    prefix = f"secpal-int-{instance}"
    return [
        "Network=none" if name == "none" else f"Network={prefix}-{name}.network"
        for name in role_spec(role).networks
    ]


def api_environment(port: int) -> list[str]:
    values = {
        "APP_DEBUG": "false",
        "APP_ENV": "local",
        "APP_NAME": "SecPal",
        "APP_URL": f"https://api.secpal.example.invalid:{port}",
        "CACHE_STORE": "redis",
        "DB_CONNECTION": "pgsql",
        "DB_DATABASE": "secpal_local",
        "DB_HOST": "postgres",
        "DB_PORT": "5432",
        "DB_USERNAME": "secpal_local",
        "FILESYSTEM_DISK": "local",
        "FRONTEND_URL": f"https://app.secpal.example.invalid:{port}",
        "LOG_CHANNEL": "stderr",
        "QUEUE_CONNECTION": "redis",
        "REDIS_CLIENT": "phpredis",
        "REDIS_CACHE_DB": "1",
        "REDIS_DB": "0",
        "REDIS_HOST": "valkey",
        "REDIS_PORT": "6379",
        "REDIS_QUEUE": "default",
        "REDIS_QUEUE_CONNECTION": "default",
        "SANCTUM_STATEFUL_DOMAINS": f"app.secpal.example.invalid:{port}",
        "CORS_ALLOWED_HEADERS": "Content-Type,Authorization,X-Requested-With,X-XSRF-TOKEN",
        "CORS_ALLOWED_METHODS": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
        "CORS_ALLOWED_ORIGINS": f"https://app.secpal.example.invalid:{port}",
        "CORS_SUPPORTS_CREDENTIALS": "true",
        "SESSION_DOMAIN": ".secpal.example.invalid",
        "SESSION_DRIVER": "database",
        "SESSION_HTTP_ONLY": "true",
        "SESSION_SAME_SITE": "lax",
        "SESSION_SECURE_COOKIE": "true",
        "TRUSTED_PROXIES": "REMOTE_ADDR",
    }
    return [f"Environment={name}={value}" for name, value in values.items()]


def api_container(
    instance: str,
    port: int,
    fixture_root: Path,
    role: str,
    command: str,
    *,
    oneshot: bool = False,
) -> str:
    prefix = f"secpal-int-{instance}"
    dependencies = [f"{prefix}-migrate.service"] if role != "migrate" else [
        f"{prefix}-postgres.service",
        f"{prefix}-valkey.service",
    ]
    lines = common_container(instance, role, API_IMAGE)
    lines.extend(api_environment(port))
    entrypoint = (
        '["/bin/sh","/run/secpal/quadlet-oneshot-entrypoint.sh"]'
        if oneshot
        else '["/bin/bash","/run/secpal/container-entrypoint.sh"]'
    )
    lines.extend(
        (
            f"Entrypoint={entrypoint}",
            f"Exec={command}",
            f"Mount=type=bind,source={fixture_root}/assets/container-entrypoint.sh,target=/run/secpal/container-entrypoint.sh,ro=true",
            f"Mount=type=bind,source={fixture_root}/assets/phase-b-runtime-probe.php,target=/run/secpal/phase-b-runtime-probe.php,ro=true",
            f"Volume={prefix}-secrets.volume:/run/secpal-secrets:ro",
            f"Volume={prefix}-private-storage.volume:/app/storage/app/private",
            *tmpfs_mounts(role),
        )
    )
    if oneshot:
        lines.append(
            f"Mount=type=bind,source={fixture_root}/assets/quadlet-oneshot-entrypoint.sh,target=/run/secpal/quadlet-oneshot-entrypoint.sh,ro=true"
        )
    lines.extend(network_lines(instance, role))
    lines.append(f"NetworkAlias={role}")
    if role_spec(role).health is not None:
        lines.extend(health_lines(role))
    service_lines = ["Restart=no", "TimeoutStartSec=180"] if oneshot else [
        "Restart=on-failure",
        "RestartSec=2",
        "TimeoutStartSec=180",
    ]
    if oneshot:
        service_lines.extend(("Type=oneshot", "RemainAfterExit=yes"))
    return unit_description(
        f"SecPal integration {role} ({instance})",
        dependencies,
        f"{prefix}.target",
        not oneshot,
    ) + section("Container", lines) + section("Service", service_lines)


def build_units(
    instance: str, port: int, fixture_root: Path, failure_case: str | None = None
) -> dict[str, str]:
    if failure_case is not None and failure_case not in FAILURE_CASES:
        raise ContractError("unsupported failure profile")
    prefix = f"secpal-int-{instance}"
    labels = [
        "Label=org.secpal.integration=true",
        f"Label=org.secpal.integration.instance={instance}",
    ]
    units: dict[str, str] = {}

    for name in INTERNAL_NETWORKS:
        network_section = [f"NetworkName={prefix}-{name}", *labels]
        network_section.append("Internal=true")
        units[f"{prefix}-{name}.network"] = unit_description(
            f"SecPal integration {name} network ({instance})",
            part_of=f"{prefix}.target",
        ) + section("Network", network_section)

    for name in VOLUME_NAMES:
        units[f"{prefix}-{name}.volume"] = unit_description(
            f"SecPal integration {name} volume ({instance})",
            part_of=f"{prefix}.target",
        ) + section("Volume", [f"VolumeName={prefix}-{name}", *labels])

    secret_dependencies: list[str] = []
    secret_lines = common_container(instance, "secrets-init", API_IMAGE)
    secret_lines.extend(
        (
            "AddCapability=CHOWN FOWNER",
            'Entrypoint=["/bin/sh","/run/secpal/quadlet-oneshot-entrypoint.sh"]',
            "Exec=/bin/bash /run/secpal/init-local-secrets.sh",
            "Environment=SECPAL_API_UID=10001",
            "Environment=SECPAL_API_GID=10001",
            "Environment=SECPAL_POSTGRES_UID=999",
            "Environment=SECPAL_VALKEY_UID=10002",
            "Environment=SECPAL_SECRET_DIR=/run/secpal-secrets",
            "Environment=SECPAL_POSTGRES_DATA_DIR=/var/lib/postgresql/data",
            "Environment=SECPAL_PRIVATE_STORAGE_DIR=/mnt/secpal-private-storage",
            f"Mount=type=bind,source={fixture_root}/assets/init-local-secrets.sh,target=/run/secpal/init-local-secrets.sh,ro=true",
            f"Mount=type=bind,source={fixture_root}/assets/quadlet-oneshot-entrypoint.sh,target=/run/secpal/quadlet-oneshot-entrypoint.sh,ro=true",
            f"Volume={prefix}-secrets.volume:/run/secpal-secrets",
            f"Volume={prefix}-postgres.volume:/var/lib/postgresql/data",
            f"Volume={prefix}-private-storage.volume:/mnt/secpal-private-storage",
            *tmpfs_mounts("secrets-init"),
            *network_lines(instance, "secrets-init"),
        )
    )
    units[f"{prefix}-secrets-init.container"] = (
        unit_description(
            f"SecPal integration secret initialization ({instance})",
            secret_dependencies,
            f"{prefix}.target",
        )
        + section("Container", secret_lines)
        + section("Service", ["Type=oneshot", "RemainAfterExit=yes", "Restart=no", "TimeoutStartSec=60"])
    )

    postgres_lines = common_container(instance, "postgres", POSTGRES_IMAGE)
    postgres_lines.extend(
        (
            "Environment=POSTGRES_DB=secpal_local",
            "Environment=POSTGRES_USER=secpal_local",
            "Environment=POSTGRES_PASSWORD_FILE=/run/secpal-secrets/postgres-password",
            f"Volume={prefix}-secrets.volume:/run/secpal-secrets:ro",
            f"Volume={prefix}-postgres.volume:/var/lib/postgresql/data",
            *tmpfs_mounts("postgres"),
            *network_lines(instance, "postgres"),
            "NetworkAlias=postgres",
            *health_lines("postgres"),
        )
    )
    if failure_case == "dependency":
        postgres_lines.append("Exec=/bin/false")
    units[f"{prefix}-postgres.container"] = (
        unit_description(
            f"SecPal integration PostgreSQL ({instance})",
            [f"{prefix}-secrets-init.service"],
            f"{prefix}.target",
            True,
        )
        + section("Container", postgres_lines)
        + service("no" if failure_case == "dependency" else "on-failure")
    )

    valkey_lines = common_container(instance, "valkey", VALKEY_IMAGE)
    valkey_lines.extend(
        (
            'Entrypoint=["/bin/sh","/run/secpal/valkey-entrypoint.sh"]',
            f"Mount=type=bind,source={fixture_root}/assets/valkey-entrypoint.sh,target=/run/secpal/valkey-entrypoint.sh,ro=true",
            f"Volume={prefix}-secrets.volume:/run/secpal-secrets:ro",
            *tmpfs_mounts("valkey"),
            *network_lines(instance, "valkey"),
            "NetworkAlias=valkey",
            *health_lines("valkey"),
        )
    )
    units[f"{prefix}-valkey.container"] = (
        unit_description(
            f"SecPal integration Valkey ({instance})",
            [f"{prefix}-secrets-init.service"],
            f"{prefix}.target",
            True,
        )
        + section("Container", valkey_lines)
        + service()
    )

    units[f"{prefix}-migrate.container"] = api_container(
        instance,
        port,
        fixture_root,
        "migrate",
        "/bin/false"
        if failure_case == "migration"
        else "/bin/bash /run/secpal/container-entrypoint.sh php artisan migrate --force",
        oneshot=True,
    )
    units[f"{prefix}-api.container"] = api_container(
        instance,
        port,
        fixture_root,
        "api",
        "frankenphp run --config /etc/frankenphp/Caddyfile",
    )
    units[f"{prefix}-worker-general.container"] = api_container(
        instance,
        port,
        fixture_root,
        "worker-general",
        "php artisan queue:work --queue=merkle,opentimestamp,default --sleep=1 --tries=3 --timeout=90",
    )
    units[f"{prefix}-worker-hash-chain.container"] = api_container(
        instance,
        port,
        fixture_root,
        "worker-hash-chain",
        "php artisan queue:work --queue=activity-hash-chain --sleep=1 --tries=3 --timeout=90",
    )
    units[f"{prefix}-scheduler.container"] = api_container(
        instance,
        port,
        fixture_root,
        "scheduler",
        "php artisan schedule:work",
    )

    frontend_lines = common_container(instance, "frontend", FRONTEND_IMAGE)
    frontend_lines.extend(
        (
            f"Environment=SECPAL_API_URL=https://api.secpal.example.invalid:{port}",
            *tmpfs_mounts("frontend"),
            *network_lines(instance, "frontend"),
            "NetworkAlias=frontend",
            *health_lines("frontend"),
        )
    )
    units[f"{prefix}-frontend.container"] = (
        unit_description(
            f"SecPal integration frontend ({instance})",
            part_of=f"{prefix}.target",
            start_limited=True,
        )
        + section("Container", frontend_lines)
        + service()
    )

    gateway_image = f"localhost/secpal-integration-gateway-{instance}:2.10.2"
    gateway_health = (
        GATEWAY_HEALTH_FAILURE_SPEC
        if failure_case == "health"
        else role_spec("gateway").health
    )
    if gateway_health is None:
        raise ContractError("gateway health contract is missing")
    gateway_lines = common_container(instance, "gateway", gateway_image)
    gateway_lines.extend(
        (
            "Environment=HOME=/config",
            "Environment=XDG_CONFIG_HOME=/config",
            "Environment=XDG_DATA_HOME=/data",
            f"Mount=type=bind,source={fixture_root}/assets/Caddyfile,target=/etc/caddy/Caddyfile,ro=true",
            *tmpfs_mounts("gateway"),
            *network_lines(instance, "gateway"),
            "NetworkAlias=gateway",
            f"PublishPort=127.0.0.1:{port}:8443",
            "AddHost=app.secpal.example.invalid:127.0.0.1",
            *gateway_health.quadlet_lines(),
        )
    )
    units[f"{prefix}-gateway.container"] = (
        unit_description(
            f"SecPal integration gateway fixture ({instance})",
            [f"{prefix}-api.service", f"{prefix}-frontend.service"],
            f"{prefix}.target",
            True,
        )
        + section("Container", gateway_lines)
        + service("no" if failure_case == "health" else "on-failure")
    )

    target_dependencies = [
        f"{prefix}-gateway.service",
        f"{prefix}-worker-general.service",
        f"{prefix}-worker-hash-chain.service",
        f"{prefix}-scheduler.service",
    ]
    units[f"{prefix}.target"] = unit_description(
        f"SecPal rootless Podman integration fixture ({instance})",
        target_dependencies,
    ) + section("Install", ["WantedBy=default.target"])
    return units


def validate_instance(value: str) -> str:
    if not INSTANCE_PATTERN.fullmatch(value):
        raise ContractError("instance must be 8-24 lowercase ASCII letters or digits")
    return value


def validate_port(value: str) -> int:
    if not value.isascii() or not value.isdecimal():
        raise ContractError("port must be an integer from 1024 through 65535")
    port = int(value)
    if not 1024 <= port <= 65535:
        raise ContractError("port must be an integer from 1024 through 65535")
    return port


def validate_fixture_root(value: str) -> Path:
    if not SAFE_PATH_PATTERN.fullmatch(value):
        raise ContractError(
            "fixture root must use a safe ASCII path without whitespace or Quadlet delimiters"
        )
    path = Path(value)
    if not path.is_absolute() or not path.is_dir() or path.is_symlink():
        raise ContractError("fixture root must be an existing canonical absolute directory")
    resolved = path.resolve(strict=True)
    if resolved != path:
        raise ContractError("fixture root must be canonical and contain no symlink component")
    return path


def validate_directory(
    path: Path,
    expected: dict[str, str],
    require_root_owned: bool,
    allow_unrelated: bool,
) -> None:
    if not path.is_absolute() or not path.is_dir() or path.is_symlink():
        raise ContractError("unit directory must be an existing absolute non-symlink directory")
    actual_paths = list(path.iterdir())
    actual_names = {item.name for item in actual_paths}
    if not set(expected) <= actual_names or (not allow_unrelated and actual_names != set(expected)):
        raise ContractError("unit directory is incomplete or contains an unreviewed entry")
    selected_paths = actual_paths if not allow_unrelated else [path / name for name in expected]
    for item in selected_paths:
        metadata = item.lstat()
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o644:
            raise ContractError(f"unsafe unit file metadata: {item.name}")
        if require_root_owned and (metadata.st_uid != 0 or metadata.st_gid != 0):
            raise ContractError(f"active unit is not root-owned: {item.name}")
        if item.read_text(encoding="utf-8") != expected[item.name]:
            raise ContractError(f"unit content differs from the reviewed contract: {item.name}")


def render(output: Path, fixture_root: Path, expected: dict[str, str]) -> None:
    if (
        not output.is_absolute()
        or output.exists()
        or output.resolve(strict=False) != output
        or fixture_root not in output.parents
        or not output.parent.is_dir()
        or output.parent.is_symlink()
        or output.parent.resolve(strict=True) != output.parent
    ):
        raise ContractError("output must be a canonical new directory inside the fixture root")
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    try:
        os.chmod(staging, 0o700)
        for name, content in expected.items():
            destination = staging / name
            destination.write_text(content, encoding="utf-8")
            destination.chmod(0o644)
        staging.rename(output)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    subparsers = root.add_subparsers(dest="action", required=True)
    for action in ("render", "validate"):
        command = subparsers.add_parser(action)
        command.add_argument("--instance", required=True)
        command.add_argument("--port", required=True)
        command.add_argument("--fixture-root", required=True)
        command.add_argument("--failure-case", choices=FAILURE_CASES)
        if action == "render":
            command.add_argument("--output", required=True)
        else:
            command.add_argument("--input", required=True)
            command.add_argument("--require-root-owned", action="store_true")
            command.add_argument("--allow-unrelated", action="store_true")
    return root


def main() -> int:
    arguments = parser().parse_args()
    try:
        instance = validate_instance(arguments.instance)
        port = validate_port(arguments.port)
        fixture_root = validate_fixture_root(arguments.fixture_root)
        expected = build_units(instance, port, fixture_root, arguments.failure_case)
        if arguments.action == "render":
            render(Path(arguments.output), fixture_root, expected)
        else:
            validate_directory(
                Path(arguments.input),
                expected,
                arguments.require_root_owned,
                arguments.allow_unrelated,
            )
    except (ContractError, OSError, UnicodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
