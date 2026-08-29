#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Immutable role and image contract for the disposable integration runtime."""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
from types import MappingProxyType
from typing import Mapping


API_IMAGE = "ghcr.io/secpal/api@sha256:5a095b27105691139b161ac0578ceae86e68b6821afadf7cb455fb86c8009c0e"
API_DIGEST = "sha256:5a095b27105691139b161ac0578ceae86e68b6821afadf7cb455fb86c8009c0e"
API_SOURCE_COMMIT = "87d1432389adac3a02574b399322928a77c5e67f"
FRONTEND_IMAGE = "ghcr.io/secpal/frontend@sha256:cdccded2eade53d9300aafff3a2663a779d3d158cfa74f1e9c182e5786285077"
FRONTEND_DIGEST = "sha256:cdccded2eade53d9300aafff3a2663a779d3d158cfa74f1e9c182e5786285077"
FRONTEND_SOURCE_COMMIT = "b755ca0d0ee5a85eca5ad5688d457241f070b1b4"


@dataclass(frozen=True)
class PostgresFixtureIdentity:
    """One immutable authority for the active disposable PostgreSQL fixture."""

    major: int
    version: str
    image: str
    platform_digests: Mapping[str, str]
    source: str
    data_directory: str
    volume_target: str

    def __post_init__(self) -> None:
        digest = r"sha256:[0-9a-f]{64}"
        if (
            self.major != 18
            or re.fullmatch(rf"{self.major}\.[1-9][0-9]*", self.version) is None
            or re.fullmatch(rf"docker\.io/library/postgres@{digest}", self.image)
            is None
            or set(self.platform_digests) != {"linux/amd64", "linux/arm64"}
            or any(
                re.fullmatch(digest, value) is None
                for value in self.platform_digests.values()
            )
            or re.fullmatch(
                rf"https://github\.com/docker-library/postgres\.git#[0-9a-f]{{40}}:"
                rf"{self.major}/bookworm",
                self.source,
            )
            is None
            or self.data_directory != f"/var/lib/postgresql/{self.major}/docker"
            or self.volume_target != "/var/lib/postgresql"
        ):
            raise ValueError("invalid canonical PostgreSQL integration fixture")


POSTGRES_FIXTURE = PostgresFixtureIdentity(
    major=18,
    version="18.6",
    image="docker.io/library/postgres@sha256:1c59e2c3c818eaa0f0628f695b36e7c9e362d6b219b36a54a32df645cbd7e1af",
    platform_digests=MappingProxyType(
        {
            "linux/amd64": "sha256:a10c981235b4f635e65df0cfb66a5598064628128505dbc6a3ed4ca303717521",
            "linux/arm64": "sha256:4d155aa3f2c2cc1838bb70e81396f76373ec7275ec9ce9cf32873cd677c9a992",
        }
    ),
    source=(
        "https://github.com/docker-library/postgres.git#"
        "e00e1bd34ec5c8a8e7ad89b273b3d42efaf6d5bc:18/bookworm"
    ),
    data_directory="/var/lib/postgresql/18/docker",
    volume_target="/var/lib/postgresql",
)
VALKEY_IMAGE = "docker.io/valkey/valkey@sha256:3acc0687f2a2e1091fae6450d7842dd658c941338cf0a873ddd9e14b9e4ea4dd"
CADDY_IMAGE = "docker.io/library/caddy@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d"
INTERNAL_NETWORKS = ("application", "edge")
VOLUME_NAMES = ("secrets", "private-storage", "postgres")
PRIVATE_STORAGE_MODE = 0o640
CONTAINER_PIDS_LIMIT = 512
CONTAINER_STOP_TIMEOUT = 30
CONTAINER_LOG_DRIVER = "journald"
CONTAINER_PODMAN_ARGS = (
    "--http-proxy=false",
    "--pid=private",
    "--ipc=private",
    "--uts=private",
)
PROXY_ENVIRONMENT_NAMES = frozenset(
    {
        "ALL_PROXY",
        "FTP_PROXY",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "all_proxy",
        "ftp_proxy",
        "http_proxy",
        "https_proxy",
        "no_proxy",
    }
)


@dataclass(frozen=True)
class PodmanVersion:
    """Normalized Podman release with SemVer-compatible prerelease ordering."""

    release: tuple[int, int, int]
    prerelease: tuple[tuple[int, int | str], ...] | None

    def ordering_key(
        self,
    ) -> tuple[int, int, int, int, tuple[tuple[int, int | str], ...]]:
        return (
            *self.release,
            1 if self.prerelease is None else 0,
            self.prerelease or (),
        )


def parse_podman_version(value: object) -> PodmanVersion:
    """Parse release/prerelease identity while ignoring build metadata."""

    match = re.fullmatch(
        r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
        r"(?:(?:-|~)([0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*))?"
        r"(?:\+([0-9A-Za-z]+(?:[.+-][0-9A-Za-z]+)*))?",
        str(value),
    )
    if match is None:
        raise ValueError("malformed Podman version")
    prerelease_text = match.group(4)
    prerelease = None
    if prerelease_text is not None:
        fragments = re.findall(r"[A-Za-z]+|[0-9]+", prerelease_text)
        if (
            not fragments
            or "".join(fragments) != re.sub(r"[.-]", "", prerelease_text)
        ):
            raise ValueError("malformed Podman prerelease")
        prerelease = tuple(
            (0, int(fragment)) if fragment.isdecimal() else (1, fragment.lower())
            for fragment in fragments
        )
    return PodmanVersion(
        tuple(int(match.group(index)) for index in (1, 2, 3)),
        prerelease,
    )


MINIMUM_PODMAN_VERSION = PodmanVersion((5, 4, 2), None)
MAXIMUM_PODMAN_VERSION = PodmanVersion((6, 0, 0), None)


def podman_version_supported(value: object) -> bool:
    try:
        version = parse_podman_version(value)
    except ValueError:
        return False
    return (
        MINIMUM_PODMAN_VERSION.ordering_key()
        <= version.ordering_key()
        < MAXIMUM_PODMAN_VERSION.ordering_key()
    )


def podman_versions_compatible(left: object, right: object) -> bool:
    try:
        return parse_podman_version(left) == parse_podman_version(right)
    except ValueError:
        return False


@dataclass(frozen=True)
class TmpfsSpec:
    """Effective tmpfs semantics that must survive Quadlet generation."""

    size: int
    mode: int
    noexec: bool = True

    def __post_init__(self) -> None:
        if self.size <= 0 or self.mode < 0 or self.mode > 0o7777:
            raise ValueError("invalid immutable tmpfs contract")

    def quadlet_mount(self, destination: str) -> str:
        if self.size % (1024 * 1024):
            raise ValueError("Quadlet tmpfs size must use whole mebibytes")
        options = (
            f"Mount=type=tmpfs,destination={destination},"
            f"tmpfs-size={self.size // (1024 * 1024)}m,"
            f"tmpfs-mode={self.mode:04o},U=true,nosuid=true,nodev=true"
        )
        return options + (",noexec=true" if self.noexec else "")


@dataclass(frozen=True)
class HealthSpec:
    """Closed health and systemd-readiness contract for one runtime role."""

    command: str
    interval_seconds: int
    timeout_seconds: int
    retries: int
    start_period_seconds: int

    def __post_init__(self) -> None:
        if (
            not self.command
            or min(
                self.interval_seconds,
                self.timeout_seconds,
                self.retries,
                self.start_period_seconds,
            )
            <= 0
        ):
            raise ValueError("invalid immutable health contract")

    def quadlet_lines(self) -> tuple[str, ...]:
        return (
            f"HealthCmd={self.command}",
            f"HealthInterval={self.interval_seconds}s",
            f"HealthTimeout={self.timeout_seconds}s",
            f"HealthRetries={self.retries}",
            f"HealthStartPeriod={self.start_period_seconds}s",
            "HealthOnFailure=kill",
            "Notify=healthy",
        )


GATEWAY_HEALTH_FAILURE_SPEC = HealthSpec("/bin/false", 1, 5, 1, 5)


@dataclass(frozen=True)
class ExecutionSpec:
    """Exact process override; omitted fields retain the verified image default."""

    entrypoint: tuple[str, ...] | None
    command: tuple[str, ...] | None

    def __post_init__(self) -> None:
        tokens = (*(self.entrypoint or ()), *(self.command or ()))
        if (
            not tokens
            or any(
                not isinstance(token, str)
                or re.fullmatch(r"[A-Za-z0-9_./,:=-]+", token) is None
                for token in tokens
            )
        ):
            raise ValueError("invalid immutable execution contract")

    def quadlet_lines(self) -> tuple[str, ...]:
        lines: list[str] = []
        if self.entrypoint is not None:
            encoded = json.dumps(self.entrypoint, separators=(",", ":"))
            lines.append(f"Entrypoint={encoded}")
        if self.command is not None:
            lines.append(f"Exec={' '.join(self.command)}")
        return tuple(lines)


_api_entrypoint = ("/bin/bash", "/run/secpal/container-entrypoint.sh")
ROLE_EXECUTION_SPECS: Mapping[str, ExecutionSpec] = MappingProxyType(
    {
        "secrets-init": ExecutionSpec(
            ("/bin/sh", "/run/secpal/quadlet-oneshot-entrypoint.sh"),
            ("/bin/bash", "/run/secpal/init-local-secrets.sh"),
        ),
        "valkey": ExecutionSpec(
            ("/bin/sh", "/run/secpal/valkey-entrypoint.sh"),
            None,
        ),
        "migrate": ExecutionSpec(
            ("/bin/sh", "/run/secpal/quadlet-oneshot-entrypoint.sh"),
            (
                "/bin/bash",
                "/run/secpal/container-entrypoint.sh",
                "php",
                "artisan",
                "migrate",
                "--force",
            ),
        ),
        "api": ExecutionSpec(
            _api_entrypoint,
            ("frankenphp", "run", "--config", "/etc/frankenphp/Caddyfile"),
        ),
        "worker-general": ExecutionSpec(
            _api_entrypoint,
            (
                "php",
                "artisan",
                "queue:work",
                "--queue=merkle,opentimestamp,default",
                "--sleep=1",
                "--tries=3",
                "--timeout=90",
            ),
        ),
        "worker-hash-chain": ExecutionSpec(
            _api_entrypoint,
            (
                "php",
                "artisan",
                "queue:work",
                "--queue=activity-hash-chain",
                "--sleep=1",
                "--tries=3",
                "--timeout=90",
            ),
        ),
        "scheduler": ExecutionSpec(
            _api_entrypoint,
            ("php", "artisan", "schedule:work"),
        ),
    }
)
MIGRATION_FAILURE_EXECUTION_SPEC = ExecutionSpec(
    ("/bin/sh", "/run/secpal/quadlet-oneshot-entrypoint.sh"),
    ("/bin/false",),
)
DEPENDENCY_FAILURE_EXECUTION_SPEC = ExecutionSpec(None, ("/bin/false",))


@dataclass(frozen=True)
class RoleSpec:
    uid: int
    gid: int
    networks: tuple[str, ...]
    tmpfs: Mapping[str, TmpfsSpec]
    health: HealthSpec | None = None


def _tmpfs(
    *entries: tuple[str, int, int, bool],
) -> Mapping[str, TmpfsSpec]:
    return MappingProxyType(
        {
            destination: TmpfsSpec(size_mib * 1024 * 1024, mode, noexec)
            for destination, size_mib, mode, noexec in entries
        }
    )


_api_tmpfs = _tmpfs(
    ("/tmp", 32, 0o700, True),
    ("/config", 16, 0o700, True),
    ("/data", 16, 0o700, True),
    ("/app/storage/app/public", 32, 0o750, False),
    ("/app/storage/framework/cache/data", 32, 0o750, True),
    ("/app/storage/framework/sessions", 32, 0o750, True),
    ("/app/storage/framework/views", 32, 0o750, True),
    ("/app/storage/logs", 32, 0o750, True),
    ("/app/bootstrap/cache", 16, 0o750, True),
)

ROLE_SPECS: Mapping[str, RoleSpec] = MappingProxyType(
    {
        "secrets-init": RoleSpec(
            0, 0, ("none",), _tmpfs(("/tmp", 16, 0o700, True))
        ),
        "postgres": RoleSpec(
            999,
            999,
            ("application",),
            _tmpfs(
                ("/tmp", 32, 0o700, True),
                ("/run/postgresql", 16, 0o750, True),
            ),
            HealthSpec(
                "pg_isready -U secpal_local -d secpal_local", 5, 3, 20, 10
            ),
        ),
        "valkey": RoleSpec(
            10002,
            10002,
            ("application",),
            _tmpfs(("/tmp", 16, 0o700, True), ("/data", 32, 0o700, True)),
            HealthSpec(
                "VALKEYCLI_AUTH=$(cat /run/secpal-secrets/valkey-password) "
                "valkey-cli ping | grep -qx PONG",
                5,
                3,
                20,
                5,
            ),
        ),
        "migrate": RoleSpec(10001, 10001, ("application",), _api_tmpfs),
        "api": RoleSpec(
            10001,
            10001,
            ("application", "edge"),
            _api_tmpfs,
            HealthSpec("/usr/local/bin/secpal-http-live", 10, 5, 12, 15),
        ),
        "worker-general": RoleSpec(10001, 10001, ("application",), _api_tmpfs),
        "worker-hash-chain": RoleSpec(
            10001, 10001, ("application",), _api_tmpfs
        ),
        "scheduler": RoleSpec(10001, 10001, ("application",), _api_tmpfs),
        "frontend": RoleSpec(
            101,
            101,
            ("edge",),
            _tmpfs(("/tmp", 32, 0o700, True)),
            HealthSpec(
                "curl --fail --silent --show-error --max-time 3 "
                "http://127.0.0.1:8080/health/live",
                10,
                5,
                12,
                5,
            ),
        ),
        "gateway": RoleSpec(
            10003,
            10003,
            ("edge",),
            _tmpfs(
                ("/tmp", 16, 0o700, True),
                ("/config", 16, 0o700, True),
                ("/data", 32, 0o700, True),
            ),
            HealthSpec(
                "wget --no-check-certificate -q -T 3 -O /dev/null "
                "https://app.secpal.example.invalid:8443/health/live",
                10,
                5,
                12,
                5,
            ),
        ),
    }
)

CONTAINER_ROLES = tuple(ROLE_SPECS)
TARGET_REQUIRED_ROLES = (
    "gateway",
    "worker-general",
    "worker-hash-chain",
    "scheduler",
)
REQUIRED_CONTAINER_UIDS = frozenset(spec.uid for spec in ROLE_SPECS.values())
REQUIRED_CONTAINER_GIDS = frozenset(spec.gid for spec in ROLE_SPECS.values())


def role_spec(role: str) -> RoleSpec:
    try:
        return ROLE_SPECS[role]
    except KeyError as error:
        raise ValueError(f"unknown integration role: {role}") from error


def role_execution_spec(
    role: str, failure_case: str | None = None
) -> ExecutionSpec | None:
    """Return only repository-defined overrides, never copied image defaults."""

    if role == "migrate" and failure_case == "migration":
        return MIGRATION_FAILURE_EXECUTION_SPEC
    if role == "postgres" and failure_case == "dependency":
        return DEPENDENCY_FAILURE_EXECUTION_SPEC
    return ROLE_EXECUTION_SPECS.get(role)


def tmpfs_mounts(role: str) -> list[str]:
    return [
        spec.quadlet_mount(destination)
        for destination, spec in role_spec(role).tmpfs.items()
    ]


def health_lines(role: str) -> tuple[str, ...]:
    health = role_spec(role).health
    if health is None:
        raise ValueError(f"role has no health contract: {role}")
    return health.quadlet_lines()
