#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Immutable role and image contract for the disposable integration runtime."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping


API_IMAGE = "ghcr.io/secpal/api@sha256:5a095b27105691139b161ac0578ceae86e68b6821afadf7cb455fb86c8009c0e"
API_DIGEST = "sha256:5a095b27105691139b161ac0578ceae86e68b6821afadf7cb455fb86c8009c0e"
API_SOURCE_COMMIT = "87d1432389adac3a02574b399322928a77c5e67f"
FRONTEND_IMAGE = "ghcr.io/secpal/frontend@sha256:cdccded2eade53d9300aafff3a2663a779d3d158cfa74f1e9c182e5786285077"
FRONTEND_DIGEST = "sha256:cdccded2eade53d9300aafff3a2663a779d3d158cfa74f1e9c182e5786285077"
FRONTEND_SOURCE_COMMIT = "b755ca0d0ee5a85eca5ad5688d457241f070b1b4"
POSTGRES_IMAGE = "docker.io/library/postgres@sha256:38471f330eb885e04de130b768d6db4e10469e2311879c7e5c699f6d2d8a1c74"
VALKEY_IMAGE = "docker.io/valkey/valkey@sha256:3acc0687f2a2e1091fae6450d7842dd658c941338cf0a873ddd9e14b9e4ea4dd"
CADDY_IMAGE = "docker.io/library/caddy@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d"


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
class RoleSpec:
    uid: int
    gid: int
    networks: tuple[str, ...]
    tmpfs: Mapping[str, TmpfsSpec]


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
        ),
        "valkey": RoleSpec(
            10002,
            10002,
            ("application",),
            _tmpfs(("/tmp", 16, 0o700, True), ("/data", 32, 0o700, True)),
        ),
        "migrate": RoleSpec(10001, 10001, ("application",), _api_tmpfs),
        "api": RoleSpec(10001, 10001, ("application", "edge"), _api_tmpfs),
        "worker-general": RoleSpec(10001, 10001, ("application",), _api_tmpfs),
        "worker-hash-chain": RoleSpec(
            10001, 10001, ("application",), _api_tmpfs
        ),
        "scheduler": RoleSpec(10001, 10001, ("application",), _api_tmpfs),
        "frontend": RoleSpec(
            101, 101, ("edge",), _tmpfs(("/tmp", 32, 0o700, True))
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
        ),
    }
)

REQUIRED_CONTAINER_UIDS = frozenset(spec.uid for spec in ROLE_SPECS.values())
REQUIRED_CONTAINER_GIDS = frozenset(spec.gid for spec in ROLE_SPECS.values())


def role_spec(role: str) -> RoleSpec:
    try:
        return ROLE_SPECS[role]
    except KeyError as error:
        raise ValueError(f"unknown integration role: {role}") from error


def tmpfs_mounts(role: str) -> list[str]:
    return [
        spec.quadlet_mount(destination)
        for destination, spec in role_spec(role).tmpfs.items()
    ]
