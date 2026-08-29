#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Build the one admitted direct runtime-user readiness query."""

from __future__ import annotations

import re


ACCOUNT = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


def direct_user_show_environment(
    runtime_account: str, runtime_uid: int, runtime_home: str
) -> list[str]:
    """Return the bounded, identity-bound local readiness query."""
    if (
        ACCOUNT.fullmatch(runtime_account) is None
        or type(runtime_uid) is not int
        or runtime_uid < 1
        or not runtime_home.startswith("/")
    ):
        raise ValueError("invalid runtime-user systemd identity")
    runtime_directory = f"/run/user/{runtime_uid}"
    return [
        "runuser",
        "--user",
        runtime_account,
        "--",
        "env",
        "-u",
        "CONTAINER_HOST",
        "-u",
        "CONTAINER_CONNECTION",
        f"HOME={runtime_home}",
        f"XDG_RUNTIME_DIR={runtime_directory}",
        f"DBUS_SESSION_BUS_ADDRESS=unix:path={runtime_directory}/bus",
        "systemctl",
        "--user",
        "show-environment",
    ]
