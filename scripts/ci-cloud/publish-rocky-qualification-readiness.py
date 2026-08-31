#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Publish current-boot Rocky readiness after bounded runtime-user admission."""

from __future__ import annotations

import argparse
import json
import os
import pwd
import re
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable, NamedTuple

SCRIPT_DIRECTORY = str(Path(__file__).resolve().parent)
if SCRIPT_DIRECTORY not in sys.path:
    sys.path.insert(0, SCRIPT_DIRECTORY)
from runtime_user_systemd import direct_user_show_environment


RUNTIME_ACCOUNT = "secpal-runtime"
WAIT_SECONDS = 60
PROBE_INTERVAL_SECONDS = 5
MAX_PROBES = 13
COMMAND_TIMEOUT_SECONDS = 5
BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")
BOOT_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)


class RuntimeUserObservation(NamedTuple):
    manager_active: bool
    bus_available: bool
    control_reachable: bool


class RuntimeUserResult(NamedTuple):
    ready: bool
    observation: RuntimeUserObservation


def quiet_run(
    command: list[str],
    *,
    deadline: float,
    monotonic: Callable[[], float] = time.monotonic,
) -> bool:
    remaining = deadline - monotonic()
    if remaining <= 0:
        return False
    try:
        result = subprocess.run(
            command,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=min(COMMAND_TIMEOUT_SECONDS, remaining),
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def observe_runtime_user(
    *, deadline: float, monotonic: Callable[[], float] = time.monotonic
) -> RuntimeUserObservation:
    try:
        runtime = pwd.getpwnam(RUNTIME_ACCOUNT)
    except KeyError:
        return RuntimeUserObservation(False, False, False)

    runtime_uid = runtime.pw_uid
    manager_active = quiet_run(
        ["systemctl", "is-active", "--quiet", f"user@{runtime_uid}.service"],
        deadline=deadline,
        monotonic=monotonic,
    )
    try:
        bus_available = stat.S_ISSOCK(os.stat(f"/run/user/{runtime_uid}/bus").st_mode)
    except OSError:
        bus_available = False

    control_reachable = False
    if manager_active and bus_available:
        control_reachable = quiet_run(
            direct_user_show_environment(RUNTIME_ACCOUNT, runtime_uid, runtime.pw_dir),
            deadline=deadline,
            monotonic=monotonic,
        )
    return RuntimeUserObservation(manager_active, bus_available, control_reachable)


def wait_for_runtime_user(
    probe: Callable[[float], RuntimeUserObservation],
    *,
    deadline: float,
    interval: float,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> RuntimeUserResult:
    observation = RuntimeUserObservation(False, False, False)
    for probe_number in range(MAX_PROBES):
        if deadline - monotonic() <= 0:
            return RuntimeUserResult(False, observation)
        observation = probe(deadline)
        if all(observation):
            return RuntimeUserResult(True, observation)
        remaining = deadline - monotonic()
        if remaining <= 0 or probe_number + 1 == MAX_PROBES:
            return RuntimeUserResult(False, observation)
        sleep(min(interval, remaining))
    raise AssertionError("bounded runtime-user loop exhausted unexpectedly")


def current_boot_id() -> str:
    boot_id = BOOT_ID_PATH.read_text(encoding="ascii").strip()
    if BOOT_ID.fullmatch(boot_id) is None:
        raise RuntimeError("invalid current boot identity")
    return boot_id


def assemble_readiness(
    *,
    target_sha: str,
    trusted_control_sha: str,
    access_run_id: str,
    access_run_attempt: str,
    boot_id: str,
    ssh_public_key_sha256: str,
    result: RuntimeUserResult,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "target_sha": target_sha,
        "trusted_control_sha": trusted_control_sha,
        "access_run_id": access_run_id,
        "access_run_attempt": access_run_attempt,
        "boot_id": boot_id,
        "ssh_public_key_sha256": ssh_public_key_sha256,
        "cloud_identity_absent": True,
        "guest_startup_complete": result.ready,
        "runtime_user_manager_active": result.observation.manager_active,
        "runtime_user_bus_available": result.observation.bus_available,
        "runtime_user_control_reachable": result.observation.control_reachable,
    }


def atomic_publish(path: Path, document: dict[str, object]) -> None:
    encoded = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o440)
        os.fchown(descriptor, 0, pwd.getpwnam("secpal-cloud").pw_gid)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-sha", required=True)
    parser.add_argument("--trusted-control-sha", required=True)
    parser.add_argument("--access-run-id", required=True)
    parser.add_argument("--access-run-attempt", required=True)
    parser.add_argument("--boot-id", required=True)
    parser.add_argument("--ssh-public-key-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    if current_boot_id() != arguments.boot_id:
        raise RuntimeError("startup boot identity changed before readiness observation")
    result = wait_for_runtime_user(
        lambda deadline: observe_runtime_user(deadline=deadline),
        deadline=time.monotonic() + WAIT_SECONDS,
        interval=PROBE_INTERVAL_SECONDS,
    )
    if current_boot_id() != arguments.boot_id:
        raise RuntimeError("startup boot identity changed during readiness observation")
    document = assemble_readiness(
        target_sha=arguments.target_sha,
        trusted_control_sha=arguments.trusted_control_sha,
        access_run_id=arguments.access_run_id,
        access_run_attempt=arguments.access_run_attempt,
        boot_id=arguments.boot_id,
        ssh_public_key_sha256=arguments.ssh_public_key_sha256,
        result=result,
    )
    atomic_publish(arguments.output, document)
    return 0 if result.ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
