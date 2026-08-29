#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT
"""Observe bounded negative facts adjacent to the exact d892 daemon reload."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import re
import select
import signal
import stat
import subprocess
import tempfile
import time
from pathlib import Path
from typing import IO, Any


EVENT = re.compile(
    rb"^SECPAL_QUADLET_RELOAD_FAILURE_V3:([1-9][0-9]{0,2}):"
    rb"([1-9][0-9]{0,9}):"
    rb"(unavailable|[0-9]{1,19}):"
    rb"(unavailable|[0-9]{14}):"
    rb"(unavailable|[A-Za-z0-9=;._-]{1,384}):"
    rb"([1-9][0-9]{0,3}(?:,[1-9][0-9]{0,3}){0,7})\n$"
)
CLIENT_EVENT = re.compile(
    rb"^SECPAL_QUADLET_RELOAD_CLIENT_V1:([1-9][0-9]{0,9})\n$"
)
SHA = re.compile(r"^[0-9a-f]{40}$")
RUN_ID = re.compile(r"^[1-9][0-9]{0,19}$")
RUN_ATTEMPT = re.compile(r"^[1-9][0-9]{0,2}$")
BOOT_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
INPUT_NAME = re.compile(r"^secpal-host-qualification-[A-Za-z0-9]{6}\.container$")
SAFE_BASENAME = re.compile(r"^[A-Za-z0-9_.@+-]{1,128}$")
GENERATOR_MESSAGE = re.compile(
    r"^(?P<path>/[^\r\n]{1,384}) failed with exit status "
    r"(?P<status>[1-9][0-9]{0,2}), ignoring\.$"
)
MAX_INPUT_BYTES = 4_096
MAX_COMMAND_BYTES = 65_536
MAX_GENERATOR_RECORD_BYTES = 2_048
MAX_GENERATOR_CANDIDATE_RECORDS = 3
MAX_GENERATOR_JOURNAL_BYTES = (MAX_GENERATOR_RECORD_BYTES + 1) * (
    MAX_GENERATOR_CANDIDATE_RECORDS + 1
)
MAX_RELOAD_RECORD_BYTES = 2_048
MAX_RELOAD_CANDIDATE_RECORDS = 8
MAX_RELOAD_JOURNAL_BYTES = (MAX_RELOAD_RECORD_BYTES + 1) * (
    MAX_RELOAD_CANDIDATE_RECORDS + 1
)
MAX_OBSERVATION_BYTES = 8_192
COMMAND_TIMEOUT_SECONDS = 3
MANAGER_CONTINUITY_TIMEOUT_SECONDS = 2
PACKAGE_QUERY_TIMEOUT_SECONDS = 1
RELOAD_JOURNAL_TIMEOUT_SECONDS = 1
GENERATOR_TIMEOUT_SECONDS = 8
CAPTURE_DEADLINE_SECONDS = 22
RUNTIME_ACCOUNT = "secpal-runtime"
GENERATOR_CANDIDATES = (
    Path("/usr/lib/systemd/user-generators/podman-system-generator"),
    Path("/usr/local/lib/systemd/user-generators/podman-system-generator"),
    Path("/usr/lib/systemd/system-generators/podman-system-generator"),
)
ADMITTED_USER_GENERATOR_ROOTS = (
    Path("/run/systemd/user-generators"),
    Path("/etc/systemd/user-generators"),
    Path("/usr/local/lib/systemd/user-generators"),
    Path("/usr/lib/systemd/user-generators"),
)
ADMITTED_PODMAN_GENERATOR_ROOTS = (
    *ADMITTED_USER_GENERATOR_ROOTS,
    Path("/usr/lib/systemd/system-generators"),
)
GENERATOR_CODE_FUNC = "do_execute"
# Rocky's reviewed systemd 257 build records this compiled relative source path.
GENERATOR_CODE_FILE = "../src/shared/exec-util.c"
GENERATOR_OUTPUT_FIELDS = "_UID,_BOOT_ID,CODE_FUNC,CODE_FILE,MESSAGE"
ROCKY_SYSTEMD_SOURCE_RPM = "systemd-257-23.el10_2.2.rocky.0.1.src.rpm"
ADMITTED_SYSTEMD_NEVRAS = frozenset(
    {
        "systemd-257-23.el10_2.2.rocky.0.1.aarch64",
        "systemd-257-23.el10_2.2.rocky.0.1.x86_64",
    }
)
RELOAD_SPACE_MINIMUM_BYTES = 16 * 1024 * 1024
RELOAD_OUTPUT_FIELDS = "_PID,_BOOT_ID,CODE_FUNC,CODE_FILE,MESSAGE"
RELOAD_EVENT_SOURCES = (
    ("../src/core/dbus-manager.c", "log_caller"),
    ("../src/core/dbus-manager.c", "method_reload"),
    ("../src/core/main.c", "invoke_main_loop"),
    ("../src/core/manager.c", "manager_reload"),
    ("../src/core/manager-serialize.c", "manager_serialize"),
    ("../src/core/dbus.c", "bus_send_pending_reload_message"),
)
RELOAD_OBSERVATION_REASONS = frozenset(
    {
        "none",
        "journal-command-failed",
        "journal-timeout",
        "journal-output-bound-exceeded",
        "candidate-representation-invalid",
        "candidate-count-exceeded",
        "manager-pid-unavailable",
        "journal-cursor-unavailable",
        "request-client-unbound",
        "multiple-causes",
    }
)
GENERATOR_OBSERVATION_REASONS = frozenset(
    {
        "none",
        "journal-command-failed",
        "journal-timeout",
        "journal-output-bound-exceeded",
        "candidate-representation-invalid",
        "candidate-generator-unadmitted",
        "candidate-count-exceeded",
        "multiple-causes",
    }
)


class ObservationError(RuntimeError):
    """The failure-time observation could not stay inside its closed contract."""


def terminate_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        pass
    try:
        process.wait(timeout=2)
    except (OSError, subprocess.TimeoutExpired):
        pass


def command_status(command: list[str], *, timeout: int = COMMAND_TIMEOUT_SECONDS) -> int:
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        status = process.wait(timeout=timeout)
    except OSError:
        raise ObservationError("adjacency command could not execute")
    except subprocess.TimeoutExpired:
        terminate_group(process)
        raise ObservationError("adjacency command exceeded its timeout")
    if not 0 <= status <= 255:
        raise ObservationError("adjacency command status is outside its bound")
    return status


def bounded_command_output(
    command: list[str], *, timeout: int, max_bytes: int = MAX_COMMAND_BYTES
) -> tuple[int, bytes, str | None]:
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError:
        return 125, b"", "command-failed"
    assert process.stdout is not None
    descriptor = process.stdout.fileno()
    os.set_blocking(descriptor, False)
    deadline = time.monotonic() + timeout
    chunks: list[bytes] = []
    observed = 0
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, timeout)
            readable, _, _ = select.select([descriptor], [], [], remaining)
            if readable:
                chunk = os.read(descriptor, min(8_192, max_bytes + 1 - observed))
                if not chunk:
                    return (
                        process.wait(timeout=max(0.1, remaining)),
                        b"".join(chunks),
                        None,
                    )
                chunks.append(chunk)
                observed += len(chunk)
                if observed > max_bytes:
                    terminate_group(process)
                    return 125, b"", "output-bound-exceeded"
            elif process.poll() is not None:
                return process.returncode, b"".join(chunks), None
    except OSError:
        terminate_group(process)
        return 125, b"", "command-failed"
    except subprocess.TimeoutExpired:
        terminate_group(process)
        return 124, b"", "timeout"


def admitted_generator(path: Path, *, podman: bool = False) -> Path | None:
    roots = (
        ADMITTED_PODMAN_GENERATOR_ROOTS if podman else ADMITTED_USER_GENERATOR_ROOTS
    )
    try:
        link_metadata = path.lstat()
        parent_metadata = path.parent.lstat()
        parent_resolved = path.parent.resolve(strict=True)
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError:
        return None
    if (
        not any(path.is_relative_to(root) for root in roots)
        or parent_resolved != path.parent
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != 0
        or parent_metadata.st_gid != 0
        or parent_metadata.st_mode & 0o022
        or not (
            stat.S_ISREG(link_metadata.st_mode)
            or stat.S_ISLNK(link_metadata.st_mode)
        )
        or link_metadata.st_uid != 0
        or link_metadata.st_gid != 0
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or metadata.st_mode & 0o022
        or metadata.st_mode & 0o111 == 0
        or not SAFE_BASENAME.fullmatch(path.name)
    ):
        return None
    if podman and path.name != "podman-system-generator":
        return None
    return path


def podman_generator_path() -> Path | None:
    admitted = {
        resolved
        for candidate in GENERATOR_CANDIDATES
        if (resolved := admitted_generator(candidate, podman=True)) is not None
    }
    return next(iter(admitted)) if len(admitted) == 1 else None


def input_facts(runtime_uid: int) -> tuple[dict[str, Any], Path | None]:
    directory = Path(f"/etc/containers/systemd/users/{runtime_uid}")
    try:
        directory_metadata = directory.lstat()
        directory_admitted = (
            stat.S_ISDIR(directory_metadata.st_mode)
            and not stat.S_ISLNK(directory_metadata.st_mode)
            and directory_metadata.st_uid == 0
            and directory_metadata.st_gid == 0
            and not directory_metadata.st_mode & 0o022
            and directory.resolve(strict=True) == directory
        )
    except OSError:
        directory_admitted = False
    try:
        matches = (
            sorted(
                entry
                for entry in directory.iterdir()
                if INPUT_NAME.fullmatch(entry.name)
            )
            if directory_admitted
            else []
        )
    except OSError:
        matches = []
    facts: dict[str, Any] = {
        "match_count": min(len(matches), 2),
        "present": len(matches) == 1,
        "regular_file": False,
        "not_symlink": False,
        "owner_uid": None,
        "owner_gid": None,
        "mode": None,
        "size": None,
        "sha256": None,
    }
    if len(matches) != 1:
        return facts, None
    path = matches[0]
    try:
        metadata = path.lstat()
    except OSError:
        return facts, None
    facts.update(
        {
            "regular_file": stat.S_ISREG(metadata.st_mode),
            "not_symlink": not stat.S_ISLNK(metadata.st_mode),
            "owner_uid": metadata.st_uid,
            "owner_gid": metadata.st_gid,
            "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
            "size": min(metadata.st_size, MAX_INPUT_BYTES + 1),
        }
    )
    if not facts["regular_file"] or not facts["not_symlink"]:
        return facts, None
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        opened = os.fstat(descriptor)
        if (
            opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
            or opened.st_size > MAX_INPUT_BYTES
        ):
            return facts, None
        with os.fdopen(descriptor, "rb") as source:
            descriptor = -1
            payload = source.read(MAX_INPUT_BYTES + 1)
        if len(payload) > MAX_INPUT_BYTES:
            return facts, None
    except OSError:
        return facts, None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    facts["sha256"] = hashlib.sha256(payload).hexdigest()
    return facts, path


def generator_failures(
    payload: bytes, runtime_uid: int, boot_id: str
) -> tuple[list[dict[str, Any]], str]:
    failures: list[dict[str, Any]] = []
    reasons: set[str] = set()
    candidate_count = 0
    for raw_line in payload.splitlines():
        candidate_count += 1
        if candidate_count > MAX_GENERATOR_CANDIDATE_RECORDS:
            reasons.add("candidate-count-exceeded")
            continue
        if len(raw_line) > MAX_GENERATOR_RECORD_BYTES:
            reasons.add("candidate-representation-invalid")
            continue
        try:
            entry = json.loads(raw_line)
        except (UnicodeDecodeError, json.JSONDecodeError):
            reasons.add("candidate-representation-invalid")
            continue
        if not isinstance(entry, dict):
            reasons.add("candidate-representation-invalid")
            continue
        if str(entry.get("_UID")) != str(runtime_uid):
            reasons.add("candidate-representation-invalid")
            continue
        if entry.get("_BOOT_ID") != boot_id.replace("-", ""):
            reasons.add("candidate-representation-invalid")
            continue
        if (
            entry.get("CODE_FUNC") != GENERATOR_CODE_FUNC
            or entry.get("CODE_FILE") != GENERATOR_CODE_FILE
        ):
            reasons.add("candidate-representation-invalid")
            continue
        match = GENERATOR_MESSAGE.fullmatch(str(entry.get("MESSAGE", "")))
        if match is None:
            reasons.add("candidate-representation-invalid")
            continue
        generator_path = Path(match.group("path"))
        resolved = admitted_generator(
            generator_path,
            podman=generator_path.name == "podman-system-generator",
        )
        status = int(match.group("status"))
        if resolved is None or status > 255:
            reasons.add("candidate-generator-unadmitted")
            continue
        failure = {"basename": resolved.name, "exit_status": status}
        if failure not in failures:
            failures.append(failure)
    if not reasons:
        return failures, "none"
    if len(reasons) == 1:
        return failures, next(iter(reasons))
    return failures, "multiple-causes"


def generator_journal_command(
    runtime_uid: int, boot_id: str, journal_baseline: str
) -> list[str]:
    return [
        "journalctl",
        "--no-pager",
        "--output=json",
        f"--output-fields={GENERATOR_OUTPUT_FIELDS}",
        f"--boot={boot_id.replace('-', '')}",
        f"--since={journal_baseline}",
        f"_UID={runtime_uid}",
        f"CODE_FUNC={GENERATOR_CODE_FUNC}",
        f"CODE_FILE={GENERATOR_CODE_FILE}",
    ]


def generator_observation(
    status: int,
    payload: bytes,
    command_failure: str | None,
    runtime_uid: int,
    boot_id: str,
) -> tuple[list[dict[str, Any]], str]:
    if status == 0 and command_failure is None:
        return generator_failures(payload, runtime_uid, boot_id)
    reason = {
        "timeout": "journal-timeout",
        "output-bound-exceeded": "journal-output-bound-exceeded",
        "command-failed": "journal-command-failed",
    }.get(command_failure, "journal-command-failed")
    if reason not in GENERATOR_OBSERVATION_REASONS:
        return [], "candidate-representation-invalid"
    return [], reason


def empty_reload_stage_markers() -> dict[str, Any]:
    return {
        "reload_request_logged": False,
        "reload_request_client_pid": None,
        "reload_rate_limit_rejected": False,
        "reload_started": False,
        "reload_finished": False,
        "reload_internal_failure": "none",
        "reload_reply_send_failed": False,
    }


def reload_journal_command(
    manager_pid: int, boot_id: str, journal_cursor: str
) -> list[str]:
    command = [
        "journalctl",
        "--no-pager",
        "--output=json",
        f"--output-fields={RELOAD_OUTPUT_FIELDS}",
        f"--boot={boot_id.replace('-', '')}",
        f"--after-cursor={journal_cursor}",
    ]
    for index, (code_file, code_func) in enumerate(RELOAD_EVENT_SOURCES):
        if index:
            command.append("+")
        command.extend(
            [
                f"_PID={manager_pid}",
                f"CODE_FUNC={code_func}",
                f"CODE_FILE={code_file}",
            ]
        )
    return command


def reload_stage_markers(
    payload: bytes, manager_pid: int, boot_id: str, expected_client_pid: int
) -> tuple[dict[str, Any], str]:
    facts = empty_reload_stage_markers()
    reasons: set[str] = set()
    internal_failures: set[str] = set()
    request_client_pids: set[int] = set()
    stage_counts: dict[int, int] = {}
    last_stage = -1
    candidate_count = 0
    for raw_line in payload.splitlines():
        candidate_count += 1
        if candidate_count > MAX_RELOAD_CANDIDATE_RECORDS:
            reasons.add("candidate-count-exceeded")
            continue
        if len(raw_line) > MAX_RELOAD_RECORD_BYTES:
            reasons.add("candidate-representation-invalid")
            continue
        try:
            entry = json.loads(raw_line)
        except (UnicodeDecodeError, json.JSONDecodeError):
            reasons.add("candidate-representation-invalid")
            continue
        if not isinstance(entry, dict):
            reasons.add("candidate-representation-invalid")
            continue
        code_file = entry.get("CODE_FILE")
        code_func = entry.get("CODE_FUNC")
        message = entry.get("MESSAGE")
        if (
            str(entry.get("_PID")) != str(manager_pid)
            or entry.get("_BOOT_ID") != boot_id.replace("-", "")
            or (code_file, code_func) not in RELOAD_EVENT_SOURCES
            or not isinstance(message, str)
            or len(message.encode("utf-8")) > 1_024
        ):
            reasons.add("candidate-representation-invalid")
            continue

        if (code_file, code_func) == ("../src/core/dbus-manager.c", "log_caller"):
            request = re.fullmatch(
                r"Reload requested from client PID (?P<pid>[1-9][0-9]{0,9})"
                r"(?: \('[A-Za-z0-9_.@+-]{1,64}'\))?"
                r"(?: \(unit [A-Za-z0-9_.@+-]{1,128}\))?\.\.\.",
                message,
            )
            if request is not None and int(request.group("pid")) <= 2**31 - 1:
                stage_counts[0] = stage_counts.get(0, 0) + 1
                if stage_counts[0] > 1 or last_stage >= 0:
                    reasons.add("multiple-causes")
                last_stage = max(last_stage, 0)
                request_client_pids.add(int(request.group("pid")))
                facts["reload_request_logged"] = True
                continue
        elif (code_file, code_func) == (
            "../src/core/dbus-manager.c",
            "method_reload",
        ):
            if message == "Reloading request rejected due to rate limit.":
                stage_counts[1] = stage_counts.get(1, 0) + 1
                if stage_counts[1] > 1 or last_stage > 1:
                    reasons.add("multiple-causes")
                last_stage = max(last_stage, 1)
                facts["reload_rate_limit_rejected"] = True
                continue
        elif (code_file, code_func) == ("../src/core/main.c", "invoke_main_loop"):
            if message == "Reloading...":
                stage_counts[2] = stage_counts.get(2, 0) + 1
                if stage_counts[2] > 1 or last_stage > 2:
                    reasons.add("multiple-causes")
                last_stage = max(last_stage, 2)
                facts["reload_started"] = True
                continue
            if re.fullmatch(r"Reloading finished in [0-9]{1,12} ms\.", message):
                stage_counts[4] = stage_counts.get(4, 0) + 1
                if stage_counts[4] > 1 or last_stage > 4:
                    reasons.add("multiple-causes")
                last_stage = max(last_stage, 4)
                facts["reload_finished"] = True
                continue
        elif (code_file, code_func) == ("../src/core/manager.c", "manager_reload"):
            internal_reason: str | None = None
            if message.startswith("Failed to create serialization file: "):
                internal_reason = "serialization-file-failed"
            elif message == "Out of memory.":
                internal_reason = "resource-allocation-failed"
            elif message.startswith("Failed to seek to beginning of serialization: "):
                internal_reason = "serialization-seek-failed"
            if internal_reason is not None:
                stage_counts[3] = stage_counts.get(3, 0) + 1
                if stage_counts[3] > 1 or last_stage > 3:
                    reasons.add("multiple-causes")
                last_stage = max(last_stage, 3)
                internal_failures.add(internal_reason)
                continue
        elif (code_file, code_func) == (
            "../src/core/manager-serialize.c",
            "manager_serialize",
        ):
            internal_reason = None
            if message == "Out of memory.":
                internal_reason = "resource-allocation-failed"
            if message.startswith((
                "Failed to flush serialization: ",
                "Failed to add bus sockets to serialization: ",
            )):
                internal_reason = "serialization-failed"
            if internal_reason is not None:
                stage_counts[3] = stage_counts.get(3, 0) + 1
                if stage_counts[3] > 1 or last_stage > 3:
                    reasons.add("multiple-causes")
                last_stage = max(last_stage, 3)
                internal_failures.add(internal_reason)
                continue
        elif (code_file, code_func) == (
            "../src/core/dbus.c",
            "bus_send_pending_reload_message",
        ):
            if message.startswith("Failed to send queued reload message, ignoring: "):
                stage_counts[5] = stage_counts.get(5, 0) + 1
                if stage_counts[5] > 1:
                    reasons.add("multiple-causes")
                last_stage = max(last_stage, 5)
                facts["reload_reply_send_failed"] = True
                continue
        reasons.add("candidate-representation-invalid")

    if len(internal_failures) == 1:
        facts["reload_internal_failure"] = next(iter(internal_failures))
    elif len(internal_failures) > 1:
        reasons.add("multiple-causes")
    if len(request_client_pids) == 1:
        facts["reload_request_client_pid"] = next(iter(request_client_pids))
        if facts["reload_request_client_pid"] != expected_client_pid:
            reasons.add("request-client-unbound")
    elif len(request_client_pids) > 1:
        reasons.add("multiple-causes")
    if facts["reload_rate_limit_rejected"] and (
        facts["reload_started"]
        or facts["reload_finished"]
        or facts["reload_internal_failure"] != "none"
        or facts["reload_reply_send_failed"]
    ):
        reasons.add("candidate-representation-invalid")
    if facts["reload_internal_failure"] != "none" and (
        facts["reload_finished"] or facts["reload_reply_send_failed"]
    ):
        reasons.add("candidate-representation-invalid")
    if not reasons:
        return facts, "none"
    if len(reasons) == 1:
        return facts, next(iter(reasons))
    return facts, "multiple-causes"


def reload_stage_observation(
    status: int,
    payload: bytes,
    command_failure: str | None,
    manager_pid: int,
    boot_id: str,
    expected_client_pid: int,
) -> tuple[dict[str, Any], str]:
    if status == 0 and command_failure is None:
        return reload_stage_markers(
            payload, manager_pid, boot_id, expected_client_pid
        )
    reason = {
        "timeout": "journal-timeout",
        "output-bound-exceeded": "journal-output-bound-exceeded",
        "command-failed": "journal-command-failed",
    }.get(command_failure, "journal-command-failed")
    return empty_reload_stage_markers(), reason


def selinux_adjacency(
    payload: bytes,
    input_path: Path | None,
    generator_basenames: set[str],
) -> tuple[bool, dict[str, str] | None, bool]:
    observations: list[dict[str, str]] = []
    input_tokens = set()
    if input_path is not None:
        input_tokens = {str(input_path), input_path.name}
    for event in payload.decode("utf-8", errors="replace").split("----"):
        if "avc:  denied" not in event or "permissive=0" not in event:
            continue
        relevant = any(token and token in event for token in input_tokens) or any(
            marker in event
            for marker in (
                'comm="podman-system-g"',
                "podman-system-generator",
                *generator_basenames,
            )
        )
        if not relevant:
            continue
        context = re.search(
            r"scontext=([^\s]+).*tcontext=([^\s]+).*tclass=([a-z_]{1,32})",
            event,
            re.DOTALL,
        )
        permission = re.search(r"avc:\s+denied\s+\{\s*([a-z_]{1,32})", event)
        if context is None or permission is None:
            return True, None, True
        source = context.group(1).split(":")
        target = context.group(2).split(":")
        if len(source) < 3 or len(target) < 3:
            return True, None, True
        observation = {
            "source_type": source[2],
            "target_type": target[2],
            "object_class": context.group(3),
            "denied_permission": permission.group(1),
        }
        if observation not in observations:
            observations.append(observation)
    if not observations:
        return False, None, False
    return True, observations[0], len(observations) > 1


def run_space_observation() -> tuple[bool, int | None]:
    try:
        filesystem = os.statvfs("/run/systemd")
    except OSError:
        return False, None
    free_bytes = filesystem.f_bfree * filesystem.f_bsize
    if not 0 <= free_bytes <= 2**63 - 1:
        return False, None
    return True, free_bytes


def systemd_package_identity() -> str | None:
    status, payload, failure = bounded_command_output(
        [
            "rpm",
            "-q",
            "--qf",
            "%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\\n",
            "systemd",
        ],
        timeout=PACKAGE_QUERY_TIMEOUT_SECONDS,
        max_bytes=128,
    )
    if status != 0 or failure is not None:
        return None
    try:
        value = payload.decode("ascii").strip()
    except UnicodeDecodeError:
        return None
    return value if value in ADMITTED_SYSTEMD_NEVRAS else None


def manager_state(runtime_uid: int) -> tuple[bool, bool, int | None]:
    status, payload, failure = bounded_command_output(
        [
            "systemctl",
            "show",
            f"user@{runtime_uid}.service",
            "--property=ActiveState",
            "--property=MainPID",
        ],
        timeout=MANAGER_CONTINUITY_TIMEOUT_SECONDS,
        max_bytes=128,
    )
    if status != 0 or failure is not None:
        return False, False, None
    try:
        values = dict(
            line.split("=", 1)
            for line in payload.decode("ascii").splitlines()
            if "=" in line
        )
    except UnicodeDecodeError:
        return False, False, None
    if set(values) != {"ActiveState", "MainPID"}:
        return False, False, None
    if values["ActiveState"] != "active":
        return True, False, None
    if re.fullmatch(r"[1-9][0-9]{0,9}", values["MainPID"]) is None:
        return False, False, None
    value = int(values["MainPID"])
    if value > 2**31 - 1:
        return False, False, None
    return True, True, value


def process_selinux_type(pid: int) -> str | None:
    try:
        payload = Path(f"/proc/{pid}/attr/current").read_bytes()
    except OSError:
        return None
    if len(payload) > 512:
        return None
    try:
        fields = payload.decode("ascii").strip().split(":")
    except UnicodeDecodeError:
        return None
    if len(fields) < 3 or re.fullmatch(r"[A-Za-z0-9_]{1,64}", fields[2]) is None:
        return None
    return fields[2]


def reload_access_avc(
    payload: bytes,
    expected_client_pid: int,
) -> tuple[bool, dict[str, str] | None, bool]:
    observations: list[dict[str, str]] = []
    for event in payload.decode("utf-8", errors="replace").split("----"):
        if (
            "avc:  denied" not in event
            or "permissive=0" not in event
            or "tclass=system" not in event
            or re.search(r"avc:\s+denied\s+\{\s*reload\s*\}", event) is None
        ):
            continue
        pids = {
            int(match)
            for match in re.findall(r"\bpid=([1-9][0-9]{0,9})\b", event)
            if int(match) <= 2**31 - 1
        }
        if len(pids) != 1:
            return True, None, True
        if next(iter(pids)) != expected_client_pid:
            continue
        context = re.search(
            r"scontext=([^\s]+).*tcontext=([^\s]+).*tclass=(system)",
            event,
            re.DOTALL,
        )
        if context is None:
            return True, None, True
        source = context.group(1).split(":")
        target = context.group(2).split(":")
        if len(source) < 3 or len(target) < 3:
            return True, None, True
        observation = {
            "source_type": source[2],
            "target_type": target[2],
            "object_class": "system",
            "denied_permission": "reload",
        }
        if observation not in observations:
            observations.append(observation)
    if not observations:
        return False, None, False
    return True, observations[0], len(observations) > 1


def collect_observation(
    arguments: argparse.Namespace,
    failure_status: int,
    event: bytes,
    run_space_before: tuple[bool, int | None],
    control_pid: int,
    journal_cursor: str | None,
    audit_baseline: str | None,
    expected_client_pid: int,
) -> dict[str, Any]:
    runtime = pwd.getpwnam(RUNTIME_ACCOUNT)
    runtime_uid = runtime.pw_uid
    bus_path = Path(f"/run/user/{runtime_uid}/bus")
    manager_state_observed, manager_active, manager_pid = manager_state(runtime_uid)
    try:
        bus_available = stat.S_ISSOCK(bus_path.stat().st_mode)
        bus_state_observed = True
    except FileNotFoundError:
        bus_available = False
        bus_state_observed = True
    except OSError:
        bus_available = False
        bus_state_observed = False
    control_status = command_status(
        [
            "systemctl",
            f"--machine={RUNTIME_ACCOUNT}@.host",
            "--user",
            "show-environment",
        ],
        timeout=MANAGER_CONTINUITY_TIMEOUT_SECONDS,
    )
    control_reachable = control_status == 0
    manager_continuity_observed = (
        manager_state_observed and bus_state_observed and control_status != 125
    )
    manager_selinux_type = (
        process_selinux_type(manager_pid) if manager_pid is not None else None
    )
    control_selinux_type = process_selinux_type(control_pid)
    systemd_nevra = systemd_package_identity()
    run_space_after = run_space_observation()
    quadlet_input, input_path = input_facts(runtime_uid)
    generator = podman_generator_path()
    generator_executed = input_path is not None and generator is not None
    generator_status: int | None = None
    if generator_executed:
        generator_status = command_status(
            [
                "runuser",
                "--user",
                RUNTIME_ACCOUNT,
                "--",
                "env",
                f"HOME={runtime.pw_dir}",
                f"XDG_RUNTIME_DIR=/run/user/{runtime_uid}",
                f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{runtime_uid}/bus",
                f"QUADLET_UNIT_DIRS={input_path.parent}",
                str(generator),
                "--user",
                "--dryrun",
            ],
            timeout=GENERATOR_TIMEOUT_SECONDS,
        )
    journal_status, journal, journal_failure = bounded_command_output(
        generator_journal_command(
            runtime_uid, arguments.boot_id, arguments.journal_baseline
        ),
        timeout=COMMAND_TIMEOUT_SECONDS,
        max_bytes=MAX_GENERATOR_JOURNAL_BYTES,
    )
    failures, generator_reason = generator_observation(
        journal_status,
        journal,
        journal_failure,
        runtime_uid,
        arguments.boot_id,
    )
    generator_ambiguous = generator_reason != "none"
    if manager_pid is None:
        reload_facts = empty_reload_stage_markers()
        reload_reason = "manager-pid-unavailable"
    elif journal_cursor is None:
        reload_facts = empty_reload_stage_markers()
        reload_reason = "journal-cursor-unavailable"
    else:
        reload_status, reload_journal, reload_failure = bounded_command_output(
            reload_journal_command(
                manager_pid, arguments.boot_id, journal_cursor
            ),
            timeout=RELOAD_JOURNAL_TIMEOUT_SECONDS,
            max_bytes=MAX_RELOAD_JOURNAL_BYTES,
        )
        reload_facts, reload_reason = reload_stage_observation(
            reload_status,
            reload_journal,
            reload_failure,
            manager_pid,
            arguments.boot_id,
            expected_client_pid,
        )
    if audit_baseline is None:
        audit_status, audit = 125, b""
    else:
        audit_date = (
            f"{audit_baseline[4:6]}/{audit_baseline[6:8]}/{audit_baseline[0:4]}"
        )
        audit_time = (
            f"{audit_baseline[8:10]}:{audit_baseline[10:12]}:{audit_baseline[12:14]}"
        )
        audit_status, audit, _ = bounded_command_output(
            ["ausearch", "-m", "AVC", "-ts", audit_date, audit_time, "-i"],
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
    avc_observed, avc, avc_ambiguous = (
        selinux_adjacency(
            audit,
            input_path,
            {str(failure["basename"]) for failure in failures},
        )
        if audit_status in (0, 1)
        else (False, None, True)
    )
    reload_avc_observed, reload_avc, reload_avc_ambiguous = (
        reload_access_avc(audit, expected_client_pid)
        if audit_status in (0, 1)
        else (False, None, True)
    )
    run_space_success = run_space_before[0] and run_space_after[0]
    run_space_free = (
        min(run_space_before[1], run_space_after[1])
        if run_space_success
        and run_space_before[1] is not None
        and run_space_after[1] is not None
        else None
    )
    return {
        "schema_version": 1,
        "target_sha": arguments.target_sha,
        "trusted_control_sha": arguments.control_sha,
        "qualification_run_id": arguments.run_id,
        "qualification_run_attempt": arguments.run_attempt,
        "boot_id": arguments.boot_id,
        "failure_status": failure_status,
        "failure_event_sha256": hashlib.sha256(event).hexdigest(),
        "captured_before_cleanup": True,
        "capture_monotonic_ns": time.monotonic_ns(),
        "manager_continuity_observed": manager_continuity_observed,
        "manager_active_after_reload_failure": manager_active,
        "bus_available_after_reload_failure": bus_available,
        "control_reachable_after_reload_failure": control_reachable,
        "manager_pid": manager_pid,
        "control_process_pid": control_pid,
        "control_process_selinux_type": control_selinux_type,
        "manager_process_selinux_type": manager_selinux_type,
        "systemd_nevra": systemd_nevra,
        "run_systemd_statvfs_success": run_space_success,
        "run_systemd_free_bytes": run_space_free,
        "run_systemd_reload_minimum_bytes": RELOAD_SPACE_MINIMUM_BYTES,
        "run_systemd_space_sufficient": bool(
            run_space_success
            and run_space_free is not None
            and run_space_free >= RELOAD_SPACE_MINIMUM_BYTES
        ),
        "quadlet_input": quadlet_input,
        "podman_generator_executed": generator_executed,
        "podman_generator_exit_status": generator_status,
        "podman_generator_accepted_actual_input": generator_status == 0,
        "generator_failures": failures,
        "generator_failure_ambiguous": generator_ambiguous,
        "generator_observation_reason": generator_reason,
        **reload_facts,
        "reload_journal_observation_reason": reload_reason,
        "reload_access_avc_observed": reload_avc_observed,
        "reload_access_avc": reload_avc,
        "reload_access_avc_ambiguous": reload_avc_ambiguous,
        "selinux_avc_observed": avc_observed,
        "selinux_avc": avc,
        "selinux_avc_ambiguous": avc_ambiguous,
    }


def write_document(path: Path, document: dict[str, Any], deadline: float) -> None:
    encoded = (
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    if len(encoded) > MAX_OBSERVATION_BYTES:
        raise ObservationError("adjacency observation exceeds its byte bound")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".reload-adjacency.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as temporary:
            temporary.write(encoded)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.chmod(temporary_name, 0o600)
        if time.monotonic() > deadline:
            raise ObservationError("adjacency publication missed its pre-cleanup bound")
        os.replace(temporary_name, path)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def admitted_fifo(path: Path, flags: int) -> IO[bytes]:
    descriptor = os.open(path, flags | os.O_CLOEXEC | os.O_NOFOLLOW)
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISFIFO(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        os.close(descriptor)
        raise ObservationError("adjacency channel is outside the closed contract")
    mode = "rb" if flags == os.O_RDONLY else "wb"
    return os.fdopen(descriptor, mode, buffering=0)


def observe(arguments: argparse.Namespace) -> int:
    acknowledgement: IO[bytes] | None = None
    try:
        event_channel = admitted_fifo(arguments.event, os.O_RDONLY)
        acknowledgement = admitted_fifo(arguments.ack, os.O_WRONLY)
        with event_channel:
            client_event = event_channel.readline(65)
            event = event_channel.readline(513)
        client_match = CLIENT_EVENT.fullmatch(client_event)
        if client_match is None or len(client_event) > 64:
            raise ObservationError("daemon-reload client identity is malformed")
        expected_client_pid = int(client_match.group(1))
        match = EVENT.fullmatch(event)
        if match is None or len(event) > 512:
            raise ObservationError("daemon-reload event is malformed")
        failure_status = int(match.group(1))
        control_pid = int(match.group(2))
        run_space_raw = match.group(3).decode("ascii")
        audit_raw = match.group(4).decode("ascii")
        cursor_raw = match.group(5).decode("ascii")
        frames = {int(frame) for frame in match.group(6).split(b",")}
        if (
            failure_status > 255
            or control_pid > 2**31 - 1
            or expected_client_pid > 2**31 - 1
            or 242 not in frames
        ):
            raise ObservationError("daemon-reload event is outside the exact call site")
        run_space_before = (
            (True, int(run_space_raw))
            if run_space_raw != "unavailable"
            else (False, None)
        )
        if run_space_before[1] is not None and run_space_before[1] > 2**63 - 1:
            raise ObservationError("daemon-reload run space is outside its bound")
        deadline = time.monotonic() + CAPTURE_DEADLINE_SECONDS
        document = collect_observation(
            arguments,
            failure_status,
            client_event + event,
            run_space_before,
            control_pid,
            cursor_raw if cursor_raw != "unavailable" else None,
            audit_raw if audit_raw != "unavailable" else None,
            expected_client_pid,
        )
        write_document(arguments.output, document, deadline)
        acknowledgement.write(b"SECPAL_RELOAD_ADJACENCY_CAPTURED_V1\n")
        return 0
    except (OSError, ObservationError, KeyError, pwd.error, ValueError):
        if acknowledgement is not None:
            try:
                acknowledgement.write(b"SECPAL_RELOAD_ADJACENCY_FAILED_V1\n")
            except OSError:
                pass
        return 1
    finally:
        if acknowledgement is not None:
            acknowledgement.close()


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--event", required=True, type=Path)
    result.add_argument("--ack", required=True, type=Path)
    result.add_argument("--output", required=True, type=Path)
    result.add_argument("--target-sha", required=True)
    result.add_argument("--control-sha", required=True)
    result.add_argument("--run-id", required=True)
    result.add_argument("--run-attempt", required=True)
    result.add_argument("--boot-id", required=True)
    result.add_argument("--journal-baseline", required=True)
    return result


def main() -> int:
    arguments = parser().parse_args()
    if (
        SHA.fullmatch(arguments.target_sha) is None
        or SHA.fullmatch(arguments.control_sha) is None
        or RUN_ID.fullmatch(arguments.run_id) is None
        or RUN_ATTEMPT.fullmatch(arguments.run_attempt) is None
        or BOOT_ID.fullmatch(arguments.boot_id) is None
    ):
        return 64
    return observe(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
