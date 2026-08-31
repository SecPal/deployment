#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Capture and emit one bounded, inert target-phase failure diagnostic."""

from __future__ import annotations

import json
import os
import re
import signal
import stat
import sys
from pathlib import Path


MAX_CAPTURE_BYTES = 16 * 1024
MAX_EMITTED_BYTES = 8 * 1024
PHASES = frozenset({"host", "workload-prepare-start", "workload-cleanup"})
OUTPUT_PREFIX = "Target phase diagnostic: "
TARGET_STAGE_PREFIX = b"SECPAL_TARGET_DIAGNOSTIC_V1:"
TARGET_FAILURE_PREFIX = b"SECPAL_TARGET_DIAGNOSTIC_FAILURE_V1:"
NO_COMMAND_STATUS = "none"
MAX_STAGE_LINE_BYTES = (
    len(TARGET_FAILURE_PREFIX)
    + 64
    + 1
    + 64
    + 1
    + max(3, len(NO_COMMAND_STATUS.encode("ascii")))
)
PHASE_STAGES = {
    "host": frozenset({"host-contract"}),
    "workload-prepare-start": frozenset(
        {
            "workload-target-entrypoint",
            "workload-fixture-initialization",
            "workload-runtime-admission",
            "workload-gh-cli-staging",
            "workload-api-attestation-fetch",
            "workload-api-attestation-verify",
            "workload-api-image-pull",
            "workload-api-image-admission",
            "workload-api-image-alias",
            "workload-frontend-attestation-fetch",
            "workload-frontend-attestation-verify",
            "workload-frontend-image-pull",
            "workload-frontend-image-admission",
            "workload-frontend-image-alias",
            "workload-postgres-image-pull",
            "workload-postgres-image-admission",
            "workload-postgres-major-admission",
            "workload-postgres-image-alias",
            "workload-caddy-image-pull",
            "workload-caddy-image-admission",
            "workload-gateway-build",
            "workload-gateway-image-admission",
            "workload-quadlet-render-publish",
        }
    ),
    "workload-cleanup": frozenset({"workload-cleanup"}),
}
ADMITTED_STAGES = frozenset().union(*PHASE_STAGES.values())
PULL_STAGES = frozenset(
    stage for stage in ADMITTED_STAGES if stage.endswith("-image-pull")
)
TARGET_FAILURE_REASONS = frozenset(
    {
        "command-exit",
        "command-unavailable",
        "contract-rejected",
        "filesystem-error",
        "interrupted",
        "attestation-content-rejected",
        "registry-policy-rejected",
        "registry-request-failed",
        "registry-response-rejected",
        "unexpected-error",
    }
)
INFERRED_FAILURE_REASONS = frozenset(
    {
        "file-size-limit-exceeded",
        "storage-write-failed",
    }
)
FAILURE_REASONS = TARGET_FAILURE_REASONS | INFERRED_FAILURE_REASONS
# Ordered from deterministic local failures to remote failures. The scanner
# retains only these reason identities and a marker-sized overlap tail.
PULL_FAILURE_MARKERS = (
    (
        "file-size-limit-exceeded",
        (
            b"file too large",
            b"file size limit exceeded",
            b"exceeded file size limit",
        ),
    ),
    (
        "storage-write-failed",
        (
            b"no space left on device",
            b"read-only file system",
            b"disk quota exceeded",
            b"input/output error",
        ),
    ),
    (
        "registry-response-rejected",
        (
            b"unauthorized",
            b"authentication required",
            b"requested access to the resource is denied",
            b"manifest unknown",
            b"name unknown",
            b"too many requests",
            b"status code: 4",
            b"status code: 5",
            b"status code 4",
            b"status code 5",
            b"statuscode: 4",
            b"statuscode: 5",
        ),
    ),
    (
        "registry-request-failed",
        (
            b"network is unreachable",
            b"no such host",
            b"connection refused",
            b"connection reset",
            b"connection timed out",
            b"i/o timeout",
            b"tls handshake timeout",
            b"context deadline exceeded",
            b"temporary failure in name resolution",
            b"server misbehaving",
            b"unexpected eof",
        ),
    ),
)
PULL_FAILURE_MARKER_BYTES = max(
    len(marker)
    for _reason, markers in PULL_FAILURE_MARKERS
    for marker in markers
)
UNREPORTED_STAGE = "unreported"
UNREPORTED_REASON = "unreported"


def admitted_stage(line: bytes) -> str | None:
    if not line.startswith(TARGET_STAGE_PREFIX):
        return None
    value = line.removeprefix(TARGET_STAGE_PREFIX)
    try:
        candidate = value.decode("ascii")
    except UnicodeDecodeError:
        return None
    return candidate if candidate in ADMITTED_STAGES else None


def admitted_command_status(value: bytes) -> int | None:
    if value == NO_COMMAND_STATUS.encode("ascii"):
        return None
    if re.fullmatch(rb"[1-9][0-9]{0,2}", value) is None:
        raise ValueError("target diagnostic command status is malformed")
    status = int(value)
    if status > 255:
        raise ValueError("target diagnostic command status is outside the closed contract")
    return status


def scanned_diagnostic(
    line: bytes,
    stage: str,
    failure_reason: str,
    command_status: int | None,
) -> tuple[str, str, int | None]:
    candidate_stage = admitted_stage(line)
    if candidate_stage is not None:
        return candidate_stage, UNREPORTED_REASON, None
    if not line.startswith(TARGET_FAILURE_PREFIX):
        return stage, failure_reason, command_status
    parts = line.removeprefix(TARGET_FAILURE_PREFIX).split(b":")
    if len(parts) != 3:
        return stage, failure_reason, command_status
    try:
        failed_stage = parts[0].decode("ascii")
        candidate_reason = parts[1].decode("ascii")
        candidate_status = admitted_command_status(parts[2])
    except (UnicodeDecodeError, ValueError):
        return stage, failure_reason, command_status
    if (
        failed_stage != stage
        or candidate_reason not in TARGET_FAILURE_REASONS
        or failure_reason != UNREPORTED_REASON
        or (candidate_reason == "command-exit") != (candidate_status is not None)
    ):
        return stage, failure_reason, command_status
    return stage, candidate_reason, candidate_status


def scan_pull_output(
    fragment: bytes,
    tail: bytes,
    observed: set[str],
) -> bytes:
    window = (tail + fragment).lower()
    for reason, markers in PULL_FAILURE_MARKERS:
        if any(marker in window for marker in markers):
            observed.add(reason)
    return window[-(PULL_FAILURE_MARKER_BYTES - 1) :]


def classified_pull_failure(observed: set[str]) -> str | None:
    return next(
        (reason for reason, _markers in PULL_FAILURE_MARKERS if reason in observed),
        None,
    )


def admitted_file(path: Path, *, require_empty: bool) -> os.stat_result:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_gid != os.getgid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
        or (require_empty and metadata.st_size != 0)
        or metadata.st_size > MAX_CAPTURE_BYTES
    ):
        raise ValueError("target diagnostic file is outside the closed contract")
    return metadata


def capture(path: Path) -> None:
    admitted_file(path, require_empty=True)
    observed_bytes = 0
    truncated = False
    stage = UNREPORTED_STAGE
    failure_reason = UNREPORTED_REASON
    command_status: int | None = None
    stage_line = b""
    discarding_stage_line = False
    pull_scan_tail = b""
    pull_failures: set[str] = set()
    while chunk := sys.stdin.buffer.read(64 * 1024):
        remaining = max(0, MAX_CAPTURE_BYTES - observed_bytes)
        observed_bytes += min(len(chunk), remaining)
        if len(chunk) > remaining:
            truncated = True
        segments = chunk.split(b"\n")
        for index, segment in enumerate(segments):
            line_complete = index < len(segments) - 1
            if stage in PULL_STAGES:
                pull_scan_tail = scan_pull_output(
                    segment + (b"\n" if line_complete else b""),
                    pull_scan_tail,
                    pull_failures,
                )
            if not discarding_stage_line:
                if len(stage_line) + len(segment) <= MAX_STAGE_LINE_BYTES:
                    stage_line += segment
                else:
                    stage_line = b""
                    discarding_stage_line = True
            if line_complete:
                previous_stage = stage
                if not discarding_stage_line:
                    stage, failure_reason, command_status = scanned_diagnostic(
                        stage_line,
                        stage,
                        failure_reason,
                        command_status,
                    )
                if stage != previous_stage:
                    pull_scan_tail = b""
                    pull_failures.clear()
                stage_line = b""
                discarding_stage_line = False
    if stage_line and not discarding_stage_line:
        stage, failure_reason, command_status = scanned_diagnostic(
            stage_line,
            stage,
            failure_reason,
            command_status,
        )
    classified_failure = classified_pull_failure(pull_failures)
    if (
        stage in PULL_STAGES
        and failure_reason == "command-exit"
        and command_status == 128 + signal.SIGXFSZ
    ):
        classified_failure = "file-size-limit-exceeded"
    if (
        stage in PULL_STAGES
        and classified_failure is not None
        and failure_reason in {UNREPORTED_REASON, "command-exit"}
    ):
        failure_reason = classified_failure
        command_status = None
    status_token = NO_COMMAND_STATUS if command_status is None else str(command_status)
    metadata = (
        f"{observed_bytes} {int(truncated)} {stage} "
        f"{failure_reason} {status_token}\n"
    ).encode("ascii")
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        remaining = memoryview(metadata)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("target diagnostic write made no progress")
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    written_metadata = admitted_file(path, require_empty=False)
    if written_metadata.st_size != len(metadata):
        raise ValueError("target diagnostic write was incomplete")


def captured_metadata(path: Path) -> tuple[int, bool, str, str, int | None]:
    admitted_file(path, require_empty=False)
    payload = path.read_bytes()
    match = re.fullmatch(
        rb"(0|[1-9][0-9]{0,4}) ([01]) ([a-z0-9-]{1,64}) "
        rb"([a-z0-9-]{1,64}) (none|[1-9][0-9]{0,2})\n",
        payload,
    )
    if match is None:
        raise ValueError("target diagnostic metadata is malformed")
    observed_bytes = int(match.group(1))
    truncated = match.group(2) == b"1"
    if observed_bytes > MAX_CAPTURE_BYTES or (
        truncated and observed_bytes != MAX_CAPTURE_BYTES
    ):
        raise ValueError("target diagnostic metadata is outside its bound")
    stage = match.group(3).decode("ascii")
    if stage != UNREPORTED_STAGE and stage not in ADMITTED_STAGES:
        raise ValueError("target diagnostic stage is outside the closed contract")
    failure_reason = match.group(4).decode("ascii")
    if failure_reason != UNREPORTED_REASON and failure_reason not in FAILURE_REASONS:
        raise ValueError("target diagnostic failure reason is outside the closed contract")
    command_status = admitted_command_status(match.group(5))
    if (
        (stage == UNREPORTED_STAGE and failure_reason != UNREPORTED_REASON)
        or (failure_reason == UNREPORTED_REASON and command_status is not None)
        or (failure_reason == "command-exit") != (command_status is not None)
    ):
        raise ValueError("target diagnostic failure metadata is inconsistent")
    return observed_bytes, truncated, stage, failure_reason, command_status


def rendered_diagnostic(path: Path, phase: str, status: int) -> str:
    (
        output_bytes,
        output_truncated,
        captured_stage,
        captured_reason,
        captured_command_status,
    ) = captured_metadata(path)
    phase_compatible = captured_stage in PHASE_STAGES.get(phase, frozenset())
    stage = captured_stage if phase_compatible else UNREPORTED_STAGE
    failure_reason = captured_reason if phase_compatible else UNREPORTED_REASON
    command_status = captured_command_status if phase_compatible else None
    document = {
        "phase": phase,
        "status": status,
        "stage": stage,
        "failure_reason": failure_reason,
        "command_status": command_status,
        "output_bytes": output_bytes,
        "output_truncated": output_truncated,
    }
    rendered = OUTPUT_PREFIX + json.dumps(
        document,
        ensure_ascii=True,
        separators=(",", ":"),
    )
    if len((rendered + "\n").encode("utf-8")) > MAX_EMITTED_BYTES:
        raise ValueError("target diagnostic metadata exceeds its byte limit")
    return rendered


def emit(path: Path, phase: str, status_value: str) -> None:
    if phase not in PHASES or re.fullmatch(r"[1-9][0-9]{0,2}", status_value) is None:
        raise ValueError("target diagnostic identity is outside the closed contract")
    status = int(status_value)
    if status > 255:
        raise ValueError("target diagnostic status is outside the closed contract")
    print(rendered_diagnostic(path, phase, status))


def main() -> int:
    if len(sys.argv) == 3 and sys.argv[1] == "capture":
        operation = lambda: capture(Path(sys.argv[2]))
    elif len(sys.argv) == 5 and sys.argv[1] == "emit":
        operation = lambda: emit(Path(sys.argv[2]), sys.argv[3], sys.argv[4])
    else:
        print("ERROR: bounded target diagnostic arguments are invalid.", file=sys.stderr)
        return 64
    try:
        operation()
    except (OSError, UnicodeError, ValueError) as error:
        print(f"ERROR: bounded target diagnostic failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
