#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT
"""Create one bounded negative-only diagnostic for the exact Rocky target harness."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import tempfile
from pathlib import Path

EXPECTED_TARGET_SHA = "d89214795bc1bdf0e65d9bbf7c8b9647b7e1ebd6"
EXPECTED_HARNESS_SHA256 = "ad6d2518aa3f72054e6fa373b05345e7c37c21ac65feb6075eb69f3c434fea53"
MAX_STDOUT_BYTES = 65_536
MAX_TRACE_BYTES = 4_096
MAX_ARTIFACT_BYTES = 2_048
MAX_CAPTURE_FILE_BYTES = 65_536
MAX_TRACE_FRAMES = 8
MAX_TRACE_LINE = 9_999

OPERATIONS = frozenset(
    {
        "qualification-harness",
        "qualify-host-identity",
        "qualify-administrator-execution",
        "qualify-fixture-reference",
        "qualify-service-account",
        "qualify-selinux-host",
        "qualify-package-prerequisites",
        "qualify-native-architecture",
        "qualify-cgroup",
        "qualify-rootless-runtime",
        "qualify-fixture-presence",
        "qualify-fixture-setup",
        "qualify-quadlet-authority",
        "qualify-quadlet-runtime",
        "qualify-selinux-storage",
        "qualify-workload-primary",
        "qualify-seccomp",
        "qualify-workload-secondary",
        "qualify-mcs-relationship",
        "qualify-cross-mcs-denial",
        "qualify-avc-correlation",
        "qualify-selinux-policy-restoration",
        "qualify-runtime-fallback-absence",
        "qualify-fixture-cleanup",
    }
)
REASONS = frozenset(
    {
        "invariant-failed",
        "command-failed",
        "representation-invalid",
        "cleanup-failed",
        "timeout",
        "unclassified-target-failure",
    }
)

# These are exact reviewed d892 target messages.  Variable suffixes are never
# copied to evidence; a prefix match selects only the finite semantic identity.
EXPLICIT_RULES = (
    ("NOT RUN: Rocky Linux ", "qualify-host-identity", "invariant-failed"),
    ("ERROR: native qualification must run as an administrator", "qualify-administrator-execution", "invariant-failed"),
    ("ERROR: --image must be a fully qualified, pre-staged digest reference", "qualify-fixture-reference", "invariant-failed"),
    ("ERROR: required service account does not exist", "qualify-service-account", "invariant-failed"),
    ("ERROR: service-account home must be an existing absolute directory", "qualify-service-account", "invariant-failed"),
    ("ERROR: service-account home is not usable", "qualify-service-account", "invariant-failed"),
    ("ERROR: SELinux is not Enforcing.", "qualify-selinux-host", "invariant-failed"),
    ("ERROR: x86_64 CPU does not satisfy Rocky Linux 10 x86-64-v3", "qualify-native-architecture", "invariant-failed"),
    ("ERROR: unsupported native architecture", "qualify-native-architecture", "invariant-failed"),
    ("ERROR: unified cgroup v2 is not effective", "qualify-cgroup", "invariant-failed"),
    ("ERROR: rootless Podman does not select crun", "qualify-rootless-runtime", "invariant-failed"),
    ("ERROR: rootless Podman does not select Netavark", "qualify-rootless-runtime", "invariant-failed"),
    ("ERROR: digest-only fixture image is not pre-staged", "qualify-fixture-presence", "invariant-failed"),
    ("ERROR: service account can write the administrator Quadlet", "qualify-quadlet-authority", "invariant-failed"),
    ("ERROR: unsafe Quadlet symlink detected", "qualify-quadlet-authority", "invariant-failed"),
    ("ERROR: unsafe Quadlet setting detected", "qualify-quadlet-authority", "invariant-failed"),
    ("ERROR: representative rootless workload is not effectively seccomp-confined", "qualify-seccomp", "invariant-failed"),
    ("ERROR: representative process or storage label is not container-confined", "qualify-selinux-storage", "invariant-failed"),
    ("ERROR: representative SELinux MCS boundaries are not distinct and effective", "qualify-mcs-relationship", "invariant-failed"),
    ("ERROR: cross-boundary read unexpectedly succeeded", "qualify-cross-mcs-denial", "invariant-failed"),
    ("ERROR: negative test cannot distinguish missing path or DAC denial", "qualify-cross-mcs-denial", "invariant-failed"),
    ("ERROR: repeated negative test cannot distinguish missing path or DAC denial", "qualify-cross-mcs-denial", "invariant-failed"),
    ("ERROR: unable to temporarily expose SELinux dontaudit denials", "qualify-selinux-policy-restoration", "command-failed"),
    ("ERROR: SELinux stopped Enforcing while exposing dontaudit denials", "qualify-selinux-policy-restoration", "invariant-failed"),
    ("ERROR: cross-boundary failure lacks a matching SELinux AVC denial", "qualify-avc-correlation", "invariant-failed"),
    ("ERROR: unable to restore SELinux dontaudit policy", "qualify-selinux-policy-restoration", "command-failed"),
    ("ERROR: SELinux is not Enforcing after restoring dontaudit policy", "qualify-selinux-policy-restoration", "invariant-failed"),
    ("ERROR: effective runtime facts contain a forbidden security fallback", "qualify-runtime-fallback-absence", "invariant-failed"),
)

# Line ranges name semantic call sites in the immutable d892 harness.  Helper
# frames and cleanup internals are deliberately absent.  Nested ERR frames are
# reduced only when every admitted call-site line agrees on one operation.
LINE_RULES = (
    (117, 123, "qualify-host-identity"),
    (125, 128, "qualify-administrator-execution"),
    (129, 132, "qualify-fixture-reference"),
    (133, 151, "qualify-service-account"),
    (153, 156, "qualify-selinux-host"),
    (158, 163, "qualify-package-prerequisites"),
    (164, 177, "qualify-native-architecture"),
    (179, 182, "qualify-cgroup"),
    (183, 190, "qualify-rootless-runtime"),
    (191, 194, "qualify-fixture-presence"),
    (196, 204, "qualify-fixture-setup"),
    (206, 241, "qualify-quadlet-authority"),
    (242, 244, "qualify-quadlet-runtime"),
    (246, 253, "qualify-selinux-storage"),
    (254, 260, "qualify-workload-primary"),
    (261, 264, "qualify-seccomp"),
    (266, 270, "qualify-workload-secondary"),
    (271, 277, "qualify-selinux-storage"),
    (278, 284, "qualify-mcs-relationship"),
    (286, 297, "qualify-cross-mcs-denial"),
    (298, 299, "qualify-avc-correlation"),
    (300, 307, "qualify-selinux-policy-restoration"),
    (308, 320, "qualify-avc-correlation"),
    (321, 330, "qualify-selinux-policy-restoration"),
    (332, 335, "qualify-runtime-fallback-absence"),
    (337, 337, "qualification-harness"),
)

TRACE_PATTERN = re.compile(
    r"^SECPAL_TARGET_ERR_V2:([1-9][0-9]{0,2}):"
    r"([1-9][0-9]{0,3}(?:,[1-9][0-9]{0,3}){0,7})$"
)
MARKER_PATTERN = re.compile(
    r"^(qualification-harness|qualify-[a-z0-9-]+) "
    r"(invariant-failed|command-failed|representation-invalid|cleanup-failed)$"
)
HEX40 = re.compile(r"^[0-9a-f]{40}$")
POSITIVE_INTEGER = re.compile(r"^[1-9][0-9]{0,19}$")


def operation_for_line(line: int) -> str | None:
    for first, last, operation in LINE_RULES:
        if first <= line <= last:
            return operation
    return None


def trace_operations(trace_text: str, exit_status: int) -> tuple[set[str], bool]:
    operations: set[str] = set()
    if not trace_text:
        return operations, True
    for raw_line in trace_text.splitlines():
        match = TRACE_PATTERN.fullmatch(raw_line)
        if match is None or int(match.group(1)) != exit_status:
            return set(), False
        frames = match.group(2).split(",")
        if not 1 <= len(frames) <= MAX_TRACE_FRAMES:
            return set(), False
        for raw_frame in frames:
            line = int(raw_frame)
            if not 1 <= line <= MAX_TRACE_LINE:
                return set(), False
            operation = operation_for_line(line)
            if operation is not None:
                operations.add(operation)
    return operations, True


def classify_failure(
    stdout: bytes,
    trace: bytes,
    exit_status: int,
    *,
    target_bound: bool,
    trusted_marker: str | None = None,
    representation_invalid: bool = False,
) -> tuple[str, str]:
    if representation_invalid:
        return "qualification-harness", "representation-invalid"
    if trusted_marker is not None:
        match = MARKER_PATTERN.fullmatch(trusted_marker.strip())
        if match is not None and match.group(1) in OPERATIONS and match.group(2) in REASONS:
            return match.group(1), match.group(2)
        return "qualification-harness", "unclassified-target-failure"
    if not target_bound:
        return "qualification-harness", "representation-invalid"
    try:
        text = stdout.decode("utf-8")
        trace_text = trace.decode("ascii")
    except UnicodeDecodeError:
        return "qualification-harness", "representation-invalid"
    traced_operations, trace_valid = trace_operations(trace_text, exit_status)
    if not trace_valid:
        return "qualification-harness", "representation-invalid"
    if exit_status in (124, 137):
        return "qualification-harness", "timeout"

    explicit = {
        (operation, reason)
        for prefix, operation, reason in EXPLICIT_RULES
        if any(line.startswith(prefix) for line in text.splitlines())
    }
    if len(explicit) > 1:
        return "qualification-harness", "unclassified-target-failure"

    if len(explicit) == 1 and len(traced_operations) == 1:
        explicit_result = next(iter(explicit))
        traced_operation = next(iter(traced_operations))
        if explicit_result[0] != traced_operation:
            return "qualification-harness", "unclassified-target-failure"
        return explicit_result
    if len(explicit) == 1 and len(traced_operations) > 1:
        return "qualification-harness", "unclassified-target-failure"
    if len(explicit) == 1:
        return next(iter(explicit))
    if len(traced_operations) == 1:
        return traced_operations.pop(), "command-failed"
    return "qualification-harness", "unclassified-target-failure"


def bounded_bytes(path: Path, maximum: int) -> bytes:
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
            raise ValueError("diagnostic input is outside its closed file bound")
        with os.fdopen(descriptor, "rb") as source:
            descriptor = -1
            payload = source.read(maximum + 1)
    except OSError as error:
        raise ValueError("diagnostic input is outside its closed file bound") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(payload) > maximum:
        raise ValueError("diagnostic input is outside its closed file bound")
    return payload


def write_document(path: Path, document: dict[str, object]) -> None:
    encoded = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(encoded) > MAX_ARTIFACT_BYTES:
        raise ValueError("failure artifact exceeds its closed bound")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".target-qualification-failure.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as temporary:
            temporary.write(encoded)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.chmod(temporary_name, 0o600)
        os.replace(temporary_name, path)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-sha", required=True)
    parser.add_argument("--control-sha", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--harness", required=True, type=Path)
    parser.add_argument("--stdout", required=True, type=Path)
    parser.add_argument("--trace", required=True, type=Path)
    parser.add_argument("--exit-status", required=True, type=int)
    parser.add_argument("--trusted-marker", type=Path)
    parser.add_argument("--representation-invalid", action="store_true")
    parser.add_argument("--output", required=True, type=Path)
    options = parser.parse_args()
    if not HEX40.fullmatch(options.target_sha) or not HEX40.fullmatch(options.control_sha):
        raise SystemExit("target and control SHAs must be exact lowercase commits")
    if not POSITIVE_INTEGER.fullmatch(options.run_id) or not POSITIVE_INTEGER.fullmatch(options.run_attempt):
        raise SystemExit("qualification run identity is outside the closed format")
    if not 1 <= options.exit_status <= 255:
        raise SystemExit("target harness status is outside the closed range")

    stdout = bounded_bytes(options.stdout, MAX_STDOUT_BYTES)
    trace = bounded_bytes(options.trace, MAX_CAPTURE_FILE_BYTES)
    harness = bounded_bytes(options.harness, 128 * 1024)
    harness_sha256 = hashlib.sha256(harness).hexdigest()
    target_bound = options.target_sha == EXPECTED_TARGET_SHA and harness_sha256 == EXPECTED_HARNESS_SHA256
    marker = None
    marker_bytes = b""
    if options.trusted_marker is not None and options.trusted_marker.exists():
        marker_bytes = bounded_bytes(options.trusted_marker, 256)
        marker = marker_bytes.decode("ascii")
    operation, reason = classify_failure(
        stdout,
        trace,
        options.exit_status,
        target_bound=target_bound,
        trusted_marker=marker,
        representation_invalid=options.representation_invalid,
    )
    document: dict[str, object] = {
        "schema_version": 1,
        "phase": "target-qualification",
        "target_sha": options.target_sha,
        "trusted_control_sha": options.control_sha,
        "qualification_run_id": options.run_id,
        "qualification_run_attempt": options.run_attempt,
        "harness_sha256": harness_sha256,
        "operation": operation,
        "reason": reason,
        "exit_status": options.exit_status,
        "diagnostic_input_sha256": hashlib.sha256(
            stdout + b"\0" + trace + b"\0" + marker_bytes
        ).hexdigest(),
        "diagnostic_input_bytes": len(stdout) + len(trace) + len(marker_bytes),
    }
    write_document(options.output, document)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
