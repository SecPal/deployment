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

EXPECTED_TARGET_SHA = "83d0c3720d342d0222e8dee9819e28d0c6739f84"
EXPECTED_HARNESS_SHA256 = "ba4daa656cc462264c00f830985ad3c346e7ca4db8df9a50e8ee0c7a7d499946"
MAX_STDOUT_BYTES = 65_536
MAX_TRACE_BYTES = 4_096
MAX_ARTIFACT_BYTES = 8_192
MAX_CAPTURE_FILE_BYTES = 65_536
MAX_ADJACENCY_BYTES = 8_192
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
        "qualify-quadlet-daemon-reload",
        "qualify-quadlet-start",
        "qualify-quadlet-active-state",
        "qualify-selinux-storage",
        "qualify-selinux-storage-directory-create",
        "qualify-selinux-storage-fcontext-add",
        "qualify-selinux-storage-restorecon",
        "qualify-selinux-storage-matchpathcon",
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

# Line ranges name semantic call sites in the immutable expected target harness.
# Helper
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
    (242, 242, "qualify-quadlet-daemon-reload"),
    (243, 243, "qualify-quadlet-start"),
    (244, 244, "qualify-quadlet-active-state"),
    (249, 249, "qualify-selinux-storage-directory-create"),
    (250, 250, "qualify-selinux-storage-fcontext-add"),
    (252, 252, "qualify-selinux-storage-restorecon"),
    (253, 253, "qualify-selinux-storage-matchpathcon"),
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
BOOT_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
SAFE_BASENAME = re.compile(r"^[A-Za-z0-9_.@+-]{1,128}$")
SELINUX_TYPE = re.compile(r"^[a-zA-Z0-9_]{1,64}$")
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
        "observation-unavailable",
    }
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
        "observation-unavailable",
    }
)
ADMITTED_SYSTEMD_NEVRAS = frozenset(
    {
        "systemd-257-23.el10_2.2.rocky.0.1.aarch64",
        "systemd-257-23.el10_2.2.rocky.0.1.x86_64",
    }
)
RELOAD_INTERNAL_FAILURES = frozenset(
    {
        "none",
        "serialization-file-failed",
        "resource-allocation-failed",
        "serialization-failed",
        "serialization-seek-failed",
    }
)
CLIENT_RELOAD_ERRORS = frozenset(
    {
        "rate-limited",
        "run-space-rejected",
        "interactive-auth-required",
        "selinux-access-denied",
        "access-denied",
        "timeout",
        "connection-reset",
        "transport-unavailable",
        "other-admitted-bus-error",
        "unavailable",
    }
)

ADJACENCY_KEYS = frozenset(
    {
        "schema_version",
        "target_sha",
        "trusted_control_sha",
        "qualification_run_id",
        "qualification_run_attempt",
        "boot_id",
        "failure_status",
        "failure_event_sha256",
        "captured_before_cleanup",
        "capture_monotonic_ns",
        "manager_continuity_observed",
        "manager_active_after_reload_failure",
        "bus_available_after_reload_failure",
        "control_reachable_after_reload_failure",
        "manager_pid",
        "control_process_pid",
        "control_process_selinux_type",
        "manager_process_selinux_type",
        "systemd_nevra",
        "run_systemd_statvfs_success",
        "run_systemd_free_bytes",
        "run_systemd_reload_minimum_bytes",
        "run_systemd_space_sufficient",
        "quadlet_input",
        "podman_generator_executed",
        "podman_generator_exit_status",
        "podman_generator_accepted_actual_input",
        "generator_failures",
        "generator_failure_ambiguous",
        "generator_observation_reason",
        "reload_request_logged",
        "reload_request_client_pid",
        "reload_rate_limit_rejected",
        "reload_started",
        "reload_finished",
        "reload_internal_failure",
        "reload_reply_send_failed",
        "reload_journal_observation_reason",
        "reload_access_avc_observed",
        "reload_access_avc",
        "reload_access_avc_ambiguous",
        "selinux_avc_observed",
        "selinux_avc",
        "selinux_avc_ambiguous",
    }
)
INPUT_KEYS = frozenset(
    {
        "match_count",
        "present",
        "regular_file",
        "not_symlink",
        "owner_uid",
        "owner_gid",
        "mode",
        "size",
        "sha256",
    }
)
AVC_KEYS = frozenset(
    {"source_type", "target_type", "object_class", "denied_permission"}
)


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


def unavailable_daemon_reload_adjacency() -> dict[str, object]:
    return {
        "classification": "diagnostic-unavailable",
        "capture_complete": False,
        "captured_before_cleanup": False,
        "boot_id": None,
        "manager_continuity_observed": False,
        "manager_active_after_reload_failure": None,
        "bus_available_after_reload_failure": None,
        "control_reachable_after_reload_failure": None,
        "manager_pid": None,
        "control_process_pid": None,
        "control_process_selinux_type": None,
        "manager_process_selinux_type": None,
        "systemd_nevra": None,
        "run_systemd_statvfs_success": False,
        "run_systemd_free_bytes": None,
        "run_systemd_reload_minimum_bytes": 16 * 1024 * 1024,
        "run_systemd_space_sufficient": False,
        "quadlet_input_admitted": False,
        "quadlet_input": None,
        "podman_generator_executed": False,
        "podman_generator_exit_status": None,
        "podman_generator_accepted_actual_input": False,
        "generator_failure_observed": False,
        "generator_failures": [],
        "generator_failure_ambiguous": True,
        "generator_observation_reason": "observation-unavailable",
        "client_reload_error": "unavailable",
        "reload_authorization_outcome": "observation-unavailable",
        "reload_request_logged": False,
        "reload_request_client_pid": None,
        "reload_rate_limit_rejected": False,
        "reload_started": False,
        "reload_finished": False,
        "reload_internal_failure": "none",
        "reload_reply_send_failed": False,
        "reload_journal_observation_reason": "observation-unavailable",
        "reload_access_avc_observed": False,
        "reload_access_avc": None,
        "reload_access_avc_ambiguous": True,
        "reload_diagnostic_reason": "observation-unavailable",
        "selinux_avc_observed": False,
        "selinux_avc": None,
        "selinux_avc_ambiguous": True,
    }


def _closed_boolean(document: dict[str, object], name: str) -> bool:
    value = document.get(name)
    if type(value) is not bool:
        raise ValueError(f"{name} is not a closed boolean")
    return value


def _admitted_input(value: object) -> tuple[dict[str, object], bool]:
    if not isinstance(value, dict) or set(value) != INPUT_KEYS:
        raise ValueError("Quadlet input observation is not closed")
    match_count = value["match_count"]
    if type(match_count) is not int or not 0 <= match_count <= 2:
        raise ValueError("Quadlet input count is outside its bound")
    present = _closed_boolean(value, "present")
    regular = _closed_boolean(value, "regular_file")
    not_symlink = _closed_boolean(value, "not_symlink")
    if present != (match_count == 1):
        raise ValueError("Quadlet input presence contradicts its count")
    for name in ("owner_uid", "owner_gid"):
        item = value[name]
        if item is not None and (type(item) is not int or not 0 <= item <= 2**31 - 1):
            raise ValueError(f"Quadlet input {name} is outside its bound")
    mode = value["mode"]
    if mode is not None and re.fullmatch(r"[0-7]{4}", str(mode)) is None:
        raise ValueError("Quadlet input mode is malformed")
    size = value["size"]
    if size is not None and (type(size) is not int or not 0 <= size <= 4_097):
        raise ValueError("Quadlet input size is outside its bound")
    digest = value["sha256"]
    if digest is not None and re.fullmatch(r"[0-9a-f]{64}", str(digest)) is None:
        raise ValueError("Quadlet input digest is malformed")
    readable = (
        regular
        and not_symlink
        and size is not None
        and size <= 4_096
        and digest is not None
    )
    admitted = (
        present
        and readable
        and value["owner_uid"] == 0
        and value["owner_gid"] == 0
        and mode == "0644"
    )
    return value, admitted


def _admitted_generator_failures(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list) or len(value) > 3:
        raise ValueError("generator failures are outside their count bound")
    failures: list[dict[str, object]] = []
    for failure in value:
        if not isinstance(failure, dict) or set(failure) != {"basename", "exit_status"}:
            raise ValueError("generator failure is not closed")
        basename = failure["basename"]
        status = failure["exit_status"]
        if (
            not isinstance(basename, str)
            or SAFE_BASENAME.fullmatch(basename) is None
            or type(status) is not int
            or not 1 <= status <= 255
            or failure in failures
        ):
            raise ValueError("generator failure is malformed or duplicated")
        failures.append(failure)
    return failures


def _admitted_avc(value: object, observed: bool) -> dict[str, str] | None:
    if value is None:
        if observed:
            raise ValueError("observed SELinux denial lacks closed fields")
        return None
    if not observed or not isinstance(value, dict) or set(value) != AVC_KEYS:
        raise ValueError("SELinux adjacency is inconsistent")
    for name, item in value.items():
        if not isinstance(item, str) or SELINUX_TYPE.fullmatch(item) is None:
            raise ValueError(f"SELinux adjacency {name} is malformed")
    return value


def reload_client_error(payload: bytes) -> str:
    """Normalize only the exact installed systemctl daemon-reload error line."""
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return "unavailable"
    messages = [
        line.removeprefix("Reload daemon failed: ")
        for line in lines
        if line.startswith("Reload daemon failed: ")
        and 1 <= len(line.encode("utf-8")) <= 768
    ]
    if len(messages) != 1:
        return "unavailable"
    message = messages[0]
    if message == "Reload() request rejected due to rate limit.":
        return "rate-limited"
    if message.startswith(
        "Refusing to reload, not enough space available on /run/systemd."
    ):
        return "run-space-rejected"
    if message == "Interactive authentication required.":
        return "interactive-auth-required"
    if message.startswith("SELinux policy denies access: "):
        return "selinux-access-denied"
    if message == "Access denied":
        return "access-denied"
    if message == "Connection timed out":
        return "timeout"
    if message == "Connection reset by peer":
        return "connection-reset"
    if message in {
        "Transport endpoint is not connected",
        "No route to host",
        "Connection refused",
    }:
        return "transport-unavailable"
    return "other-admitted-bus-error"


def reload_authorization_outcome(request_logged: bool, client_error: str) -> str:
    if request_logged:
        if client_error in {"access-denied", "interactive-auth-required"}:
            return "observation-unavailable"
        return "authorized"
    if client_error == "interactive-auth-required":
        return "interactive-auth-required"
    if client_error == "access-denied":
        return "denied"
    if client_error in {"other-admitted-bus-error", "unavailable"}:
        return "observation-unavailable"
    return "not-reached-or-transport-failed"


def daemon_reload_classification(
    *,
    manager_continuity_observed: bool,
    manager_active: bool,
    bus_available: bool,
    control_reachable: bool,
    input_admitted: bool,
    generator_executed: bool,
    generator_accepted: bool,
    failures: list[dict[str, object]],
    generator_ambiguous: bool,
    avc_observed: bool,
    avc_ambiguous: bool,
    run_space_observed: bool,
    run_space_sufficient: bool,
    client_error: str,
    reload_request_logged: bool,
    reload_rate_limit_rejected: bool,
    reload_started: bool,
    reload_finished: bool,
    reload_internal_failure: str,
    reload_reply_send_failed: bool,
    reload_journal_reason: str,
    reload_access_avc_observed: bool,
    reload_access_avc_ambiguous: bool,
    reload_selinux_contexts_admitted: bool,
    reload_access_avc_matches_contexts: bool,
    systemd_source_contract_admitted: bool,
) -> tuple[str, str]:
    if not manager_continuity_observed:
        return "diagnostic-unavailable", "manager-continuity-observation-unavailable"
    if not (manager_active and bus_available and control_reachable):
        return "manager-continuity-lost", "none"
    if not input_admitted:
        return "target-input-invalid", "none"
    if not generator_executed:
        return "diagnostic-unavailable", "podman-generator-not-executed"
    if not generator_accepted:
        return "podman-generator-rejected", "none"
    if generator_ambiguous or any(
        failure["basename"] == "podman-system-generator" for failure in failures
    ):
        return "diagnostic-unavailable", "generator-observation-unavailable"
    if failures:
        return "other-generator-failed", "none"
    if avc_ambiguous:
        return "diagnostic-unavailable", "quadlet-selinux-observation-unavailable"
    if avc_observed:
        return "selinux-reload-denied", "none"
    if not systemd_source_contract_admitted:
        return "diagnostic-unavailable", "systemd-source-contract-mismatch"
    if reload_journal_reason != "none":
        return "diagnostic-unavailable", f"reload-{reload_journal_reason}"
    if not run_space_observed:
        return "diagnostic-unavailable", "run-space-observation-unavailable"
    if not run_space_sufficient:
        if client_error == "run-space-rejected" and not (
            reload_request_logged
            or reload_rate_limit_rejected
            or reload_started
            or reload_finished
            or reload_internal_failure != "none"
            or reload_reply_send_failed
        ):
            return "reload-run-space-rejected", "none"
        return "diagnostic-unavailable", "reload-stage-evidence-contradictory"
    if client_error == "run-space-rejected":
        return "diagnostic-unavailable", "reload-stage-evidence-contradictory"
    if not reload_selinux_contexts_admitted:
        return "diagnostic-unavailable", "reload-selinux-context-observation-unavailable"
    if not reload_access_avc_matches_contexts:
        return "diagnostic-unavailable", "reload-selinux-observation-ambiguous"
    if reload_access_avc_ambiguous:
        return "diagnostic-unavailable", "reload-selinux-observation-ambiguous"
    if reload_request_logged and client_error in {
        "access-denied",
        "interactive-auth-required",
    }:
        return "diagnostic-unavailable", "reload-stage-evidence-contradictory"
    if reload_access_avc_observed or client_error == "selinux-access-denied":
        if (
            reload_request_logged
            or reload_rate_limit_rejected
            or reload_started
            or reload_finished
            or reload_internal_failure != "none"
            or reload_reply_send_failed
            or client_error
            in {
                "run-space-rejected",
                "access-denied",
                "interactive-auth-required",
                "rate-limited",
            }
        ):
            return "diagnostic-unavailable", "reload-stage-evidence-contradictory"
        return "reload-selinux-access-denied", "none"
    if not reload_request_logged:
        if (
            reload_rate_limit_rejected
            or reload_started
            or reload_finished
            or reload_internal_failure != "none"
            or reload_reply_send_failed
        ):
            return "diagnostic-unavailable", "reload-stage-evidence-contradictory"
        if client_error == "interactive-auth-required":
            return "reload-authorization-interactive-required", "none"
        if client_error == "access-denied":
            return "reload-authorization-denied", "none"
        if client_error in {"timeout", "connection-reset", "transport-unavailable"}:
            return "reload-reply-transport-failed", "none"
        return "diagnostic-unavailable", "reload-authorization-observation-unavailable"
    if (reload_rate_limit_rejected or client_error == "rate-limited") and (
        reload_started
        or reload_finished
        or reload_internal_failure != "none"
        or reload_reply_send_failed
    ):
        return "diagnostic-unavailable", "reload-stage-evidence-contradictory"
    if reload_rate_limit_rejected or client_error == "rate-limited":
        return "reload-rate-limited", "none"
    if reload_internal_failure != "none" and (
        reload_finished or reload_reply_send_failed
    ):
        return "diagnostic-unavailable", "reload-stage-evidence-contradictory"
    if reload_reply_send_failed:
        return "reload-reply-transport-failed", "none"
    if not reload_started:
        return "diagnostic-unavailable", "reload-main-loop-entry-not-observed"
    if reload_internal_failure != "none":
        return "reload-manager-serialization-failed", "none"
    if not reload_finished:
        return "diagnostic-unavailable", "reload-completion-not-observed"
    return "reload-reply-transport-failed", "none"


def admit_daemon_reload_adjacency(
    observation: object,
    expected: dict[str, object],
    client_error: str = "unavailable",
) -> dict[str, object]:
    """Purely admit one failure-time observation under the d892 contract."""
    unavailable = unavailable_daemon_reload_adjacency()
    try:
        if not isinstance(observation, dict) or set(observation) != ADJACENCY_KEYS:
            raise ValueError("daemon-reload observation is not closed")
        if observation["schema_version"] != 1:
            raise ValueError("daemon-reload observation version is unsupported")
        for name in (
            "target_sha",
            "trusted_control_sha",
            "qualification_run_id",
            "qualification_run_attempt",
            "failure_status",
        ):
            if observation[name] != expected[name]:
                raise ValueError("daemon-reload observation binding disagrees")
        if BOOT_ID.fullmatch(str(observation["boot_id"])) is None:
            raise ValueError("daemon-reload boot identity is malformed")
        if re.fullmatch(r"[0-9a-f]{64}", str(observation["failure_event_sha256"])) is None:
            raise ValueError("daemon-reload event digest is malformed")
        if (
            type(observation["capture_monotonic_ns"]) is not int
            or observation["capture_monotonic_ns"] <= 0
            or not _closed_boolean(observation, "captured_before_cleanup")
        ):
            raise ValueError("daemon-reload capture is not failure-time bound")
        manager_continuity_observed = _closed_boolean(
            observation, "manager_continuity_observed"
        )
        manager_active = _closed_boolean(
            observation, "manager_active_after_reload_failure"
        )
        bus_available = _closed_boolean(
            observation, "bus_available_after_reload_failure"
        )
        control_reachable = _closed_boolean(
            observation, "control_reachable_after_reload_failure"
        )
        manager_pid = observation["manager_pid"]
        if manager_pid is not None and (
            type(manager_pid) is not int or not 1 <= manager_pid <= 2**31 - 1
        ):
            raise ValueError("user manager PID is outside its bound")
        control_pid = observation["control_process_pid"]
        if type(control_pid) is not int or not 1 <= control_pid <= 2**31 - 1:
            raise ValueError("Reload control PID is outside its bound")
        for name in (
            "control_process_selinux_type",
            "manager_process_selinux_type",
        ):
            value = observation[name]
            if value is not None and (
                not isinstance(value, str) or SELINUX_TYPE.fullmatch(value) is None
            ):
                raise ValueError("Reload SELinux process type is malformed")
        systemd_nevra = observation["systemd_nevra"]
        systemd_source_contract_admitted = systemd_nevra in ADMITTED_SYSTEMD_NEVRAS
        run_space_observed = _closed_boolean(
            observation, "run_systemd_statvfs_success"
        )
        run_space_sufficient = _closed_boolean(
            observation, "run_systemd_space_sufficient"
        )
        free_bytes = observation["run_systemd_free_bytes"]
        if free_bytes is not None and (
            type(free_bytes) is not int or not 0 <= free_bytes <= 2**63 - 1
        ):
            raise ValueError("Reload run-space value is outside its bound")
        if observation["run_systemd_reload_minimum_bytes"] != 16 * 1024 * 1024:
            raise ValueError("Reload run-space minimum contradicts exact systemd source")
        if (
            run_space_observed != (free_bytes is not None)
            or run_space_sufficient
            != (run_space_observed and free_bytes >= 16 * 1024 * 1024)
        ):
            raise ValueError("Reload run-space facts are inconsistent")
        quadlet_input, input_admitted = _admitted_input(observation["quadlet_input"])
        generator_executed = _closed_boolean(observation, "podman_generator_executed")
        generator_accepted = _closed_boolean(
            observation, "podman_generator_accepted_actual_input"
        )
        generator_status = observation["podman_generator_exit_status"]
        if generator_status is not None and (
            type(generator_status) is not int or not 0 <= generator_status <= 255
        ):
            raise ValueError("Podman generator status is outside its bound")
        if (
            generator_executed != (generator_status is not None)
            or generator_accepted != (generator_status == 0)
        ):
            raise ValueError("Podman generator observation is inconsistent")
        failures = _admitted_generator_failures(observation["generator_failures"])
        generator_ambiguous = _closed_boolean(
            observation, "generator_failure_ambiguous"
        )
        generator_reason = observation["generator_observation_reason"]
        if (
            generator_reason not in GENERATOR_OBSERVATION_REASONS
            or generator_ambiguous != (generator_reason != "none")
        ):
            raise ValueError("generator observation reason contradicts ambiguity")
        avc_observed = _closed_boolean(observation, "selinux_avc_observed")
        avc_ambiguous = _closed_boolean(observation, "selinux_avc_ambiguous")
        avc = _admitted_avc(observation["selinux_avc"], avc_observed)

        reload_request_logged = _closed_boolean(
            observation, "reload_request_logged"
        )
        reload_request_client_pid = observation["reload_request_client_pid"]
        if reload_request_client_pid is not None and (
            type(reload_request_client_pid) is not int
            or not 1 <= reload_request_client_pid <= 2**31 - 1
        ):
            raise ValueError("Reload request client PID is outside its bound")
        reload_rate_limit_rejected = _closed_boolean(
            observation, "reload_rate_limit_rejected"
        )
        reload_started = _closed_boolean(observation, "reload_started")
        reload_finished = _closed_boolean(observation, "reload_finished")
        reload_reply_send_failed = _closed_boolean(
            observation, "reload_reply_send_failed"
        )
        reload_internal_failure = observation["reload_internal_failure"]
        reload_journal_reason = observation["reload_journal_observation_reason"]
        if (
            reload_internal_failure not in RELOAD_INTERNAL_FAILURES
            or reload_journal_reason not in RELOAD_OBSERVATION_REASONS
            or client_error not in CLIENT_RELOAD_ERRORS
            or reload_finished and not reload_started
            or reload_rate_limit_rejected and not reload_request_logged
            or reload_request_logged != (reload_request_client_pid is not None)
        ):
            raise ValueError("Reload stage facts are inconsistent")
        reload_access_avc_observed = _closed_boolean(
            observation, "reload_access_avc_observed"
        )
        reload_access_avc_ambiguous = _closed_boolean(
            observation, "reload_access_avc_ambiguous"
        )
        reload_access_avc = _admitted_avc(
            observation["reload_access_avc"], reload_access_avc_observed
        )
        if reload_access_avc is not None and (
            reload_access_avc["object_class"] != "system"
            or reload_access_avc["denied_permission"] != "reload"
        ):
            raise ValueError("SELinux denial is not the exact Reload access check")
        reload_selinux_contexts_admitted = (
            observation["control_process_selinux_type"] is not None
            and observation["manager_process_selinux_type"] is not None
        )
        reload_access_avc_matches_contexts = (
            reload_access_avc is None
            or (
                reload_access_avc["source_type"]
                == observation["control_process_selinux_type"]
                and reload_access_avc["target_type"]
                == observation["manager_process_selinux_type"]
            )
        )

        classification, diagnostic_reason = daemon_reload_classification(
            manager_continuity_observed=manager_continuity_observed,
            manager_active=manager_active,
            bus_available=bus_available,
            control_reachable=control_reachable,
            input_admitted=input_admitted,
            generator_executed=generator_executed,
            generator_accepted=generator_accepted,
            failures=failures,
            generator_ambiguous=generator_ambiguous,
            avc_observed=avc_observed,
            avc_ambiguous=avc_ambiguous,
            run_space_observed=run_space_observed,
            run_space_sufficient=run_space_sufficient,
            client_error=client_error,
            reload_request_logged=reload_request_logged,
            reload_rate_limit_rejected=reload_rate_limit_rejected,
            reload_started=reload_started,
            reload_finished=reload_finished,
            reload_internal_failure=reload_internal_failure,
            reload_reply_send_failed=reload_reply_send_failed,
            reload_journal_reason=reload_journal_reason,
            reload_access_avc_observed=reload_access_avc_observed,
            reload_access_avc_ambiguous=reload_access_avc_ambiguous,
            reload_selinux_contexts_admitted=reload_selinux_contexts_admitted,
            reload_access_avc_matches_contexts=reload_access_avc_matches_contexts,
            systemd_source_contract_admitted=systemd_source_contract_admitted,
        )

        return {
            "classification": classification,
            "capture_complete": True,
            "captured_before_cleanup": True,
            "boot_id": observation["boot_id"],
            "manager_continuity_observed": manager_continuity_observed,
            "manager_active_after_reload_failure": manager_active,
            "bus_available_after_reload_failure": bus_available,
            "control_reachable_after_reload_failure": control_reachable,
            "manager_pid": manager_pid,
            "control_process_pid": control_pid,
            "control_process_selinux_type": observation[
                "control_process_selinux_type"
            ],
            "manager_process_selinux_type": observation[
                "manager_process_selinux_type"
            ],
            "systemd_nevra": systemd_nevra,
            "run_systemd_statvfs_success": run_space_observed,
            "run_systemd_free_bytes": free_bytes,
            "run_systemd_reload_minimum_bytes": 16 * 1024 * 1024,
            "run_systemd_space_sufficient": run_space_sufficient,
            "quadlet_input_admitted": input_admitted,
            "quadlet_input": quadlet_input,
            "podman_generator_executed": generator_executed,
            "podman_generator_exit_status": generator_status,
            "podman_generator_accepted_actual_input": generator_accepted,
            "generator_failure_observed": bool(failures),
            "generator_failures": failures,
            "generator_failure_ambiguous": generator_ambiguous,
            "generator_observation_reason": generator_reason,
            "client_reload_error": client_error,
            "reload_authorization_outcome": reload_authorization_outcome(
                reload_request_logged, client_error
            ),
            "reload_request_logged": reload_request_logged,
            "reload_request_client_pid": reload_request_client_pid,
            "reload_rate_limit_rejected": reload_rate_limit_rejected,
            "reload_started": reload_started,
            "reload_finished": reload_finished,
            "reload_internal_failure": reload_internal_failure,
            "reload_reply_send_failed": reload_reply_send_failed,
            "reload_journal_observation_reason": reload_journal_reason,
            "reload_access_avc_observed": reload_access_avc_observed,
            "reload_access_avc": reload_access_avc,
            "reload_access_avc_ambiguous": reload_access_avc_ambiguous,
            "reload_diagnostic_reason": diagnostic_reason,
            "selinux_avc_observed": avc_observed,
            "selinux_avc": avc,
            "selinux_avc_ambiguous": avc_ambiguous,
        }
    except (KeyError, TypeError, ValueError):
        return unavailable


def validate_admitted_daemon_reload_adjacency(document: object) -> None:
    """Reject a final adjacency whose classification contradicts its facts."""
    if document == unavailable_daemon_reload_adjacency():
        return
    if not isinstance(document, dict):
        raise ValueError("admitted daemon-reload adjacency is not an object")
    try:
        if (
            document["capture_complete"] is not True
            or document["captured_before_cleanup"] is not True
        ):
            raise ValueError("admitted daemon-reload capture is incomplete")
        if BOOT_ID.fullmatch(str(document["boot_id"])) is None:
            raise ValueError("admitted daemon-reload boot identity is malformed")
        manager_continuity_observed = _closed_boolean(
            document, "manager_continuity_observed"
        )
        manager_active = _closed_boolean(
            document, "manager_active_after_reload_failure"
        )
        bus_available = _closed_boolean(document, "bus_available_after_reload_failure")
        control_reachable = _closed_boolean(
            document, "control_reachable_after_reload_failure"
        )
        manager_pid = document["manager_pid"]
        if manager_pid is not None and (
            type(manager_pid) is not int or not 1 <= manager_pid <= 2**31 - 1
        ):
            raise ValueError("admitted user manager PID is outside its bound")
        control_pid = document["control_process_pid"]
        if type(control_pid) is not int or not 1 <= control_pid <= 2**31 - 1:
            raise ValueError("admitted Reload control PID is outside its bound")
        for name in (
            "control_process_selinux_type",
            "manager_process_selinux_type",
        ):
            value = document[name]
            if value is not None and (
                not isinstance(value, str) or SELINUX_TYPE.fullmatch(value) is None
            ):
                raise ValueError("admitted Reload SELinux type is malformed")
        systemd_nevra = document["systemd_nevra"]
        systemd_source_contract_admitted = systemd_nevra in ADMITTED_SYSTEMD_NEVRAS
        run_space_observed = _closed_boolean(
            document, "run_systemd_statvfs_success"
        )
        run_space_sufficient = _closed_boolean(
            document, "run_systemd_space_sufficient"
        )
        free_bytes = document["run_systemd_free_bytes"]
        if (
            document["run_systemd_reload_minimum_bytes"] != 16 * 1024 * 1024
            or run_space_observed != (free_bytes is not None)
            or (
                free_bytes is not None
                and (type(free_bytes) is not int or not 0 <= free_bytes <= 2**63 - 1)
            )
            or run_space_sufficient
            != (run_space_observed and free_bytes >= 16 * 1024 * 1024)
        ):
            raise ValueError("admitted Reload run-space facts are inconsistent")
        _, input_admitted = _admitted_input(document["quadlet_input"])
        if document["quadlet_input_admitted"] is not input_admitted:
            raise ValueError("admitted Quadlet input decision contradicts its facts")
        generator_executed = _closed_boolean(document, "podman_generator_executed")
        generator_accepted = _closed_boolean(
            document, "podman_generator_accepted_actual_input"
        )
        generator_status = document["podman_generator_exit_status"]
        if (
            generator_executed != (generator_status is not None)
            or generator_accepted != (generator_status == 0)
        ):
            raise ValueError("admitted Podman generator facts are inconsistent")
        failures = _admitted_generator_failures(document["generator_failures"])
        if document["generator_failure_observed"] is not bool(failures):
            raise ValueError("admitted generator failure presence is inconsistent")
        generator_ambiguous = _closed_boolean(
            document, "generator_failure_ambiguous"
        )
        generator_reason = document["generator_observation_reason"]
        if (
            generator_reason not in GENERATOR_OBSERVATION_REASONS
            or generator_ambiguous != (generator_reason != "none")
        ):
            raise ValueError("admitted generator reason contradicts ambiguity")
        avc_observed = _closed_boolean(document, "selinux_avc_observed")
        avc_ambiguous = _closed_boolean(document, "selinux_avc_ambiguous")
        _admitted_avc(document["selinux_avc"], avc_observed)
        client_error = document["client_reload_error"]
        reload_request_logged = _closed_boolean(document, "reload_request_logged")
        reload_request_client_pid = document["reload_request_client_pid"]
        if reload_request_client_pid is not None and (
            type(reload_request_client_pid) is not int
            or not 1 <= reload_request_client_pid <= 2**31 - 1
        ):
            raise ValueError("admitted Reload request client PID is outside its bound")
        reload_rate_limit_rejected = _closed_boolean(
            document, "reload_rate_limit_rejected"
        )
        reload_started = _closed_boolean(document, "reload_started")
        reload_finished = _closed_boolean(document, "reload_finished")
        reload_reply_send_failed = _closed_boolean(
            document, "reload_reply_send_failed"
        )
        reload_internal_failure = document["reload_internal_failure"]
        reload_journal_reason = document["reload_journal_observation_reason"]
        if (
            client_error not in CLIENT_RELOAD_ERRORS
            or reload_internal_failure not in RELOAD_INTERNAL_FAILURES
            or reload_journal_reason not in RELOAD_OBSERVATION_REASONS
            or reload_finished and not reload_started
            or reload_rate_limit_rejected and not reload_request_logged
            or reload_request_logged != (reload_request_client_pid is not None)
        ):
            raise ValueError("admitted Reload stages are inconsistent")
        if document["reload_authorization_outcome"] != reload_authorization_outcome(
            reload_request_logged, client_error
        ):
            raise ValueError("admitted Reload authorization contradicts source order")
        reload_access_avc_observed = _closed_boolean(
            document, "reload_access_avc_observed"
        )
        reload_access_avc_ambiguous = _closed_boolean(
            document, "reload_access_avc_ambiguous"
        )
        reload_access_avc = _admitted_avc(
            document["reload_access_avc"], reload_access_avc_observed
        )
        if reload_access_avc is not None and (
            reload_access_avc["object_class"] != "system"
            or reload_access_avc["denied_permission"] != "reload"
        ):
            raise ValueError("admitted SELinux denial is not Reload-specific")
        reload_selinux_contexts_admitted = (
            document["control_process_selinux_type"] is not None
            and document["manager_process_selinux_type"] is not None
        )
        reload_access_avc_matches_contexts = (
            reload_access_avc is None
            or (
                reload_access_avc["source_type"]
                == document["control_process_selinux_type"]
                and reload_access_avc["target_type"]
                == document["manager_process_selinux_type"]
            )
        )
        expected, diagnostic_reason = daemon_reload_classification(
            manager_continuity_observed=manager_continuity_observed,
            manager_active=manager_active,
            bus_available=bus_available,
            control_reachable=control_reachable,
            input_admitted=input_admitted,
            generator_executed=generator_executed,
            generator_accepted=generator_accepted,
            failures=failures,
            generator_ambiguous=generator_ambiguous,
            avc_observed=avc_observed,
            avc_ambiguous=avc_ambiguous,
            run_space_observed=run_space_observed,
            run_space_sufficient=run_space_sufficient,
            client_error=client_error,
            reload_request_logged=reload_request_logged,
            reload_rate_limit_rejected=reload_rate_limit_rejected,
            reload_started=reload_started,
            reload_finished=reload_finished,
            reload_internal_failure=reload_internal_failure,
            reload_reply_send_failed=reload_reply_send_failed,
            reload_journal_reason=reload_journal_reason,
            reload_access_avc_observed=reload_access_avc_observed,
            reload_access_avc_ambiguous=reload_access_avc_ambiguous,
            reload_selinux_contexts_admitted=reload_selinux_contexts_admitted,
            reload_access_avc_matches_contexts=reload_access_avc_matches_contexts,
            systemd_source_contract_admitted=systemd_source_contract_admitted,
        )
        if (
            document["classification"] != expected
            or document["reload_diagnostic_reason"] != diagnostic_reason
        ):
            raise ValueError("daemon-reload classification contradicts its facts")
    except (KeyError, TypeError) as error:
        raise ValueError("admitted daemon-reload adjacency is malformed") from error


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
    parser.add_argument("--reload-adjacency", type=Path)
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
    adjacency_bytes = b""
    adjacency: dict[str, object] | None = None
    if operation == "qualify-quadlet-daemon-reload" and reason == "command-failed":
        raw_adjacency: object = None
        if options.reload_adjacency is not None and options.reload_adjacency.exists():
            try:
                adjacency_bytes = bounded_bytes(
                    options.reload_adjacency, MAX_ADJACENCY_BYTES
                )
                raw_adjacency = json.loads(adjacency_bytes)
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                raw_adjacency = None
        adjacency = admit_daemon_reload_adjacency(
            raw_adjacency,
            {
                "target_sha": options.target_sha,
                "trusted_control_sha": options.control_sha,
                "qualification_run_id": options.run_id,
                "qualification_run_attempt": options.run_attempt,
                "failure_status": options.exit_status,
            },
            reload_client_error(stdout),
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
            stdout + b"\0" + trace + b"\0" + marker_bytes + b"\0" + adjacency_bytes
        ).hexdigest(),
        "diagnostic_input_bytes": len(stdout)
        + len(trace)
        + len(marker_bytes)
        + len(adjacency_bytes),
    }
    if adjacency is not None:
        document["daemon_reload_adjacency"] = adjacency
    write_document(options.output, document)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
