#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT
"""Create one bounded negative-only diagnostic for the exact Rocky target harness."""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
import re
import stat
import tempfile
from pathlib import Path

EXPECTED_TARGET_SHA = "c76742c828fefd71dda2b2d73fda6a0c43969426"
EXPECTED_HARNESS_SHA256 = "436756f79c7f120d5c4b9fc15b12b2fd91da0fdea5e93ed2907172a73c2861ac"
HISTORICAL_PRE_269_TARGET_SHA = "b76c24fe59fbe2406d8b84094fc9e6694c57f0c6"
HISTORICAL_PRE_269_HARNESS_SHA256 = "f1ed6f62f769d608b721592b28835daca5ea7c0b0c3575311691628383e88f3c"
HISTORICAL_PRE_265_TARGET_SHA = "539d5faa6549be62060c8e20028caf200e5eca01"
HISTORICAL_PRE_265_HARNESS_SHA256 = "f1ed6f62f769d608b721592b28835daca5ea7c0b0c3575311691628383e88f3c"
HISTORICAL_202_TARGET_SHA = "293977ae93408a7bb812619de58649ab8a92d438"
HISTORICAL_202_HARNESS_SHA256 = "8459724a91bee7643d6f0e3d64984161a3441848e9d836ce1210ccef689fb4db"
HISTORICAL_TARGET_SHA = "83d0c3720d342d0222e8dee9819e28d0c6739f84"
HISTORICAL_HARNESS_SHA256 = "ba4daa656cc462264c00f830985ad3c346e7ca4db8df9a50e8ee0c7a7d499946"
MAX_STDOUT_BYTES = 65_536
MAX_STDOUT_CAPTURE_BYTES = MAX_STDOUT_BYTES + 1
MAX_TRACE_BYTES = 4_096
MAX_ARTIFACT_BYTES = 16_384
MAX_CAPTURE_FILE_BYTES = 65_536
MAX_ADJACENCY_BYTES = 8_192
MAX_START_OBSERVATION_BYTES = 2_048
MAX_ACTIVE_OBSERVATION_BYTES = 2_048
MAX_PRIMARY_OBSERVATION_BYTES = 2_048
MAX_AVC_CORRELATION_DIAGNOSTIC_BYTES = 12_288
INSTALLED_SELINUX_ISOLATION_CONTRACT = Path(
    "/opt/secpal-control/scripts/selinux_isolation_contract.py"
)
MAX_TRACE_FRAMES = 8
MAX_TRACE_LINE = 9_999
LEGACY_REPLAY_OPTIONAL_CONTROL_SHA = "f7a298d19bf4a0957d6b3db383a1f1bb2eeb309e"
REPLAY_COMPONENT_ORDER = (
    "qualification_stdout",
    "target_qualification_trace",
    "trusted_marker",
    "reload_adjacency",
    "start_observation",
    "active_observation",
    "primary_observation",
)
REPLAY_COMPONENT_BOUNDS = {
    "qualification_stdout": MAX_STDOUT_CAPTURE_BYTES,
    "target_qualification_trace": MAX_CAPTURE_FILE_BYTES,
    "trusted_marker": 257,
    "reload_adjacency": MAX_ADJACENCY_BYTES + 1,
    "start_observation": MAX_START_OBSERVATION_BYTES + 1,
    "active_observation": MAX_ACTIVE_OBSERVATION_BYTES + 1,
    "primary_observation": MAX_PRIMARY_OBSERVATION_BYTES + 1,
}
REPLAY_EXACT_COMPONENT_BOUNDS = {
    "qualification_stdout": MAX_STDOUT_BYTES,
    "target_qualification_trace": MAX_TRACE_BYTES,
    "trusted_marker": 256,
    "reload_adjacency": MAX_ADJACENCY_BYTES,
    "start_observation": MAX_START_OBSERVATION_BYTES,
    "active_observation": MAX_ACTIVE_OBSERVATION_BYTES,
    "primary_observation": MAX_PRIMARY_OBSERVATION_BYTES,
}
REPLAYABLE_STDOUT_RECORDS = frozenset(
    {
        b"ERROR: SELinux is not Enforcing.\n",
    }
)

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
        "qualify-quadlet-start-runuser",
        "qualify-quadlet-start-env",
        "qualify-quadlet-start-systemctl",
        "qualify-quadlet-start-service-job",
        "qualify-quadlet-active-state",
        "qualify-quadlet-active-state-runuser",
        "qualify-quadlet-active-state-env",
        "qualify-quadlet-active-state-systemctl",
        "qualify-selinux-storage",
        "qualify-selinux-storage-directory-create",
        "qualify-selinux-storage-fcontext-add",
        "qualify-selinux-storage-restorecon",
        "qualify-selinux-storage-matchpathcon",
        "qualify-workload-primary",
        "qualify-workload-primary-runuser",
        "qualify-workload-primary-env",
        "qualify-workload-primary-podman",
        "qualify-workload-primary-podman-oci",
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
        "exec-failed",
        "invocation-failed",
        "command-exec-failed",
        "request-failed",
        "job-failed",
        "diagnostic-unavailable",
        "semanage-store-access-failed",
        "semanage-transaction-begin-failed",
        "semanage-fcontext-equivalency-conflict",
        "semanage-fcontext-key-create-failed",
        "semanage-fcontext-existence-check-failed",
        "semanage-fcontext-record-create-failed",
        "semanage-fcontext-context-create-failed",
        "semanage-fcontext-type-set-failed",
        "semanage-fcontext-context-attach-failed",
        "semanage-fcontext-local-add-failed",
        "semanage-transaction-commit-failed",
    }
)
ZERO_STATUS_TRUSTED_DECISIONS = frozenset(
    {
        ("qualification-harness", "representation-invalid"),
        ("qualify-selinux-storage", "representation-invalid"),
        ("qualify-selinux-storage", "invariant-failed"),
        ("qualify-mcs-relationship", "invariant-failed"),
        ("qualify-seccomp", "invariant-failed"),
        ("qualify-avc-correlation", "command-failed"),
        ("qualify-avc-correlation", "invariant-failed"),
        ("qualify-fixture-cleanup", "cleanup-failed"),
    }
)

# Historical rules remain available only with a historical immutable line map.
HISTORICAL_EXPLICIT_RULES = (
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

# These are exact reviewed current-target messages.  Variable suffixes are never
# copied to evidence; a prefix match selects only the finite semantic identity.
EXPLICIT_RULES = (
    ("NOT RUN: Rocky Linux ", "qualify-host-identity", "invariant-failed"),
    ("ERROR: native qualification must run as an administrator", "qualify-administrator-execution", "invariant-failed"),
    ("ERROR: --image must be a fully qualified, pre-staged digest reference", "qualify-fixture-reference", "invariant-failed"),
    ("ERROR: required service account does not exist", "qualify-service-account", "invariant-failed"),
    ("ERROR: service-account home must be an existing absolute directory", "qualify-service-account", "invariant-failed"),
    ("ERROR: service account must resolve to a non-root runtime identity", "qualify-service-account", "invariant-failed"),
    ("ERROR: service-account home is not usable", "qualify-service-account", "invariant-failed"),
    ("ERROR: SELinux is not Enforcing.", "qualify-selinux-host", "invariant-failed"),
    ("ERROR: x86_64 CPU does not satisfy Rocky Linux 10 x86-64-v3", "qualify-native-architecture", "invariant-failed"),
    ("ERROR: unsupported native architecture", "qualify-native-architecture", "invariant-failed"),
    ("ERROR: unified cgroup v2 is not effective", "qualify-cgroup", "invariant-failed"),
    ("ERROR: rootless Podman does not select crun", "qualify-rootless-runtime", "invariant-failed"),
    ("ERROR: rootless Podman does not select Netavark", "qualify-rootless-runtime", "invariant-failed"),
    ("ERROR: effective Podman runtime is not the admitted rootless service identity", "qualify-rootless-runtime", "invariant-failed"),
    ("ERROR: digest-only fixture image is not pre-staged", "qualify-fixture-presence", "invariant-failed"),
    ("ERROR: administrator Quadlet path ancestry is not trusted", "qualify-quadlet-authority", "invariant-failed"),
    ("ERROR: administrator Quadlet search-path policy is not trusted", "qualify-quadlet-authority", "invariant-failed"),
    ("ERROR: effective Quadlet search path is not the admitted administrator directory", "qualify-quadlet-authority", "invariant-failed"),
    ("ERROR: unsafe Quadlet setting detected", "qualify-quadlet-authority", "invariant-failed"),
    ("ERROR: unable to evaluate effective Quadlet service authority", "qualify-quadlet-authority", "command-failed"),
    ("ERROR: effective Quadlet service contradicts the admitted administrator configuration", "qualify-quadlet-authority", "invariant-failed"),
    ("ERROR: effective Quadlet runtime identity contradicts the service account", "qualify-quadlet-authority", "invariant-failed"),
    ("ERROR: representative workload lacks the effective least-authority process state", "qualify-seccomp", "invariant-failed"),
    ("ERROR: representative process or storage label is not container-confined", "qualify-selinux-storage", "invariant-failed"),
    ("ERROR: cross-boundary denial observation is invalid", "qualify-avc-correlation", "invariant-failed"),
    ("ERROR: unable to temporarily expose SELinux dontaudit denials", "qualify-selinux-policy-restoration", "command-failed"),
    ("ERROR: SELinux stopped Enforcing while exposing dontaudit denials", "qualify-selinux-policy-restoration", "invariant-failed"),
    ("ERROR: cross-boundary failure lacks one correlated enforcing SELinux AVC denial", "qualify-avc-correlation", "command-failed"),
    ("ERROR: unable to restore SELinux dontaudit policy", "qualify-selinux-policy-restoration", "command-failed"),
    ("ERROR: SELinux is not Enforcing after restoring dontaudit policy", "qualify-selinux-policy-restoration", "invariant-failed"),
    ("ERROR: effective runtime facts contain a forbidden security fallback", "qualify-runtime-fallback-absence", "invariant-failed"),
)

# Line ranges name semantic call sites in the immutable expected target harness.
# Helper
# frames and cleanup internals are deliberately absent.  Nested ERR frames are
# reduced only when every admitted call-site line agrees on one operation.
HISTORICAL_LINE_RULES = (
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

HISTORICAL_202_LINE_RULES = (
    (113, 119, "qualify-host-identity"), (121, 124, "qualify-administrator-execution"),
    (125, 128, "qualify-fixture-reference"), (129, 146, "qualify-service-account"),
    (149, 152, "qualify-selinux-host"), (154, 158, "qualify-package-prerequisites"),
    (160, 173, "qualify-native-architecture"), (175, 178, "qualify-cgroup"),
    (179, 186, "qualify-rootless-runtime"), (187, 190, "qualify-fixture-presence"),
    (192, 199, "qualify-fixture-setup"), (201, 236, "qualify-quadlet-authority"),
    (237, 237, "qualify-quadlet-daemon-reload"), (238, 238, "qualify-quadlet-start"),
    (239, 239, "qualify-quadlet-active-state"), (241, 244, "qualify-selinux-storage-directory-create"),
    (245, 249, "qualify-workload-primary"), (250, 255, "qualify-seccomp"),
    (257, 260, "qualify-workload-secondary"), (262, 268, "qualify-selinux-storage"),
    (269, 275, "qualify-mcs-relationship"), (280, 288, "qualify-cross-mcs-denial"),
    (289, 290, "qualify-avc-correlation"), (291, 298, "qualify-selinux-policy-restoration"),
    (299, 307, "qualify-cross-mcs-denial"), (308, 311, "qualify-avc-correlation"),
    (312, 320, "qualify-selinux-policy-restoration"), (323, 326, "qualify-runtime-fallback-absence"),
)

HISTORICAL_PRE_269_LINE_RULES = (
    (368, 374, "qualify-host-identity"),
    (376, 379, "qualify-administrator-execution"),
    (380, 383, "qualify-fixture-reference"),
    (384, 405, "qualify-service-account"),
    (409, 412, "qualify-selinux-host"),
    (414, 427, "qualify-native-architecture"),
    (429, 432, "qualify-cgroup"),
    (433, 449, "qualify-rootless-runtime"),
    (450, 453, "qualify-fixture-presence"),
    (455, 463, "qualify-fixture-setup"),
    (465, 524, "qualify-quadlet-authority"),
    (525, 525, "qualify-quadlet-daemon-reload"),
    (526, 548, "qualify-quadlet-authority"),
    (549, 549, "qualify-quadlet-start"),
    (550, 550, "qualify-quadlet-active-state"),
    (552, 563, "qualify-quadlet-authority"),
    (564, 569, "qualify-workload-primary"),
    (570, 576, "qualify-seccomp"),
    (579, 579, "qualify-selinux-storage-directory-create"),
    (581, 585, "qualify-workload-primary"),
    (586, 589, "qualify-workload-secondary"),
    (591, 597, "qualify-selinux-storage"),
    (601, 607, "qualify-avc-correlation"),
    (610, 616, "qualify-selinux-policy-restoration"),
    (619, 624, "qualify-avc-correlation"),
    (626, 634, "qualify-selinux-policy-restoration"),
    (637, 653, "qualify-avc-correlation"),
    (662, 665, "qualify-runtime-fallback-absence"),
    (667, 667, "qualification-harness"),
)

LINE_RULES = (
    (456, 462, "qualify-host-identity"),
    (464, 467, "qualify-administrator-execution"),
    (468, 471, "qualify-fixture-reference"),
    (472, 493, "qualify-service-account"),
    (497, 500, "qualify-selinux-host"),
    (502, 515, "qualify-native-architecture"),
    (517, 520, "qualify-cgroup"),
    (521, 537, "qualify-rootless-runtime"),
    (538, 541, "qualify-fixture-presence"),
    (543, 552, "qualify-fixture-setup"),
    (554, 613, "qualify-quadlet-authority"),
    (614, 614, "qualify-quadlet-daemon-reload"),
    (615, 637, "qualify-quadlet-authority"),
    (638, 638, "qualify-quadlet-start"),
    (639, 639, "qualify-quadlet-active-state"),
    (641, 652, "qualify-quadlet-authority"),
    (653, 658, "qualify-workload-primary"),
    (659, 665, "qualify-seccomp"),
    (668, 668, "qualify-selinux-storage-directory-create"),
    (670, 674, "qualify-workload-primary"),
    (675, 678, "qualify-workload-secondary"),
    (680, 686, "qualify-selinux-storage"),
    (690, 694, "qualify-avc-correlation"),
    (698, 704, "qualify-selinux-policy-restoration"),
    (707, 711, "qualify-avc-correlation"),
    (713, 721, "qualify-selinux-policy-restoration"),
    (724, 740, "qualify-avc-correlation"),
    (749, 752, "qualify-runtime-fallback-absence"),
    (754, 754, "qualification-harness"),
    (760, 768, "qualify-avc-correlation"),
)

TRACE_PATTERN = re.compile(
    r"^SECPAL_TARGET_ERR_V2:([1-9][0-9]{0,2}):"
    r"([1-9][0-9]{0,3}(?:,[1-9][0-9]{0,3}){0,7})$"
)
MARKER_PATTERN = re.compile(
    r"^(qualification-harness|qualify-[a-z0-9-]+) "
    r"(invariant-failed|command-failed|representation-invalid|cleanup-failed)$"
)
AVC_OBSERVATION_TRACE_STATUS = 1
AVC_OBSERVATION_TARGET_STATUS = 3
AVC_OBSERVATION_REQUIRED_FRAMES = frozenset({375, 690, 772})
HISTORICAL_PRE_269_AVC_OBSERVATION_REQUIRED_FRAMES = frozenset({300, 601, 674})
HEX40 = re.compile(r"^[0-9a-f]{40}$")
POSITIVE_INTEGER = re.compile(r"^[1-9][0-9]{0,19}$")
BOOT_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
SAFE_BASENAME = re.compile(r"^[A-Za-z0-9_.@+-]{1,128}$")
SELINUX_TYPE = re.compile(r"^[a-zA-Z0-9_]{1,64}$")
SEMANAGE_FCONTEXT_EXPRESSION = (
    r"/var/tmp/secpal-host-qualification-[A-Za-z0-9]{6}\(/\.\*\)\?"
)
SEMANAGE_FCONTEXT_PATH_FAILURES = (
    ("Could not create key for", "", "semanage-fcontext-key-create-failed"),
    (
        "Could not check if file context for",
        "is defined",
        "semanage-fcontext-existence-check-failed",
    ),
    ("Could not create file context for", "", "semanage-fcontext-record-create-failed"),
    ("Could not create context for", "", "semanage-fcontext-context-create-failed"),
    ("Could not set type in file context for", "", "semanage-fcontext-type-set-failed"),
    (
        "Could not set file context for",
        "",
        "semanage-fcontext-context-attach-failed",
    ),
    ("Could not add file context for", "", "semanage-fcontext-local-add-failed"),
)
SEMANAGE_FCONTEXT_STATIC_FAILURES = {
    "SELinux policy is not managed or store cannot be accessed.": "semanage-store-access-failed",
    "Cannot read policy store.": "semanage-store-access-failed",
    "Could not establish semanage connection": "semanage-store-access-failed",
    "Could not test MLS enabled status": "semanage-store-access-failed",
    "Could not start semanage transaction": "semanage-transaction-begin-failed",
    "Could not commit semanage transaction": "semanage-transaction-commit-failed",
}
SEMANAGE_FCONTEXT_EQUIVALENCY_FAILURE = re.compile(
    r"^ValueError: File spec "
    + SEMANAGE_FCONTEXT_EXPRESSION
    + r" conflicts with equivalency rule '/[^'\r\n ]+ /[^'\r\n ]+'; "
    r"Try adding '/[^'\r\n ]+' instead$"
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

START_OBSERVATION_KEYS = frozenset(
    {
        "schema_version",
        "stage",
        "runuser_status",
        "systemctl_client_status",
        "service_result",
        "exec_main_code",
        "exec_main_status",
    }
)
START_STAGES = frozenset(
    {
        "runuser-exec-failed",
        "runuser-invocation-failed",
        "env-exec-failed",
        "env-command-exec-failed",
        "systemctl-exec-failed",
        "systemctl-request-failed",
        "service-job-failed",
        "diagnostic-unavailable",
        "success",
    }
)
START_STAGE_DECISIONS = {
    "runuser-exec-failed": ("qualify-quadlet-start-runuser", "exec-failed"),
    "runuser-invocation-failed": (
        "qualify-quadlet-start-runuser",
        "invocation-failed",
    ),
    "env-exec-failed": ("qualify-quadlet-start-env", "exec-failed"),
    "env-command-exec-failed": (
        "qualify-quadlet-start-env",
        "command-exec-failed",
    ),
    "systemctl-exec-failed": (
        "qualify-quadlet-start-systemctl",
        "exec-failed",
    ),
    "systemctl-request-failed": (
        "qualify-quadlet-start-systemctl",
        "request-failed",
    ),
    "service-job-failed": ("qualify-quadlet-start-service-job", "job-failed"),
}
ACTIVE_STAGES = frozenset(
    {
        "runuser-exec-failed",
        "runuser-invocation-failed",
        "env-exec-failed",
        "env-command-exec-failed",
        "systemctl-exec-failed",
        "systemctl-request-failed",
        "diagnostic-unavailable",
        "success",
    }
)
ACTIVE_STAGE_DECISIONS = {
    "runuser-exec-failed": ("qualify-quadlet-active-state-runuser", "exec-failed"),
    "runuser-invocation-failed": (
        "qualify-quadlet-active-state-runuser",
        "invocation-failed",
    ),
    "env-exec-failed": ("qualify-quadlet-active-state-env", "exec-failed"),
    "env-command-exec-failed": (
        "qualify-quadlet-active-state-env",
        "command-exec-failed",
    ),
    "systemctl-exec-failed": (
        "qualify-quadlet-active-state-systemctl",
        "exec-failed",
    ),
    "systemctl-request-failed": (
        "qualify-quadlet-active-state-systemctl",
        "request-failed",
    ),
}
PRIMARY_STAGES = frozenset(
    {
        "runuser-exec-failed",
        "runuser-invocation-failed",
        "env-preparation-failed",
        "podman-exec-failed",
        "podman-internal-failed",
        "podman-oci-status-126",
        "podman-oci-status-127",
        "podman-request-failed",
        "diagnostic-unavailable",
        "success",
    }
)
PRIMARY_STAGE_DECISIONS = {
    "runuser-exec-failed": ("qualify-workload-primary-runuser", "exec-failed"),
    "runuser-invocation-failed": (
        "qualify-workload-primary-runuser",
        "invocation-failed",
    ),
    "env-preparation-failed": (
        "qualify-workload-primary-env",
        "invariant-failed",
    ),
    "podman-exec-failed": ("qualify-workload-primary-podman", "exec-failed"),
    "podman-internal-failed": (
        "qualify-workload-primary-podman",
        "request-failed",
    ),
    "podman-request-failed": (
        "qualify-workload-primary-podman",
        "request-failed",
    ),
    "podman-oci-status-126": (
        "qualify-workload-primary-podman-oci",
        "invocation-failed",
    ),
    "podman-oci-status-127": (
        "qualify-workload-primary-podman-oci",
        "command-exec-failed",
    ),
}
SERVICE_RESULTS = frozenset(
    {
        "success",
        "resources",
        "protocol",
        "timeout",
        "exit-code",
        "signal",
        "core-dump",
        "watchdog",
        "start-limit-hit",
        "oom-kill",
        "exec-condition",
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


def operation_for_line(line: int, line_rules: tuple[tuple[int, int, str], ...] = LINE_RULES) -> str | None:
    for first, last, operation in line_rules:
        if first <= line <= last:
            return operation
    return None


def trace_operations(
    trace_text: str,
    exit_status: int,
    line_rules: tuple[tuple[int, int, str], ...] = LINE_RULES,
) -> tuple[set[str], bool]:
    operations: set[str] = set()
    if not trace_text:
        return operations, True
    if type(exit_status) is not int or not 1 <= exit_status <= 255:
        return set(), False
    # ERR owns the status of its inner command; the caller owns the target's
    # eventual status. Repeated trap propagation is coherent only while every
    # retained record agrees on the inner status.
    trace_status: int | None = None
    trace_frames: list[tuple[int, ...]] = []
    for raw_line in trace_text.splitlines():
        match = TRACE_PATTERN.fullmatch(raw_line)
        if match is None:
            return set(), False
        status = int(match.group(1))
        if not 1 <= status <= 255:
            return set(), False
        if trace_status is None:
            trace_status = status
        elif status != trace_status:
            return set(), False
        raw_frames = match.group(2).split(",")
        if not 1 <= len(raw_frames) <= MAX_TRACE_FRAMES:
            return set(), False
        frames = tuple(int(raw_frame) for raw_frame in raw_frames)
        trace_frames.append(frames)
        for line in frames:
            if not 1 <= line <= MAX_TRACE_LINE:
                return set(), False
            operation = operation_for_line(line, line_rules)
            if operation is not None:
                operations.add(operation)
    avc_required_frames = (
        AVC_OBSERVATION_REQUIRED_FRAMES
        if line_rules is LINE_RULES
        else (
            HISTORICAL_PRE_269_AVC_OBSERVATION_REQUIRED_FRAMES
            if line_rules is HISTORICAL_PRE_269_LINE_RULES
            else frozenset()
        )
    )
    if trace_status != exit_status and not (
        avc_required_frames
        and trace_status == AVC_OBSERVATION_TRACE_STATUS
        and exit_status == AVC_OBSERVATION_TARGET_STATUS
        and all(
            avc_required_frames.issubset(frames)
            and {
                operation_for_line(line, line_rules)
                for line in frames
                if operation_for_line(line, line_rules) is not None
            }
            == {"qualify-avc-correlation"}
            for frames in trace_frames
        )
    ):
        return set(), False
    return operations, True


def semanage_fcontext_add_reason(text: str) -> str | None:
    """Admit only exact Rocky 10.2 fcontext-add ValueError grammar.

    This function receives transient target output.  It never returns a source
    string, path, expression, command, or arbitrary exception text.
    """
    if text.endswith("\n"):
        text = text[:-1]
    if not text.startswith("ValueError: ") or "\n" in text or "\r" in text:
        return None
    message = text.removeprefix("ValueError: ")
    static_reason = SEMANAGE_FCONTEXT_STATIC_FAILURES.get(message)
    if static_reason is not None:
        return static_reason
    for prefix, suffix, reason in SEMANAGE_FCONTEXT_PATH_FAILURES:
        if re.fullmatch(
            prefix + r" " + SEMANAGE_FCONTEXT_EXPRESSION + (r" " + suffix if suffix else ""),
            message,
        ):
            return reason
    if SEMANAGE_FCONTEXT_EQUIVALENCY_FAILURE.fullmatch(text):
        return "semanage-fcontext-equivalency-conflict"
    return None


def classify_failure(
    stdout: bytes,
    trace: bytes,
    exit_status: int,
    *,
    target_bound: bool,
    trusted_marker: str | None = None,
    representation_invalid: bool = False,
    line_rules: tuple[tuple[int, int, str], ...] = LINE_RULES,
) -> tuple[str, str]:
    if representation_invalid:
        return "qualification-harness", "representation-invalid"
    if trusted_marker is not None:
        match = MARKER_PATTERN.fullmatch(trusted_marker.strip())
        if match is not None and match.group(1) in OPERATIONS and match.group(2) in REASONS:
            decision = (match.group(1), match.group(2))
            if exit_status != 0 or decision in ZERO_STATUS_TRUSTED_DECISIONS:
                return decision
            return "qualification-harness", "representation-invalid"
        return "qualification-harness", "unclassified-target-failure"
    if not target_bound:
        return "qualification-harness", "representation-invalid"
    try:
        text = stdout.decode("utf-8")
        trace_text = trace.decode("ascii")
    except UnicodeDecodeError:
        return "qualification-harness", "representation-invalid"
    traced_operations, trace_valid = trace_operations(trace_text, exit_status, line_rules)
    if not trace_valid:
        return "qualification-harness", "representation-invalid"
    if exit_status in (124, 137):
        return "qualification-harness", "timeout"

    explicit_rules = (
        EXPLICIT_RULES
        if line_rules in (LINE_RULES, HISTORICAL_PRE_269_LINE_RULES)
        else HISTORICAL_EXPLICIT_RULES
    )
    explicit = {
        (operation, reason)
        for prefix, operation, reason in explicit_rules
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
        traced_operation = next(iter(traced_operations))
        if traced_operation == "qualify-selinux-storage-fcontext-add":
            semanage_reason = semanage_fcontext_add_reason(text)
            if semanage_reason is not None:
                return traced_operation, semanage_reason
    if len(traced_operations) == 1:
        return traced_operations.pop(), "command-failed"
    return "qualification-harness", "unclassified-target-failure"


def replay_line_rules(
    target_sha: str, harness_sha256: str
) -> tuple[tuple[int, int, str], ...]:
    """Select only the immutable line map owned by an admitted replay pair."""
    pair = target_sha, harness_sha256
    if pair == (EXPECTED_TARGET_SHA, EXPECTED_HARNESS_SHA256):
        return LINE_RULES
    if pair in {
        (HISTORICAL_PRE_269_TARGET_SHA, HISTORICAL_PRE_269_HARNESS_SHA256),
        (HISTORICAL_PRE_265_TARGET_SHA, HISTORICAL_PRE_265_HARNESS_SHA256),
    }:
        return HISTORICAL_PRE_269_LINE_RULES
    raise ValueError("replay target/harness pair has no immutable line map")


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


def unavailable_quadlet_start_diagnostic() -> dict[str, object]:
    return {
        "classification": "diagnostic-unavailable",
        "observation_complete": False,
        "runuser_status": None,
        "systemctl_client_status": None,
        "service_result": None,
        "exec_main_code": None,
        "exec_main_status": None,
    }


def admit_quadlet_start_observation(
    document: object, failure_status: int
) -> tuple[str, str, dict[str, object]]:
    unavailable = unavailable_quadlet_start_diagnostic()
    fallback = ("qualify-quadlet-start", "diagnostic-unavailable", unavailable)
    if not isinstance(document, dict) or set(document) != START_OBSERVATION_KEYS:
        return fallback
    if document.get("schema_version") != 1 or document.get("stage") not in START_STAGES:
        return fallback
    stage = str(document["stage"])
    runuser_status = document.get("runuser_status")
    client_status = document.get("systemctl_client_status")
    service_result = document.get("service_result")
    exec_main_code = document.get("exec_main_code")
    exec_main_status = document.get("exec_main_status")
    if runuser_status is not None and (
        type(runuser_status) is not int or not 0 <= runuser_status <= 255
    ):
        return fallback
    if client_status is not None and (
        type(client_status) is not int or not 0 <= client_status <= 255
    ):
        return fallback
    if service_result is not None and service_result not in SERVICE_RESULTS:
        return fallback
    if exec_main_code is not None and (
        type(exec_main_code) is not int or not 0 <= exec_main_code <= 6
    ):
        return fallback
    if exec_main_status is not None and (
        type(exec_main_status) is not int or not 0 <= exec_main_status <= 255
    ):
        return fallback
    empty_service = (
        service_result is None and exec_main_code is None and exec_main_status is None
    )
    if stage == "runuser-exec-failed":
        consistent = (
            failure_status in {126, 127}
            and runuser_status is None
            and client_status is None
            and empty_service
        )
    elif stage in {
        "runuser-invocation-failed",
        "env-exec-failed",
        "env-command-exec-failed",
    }:
        consistent = (
            runuser_status == failure_status
            and client_status is None
            and empty_service
        )
    elif stage == "systemctl-exec-failed":
        consistent = (
            runuser_status == failure_status
            and failure_status in {126, 127}
            and client_status is None
            and empty_service
        )
    elif stage == "systemctl-request-failed":
        consistent = (
            runuser_status == failure_status
            and client_status == failure_status
            and failure_status != 0
            and empty_service
        )
    elif stage == "service-job-failed":
        consistent = (
            runuser_status == failure_status
            and client_status == failure_status
            and failure_status != 0
            and service_result in SERVICE_RESULTS - {"success"}
            and exec_main_code is not None
            and exec_main_status is not None
        )
    else:
        consistent = False
    if not consistent or stage not in START_STAGE_DECISIONS:
        return fallback
    operation, reason = START_STAGE_DECISIONS[stage]
    return operation, reason, {
        "classification": stage,
        "observation_complete": True,
        "runuser_status": runuser_status,
        "systemctl_client_status": client_status,
        "service_result": service_result,
        "exec_main_code": exec_main_code,
        "exec_main_status": exec_main_status,
    }


def validate_admitted_quadlet_start_diagnostic(
    diagnostic: object, operation: str, reason: str, failure_status: int
) -> None:
    if not isinstance(diagnostic, dict):
        raise ValueError("Quadlet start diagnostic is not closed")
    raw = {"schema_version": 1, "stage": diagnostic.get("classification")}
    for name in (
        "runuser_status",
        "systemctl_client_status",
        "service_result",
        "exec_main_code",
        "exec_main_status",
    ):
        raw[name] = diagnostic.get(name)
    expected_operation, expected_reason, expected = admit_quadlet_start_observation(
        raw, failure_status
    )
    if (
        diagnostic != expected
        or operation != expected_operation
        or reason != expected_reason
    ):
        raise ValueError("Quadlet start classification contradicts its facts")


def unavailable_quadlet_active_diagnostic() -> dict[str, object]:
    return {
        "classification": "diagnostic-unavailable",
        "observation_complete": False,
        "runuser_status": None,
        "systemctl_client_status": None,
    }


def admit_quadlet_active_observation(
    document: object, failure_status: int
) -> tuple[str, str, dict[str, object]]:
    unavailable = unavailable_quadlet_active_diagnostic()
    fallback = ("qualify-quadlet-active-state", "diagnostic-unavailable", unavailable)
    if not isinstance(document, dict) or set(document) != {
        "schema_version",
        "stage",
        "runuser_status",
        "systemctl_client_status",
    }:
        return fallback
    stage = document.get("stage")
    runuser_status = document.get("runuser_status")
    client_status = document.get("systemctl_client_status")
    if document.get("schema_version") != 1 or stage not in ACTIVE_STAGES:
        return fallback
    if runuser_status is not None and (
        type(runuser_status) is not int or not 0 <= runuser_status <= 255
    ):
        return fallback
    if client_status is not None and (
        type(client_status) is not int or not 0 <= client_status <= 255
    ):
        return fallback
    if stage == "runuser-exec-failed":
        consistent = (
            failure_status in {126, 127}
            and runuser_status is None
            and client_status is None
        )
    elif stage in {
        "runuser-invocation-failed",
        "env-exec-failed",
        "env-command-exec-failed",
    }:
        consistent = runuser_status == failure_status and client_status is None
    elif stage == "systemctl-exec-failed":
        consistent = (
            failure_status in {126, 127}
            and runuser_status == failure_status
            and client_status is None
        )
    elif stage == "systemctl-request-failed":
        consistent = (
            failure_status != 0
            and runuser_status == failure_status
            and client_status == failure_status
        )
    else:
        consistent = False
    if not consistent or stage not in ACTIVE_STAGE_DECISIONS:
        return fallback
    operation, reason = ACTIVE_STAGE_DECISIONS[str(stage)]
    return operation, reason, {
        "classification": stage,
        "observation_complete": True,
        "runuser_status": runuser_status,
        "systemctl_client_status": client_status,
    }


def validate_admitted_quadlet_active_diagnostic(
    diagnostic: object, operation: str, reason: str, failure_status: int
) -> None:
    if not isinstance(diagnostic, dict):
        raise ValueError("Quadlet active-state diagnostic is not closed")
    raw = {
        "schema_version": 1,
        "stage": diagnostic.get("classification"),
        "runuser_status": diagnostic.get("runuser_status"),
        "systemctl_client_status": diagnostic.get("systemctl_client_status"),
    }
    expected_operation, expected_reason, expected = admit_quadlet_active_observation(
        raw, failure_status
    )
    if diagnostic != expected or (operation, reason) != (
        expected_operation,
        expected_reason,
    ):
        raise ValueError("Quadlet active-state classification contradicts its facts")


def unavailable_primary_workload_diagnostic() -> dict[str, object]:
    return {
        "classification": "diagnostic-unavailable",
        "observation_complete": False,
        "runuser_status": None,
        "podman_status": None,
    }


def admit_primary_workload_observation(
    document: object, failure_status: int
) -> tuple[str, str, dict[str, object]]:
    unavailable = unavailable_primary_workload_diagnostic()
    fallback = ("qualify-workload-primary", "diagnostic-unavailable", unavailable)
    if not isinstance(document, dict) or set(document) != {
        "schema_version", "stage", "runuser_status", "podman_status",
    }:
        return fallback
    stage = document.get("stage")
    runuser_status = document.get("runuser_status")
    podman_status = document.get("podman_status")
    if document.get("schema_version") != 1 or stage not in PRIMARY_STAGES:
        return fallback
    for status in (runuser_status, podman_status):
        if status is not None and (
            type(status) is not int or not 0 <= status <= 255
        ):
            return fallback
    if stage == "runuser-exec-failed":
        consistent = (
            failure_status in {126, 127}
            and runuser_status is None
            and podman_status is None
        )
    elif stage in {"runuser-invocation-failed", "env-preparation-failed"}:
        consistent = runuser_status == failure_status and podman_status is None
    elif stage == "podman-exec-failed":
        consistent = (
            failure_status in {126, 127}
            and runuser_status == failure_status
            and podman_status is None
        )
    elif stage == "podman-internal-failed":
        consistent = failure_status == runuser_status == podman_status == 125
    elif stage == "podman-oci-status-126":
        consistent = failure_status == runuser_status == podman_status == 126
    elif stage == "podman-oci-status-127":
        consistent = failure_status == runuser_status == podman_status == 127
    elif stage == "podman-request-failed":
        consistent = (
            failure_status == runuser_status == podman_status
            and failure_status not in {0, 125, 126, 127}
        )
    else:
        consistent = False
    if not consistent or stage not in PRIMARY_STAGE_DECISIONS:
        return fallback
    operation, reason = PRIMARY_STAGE_DECISIONS[str(stage)]
    return operation, reason, {
        "classification": stage,
        "observation_complete": True,
        "runuser_status": runuser_status,
        "podman_status": podman_status,
    }


def validate_admitted_primary_workload_diagnostic(
    diagnostic: object, operation: str, reason: str, failure_status: int
) -> None:
    if not isinstance(diagnostic, dict):
        raise ValueError("primary-workload diagnostic is not closed")
    raw = {
        "schema_version": 1,
        "stage": diagnostic.get("classification"),
        "runuser_status": diagnostic.get("runuser_status"),
        "podman_status": diagnostic.get("podman_status"),
    }
    expected_operation, expected_reason, expected = (
        admit_primary_workload_observation(raw, failure_status)
    )
    if diagnostic != expected or (operation, reason) != (
        expected_operation, expected_reason,
    ):
        raise ValueError("primary-workload classification contradicts its facts")


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


def optional_bounded_bytes(path: Path | None, maximum: int) -> tuple[bool, bytes]:
    if path is None or not path.exists():
        return False, b""
    return True, bounded_bytes(path, maximum)


def canonical_json_bytes(document: object) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "ascii"
    )


def replay_trace_admitted(payload: bytes) -> bool:
    if len(payload) > MAX_TRACE_BYTES:
        return False
    if not payload:
        return True
    if not payload.endswith(b"\n"):
        return False
    try:
        lines = payload[:-1].decode("ascii").split("\n")
    except UnicodeDecodeError:
        return False
    for line in lines:
        match = TRACE_PATTERN.fullmatch(line)
        if match is None or not 1 <= int(match.group(1)) <= 255:
            return False
        frames = match.group(2).split(",")
        if not 1 <= len(frames) <= MAX_TRACE_FRAMES:
            return False
        if any(not 1 <= int(frame) <= MAX_TRACE_LINE for frame in frames):
            return False
    return True


def replay_marker_admitted(payload: bytes) -> bool:
    try:
        marker = payload.decode("ascii")
    except UnicodeDecodeError:
        return False
    if not marker.endswith("\n"):
        return False
    match = MARKER_PATTERN.fullmatch(marker[:-1])
    return bool(
        match is not None
        and match.group(1) in OPERATIONS
        and match.group(2) in REASONS
    )


def unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("replay observation contains a duplicate key")
        document[key] = value
    return document


def reject_json_constant(value: str) -> object:
    raise ValueError(f"replay observation contains invalid JSON constant {value}")


def decode_closed_json(payload: bytes) -> object:
    return json.loads(
        payload.decode("utf-8"),
        object_pairs_hook=unique_json_object,
        parse_constant=reject_json_constant,
    )


# The rocky-*-runuser producers own these closed observation state machines.
# Failure records are re-admitted through their existing classifier semantics;
# the exact success records below are the producers' non-causative terminal state.
def replay_start_observation_admitted(document: object) -> bool:
    if (
        not isinstance(document, dict)
        or type(document.get("schema_version")) is not int
        or document.get("schema_version") != 1
        or not isinstance(document.get("stage"), str)
        or (
            document.get("service_result") is not None
            and not isinstance(document.get("service_result"), str)
        )
    ):
        return False
    if document == {
        "schema_version": 1,
        "stage": "success",
        "runuser_status": 0,
        "systemctl_client_status": 0,
        "service_result": None,
        "exec_main_code": None,
        "exec_main_status": None,
    } and all(
        type(document[name]) is int
        for name in ("runuser_status", "systemctl_client_status")
    ):
        return True
    if document.get("stage") in {
        "diagnostic-unavailable",
        "success",
    }:
        return False
    statuses = (
        (126, 127)
        if document.get("stage") == "runuser-exec-failed"
        else (document.get("runuser_status"),)
    )
    return any(
        type(status) is int
        and admit_quadlet_start_observation(document, status)[2].get(
            "observation_complete"
        )
        for status in statuses
    )


def replay_active_observation_admitted(document: object) -> bool:
    if (
        not isinstance(document, dict)
        or type(document.get("schema_version")) is not int
        or document.get("schema_version") != 1
        or not isinstance(document.get("stage"), str)
    ):
        return False
    if document == {
        "schema_version": 1,
        "stage": "success",
        "runuser_status": 0,
        "systemctl_client_status": 0,
    } and all(
        type(document[name]) is int
        for name in ("runuser_status", "systemctl_client_status")
    ):
        return True
    if document.get("stage") in {
        "diagnostic-unavailable",
        "success",
    }:
        return False
    statuses = (
        (126, 127)
        if document.get("stage") == "runuser-exec-failed"
        else (document.get("runuser_status"),)
    )
    return any(
        type(status) is int
        and admit_quadlet_active_observation(document, status)[2].get(
            "observation_complete"
        )
        for status in statuses
    )


def replay_primary_observation_admitted(document: object) -> bool:
    if (
        not isinstance(document, dict)
        or type(document.get("schema_version")) is not int
        or document.get("schema_version") != 1
        or not isinstance(document.get("stage"), str)
    ):
        return False
    if document == {
        "schema_version": 1,
        "stage": "success",
        "runuser_status": 0,
        "podman_status": 0,
    } and all(
        type(document[name]) is int
        for name in ("runuser_status", "podman_status")
    ):
        return True
    if document.get("stage") in {
        "diagnostic-unavailable",
        "success",
    }:
        return False
    statuses = (
        (126, 127)
        if document.get("stage") == "runuser-exec-failed"
        else (document.get("runuser_status"),)
    )
    return any(
        type(status) is int
        and admit_primary_workload_observation(document, status)[2].get(
            "observation_complete"
        )
        for status in statuses
    )


def replay_observation_admitted(
    name: str,
    payload: bytes,
    exit_status: int,
    bindings: dict[str, str],
    stdout: bytes,
) -> bool:
    try:
        document = decode_closed_json(payload)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        TypeError,
        ValueError,
    ):
        return False
    if name == "start_observation":
        return replay_start_observation_admitted(document)
    if name == "active_observation":
        return replay_active_observation_admitted(document)
    if name == "primary_observation":
        return replay_primary_observation_admitted(document)
    if name != "reload_adjacency":
        return False
    try:
        if canonical_json_bytes(document) != payload:
            return False
    except (UnicodeEncodeError, TypeError, ValueError):
        return False
    admitted = admit_daemon_reload_adjacency(
        document,
        {
            **bindings,
            "failure_status": exit_status,
        },
        reload_client_error(stdout),
    )
    if admitted == unavailable_daemon_reload_adjacency():
        return False
    try:
        validate_admitted_daemon_reload_adjacency(admitted)
    except ValueError:
        return False
    return True


def replay_component_admitted(
    name: str,
    payload: bytes,
    *,
    exit_status: int,
    bindings: dict[str, str],
    stdout: bytes,
) -> bool:
    if len(payload) > REPLAY_EXACT_COMPONENT_BOUNDS[name]:
        return False
    if name == "qualification_stdout":
        return not payload or payload in REPLAYABLE_STDOUT_RECORDS
    if name == "target_qualification_trace":
        return replay_trace_admitted(payload)
    if name == "trusted_marker":
        return replay_marker_admitted(payload)
    return replay_observation_admitted(
        name, payload, exit_status, bindings, stdout
    )


def build_replay_witness(
    component_sources: dict[str, tuple[bool, bytes]],
    *,
    exit_status: int,
    representation_invalid: bool,
    bindings: dict[str, str],
) -> dict[str, object]:
    if set(component_sources) != set(REPLAY_COMPONENT_ORDER):
        raise ValueError("replay component inventory is incomplete")
    stdout = component_sources["qualification_stdout"][1]
    components: dict[str, object] = {}
    available = True
    for name in REPLAY_COMPONENT_ORDER:
        source = component_sources[name]
        if (
            not isinstance(source, tuple)
            or len(source) != 2
            or type(source[0]) is not bool
            or not isinstance(source[1], bytes)
            or (not source[0] and source[1])
        ):
            raise ValueError(f"replay {name} source is invalid")
        present, payload = source
        replayable = not present or replay_component_admitted(
            name,
            payload,
            exit_status=exit_status,
            bindings=bindings,
            stdout=stdout,
        )
        if (
            name == "reload_adjacency"
            and present
            and components["qualification_stdout"]["replayability"]
            != "exact"
        ):
            replayable = False
        available = available and replayable
        components[name] = {
            "present": present,
            "byte_count": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "replayability": "exact" if replayable else "unavailable",
            "content_base64": (
                base64.b64encode(payload).decode("ascii")
                if present and replayable
                else None
            ),
        }
    return {
        "schema_version": 1,
        "available": available,
        "representation_invalid": representation_invalid,
        "exit_status": exit_status,
        "component_order": list(REPLAY_COMPONENT_ORDER),
        "separator": "NUL",
        "components": components,
    }


def build_avc_correlation_diagnostic(
    payload: bytes,
    *,
    target_sha: str,
    trusted_control_sha: str,
    qualification_run_id: str,
    qualification_run_attempt: str,
    harness_sha256: str,
) -> dict[str, object]:
    """Bind one canonical semantic projection without retaining audit output."""
    if not payload or len(payload) > MAX_AVC_CORRELATION_DIAGNOSTIC_BYTES:
        raise ValueError("AVC correlation diagnostic is outside its closed bound")
    try:
        projection = decode_closed_json(payload)
        if canonical_json_bytes(projection) != payload:
            raise ValueError("AVC correlation diagnostic is not canonical")
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        TypeError,
        ValueError,
    ) as error:
        raise ValueError("AVC correlation diagnostic is not closed JSON") from error
    repository_contract = Path(__file__).resolve().parents[1] / "selinux_isolation_contract.py"
    contract_path = (
        repository_contract
        if repository_contract.exists()
        else INSTALLED_SELINUX_ISOLATION_CONTRACT
    )
    try:
        metadata = contract_path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or contract_path.is_symlink()
            or metadata.st_mode & 0o022
            or not 0 < metadata.st_size <= 65_536
        ):
            raise ValueError("SELinux isolation contract is not trusted")
        specification = importlib.util.spec_from_file_location(
            "selinux_isolation_contract", contract_path
        )
        if specification is None or specification.loader is None:
            raise ValueError("SELinux isolation contract cannot be loaded")
        contract = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(contract)
        contract.validate_avc_correlation_diagnostic(projection)
    except (OSError, AttributeError, ValueError) as error:
        raise ValueError("AVC correlation diagnostic contradicts its facts") from error
    if projection.get("correlation_outcome") == "admitted":
        raise ValueError("AVC failure diagnostic contains an admitted candidate")
    return {
        "schema_version": projection["schema_version"],
        "target_sha": target_sha,
        "trusted_control_sha": trusted_control_sha,
        "qualification_run_id": qualification_run_id,
        "qualification_run_attempt": qualification_run_attempt,
        "harness_sha256": harness_sha256,
        "projection_bytes": len(payload),
        "projection_sha256": hashlib.sha256(payload).hexdigest(),
        "projection": projection,
    }


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
    parser.add_argument("--start-observation", type=Path)
    parser.add_argument("--active-observation", type=Path)
    parser.add_argument("--primary-observation", type=Path)
    parser.add_argument("--avc-correlation-diagnostic", type=Path)
    parser.add_argument("--exit-status", required=True, type=int)
    parser.add_argument("--trusted-marker", type=Path)
    parser.add_argument("--representation-invalid", action="store_true")
    parser.add_argument("--output", required=True, type=Path)
    options = parser.parse_args()
    if not HEX40.fullmatch(options.target_sha) or not HEX40.fullmatch(options.control_sha):
        raise SystemExit("target and control SHAs must be exact lowercase commits")
    if not POSITIVE_INTEGER.fullmatch(options.run_id) or not POSITIVE_INTEGER.fullmatch(options.run_attempt):
        raise SystemExit("qualification run identity is outside the closed format")
    if not 0 <= options.exit_status <= 255 or (
        options.exit_status == 0
        and not options.representation_invalid
        and options.trusted_marker is None
    ):
        raise SystemExit("target harness status is outside the closed range")

    stdout = bounded_bytes(
        options.stdout,
        MAX_STDOUT_CAPTURE_BYTES
        if options.representation_invalid
        else MAX_STDOUT_BYTES,
    )
    trace = bounded_bytes(options.trace, MAX_CAPTURE_FILE_BYTES)
    harness = bounded_bytes(options.harness, 128 * 1024)
    harness_sha256 = hashlib.sha256(harness).hexdigest()
    target_bound = options.target_sha == EXPECTED_TARGET_SHA and harness_sha256 == EXPECTED_HARNESS_SHA256
    marker_present = False
    marker = None
    marker_bytes = b""
    if options.trusted_marker is not None and options.trusted_marker.exists():
        marker_present, marker_bytes = optional_bounded_bytes(
            options.trusted_marker,
            REPLAY_COMPONENT_BOUNDS["trusted_marker"]
            if options.representation_invalid
            else 256,
        )
        if not options.representation_invalid:
            marker = marker_bytes.decode("ascii")
    operation, reason = classify_failure(
        stdout,
        trace,
        options.exit_status,
        target_bound=target_bound,
        trusted_marker=marker,
        representation_invalid=options.representation_invalid,
        line_rules=LINE_RULES,
    )
    adjacency_present = False
    adjacency_bytes = b""
    adjacency: dict[str, object] | None = None
    start_present = False
    start_bytes = b""
    start_diagnostic: dict[str, object] | None = None
    active_present = False
    active_bytes = b""
    active_diagnostic: dict[str, object] | None = None
    primary_present = False
    primary_bytes = b""
    primary_diagnostic: dict[str, object] | None = None
    avc_diagnostic_bytes = b""
    avc_diagnostic: dict[str, object] | None = None
    if operation == "qualify-quadlet-start" and reason == "command-failed":
        raw_start: object = None
        if options.start_observation is not None and options.start_observation.exists():
            try:
                start_present, start_bytes = optional_bounded_bytes(
                    options.start_observation, MAX_START_OBSERVATION_BYTES
                )
                raw_start = json.loads(start_bytes)
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                raw_start = None
        operation, reason, start_diagnostic = admit_quadlet_start_observation(
            raw_start, options.exit_status
        )
    if operation == "qualify-quadlet-active-state" and reason == "command-failed":
        raw_active: object = None
        if options.active_observation is not None and options.active_observation.exists():
            try:
                active_present, active_bytes = optional_bounded_bytes(
                    options.active_observation, MAX_ACTIVE_OBSERVATION_BYTES
                )
                raw_active = json.loads(active_bytes)
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                raw_active = None
        operation, reason, active_diagnostic = admit_quadlet_active_observation(
            raw_active, options.exit_status
        )
    if operation == "qualify-workload-primary" and reason == "command-failed":
        raw_primary: object = None
        if (
            options.primary_observation is not None
            and options.primary_observation.exists()
        ):
            try:
                primary_present, primary_bytes = optional_bounded_bytes(
                    options.primary_observation, MAX_PRIMARY_OBSERVATION_BYTES
                )
                raw_primary = json.loads(primary_bytes)
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                raw_primary = None
        operation, reason, primary_diagnostic = admit_primary_workload_observation(
            raw_primary, options.exit_status
        )
    if operation == "qualify-quadlet-daemon-reload" and reason == "command-failed":
        raw_adjacency: object = None
        if options.reload_adjacency is not None and options.reload_adjacency.exists():
            try:
                adjacency_present, adjacency_bytes = optional_bounded_bytes(
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
    if (
        operation == "qualify-avc-correlation"
        and reason == "command-failed"
        and options.exit_status == 3
    ):
        avc_present, avc_diagnostic_bytes = optional_bounded_bytes(
            options.avc_correlation_diagnostic,
            MAX_AVC_CORRELATION_DIAGNOSTIC_BYTES,
        )
        if not avc_present or not avc_diagnostic_bytes:
            raise ValueError("AVC correlation failure lacks its closed diagnostic")
        avc_diagnostic = build_avc_correlation_diagnostic(
            avc_diagnostic_bytes,
            target_sha=options.target_sha,
            trusted_control_sha=options.control_sha,
            qualification_run_id=options.run_id,
            qualification_run_attempt=options.run_attempt,
            harness_sha256=harness_sha256,
        )
    replay_required = (
        target_bound
        and (operation, reason) == ("qualification-harness", "representation-invalid")
        and options.control_sha != LEGACY_REPLAY_OPTIONAL_CONTROL_SHA
    )
    if replay_required:
        marker_present, marker_bytes = optional_bounded_bytes(
            options.trusted_marker, REPLAY_COMPONENT_BOUNDS["trusted_marker"]
        )
        adjacency_present, adjacency_bytes = optional_bounded_bytes(
            options.reload_adjacency, REPLAY_COMPONENT_BOUNDS["reload_adjacency"]
        )
        start_present, start_bytes = optional_bounded_bytes(
            options.start_observation, REPLAY_COMPONENT_BOUNDS["start_observation"]
        )
        active_present, active_bytes = optional_bounded_bytes(
            options.active_observation, REPLAY_COMPONENT_BOUNDS["active_observation"]
        )
        primary_present, primary_bytes = optional_bounded_bytes(
            options.primary_observation, REPLAY_COMPONENT_BOUNDS["primary_observation"]
        )
    if avc_diagnostic is not None:
        diagnostic_payload = avc_diagnostic_bytes
    elif operation == "qualify-selinux-storage-fcontext-add":
        diagnostic_payload = b"semanage-fcontext-add-v1\0" + trace + b"\0" + reason.encode("ascii")
    else:
        diagnostic_payload = (
            stdout
            + b"\0"
            + trace
            + b"\0"
            + marker_bytes
            + b"\0"
            + adjacency_bytes
            + b"\0"
            + start_bytes
            + b"\0"
            + active_bytes
            + b"\0"
            + primary_bytes
        )
    document: dict[str, object] = {
        "schema_version": (
            avc_diagnostic["schema_version"] + 2
            if avc_diagnostic is not None
            else (2 if replay_required else 1)
        ),
        "phase": "target-qualification",
        "target_sha": options.target_sha,
        "trusted_control_sha": options.control_sha,
        "qualification_run_id": options.run_id,
        "qualification_run_attempt": options.run_attempt,
        "harness_sha256": harness_sha256,
        "operation": operation,
        "reason": reason,
        "exit_status": options.exit_status,
        "diagnostic_input_sha256": hashlib.sha256(diagnostic_payload).hexdigest(),
        "diagnostic_input_bytes": (
            len(avc_diagnostic_bytes)
            if avc_diagnostic is not None
            else (
                len(trace) + len(reason)
                if operation == "qualify-selinux-storage-fcontext-add"
                else len(stdout)
                + len(trace)
                + len(marker_bytes)
                + len(adjacency_bytes)
                + len(start_bytes)
                + len(active_bytes)
                + len(primary_bytes)
            )
        ),
    }
    if adjacency is not None:
        document["daemon_reload_adjacency"] = adjacency
    if start_diagnostic is not None:
        document["quadlet_start_diagnostic"] = start_diagnostic
    if active_diagnostic is not None:
        document["quadlet_active_state_diagnostic"] = active_diagnostic
    if primary_diagnostic is not None:
        document["primary_workload_diagnostic"] = primary_diagnostic
    if avc_diagnostic is not None:
        document["avc_correlation_diagnostic"] = avc_diagnostic
    if replay_required:
        document["replay_witness"] = build_replay_witness(
            {
                "qualification_stdout": (True, stdout),
                "target_qualification_trace": (True, trace),
                "trusted_marker": (marker_present, marker_bytes),
                "reload_adjacency": (adjacency_present, adjacency_bytes),
                "start_observation": (start_present, start_bytes),
                "active_observation": (active_present, active_bytes),
                "primary_observation": (primary_present, primary_bytes),
            },
            exit_status=options.exit_status,
            representation_invalid=options.representation_invalid,
            bindings={
                "target_sha": options.target_sha,
                "trusted_control_sha": options.control_sha,
                "qualification_run_id": options.run_id,
                "qualification_run_attempt": options.run_attempt,
            },
        )
    write_document(options.output, document)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
