#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Focused Rocky Linux and SELinux production-host admission contract tests."""

from __future__ import annotations

import copy
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts/validate-production-contract.py"
INVENTORY = ROOT / "tests/fixtures/production-inventory/valid-amd64.yaml"
ARM64_INVENTORY = ROOT / "tests/fixtures/production-inventory/valid-arm64.yaml"
VALID_AMD64 = ROOT / "tests/fixtures/production-host/valid-amd64.yaml"
VALID_ARM64 = ROOT / "tests/fixtures/production-host/valid-arm64.yaml"
QUALIFICATION_HARNESS = ROOT / "scripts/qualify-production-host.sh"


def load(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"fixture must be an object: {path}")
    return value


def validate(
    facts: dict[str, Any], inventory: Path = INVENTORY
) -> subprocess.CompletedProcess[str]:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", encoding="utf-8") as handle:
        yaml.safe_dump(facts, handle, sort_keys=False)
        handle.flush()
        return subprocess.run(
            [
                sys.executable,
                str(VALIDATOR),
                "--inventory",
                str(inventory),
                "--host-facts",
                handle.name,
                "--synthetic",
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )


def set_path(document: dict[str, Any], path: tuple[str, ...], value: Any) -> None:
    target = document
    for segment in path[:-1]:
        child = target[segment]
        if not isinstance(child, dict):
            raise AssertionError(f"mutation path is not an object: {path}")
        target = child
    target[path[-1]] = value


def assert_qualification_service_account_context() -> None:
    """Keep service-account commands independent of the administrator CWD."""

    source = QUALIFICATION_HARNESS.read_text(encoding="utf-8")
    if "/home/secpal-deploy" in source:
        raise AssertionError("qualification harness must derive, not hardcode, service home")
    if 'service_passwd_entry="$(getent passwd "$service_account" || true)"' not in source:
        raise AssertionError("qualification harness must derive service home from getent passwd")
    if "service_home=\"$(awk -F: '{print $6}' <<<\"$service_passwd_entry\")\"" not in source:
        raise AssertionError("qualification harness must derive service home from passwd data")

    helper_start = source.index("run_as_service_account() (")
    helper_end = source.index("\n)\n", helper_start) + len("\n)\n")
    helper = source[helper_start:helper_end]
    cd_offset = helper.index('cd -- "$service_home"')
    runuser_offset = helper.index('runuser --user "$service_account" -- env')
    if cd_offset > runuser_offset:
        raise AssertionError("qualification helper must change to service home before runuser")
    if '"HOME=${service_home}"' not in helper:
        raise AssertionError("qualification helper must explicitly set service HOME")

    if 'run_as_service_account podman "$@"' not in source:
        raise AssertionError("rootless Podman must use the service-account context helper")
    if source.count('runuser --user "$service_account"') != 1:
        raise AssertionError("direct service-account switches must use the one context helper")
    for path in ("$quadlet_root", "$unit_path"):
        if f'run_as_service_account test -w "{path}"' not in source:
            raise AssertionError("Quadlet write-authority probes must use service context helper")


def admit_direct_user_manager_control(source: str) -> None:
    """Admit one bounded direct-runtime-user manager control seam."""

    required = (
        'service_passwd_entry="$(getent passwd "$service_account" || true)"',
        'service_uid="$(id -u "$service_account")"',
        'service_home="$(awk -F: \'{print $6}\' <<<"$service_passwd_entry")"',
        'runuser --user "$service_account" -- env -u CONTAINER_HOST '
        '-u CONTAINER_CONNECTION',
        '"HOME=${service_home}"',
        '"XDG_RUNTIME_DIR=/run/user/${service_uid}"',
        '"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/${service_uid}/bus"',
        'run_as_service_account systemctl --user "$@"',
        'rootless_podman() {\n  run_as_service_account podman "$@"',
        'install -d -o 0 -g 0 -m 0755 "$quadlet_root"',
        'if run_as_service_account test -w "$quadlet_root"; then',
        'chmod 0644 "$unit_path"',
        'if run_as_service_account test -w "$unit_path"; then',
        "user_systemctl daemon-reload",
        'user_systemctl start "${unit_name}.service"',
        'user_systemctl is-active --quiet "${unit_name}.service"',
    )
    for representation in required:
        if representation not in source:
            raise AssertionError(
                f"direct runtime-user manager contract is incomplete: {representation}"
            )

    forbidden = (
        "--machine=",
        "@.host",
        "sudo ",
        "systemctl --system",
        'systemctl --user "$@" ||',
    )
    for representation in forbidden:
        if representation in source:
            raise AssertionError(
                f"forbidden user-manager control fallback is reachable: {representation}"
            )


def assert_qualification_direct_user_manager_control() -> None:
    """Reject authority, identity, environment and fallback mutations."""

    source = QUALIFICATION_HARNESS.read_text(encoding="utf-8")
    admit_direct_user_manager_control(source)
    mutations = {
        "writable-quadlet-directory": source.replace(
            'install -d -o 0 -g 0 -m 0755 "$quadlet_root"',
            'install -d -o 0 -g 0 -m 0775 "$quadlet_root"',
        ),
        "writable-quadlet-file": source.replace(
            'chmod 0644 "$unit_path"', 'chmod 0664 "$unit_path"'
        ),
        "wrong-home": source.replace('"HOME=${service_home}"', '"HOME=/root"'),
        "wrong-account-uid": source.replace(
            'service_uid="$(id -u "$service_account")"', 'service_uid=0'
        ),
        "wrong-runtime-directory": source.replace(
            '"XDG_RUNTIME_DIR=/run/user/${service_uid}"',
            '"XDG_RUNTIME_DIR=/run/user/0"',
        ),
        "wrong-user-bus": source.replace(
            '"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/${service_uid}/bus"',
            '"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/0/bus"',
        ),
        "different-manager": source.replace(
            'systemctl --user "$@"', 'systemctl --system "$@"'
        ),
        "inherited-container-host": source.replace(" -u CONTAINER_HOST", ""),
        "inherited-container-connection": source.replace(
            " -u CONTAINER_CONNECTION", ""
        ),
        "rootful-podman": source.replace(
            'run_as_service_account podman "$@"', 'podman "$@"'
        ),
        "machine-bus-fallback": source.replace(
            'run_as_service_account systemctl --user "$@"',
            'run_as_service_account systemctl --user "$@" || '
            'systemctl "--machine=${service_account}@.host" --user "$@"',
        ),
        "sudo-fallback": source.replace(
            'run_as_service_account systemctl --user "$@"',
            'run_as_service_account systemctl --user "$@" || '
            'sudo systemctl --user "$@"',
        ),
        "ignored-manager-failure": source.replace(
            'run_as_service_account systemctl --user "$@"',
            'run_as_service_account systemctl --user "$@" || true',
        ),
    }
    for name, candidate in mutations.items():
        try:
            admit_direct_user_manager_control(candidate)
        except AssertionError:
            continue
        raise AssertionError(f"unsafe direct-user-manager mutation passed: {name}")


def assert_qualification_native_evidence_cleanup() -> None:
    """Keep AVC evidence and transient-unit cleanup bounded and observable."""

    source = QUALIFICATION_HARNESS.read_text(encoding="utf-8")
    if "read -r audit_date audit_time < <(LC_ALL=C date '+%x %T')" not in source:
        raise AssertionError("qualification harness must collect locale-stable AVC date/time")
    if 'LC_ALL=C ausearch --input-logs -m AVC -ts "$audit_date" "$audit_time" -i' not in source:
        raise AssertionError("ausearch AVC must use separate start date/time with auditd log input")

    avc_pipeline = (
        'LC_ALL=C ausearch --input-logs -m AVC -ts "$audit_date" "$audit_time" -i |\n'
        "    grep -F 'marker' >/dev/null"
    )
    if avc_pipeline not in source:
        raise AssertionError(
            "ausearch AVC evidence must force auditd log input and consume its full stream"
        )
    avc_pipeline_mutations = {
        "default-ausearch-input": source.replace(" --input-logs", "", 1),
        "quiet-grep": source.replace("grep -F 'marker' >/dev/null", "grep -Fq 'marker'", 1),
    }
    for name, candidate in avc_pipeline_mutations.items():
        if candidate == source:
            raise AssertionError(f"AVC evidence mutation did not apply: {name}")
        if avc_pipeline in candidate:
            raise AssertionError(f"unsafe AVC evidence mutation passed: {name}")

    if 'ausearch -m AVC -ts "$audit_start" -i' in source:
        raise AssertionError("qualification harness must not pass combined AVC date/time")

    fallback_start = source.index('if ! matching_marker_avc "$audit_date" "$audit_time"; then')
    dontaudit_start = source.index("semodule -DB", fallback_start)
    if fallback_start > dontaudit_start:
        raise AssertionError("dontaudit visibility may only follow a missing normal-policy AVC")
    if source.count("semodule -DB") != 1:
        raise AssertionError("qualification harness must have one bounded dontaudit fallback")
    if "setenforce 0" in source or "permissive" in source:
        raise AssertionError("qualification harness must not weaken SELinux enforcement")
    if source.index('[[ "$(getenforce)" != Enforcing ]]', dontaudit_start) < dontaudit_start:
        raise AssertionError("dontaudit fallback must verify SELinux remains Enforcing")
    repeated_avc_start = source.index(
        'if ! matching_marker_avc "$audit_date" "$audit_time"; then', fallback_start + 1
    )
    normal_restore_start = source.index("if ! semodule -B; then", repeated_avc_start)
    if normal_restore_start < repeated_avc_start:
        raise AssertionError("normal dontaudit fallback must restore policy after AVC evidence")

    cleanup_start = source.index("cleanup() {")
    cleanup_end = source.index("\nwhile (($#));", cleanup_start)
    cleanup = source[cleanup_start:cleanup_end]
    restore_offset = cleanup.index("semodule -B")
    stop_offset = cleanup.index('user_systemctl stop "${unit_name}.service"')
    if restore_offset > stop_offset:
        raise AssertionError("cleanup must restore dontaudit visibility before other cleanup")
    if 'user_systemctl reset-failed "${unit_name}.service"' not in cleanup:
        raise AssertionError("cleanup must reset only its generated unit's failed state")
    if cleanup.index('user_systemctl daemon-reload') > cleanup.index(
        'user_systemctl reset-failed "${unit_name}.service"'
    ):
        raise AssertionError("cleanup must reload before resetting its generated unit state")
    if 'semanage fcontext --delete "$fcontext_expression"' not in cleanup:
        raise AssertionError("cleanup must retain bounded fcontext restoration")
    if "trap cleanup EXIT HUP INT TERM" not in source:
        raise AssertionError("cleanup must restore dontaudit policy on abnormal exits")
    if re.search(r"(?<!user_)systemctl\\s+reset-failed(?:\\s|$)", source):
        raise AssertionError("qualification harness must not reset failed state globally")

    for container in ("$container_a", "$container_b"):
        label_start = source.index(f'rootless_podman top "{container}" label')
        label_end = source.index("\n", label_start)
        label_pipeline = source[label_start:label_end]
        if label_pipeline.index("tr -d '\\000'") > label_pipeline.index("tail -n 1"):
            raise AssertionError("NUL bytes must be removed before label command substitution")
    evidence_offset = source.index("printf 'seccomp_mode=%s")
    negative_read_offset = source.index(
        'if rootless_podman exec "$container_b" cat /foreign/marker'
    )
    if evidence_offset > negative_read_offset:
        raise AssertionError("captured label and seccomp evidence must precede AVC collection")


def main() -> int:
    assert_qualification_service_account_context()
    assert_qualification_direct_user_manager_control()
    assert_qualification_native_evidence_cleanup()
    amd64 = load(VALID_AMD64)
    arm64 = load(VALID_ARM64)
    for name, facts, inventory in (
        ("amd64", amd64, INVENTORY),
        ("arm64", arm64, ARM64_INVENTORY),
    ):
        result = validate(facts, inventory)
        if result.returncode != 0:
            raise AssertionError(f"valid Rocky {name} facts failed: {result.stderr}")
        if (
            facts["os"]["id"] != "rocky"
            or facts["os"]["version_id"] != "10.2"
            or facts["os"]["updates"]["mechanism"] != "dnf4"
            or facts["os"]["updates"]["releasever"] != "10"
        ):
            raise AssertionError(
                f"{name} fixture must use Rocky BaseOS DNF4 with release line 10"
            )

    mutations = (
        ("native-evidence-claim-in-fixture-mode", ("evidence_class",), "rocky-native"),
        ("debian", ("os", "id"), "debian"),
        ("ubuntu", ("os", "id"), "ubuntu"),
        ("rocky-9", ("os", "version_id"), "9.7"),
        ("rocky-10.1", ("os", "version_id"), "10.1"),
        ("malformed-version", ("os", "version_id"), "10"),
        ("out-of-contract-dnf5", ("os", "updates", "mechanism"), "dnf5"),
        (
            "release-line-cannot-be-installed-minor",
            ("os", "updates", "releasever"),
            "10.2",
        ),
        ("wrong-rocky-release-line", ("os", "updates", "releasever"), "9"),
        ("legacy-x86", ("cpu", "x86_64_level"), "x86-64-v2"),
        ("selinux-disabled", ("selinux", "mode"), "disabled"),
        ("selinux-permissive", ("selinux", "mode"), "permissive"),
        (
            "missing-container-selinux",
            ("selinux", "container_policy_package", "installed"),
            False,
        ),
        ("label-disabled", ("selinux", "workload", "label_disabled"), True),
        ("unconfined-process", ("selinux", "workload", "process_type"), "unconfined_t"),
        ("wrong-storage-label", ("selinux", "workload", "storage_type"), "default_t"),
        (
            "missing-positive-access",
            ("selinux", "workload", "intended_access_succeeded"),
            False,
        ),
        (
            "missing-negative-denial",
            ("selinux", "workload", "cross_boundary_access_denied"),
            False,
        ),
        ("non-selinux-denial", ("selinux", "workload", "denial_cause"), "dac"),
        ("missing-avc", ("selinux", "workload", "avc_denial_observed"), False),
        (
            "dac-blocks-boundary",
            ("selinux", "workload", "dac_would_allow_cross_boundary"),
            False,
        ),
        ("chcon-only", ("selinux", "persistent_labels", "chcon_only"), True),
        ("weakened-policy", ("selinux", "global_policy_weakened"), True),
        ("rootful", ("runtime", "rootless"), False),
        ("privileged", ("runtime", "security", "privileged"), True),
        ("host-network", ("runtime", "network", "host_network"), True),
        ("socket-api", ("runtime", "api", "socket_enabled"), True),
        ("docker-socket", ("runtime", "api", "docker_socket_mounted"), True),
        ("writable-quadlet", ("runtime", "quadlet", "tree_service_account_can_write"), True),
        (
            "writable-quadlet-policy",
            (
                "runtime",
                "quadlet",
                "persistent_search_path_configuration_account_writable",
            ),
            True,
        ),
        ("quadlet-symlink", ("runtime", "quadlet", "tree_symlinks_present"), True),
        (
            "alternate-quadlet-path",
            ("runtime", "quadlet", "effective_search_paths"),
            ["/var/lib/secpal/.config/containers/systemd"],
        ),
        ("mutable-image", ("runtime", "security", "digest_only_images"), False),
        ("automatic-update", ("runtime", "updates", "image_auto_update"), True),
        ("seccomp-disabled", ("runtime", "security", "seccomp_enabled"), False),
    )
    for name, path, value in mutations:
        candidate = copy.deepcopy(amd64)
        set_path(candidate, path, value)
        result = validate(candidate)
        if result.returncode == 0:
            raise AssertionError(f"unsafe Rocky host mutation passed: {name}")

    print(
        "Rocky/SELinux host contract passed 2 positive fixtures and "
        f"{len(mutations)} negative mutations."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
