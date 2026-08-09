#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Validate closed cloud evidence and write a concise non-secret summary."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import NoReturn


MAX_EVIDENCE_BYTES = 262_144
FORBIDDEN_KEY = re.compile(r"(?:authorization|credential|password|private.?key|secret|token)", re.IGNORECASE)
FORBIDDEN_VALUE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|"
    r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})\b|"
    r"\b(?:Basic|Bearer) [A-Za-z0-9._~+/=-]{8,}|"
    r"[a-z][a-z0-9+.-]*://[^/@\s]+:[^/@\s]+@",
    re.IGNORECASE,
)


def fail(message: str) -> NoReturn:
    raise ValueError(message)


def exact_keys(value: object, expected: set[str], path: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(f"{path} is incomplete or contains unknown fields")
    return value


def reject_sensitive(value: object, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if FORBIDDEN_KEY.search(str(key)):
                fail(f"credential-like field is forbidden at {path}")
            reject_sensitive(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_sensitive(child, f"{path}[{index}]")
    elif isinstance(value, str) and FORBIDDEN_VALUE.search(value):
        fail(f"credential-like value is forbidden at {path}")


def validate_document(document: object) -> dict[str, object]:
    reject_sensitive(document)
    root = exact_keys(document, {"schema_version", "workflow", "test", "platform", "apt", "runtime"}, "$")
    if root["schema_version"] != 1:
        fail("unsupported evidence schema version")
    workflow = exact_keys(root["workflow"], {"repository", "run_id", "run_attempt", "target_sha"}, "$.workflow")
    test = exact_keys(
        root["test"],
        {"provider", "region", "profile", "started_at", "ended_at", "target_exit_status", "result", "failed_admission_invariants"},
        "$.test",
    )
    platform = exact_keys(
        root["platform"],
        {"os_release", "architecture", "uname", "kernel", "cpu", "virtualization", "logical_cpu", "memory_bytes", "root_filesystem_bytes"},
        "$.platform",
    )
    apt = exact_keys(root["apt"], {"source_files", "source_hosts", "configured_suites", "debian_archive_keyring_version", "runtime_packages"}, "$.apt")
    runtime = exact_keys(
        root["runtime"],
        {"podman", "crun_version", "crun_features", "netavark_version", "aardvark_version", "pasta_version", "passt_version", "uidmap", "cgroup_version", "systemd_version", "apparmor_host"},
        "$.runtime",
    )
    exact_keys(platform["os_release"], {"ID", "VERSION_ID", "VERSION_CODENAME", "PRETTY_NAME"}, "$.platform.os_release")
    exact_keys(platform["cpu"], {"vendor", "model"}, "$.platform.cpu")
    podman = exact_keys(runtime["podman"], {"version", "rootless", "seccomp_enabled", "apparmor_enabled", "oci_runtime", "network_backend", "rootless_network_command", "cgroup_version"}, "$.runtime.podman")
    exact_keys(runtime["uidmap"], {"newuidmap", "newgidmap"}, "$.runtime.uidmap")
    exact_keys(runtime["apparmor_host"], {"kernel_enabled", "loaded_profiles", "enforcing_profiles"}, "$.runtime.apparmor_host")
    if workflow["repository"] != "SecPal/deployment" or re.fullmatch(r"[0-9a-f]{40}", str(workflow["target_sha"])) is None:
        fail("workflow identity is invalid")
    if test["provider"] != "digitalocean" or test["region"] != "fra1" or test["profile"] not in {"intel", "amd"}:
        fail("provider identity is outside the closed allowlist")
    for name in ("started_at", "ended_at"):
        try:
            datetime.fromisoformat(str(test[name]).replace("Z", "+00:00"))
        except ValueError:
            fail(f"{name} is not an RFC 3339 timestamp")
    failures = test["failed_admission_invariants"]
    if not isinstance(failures, list) or not all(re.fullmatch(r"[A-Z0-9_]+", str(item)) for item in failures):
        fail("failed admission invariants are malformed")
    expected_result = "passed" if not failures and test["target_exit_status"] == 0 else "failed"
    if test["result"] != expected_result:
        fail("result contradicts target status or admission failures")
    if not isinstance(apt["runtime_packages"], dict) or set(apt["runtime_packages"]) != {
        "podman", "conmon", "crun", "netavark", "aardvark-dns", "passt", "uidmap", "dbus-user-session"
    }:
        fail("runtime package provenance is incomplete")
    if podman["apparmor_enabled"] is not None and not isinstance(podman["apparmor_enabled"], bool):
        fail("Podman AppArmor capability must remain distinct boolean evidence")
    return root


def write_summary(document: dict[str, object], path: Path) -> None:
    workflow = document["workflow"]
    test = document["test"]
    platform = document["platform"]
    runtime = document["runtime"]
    assert isinstance(workflow, dict) and isinstance(test, dict)
    assert isinstance(platform, dict) and isinstance(runtime, dict)
    podman = runtime["podman"]
    apparmor = runtime["apparmor_host"]
    assert isinstance(podman, dict) and isinstance(apparmor, dict)
    failures = test["failed_admission_invariants"]
    assert isinstance(failures, list)
    lines = [
        "# Debian 13 cloud conformance evidence",
        "",
        f"- Result: `{test['result']}`",
        f"- Target SHA: `{workflow['target_sha']}`",
        f"- Provider/profile: `{test['provider']}/{test['profile']}` in `{test['region']}`",
        f"- Platform: `{platform['architecture']}` / `{platform['kernel']}`",
        f"- CPU: `{platform['cpu']['vendor']} {platform['cpu']['model']}`",
        f"- Podman: `{podman['version']}`; rootless `{podman['rootless']}`",
        f"- OCI/network: `{podman['oci_runtime']}` / `{podman['network_backend']}` / `{podman['rootless_network_command']}`",
        f"- Host AppArmor: kernel `{apparmor['kernel_enabled']}`, enforcing profiles `{apparmor['enforcing_profiles']}`",
        f"- Rootless Podman AppArmor capability: `{podman['apparmor_enabled']}`",
        f"- Podman seccomp: `{podman['seccomp_enabled']}`",
        f"- Failed admission invariants: `{', '.join(str(item) for item in failures) if failures else 'none'}`",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    parser.add_argument("summary", type=Path)
    parser.add_argument("--require-passed", action="store_true")
    arguments = parser.parse_args()
    try:
        payload = arguments.evidence.read_bytes()
        if not payload or len(payload) > MAX_EVIDENCE_BYTES:
            fail("evidence is empty or exceeds 256 KiB")
        document = validate_document(json.loads(payload))
        write_summary(document, arguments.summary)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        print(f"ERROR: evidence validation failed closed: {error}", file=sys.stderr)
        return 1
    test = document["test"]
    assert isinstance(test, dict)
    print(f"Cloud evidence is complete and reports result={test['result']}.")
    return 1 if arguments.require_passed and test["result"] != "passed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
