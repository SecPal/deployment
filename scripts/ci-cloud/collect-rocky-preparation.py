#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Collect effective Rocky preparation facts into the closed evidence shape."""

from __future__ import annotations

import argparse
import grp
import json
import os
import pwd
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


PACKAGES = (
    "podman",
    "conmon",
    "crun",
    "netavark",
    "aardvark-dns",
    "passt",
    "shadow-utils-subid",
    "systemd",
    "container-selinux",
    "audit",
    "policycoreutils",
    "policycoreutils-python-utils",
    "selinux-policy-targeted",
    "curl",
    "dnf",
    "git",
    "jq",
    "nftables",
    "openssh-server",
    "sudo",
    "python3-jsonschema",
)
REPOSITORIES = {"baseos", "appstream", "extras"}
FIXTURE = "docker.io/library/alpine@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1"
ARM_CHILD = "sha256:4562b419adf48c5f3c763995d6014c123b3ce1d2e0ef2613b189779caa787192"
SHA = re.compile(r"^[0-9a-f]{40}$")


class CollectionError(RuntimeError):
    pass


def run(arguments: list[str], *, user: str | None = None) -> str:
    command = arguments
    if user is not None:
        account = pwd.getpwnam(user)
        command = [
            "runuser",
            "--user",
            user,
            "--",
            "env",
            f"HOME={account.pw_dir}",
            f"XDG_RUNTIME_DIR=/run/user/{account.pw_uid}",
            f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{account.pw_uid}/bus",
            *arguments,
        ]
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
        env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
    )
    if completed.returncode:
        raise CollectionError(f"fact command failed: {arguments[0]}")
    return completed.stdout.strip()


def os_release() -> dict[str, str]:
    result: dict[str, str] = {}
    for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if separator and key in {"ID", "VERSION_ID"}:
            result[key] = value.strip('"')
    return result


def one_subid(path: Path, account: str) -> tuple[int, int]:
    matches: list[tuple[int, int]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        name, separator, tail = line.partition(":")
        if name != account or not separator:
            continue
        start, separator, count = tail.partition(":")
        if not separator or not start.isdecimal() or not count.isdecimal():
            raise CollectionError(f"malformed {path.name} entry")
        matches.append((int(start), int(count)))
    if len(matches) != 1 or matches[0][1] != 65536:
        raise CollectionError(f"{path.name} must contain one 65536-entry range")
    return matches[0]


def all_subid_ranges(path: Path) -> list[range]:
    result: list[range] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        _, separator, tail = line.partition(":")
        start, separator2, count = tail.partition(":")
        if not separator or not separator2 or not start.isdecimal() or not count.isdecimal():
            raise CollectionError(f"malformed {path.name} entry")
        result.append(range(int(start), int(start) + int(count)))
    return result


def subids_are_independent(candidate: tuple[int, int]) -> bool:
    selected = range(candidate[0], candidate[0] + candidate[1])
    all_ranges = all_subid_ranges(Path("/etc/subuid")) + all_subid_ranges(Path("/etc/subgid"))
    identical = sum(item.start == selected.start and item.stop == selected.stop for item in all_ranges)
    effective_ids = {entry.pw_uid for entry in pwd.getpwall()}
    effective_ids.update(entry.pw_gid for entry in pwd.getpwall())
    effective_ids.update(entry.gr_gid for entry in grp.getgrall())
    return (
        identical == 2
        and all(
            (item.start == selected.start and item.stop == selected.stop)
            or selected.stop <= item.start
            or selected.start >= item.stop
            for item in all_ranges
        )
        and all(identifier not in selected for identifier in effective_ids)
    )


def sudo_authorized(account: str) -> bool:
    completed = subprocess.run(
        ["sudo", "-l", "-U", account],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    output = f"{completed.stdout}\n{completed.stderr}".lower()
    return completed.returncode == 0 and "not allowed to run sudo" not in output


def unit_enabled(unit: str) -> bool:
    return subprocess.run(
        ["systemctl", "is-enabled", unit],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
    ).returncode == 0


def label_disable_absent(account: pwd.struct_passwd) -> bool:
    paths = [
        Path("/etc/containers/containers.conf"),
        Path(account.pw_dir) / ".config/containers/containers.conf",
    ]
    for path in paths:
        if path.exists():
            text = path.read_text(encoding="utf-8")
            if re.search(r"(?im)^\s*label\s*=\s*(?:false|['\"]?disable)", text):
                return False
    return True


def package_facts() -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for name in PACKAGES:
        nevra = run(["rpm", "-q", "--qf", "%{NEVRA}", name])
        repository = run(
            [
                "dnf4",
                "--quiet",
                "--disablerepo=*",
                "--enablerepo=baseos,appstream,extras",
                "repoquery",
                "--qf",
                "%{repoid}",
                "--nevra",
                nevra,
            ]
        ).splitlines()
        official = sorted(set(repository) & REPOSITORIES)
        if len(official) != 1:
            raise CollectionError(f"installed NEVRA lacks one official resolution: {name}")
        signature = run(["rpm", "-q", "--qf", "%{RSAHEADER:pgpsig}", name])
        if not signature or signature == "(none)" or "Key ID" not in signature:
            raise CollectionError(f"RPM signature verification failed: {name}")
        result.append(
            {
                "name": name,
                "nevra": nevra,
                "resolved_repository": official[0],
                "signature_verified": True,
            }
        )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-sha", required=True)
    parser.add_argument("--control-sha", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--expires-at", required=True, type=int)
    parser.add_argument("--image", required=True)
    parser.add_argument("--first-boot-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    options = parser.parse_args()
    try:
        if SHA.fullmatch(options.target_sha) is None or SHA.fullmatch(options.control_sha) is None:
            raise CollectionError("full immutable SHAs are required")
        release = os_release()
        if release != {"ID": "rocky", "VERSION_ID": "10.2"}:
            raise CollectionError("guest must report exactly Rocky 10.2")
        if run(["uname", "-m"]) != "aarch64":
            raise CollectionError("guest must be native aarch64")
        dnf_version = run(["dnf4", "--version"]).splitlines()[0]
        if re.match(r"^4(?:\.|$)", dnf_version) is None:
            raise CollectionError("update mechanism must be DNF4")
        releasever = run(["rpm", "--eval", "%{rhel}"])
        if releasever != "10":
            raise CollectionError("effective RPM releasever must be 10")
        if run(["getenforce"]) != "Enforcing" or run(["selinuxenabled"]) != "":
            raise CollectionError("SELinux must be enabled and Enforcing")
        if run(["sestatus"]).find("targeted") < 0:
            raise CollectionError("SELinux targeted policy is not effective")
        enabled_repos = sorted(
            line.split()[0]
            for line in run(["dnf4", "--quiet", "repolist", "--enabled"]).splitlines()
            if line and not line.lower().startswith("repo id")
        )
        if set(enabled_repos) != REPOSITORIES or len(enabled_repos) != 3:
            raise CollectionError("enabled repository set is not closed")
        account = pwd.getpwnam("secpal-runtime")
        subuid = one_subid(Path("/etc/subuid"), account.pw_name)
        subgid = one_subid(Path("/etc/subgid"), account.pw_name)
        if subuid != subgid:
            raise CollectionError("subuid and subgid ranges must match")
        subids_independent = subids_are_independent(subuid)
        supplementary = os.getgrouplist(account.pw_name, account.pw_gid)
        podman_info = json.loads(run(["podman", "info", "--format", "json"], user=account.pw_name))
        runtime = podman_info["host"]
        graphroot = Path(podman_info["store"]["graphRoot"]).resolve(strict=True)
        account_home = Path(account.pw_dir).resolve(strict=True)
        if not graphroot.is_relative_to(account_home):
            raise CollectionError("rootless graphroot must remain inside the account home")
        resolved_fixture = run(
            ["podman", "image", "inspect", "--format", "{{.Digest}}", FIXTURE],
            user=account.pw_name,
        )
        if resolved_fixture != ARM_CHILD:
            raise CollectionError("fixture did not resolve to the reviewed ARM64 child")
        automatic_units = (
            "dnf-automatic.timer",
            "dnf-automatic-install.timer",
            "dnf-automatic-download.timer",
            "dnf-automatic-notifyonly.timer",
        )
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
        if boot_id == options.first_boot_id:
            raise CollectionError("preparation reboot did not occur")
        memory_kib = next(
            int(line.split()[1])
            for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines()
            if line.startswith("MemTotal:")
        )
        filesystem = os.statvfs("/")
        document = {
            "schema_version": 1,
            "target_sha": options.target_sha,
            "run": {
                "repository": "SecPal/deployment",
                "trusted_control_sha": options.control_sha,
                "profile": "gcp-rocky-10-2-arm64",
                "run_id": options.run_id,
                "run_attempt": options.run_attempt,
                "expires_at": options.expires_at,
            },
            "image": {"project": "rocky-linux-cloud", "exact_self_link": options.image},
            "guest": {"id": release["ID"], "version_id": release["VERSION_ID"], "uname_machine": "aarch64"},
            "hardware": {
                "cpu_count": os.cpu_count(),
                "memory_bytes": memory_kib * 1024,
                "root_filesystem_bytes": filesystem.f_blocks * filesystem.f_frsize,
            },
            "repositories": {"enabled": enabled_repos, "external_enabled": False},
            "updates": {
                "mechanism": "dnf4",
                "releasever": releasever,
                "automatic": any(unit_enabled(unit) for unit in automatic_units),
                "automatic_reboot": any(unit_enabled(unit) for unit in automatic_units),
            },
            "packages": package_facts(),
            "selinux": {"enabled": True, "mode": "Enforcing", "policy": "targeted", "container_selinux_installed": True, "label_disable_absent": label_disable_absent(account)},
            "runtime": {
                "podman": run(["podman", "--version"]),
                "rootless": bool(runtime.get("security", {}).get("rootless")),
                "graphroot": str(graphroot),
                "oci_runtime": runtime.get("ociRuntime", {}).get("name"),
                "cgroup_version": 2 if run(["stat", "-fc", "%T", "/sys/fs/cgroup"]) == "cgroup2fs" else 0,
                "systemd_user": run(["systemctl", "is-active", f"user@{account.pw_uid}.service"]) == "active",
                "network_backend": runtime.get("networkBackend"),
                "seccomp_available": bool(runtime.get("security", {}).get("seccompEnabled")),
                "socket_absent": not Path(f"/run/user/{account.pw_uid}/podman/podman.sock").exists() and not unit_enabled("podman.socket"),
                "api_dependency_absent": not os.environ.get("CONTAINER_HOST") and not bool(runtime.get("remoteSocket", {}).get("exists")),
            },
            "service_account": {
                "name": account.pw_name,
                "uid": account.pw_uid,
                "gid": account.pw_gid,
                "home": account.pw_dir,
                "shell": account.pw_shell,
                "sudo": sudo_authorized(account.pw_name),
                "privileged_supplementary_groups": supplementary != [account.pw_gid],
                "subuid_start": subuid[0],
                "subuid_count": subuid[1],
                "subgid_start": subgid[0],
                "subgid_count": subgid[1],
                "subids_non_overlapping": subids_independent,
                "linger": Path(f"/var/lib/systemd/linger/{account.pw_name}").exists(),
                "quadlet_authority_writable": subprocess.run(
                    ["runuser", "--user", account.pw_name, "--", "test", "-w", f"/etc/containers/systemd/users/{account.pw_uid}"],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                ).returncode == 0,
            },
            "fixture": {
                "input": FIXTURE,
                "resolved_arm64_child": resolved_fixture,
                "pre_staged": run(["podman", "image", "exists", FIXTURE], user=account.pw_name) == "",
            },
            "persistence": {"rebooted": True, "boot_id_changed": True, "survived_reboot": True},
            "cloud_identity": {
                "control_service_account_absent": Path("/var/lib/secpal-rocky/cloud-identity-absent").is_file(),
                "credential_file_absent": not os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"),
                "metadata_token_unavailable": True,
                "useful_project_authority_absent": Path("/var/lib/secpal-rocky/cloud-identity-absent").is_file(),
            },
        }
        options.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        options.output.chmod(0o600)
    except (CollectionError, KeyError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"ERROR: Rocky preparation evidence collection failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
