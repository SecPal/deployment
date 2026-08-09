#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Collect bounded effective Debian/rootless-Podman facts without environment dumps."""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit


MAX_COMMAND_OUTPUT = 8_192
RUNTIME_PACKAGES = (
    "podman",
    "conmon",
    "crun",
    "netavark",
    "aardvark-dns",
    "passt",
    "uidmap",
    "dbus-user-session",
)


def command_environment() -> dict[str, str]:
    return {
        "HOME": os.environ.get("HOME", "/home/secpal-ci"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "XDG_RUNTIME_DIR": f"/run/user/{os.getuid()}",
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{os.getuid()}/bus",
    }


def output(arguments: list[str], timeout: int = 15) -> str:
    try:
        completed = subprocess.run(
            arguments,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            env=command_environment(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return completed.stdout[:MAX_COMMAND_OUTPUT].strip()


def json_output(arguments: list[str], timeout: int = 30) -> dict[str, object]:
    try:
        completed = subprocess.run(
            arguments,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            env=command_environment(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}
    if completed.returncode != 0 or len(completed.stdout) > MAX_COMMAND_OUTPUT * 16:
        return {}
    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return {}
    return document if isinstance(document, dict) else {}


def read_text(path: Path, limit: int = MAX_COMMAND_OUTPUT) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:limit]
    except OSError:
        return ""


def os_release() -> dict[str, str]:
    facts: dict[str, str] = {}
    for line in read_text(Path("/etc/os-release")).splitlines():
        if "=" not in line:
            continue
        name, value = line.split("=", 1)
        facts[name] = value.strip().strip('"')
    return {key: facts.get(key, "") for key in ("ID", "VERSION_ID", "VERSION_CODENAME", "PRETTY_NAME")}


def cpu_facts() -> dict[str, str]:
    values: dict[str, str] = {}
    for line in read_text(Path("/proc/cpuinfo"), 65_536).splitlines():
        if ":" not in line:
            continue
        key, value = (part.strip() for part in line.split(":", 1))
        if key in {"vendor_id", "model name", "CPU implementer", "Hardware"} and key not in values:
            values[key] = value[:512]
    return {
        "vendor": values.get("vendor_id", values.get("CPU implementer", "")),
        "model": values.get("model name", values.get("Hardware", "")),
    }


def apt_sources() -> dict[str, object]:
    suites: set[str] = set()
    hosts: set[str] = set()
    files: list[str] = []
    paths = [Path("/etc/apt/sources.list")]
    paths.extend(Path(path) for path in glob.glob("/etc/apt/sources.list.d/*.list"))
    paths.extend(Path(path) for path in glob.glob("/etc/apt/sources.list.d/*.sources"))
    for path in sorted(paths):
        content = read_text(path, 32_768)
        if not content:
            continue
        files.append(str(path))
        if path.suffix == ".sources":
            for line in content.splitlines():
                if line.startswith("Suites:"):
                    suites.update(line.removeprefix("Suites:").split())
                elif line.startswith("URIs:"):
                    for uri in line.removeprefix("URIs:").split():
                        parsed = urlsplit(uri)
                        if parsed.username or parsed.password:
                            raise RuntimeError("APT source URI contains forbidden userinfo")
                        if parsed.hostname:
                            hosts.add(parsed.hostname)
        else:
            for line in content.splitlines():
                stripped = line.strip()
                if not stripped.startswith("deb "):
                    continue
                fields = stripped.split()
                while len(fields) > 1 and fields[1].startswith("["):
                    closing = next((index for index, field in enumerate(fields[1:], 1) if field.endswith("]")), None)
                    if closing is None:
                        break
                    fields = [fields[0], *fields[closing + 1 :]]
                if len(fields) >= 3:
                    parsed = urlsplit(fields[1])
                    if parsed.username or parsed.password:
                        raise RuntimeError("APT source URI contains forbidden userinfo")
                    if parsed.hostname:
                        hosts.add(parsed.hostname)
                    suites.add(fields[2])
    return {
        "source_files": files,
        "source_hosts": sorted(hosts),
        "configured_suites": sorted(suites),
        "debian_archive_keyring_version": package_version("debian-archive-keyring"),
        "runtime_packages": {package: package_version(package) for package in RUNTIME_PACKAGES},
    }


def package_version(package: str) -> str:
    return output(["dpkg-query", "-W", "-f", "${Version}", package])


def command_version(command: str, *arguments: str) -> str:
    path = shutil.which(command)
    if path is None:
        return ""
    version_output = output([path, *arguments])
    return version_output.splitlines()[0] if version_output else ""


def podman_facts() -> dict[str, object]:
    document = json_output(["podman", "info", "--format", "json"])
    host = document.get("host", {})
    if not isinstance(host, dict):
        host = {}
    security = host.get("security", {})
    runtime = host.get("ociRuntime", {})
    if not isinstance(security, dict):
        security = {}
    if not isinstance(runtime, dict):
        runtime = {}
    return {
        "version": command_version("podman", "--version"),
        "rootless": security.get("rootless"),
        "seccomp_enabled": security.get("seccompEnabled"),
        "apparmor_enabled": security.get("apparmorEnabled"),
        "oci_runtime": runtime.get("name", ""),
        "network_backend": host.get("networkBackend", ""),
        "rootless_network_command": host.get("rootlessNetworkCmd", ""),
        "cgroup_version": host.get("cgroupVersion", ""),
    }


def apparmor_facts() -> dict[str, object]:
    parameter = read_text(Path("/sys/module/apparmor/parameters/enabled"), 16).strip()
    status = output(["aa-status"])
    loaded_match = re.search(r"([0-9]+) profiles are loaded", status)
    enforcing_match = re.search(r"([0-9]+) profiles are in enforce mode", status)
    return {
        "kernel_enabled": parameter.lower() in {"y", "yes", "1"},
        "loaded_profiles": int(loaded_match.group(1)) if loaded_match else None,
        "enforcing_profiles": int(enforcing_match.group(1)) if enforcing_match else None,
    }


def version_tuple(text: str) -> tuple[int, int, int] | None:
    match = re.search(r"([0-9]+)\.([0-9]+)\.([0-9]+)", text)
    return tuple(int(value) for value in match.groups()) if match else None


def admission_failures(
    os_facts: dict[str, str], architecture: str, cpu: dict[str, str], profile_name: str,
    apt: dict[str, object], podman: dict[str, object], apparmor: dict[str, object],
    kernel: str, cpu_count: int, memory_bytes: int, disk_bytes: int,
) -> list[str]:
    failures: list[str] = []
    if (os_facts["ID"], os_facts["VERSION_ID"], os_facts["VERSION_CODENAME"]) != ("debian", "13", "trixie"):
        failures.append("D1_OS_DEBIAN_13_TRIXIE")
    if architecture != "amd64":
        failures.append("D1_ARCHITECTURE_AMD64")
    if not kernel.startswith("6.12."):
        failures.append("D1_KERNEL_DEBIAN_6_12")
    if set(apt["configured_suites"]) != {"trixie", "trixie-security", "trixie-updates"}:
        failures.append("D1_APT_CODENAME_SUITES")
    version = version_tuple(str(podman["version"]))
    if version is None or not ((5, 4, 2) <= version < (6, 0, 0)):
        failures.append("D1_PODMAN_VERSION_5")
    if podman["rootless"] is not True:
        failures.append("D1_PODMAN_ROOTLESS")
    if podman["seccomp_enabled"] is not True:
        failures.append("D1_PODMAN_SECCOMP")
    if podman["oci_runtime"] != "crun":
        failures.append("D1_OCI_RUNTIME_CRUN")
    if podman["network_backend"] != "netavark":
        failures.append("D1_NETWORK_BACKEND_NETAVARK")
    if podman["rootless_network_command"] != "pasta":
        failures.append("D1_ROOTLESS_NETWORK_PASTA")
    if str(podman["cgroup_version"]).lower() not in {"v2", "2"}:
        failures.append("D1_CGROUP_V2")
    if apparmor["kernel_enabled"] is not True or not isinstance(apparmor["enforcing_profiles"], int) or apparmor["enforcing_profiles"] < 1:
        failures.append("D1_HOST_APPARMOR")
    combined_cpu = f"{cpu['vendor']} {cpu['model']}".lower()
    if profile_name == "intel" and "intel" not in combined_cpu:
        failures.append("PROVIDER_CPU_PROFILE_INTEL")
    if profile_name == "amd" and "amd" not in combined_cpu:
        failures.append("PROVIDER_CPU_PROFILE_AMD")
    if cpu_count < 4:
        failures.append("D1_MINIMUM_LOGICAL_CPU")
    if memory_bytes < 8 * 1024**3:
        failures.append("D1_MINIMUM_MEMORY_8_GIB")
    if disk_bytes < 100 * 1024**3:
        failures.append("D1_MINIMUM_STORAGE_100_GIB")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("provider", choices=["digitalocean"])
    parser.add_argument("region", choices=["fra1"])
    parser.add_argument("profile", choices=["intel", "amd"])
    parser.add_argument("target_sha")
    parser.add_argument("run_id")
    parser.add_argument("run_attempt")
    parser.add_argument("started_at")
    parser.add_argument("ended_at")
    parser.add_argument("target_status", type=int)
    arguments = parser.parse_args()
    if re.fullmatch(r"[0-9a-f]{40}", arguments.target_sha) is None:
        parser.error("target_sha must be a full lowercase SHA")

    os_facts = os_release()
    architecture = output(["dpkg", "--print-architecture"])
    kernel = output(["uname", "-r"])
    cpu = cpu_facts()
    apt = apt_sources()
    podman = podman_facts()
    apparmor = apparmor_facts()
    stat = os.statvfs("/")
    disk_bytes = stat.f_frsize * stat.f_blocks
    memory_match = re.search(r"^MemTotal:\s+([0-9]+) kB$", read_text(Path("/proc/meminfo"), 65_536), re.MULTILINE)
    memory_bytes = int(memory_match.group(1)) * 1024 if memory_match else 0
    cpu_count = os.cpu_count() or 0
    failures = admission_failures(
        os_facts, architecture, cpu, arguments.profile, apt, podman, apparmor,
        kernel, cpu_count, memory_bytes, disk_bytes,
    )
    if arguments.target_status != 0:
        failures.append("TARGET_CONFORMANCE_ENTRYPOINT")
    document = {
        "schema_version": 1,
        "workflow": {
            "repository": "SecPal/deployment",
            "run_id": arguments.run_id,
            "run_attempt": arguments.run_attempt,
            "target_sha": arguments.target_sha,
        },
        "test": {
            "provider": arguments.provider,
            "region": arguments.region,
            "profile": arguments.profile,
            "started_at": arguments.started_at,
            "ended_at": arguments.ended_at,
            "target_exit_status": arguments.target_status,
            "result": "passed" if not failures else "failed",
            "failed_admission_invariants": failures,
        },
        "platform": {
            "os_release": os_facts,
            "architecture": architecture,
            "uname": output(["uname", "-a"]),
            "kernel": kernel,
            "cpu": cpu,
            "virtualization": output(["systemd-detect-virt"]),
            "logical_cpu": cpu_count,
            "memory_bytes": memory_bytes,
            "root_filesystem_bytes": disk_bytes,
        },
        "apt": apt,
        "runtime": {
            "podman": podman,
            "crun_version": command_version("crun", "--version"),
            "crun_features": output(["crun", "features"]),
            "netavark_version": command_version("netavark", "--version"),
            "aardvark_version": command_version("aardvark-dns", "--version"),
            "pasta_version": command_version("pasta", "--version"),
            "passt_version": command_version("passt", "--version"),
            "uidmap": {
                "newuidmap": shutil.which("newuidmap") or "",
                "newgidmap": shutil.which("newgidmap") or "",
            },
            "cgroup_version": "v2" if Path("/sys/fs/cgroup/cgroup.controllers").is_file() else "unknown",
            "systemd_version": output(["systemctl", "--version"]).splitlines()[0],
            "apparmor_host": apparmor,
        },
    }
    json.dump(document, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
