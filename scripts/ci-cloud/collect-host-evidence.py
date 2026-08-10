#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Collect and admit bounded effective Debian/rootless-Podman host facts."""

from __future__ import annotations

import argparse
import ctypes
import glob
import json
import os
import re
import shutil
import stat as stat_module
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


MAX_COMMAND_OUTPUT = 8_192
CI_OPERATOR_UID = 20000
EXPECTED_SUITES = {"trixie", "trixie-security", "trixie-updates"}
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
FORBIDDEN_PACKAGES = (
    "docker-ce",
    "docker-ce-cli",
    "docker.io",
    "podman-docker",
    "podman-compose",
    "docker-compose",
)
REQUIRED_TOOLS = {
    "aa-status",
    "apt-cache",
    "apt-config",
    "bash",
    "curl",
    "df",
    "dpkg",
    "dpkg-query",
    "findmnt",
    "getent",
    "gh",
    "git",
    "id",
    "install",
    "jq",
    "loginctl",
    "mktemp",
    "newgidmap",
    "newuidmap",
    "podman",
    "python3",
    "realpath",
    "sha256sum",
    "ss",
    "stat",
    "systemd-detect-virt",
    "systemctl",
    "timedatectl",
    "uname",
}


def command_environment() -> dict[str, str]:
    return {
        "HOME": os.environ.get("HOME", "/home/secpal-ci"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "XDG_RUNTIME_DIR": f"/run/user/{os.getuid()}",
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{os.getuid()}/bus",
    }


def command_result(arguments: list[str], timeout: int = 15) -> tuple[int, str]:
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
        return 255, ""
    return completed.returncode, completed.stdout[:MAX_COMMAND_OUTPUT].strip()


def output(arguments: list[str], timeout: int = 15) -> str:
    return command_result(arguments, timeout)[1]


def checked_output(arguments: list[str], timeout: int = 15) -> str:
    status, text = command_result(arguments, timeout)
    return text if status == 0 else ""


def json_value_output(arguments: list[str], timeout: int = 30) -> object:
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
        return None
    if completed.returncode != 0 or len(completed.stdout) > MAX_COMMAND_OUTPUT * 16:
        return None
    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return None
    return document


def json_output(arguments: list[str], timeout: int = 30) -> dict[str, Any]:
    document = json_value_output(arguments, timeout)
    return document if isinstance(document, dict) else {}


def json_array_output(arguments: list[str], timeout: int = 30) -> list[object]:
    document = json_value_output(arguments, timeout)
    return document if isinstance(document, list) else []


def read_text(path: Path, limit: int = MAX_COMMAND_OUTPUT) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:limit]
    except OSError:
        return ""


def os_release() -> dict[str, str]:
    facts: dict[str, str] = {}
    for line in read_text(Path("/etc/os-release")).splitlines():
        if "=" in line:
            name, value = line.split("=", 1)
            facts[name] = value.strip().strip('"')
    return {
        key: facts.get(key, "")
        for key in ("ID", "VERSION_ID", "VERSION_CODENAME", "PRETTY_NAME")
    }


def cpu_facts() -> dict[str, str]:
    values: dict[str, str] = {}
    for line in read_text(Path("/proc/cpuinfo"), 65_536).splitlines():
        if ":" not in line:
            continue
        key, value = (part.strip() for part in line.split(":", 1))
        if key in {"vendor_id", "model name", "CPU implementer", "Hardware"}:
            values.setdefault(key, value[:512])
    return {
        "vendor": values.get("vendor_id", values.get("CPU implementer", "")),
        "model": values.get("model name", values.get("Hardware", "")),
    }


def package_version(package: str) -> str:
    return checked_output(["dpkg-query", "-W", "-f", "${Version}", package])


def package_suite(package: str, version: str) -> str:
    if not version:
        return ""
    policy = checked_output(["apt-cache", "policy", package], timeout=30)
    selected = False
    for line in policy.splitlines():
        if line.strip().startswith(f"*** {version} "):
            selected = True
            continue
        if selected and line.lstrip().startswith(("*** ", "Candidate:")):
            break
        if not selected or not line.rstrip().endswith(" Packages"):
            continue
        fields = line.split()
        if len(fields) >= 4 and "/" in fields[-3]:
            return fields[-3].split("/", 1)[0]
    return ""


def verified_releases() -> tuple[list[str], list[str], bool]:
    origins: set[str] = set()
    suites: set[str] = set()
    safe_files = True
    files = sorted(Path(path) for path in glob.glob("/var/lib/apt/lists/*_InRelease"))
    for path in files:
        try:
            metadata = path.stat()
        except OSError:
            safe_files = False
            continue
        if metadata.st_uid != 0 or metadata.st_mode & (stat_module.S_IWGRP | stat_module.S_IWOTH):
            safe_files = False
        content = read_text(path, 65_536)
        origin_match = re.search(r"^Origin:\s*(\S.*?)\s*$", content, re.MULTILINE)
        suite_match = re.search(r"^Codename:\s*(\S+)\s*$", content, re.MULTILINE)
        if origin_match and suite_match:
            origins.add(origin_match.group(1))
            suites.add(suite_match.group(1))
    verified = bool(files) and safe_files and origins == {"Debian"} and suites == EXPECTED_SUITES
    return sorted(origins), sorted(suites), verified


def package_metadata(package: str, architecture: str, verified_suites: set[str]) -> dict[str, object]:
    version = package_version(package)
    package_architecture = checked_output(
        ["dpkg-query", "-W", "-f", "${Architecture}", package]
    )
    suite = package_suite(package, version)
    return {
        "version": version,
        "architecture": package_architecture,
        "origin": "Debian" if suite in verified_suites else "",
        "suite": suite,
    }


def apt_sources(architecture: str) -> dict[str, object]:
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
                fields = line.strip().split()
                if not fields or fields[0] != "deb":
                    continue
                while len(fields) > 1 and fields[1].startswith("["):
                    closing = next(
                        (index for index, field in enumerate(fields[1:], 1) if field.endswith("]")),
                        None,
                    )
                    if closing is None:
                        fields = []
                        break
                    fields = [fields[0], *fields[closing + 1 :]]
                if len(fields) >= 3:
                    parsed = urlsplit(fields[1])
                    if parsed.username or parsed.password:
                        raise RuntimeError("APT source URI contains forbidden userinfo")
                    if parsed.hostname:
                        hosts.add(parsed.hostname)
                    suites.add(fields[2])
    origins, release_suites, signatures_verified = verified_releases()
    verified_suite_set = set(release_suites)
    forbidden = [package for package in FORBIDDEN_PACKAGES if package_version(package)]
    return {
        "source_files": files,
        "source_hosts": sorted(hosts),
        "configured_suites": sorted(suites),
        "release_origins": origins,
        "verified_release_suites": release_suites,
        "release_signatures_verified": signatures_verified,
        "debian_archive_keyring_version": package_version("debian-archive-keyring"),
        "runtime_packages": {
            package: package_metadata(package, architecture, verified_suite_set)
            for package in RUNTIME_PACKAGES
        },
        "forbidden_packages_present": forbidden,
    }


def command_version(command: str, *arguments: str) -> str:
    path = shutil.which(command)
    if path is None:
        return ""
    version_output = output([path, *arguments])
    return version_output.splitlines()[0] if version_output else ""


def podman_facts() -> tuple[dict[str, object], dict[str, Any]]:
    document = json_output(["podman", "info", "--format", "json"])
    host = document.get("host", {})
    store = document.get("store", {})
    if not isinstance(host, dict):
        host = {}
    if not isinstance(store, dict):
        store = {}
    security = host.get("security", {})
    runtime = host.get("ociRuntime", {})
    if not isinstance(security, dict):
        security = {}
    if not isinstance(runtime, dict):
        runtime = {}
    facts = {
        "version": command_version("podman", "--version"),
        "rootless": security.get("rootless"),
        "seccomp_enabled": security.get("seccompEnabled"),
        "apparmor_enabled": security.get("apparmorEnabled"),
        "oci_runtime": runtime.get("name", ""),
        "network_backend": host.get("networkBackend", ""),
        "rootless_network_command": host.get("rootlessNetworkCmd", ""),
        "cgroup_version": host.get("cgroupVersion", ""),
    }
    return facts, store


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


def kernel_package_facts(kernel: str, architecture: str, verified_suites: set[str]) -> dict[str, object]:
    package = ""
    for candidate in (Path(f"/boot/vmlinuz-{kernel}"), Path(f"/lib/modules/{kernel}/kernel")):
        status, ownership = command_result(["dpkg-query", "-S", str(candidate)])
        if status == 0 and ": " in ownership:
            package = ownership.split(": ", 1)[0].splitlines()[0]
            break
    metadata = package_metadata(package, architecture, verified_suites) if package else {
        "version": "", "architecture": "", "origin": "", "suite": ""
    }
    return {"name": package, **metadata, "owned": bool(package)}


def security_update_facts() -> dict[str, object]:
    config = checked_output(["apt-config", "dump"])
    origin_patterns = re.findall(
        r'^Unattended-Upgrade::Origins-Pattern(?:::[^ ]*)?\s+"([^"]+)";',
        config,
        re.MULTILINE,
    )
    blacklist = set(
        re.findall(
            r'^Unattended-Upgrade::Package-Blacklist(?:::[^ ]*)?\s+"([^"]+)";',
            config,
            re.MULTILINE,
        )
    )
    security_only = bool(origin_patterns) and all(
        "security" in pattern.lower() for pattern in origin_patterns
    )
    return {
        "mechanism": "unattended-upgrades" if package_version("unattended-upgrades") else "",
        "automatic": bool(
            re.search(r'^APT::Periodic::Enable\s+"1";', config, re.MULTILINE)
            and re.search(r'^APT::Periodic::Unattended-Upgrade\s+"1";', config, re.MULTILINE)
        ),
        "timer_enabled": command_result(["systemctl", "is-enabled", "apt-daily-upgrade.timer"])[0] == 0,
        "security_suite": "trixie-security" if security_only else "",
        "normal_updates_automatic": not security_only,
        "major_release_upgrades_automatic": not security_only,
        "automatic_reboot": not bool(
            re.search(
                r'^Unattended-Upgrade::Automatic-Reboot\s+"false";',
                config,
                re.MULTILINE,
            )
        ),
        "runtime_packages_excluded": set(RUNTIME_PACKAGES).issubset(blacklist),
    }


def subordinate_fact(path: Path, account: str, identity_database: str) -> dict[str, object]:
    entries: list[tuple[str, int, int]] = []
    for line in read_text(path, 65_536).splitlines():
        fields = line.split(":")
        if len(fields) != 3:
            continue
        try:
            entries.append((fields[0], int(fields[1]), int(fields[2])))
        except ValueError:
            continue
    selected = [entry for entry in entries if entry[0] == account]
    start = selected[0][1] if len(selected) == 1 else 0
    count = selected[0][2] if len(selected) == 1 else 0
    selected_end = start + count
    overlaps_other_ranges = any(
        name != account and start < other_start + other_count and other_start < selected_end
        for name, other_start, other_count in entries
    ) if len(selected) == 1 else True
    identity_field = 2
    host_identities: set[int] = set()
    for line in checked_output(["getent", identity_database]).splitlines():
        fields = line.split(":")
        if len(fields) > identity_field:
            try:
                host_identities.add(int(fields[identity_field]))
            except ValueError:
                continue
    overlaps_host_identity = any(start <= identity < selected_end for identity in host_identities)
    return {
        "start": start,
        "count": count,
        "entry_count": len(selected),
        "overlap": overlaps_other_ranges or overlaps_host_identity,
    }


def mapping_matches(mapping: str, start: int, count: int) -> bool:
    for line in mapping.splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[0] == "1":
            try:
                if int(fields[1]) == start and int(fields[2]) >= count:
                    return True
            except ValueError:
                return False
    return False


def uidmap_facts() -> dict[str, object]:
    subuid = subordinate_fact(Path("/etc/subuid"), "secpal-ci", "passwd")
    subgid = subordinate_fact(Path("/etc/subgid"), "secpal-ci", "group")
    uid_mapping = checked_output(["podman", "unshare", "cat", "/proc/self/uid_map"], timeout=30)
    gid_mapping = checked_output(["podman", "unshare", "cat", "/proc/self/gid_map"], timeout=30)
    return {
        "newuidmap": shutil.which("newuidmap") or "",
        "newgidmap": shutil.which("newgidmap") or "",
        "subuid": subuid,
        "subgid": subgid,
        "mapping_effective": bool(
            shutil.which("newuidmap")
            and shutil.which("newgidmap")
            and mapping_matches(uid_mapping, int(subuid["start"]), int(subuid["count"]))
            and mapping_matches(gid_mapping, int(subgid["start"]), int(subgid["count"]))
        ),
    }


def systemd_user_facts() -> tuple[dict[str, object], str]:
    status, environment = command_result(["systemctl", "--user", "show-environment"])
    linger = checked_output(["loginctl", "show-user", "secpal-ci", "-p", "Linger", "--value"])
    manager_available = status == 0
    runtime_directory = Path(f"/run/user/{os.getuid()}")
    try:
        metadata = runtime_directory.stat()
        runtime_uid = metadata.st_uid
        runtime_gid = metadata.st_gid
        runtime_mode = f"0{stat_module.S_IMODE(metadata.st_mode):03o}"
    except OSError:
        runtime_uid, runtime_gid, runtime_mode = -1, -1, "0000"
    return (
        {
            "manager_available": manager_available,
            "starts_at_boot": manager_available and linger == "yes",
            "linger_enabled": linger == "yes",
            "dbus_session_available": Path(f"/run/user/{os.getuid()}/bus").is_socket(),
            "runtime_directory": str(runtime_directory),
            "runtime_directory_uid": runtime_uid,
            "runtime_directory_gid": runtime_gid,
            "runtime_directory_mode": runtime_mode,
        },
        environment,
    )


def quadlet_facts(user_environment: str) -> dict[str, object]:
    definition_path = Path(f"/etc/containers/systemd/users/{os.getuid()}")
    try:
        metadata = definition_path.stat()
        uid = metadata.st_uid
        gid = metadata.st_gid
        mode = f"0{stat_module.S_IMODE(metadata.st_mode):03o}"
    except OSError:
        uid, gid, mode = -1, -1, "0000"
    search_paths: list[str] = []
    for line in user_environment.splitlines():
        if line.startswith("QUADLET_UNIT_DIRS="):
            search_paths = [path for path in line.split("=", 1)[1].split(":") if path]
    symlinks = False
    if definition_path.is_dir():
        symlinks = any(path.is_symlink() for path in definition_path.rglob("*"))
    generator = Path("/usr/lib/systemd/user-generators/podman-user-generator")
    return {
        "generator_path": str(generator) if generator.is_file() and os.access(generator, os.X_OK) else "",
        "effective_search_paths": search_paths,
        "definitions_uid": uid,
        "definitions_gid": gid,
        "definitions_mode": mode,
        "tree_symlinks_present": symlinks,
        "service_account_can_write": os.access(definition_path, os.W_OK),
    }


def podman_api_facts() -> dict[str, bool]:
    service_active = command_result(["systemctl", "--user", "is-active", "podman.service"])[0] == 0
    socket_active = command_result(["systemctl", "--user", "is-active", "podman.socket"])[0] == 0
    socket_enabled = command_result(["systemctl", "--user", "is-enabled", "podman.socket"])[0] == 0
    listeners = output(["ss", "-ltnp"])
    connections = json_array_output(
        ["podman", "system", "connection", "list", "--format", "json"]
    )
    return {
        "service_active": service_active,
        "socket_active": socket_active,
        "socket_enabled": socket_enabled,
        "tcp_listener": "podman" in listeners.lower(),
        "remote_connection": bool(connections),
    }


def podman_update_facts() -> dict[str, bool]:
    return {
        "auto_update_timer_enabled": command_result(
            ["systemctl", "--user", "is-enabled", "podman-auto-update.timer"]
        )[0] == 0,
        "auto_update_timer_active": command_result(
            ["systemctl", "--user", "is-active", "podman-auto-update.timer"]
        )[0] == 0,
    }


def registry_facts() -> dict[str, object]:
    paths = [Path("/usr/share/containers/registries.conf"), Path("/etc/containers/registries.conf")]
    paths.extend(Path(path) for path in glob.glob("/etc/containers/registries.conf.d/*.conf"))
    paths.append(Path(command_environment()["HOME"]) / ".config/containers/registries.conf")
    mirrors: list[str] = []
    insecure = False
    rewrite = False
    for path in paths:
        if not path.is_file():
            continue
        try:
            document = tomllib.loads(read_text(path, 65_536))
        except tomllib.TOMLDecodeError:
            return {"ghcr_insecure": True, "secpal_mirrors": ["invalid-config"], "secpal_location_rewrite": True}
        registries = document.get("registry", [])
        if not isinstance(registries, list):
            continue
        for registry in registries:
            if not isinstance(registry, dict):
                continue
            prefix = str(registry.get("prefix", registry.get("location", "")))
            location = str(registry.get("location", prefix))
            if prefix == "ghcr.io" or prefix.startswith("ghcr.io/secpal"):
                insecure = insecure or registry.get("insecure") is True
                rewrite = rewrite or location != prefix
                raw_mirrors = registry.get("mirror", [])
                if isinstance(raw_mirrors, list):
                    mirrors.extend(
                        str(item.get("location", ""))
                        for item in raw_mirrors
                        if isinstance(item, dict)
                    )
    return {
        "ghcr_insecure": insecure,
        "secpal_mirrors": sorted(item for item in mirrors if item),
        "secpal_location_rewrite": rewrite,
    }


def d_type_supported(base: Path) -> bool:
    system_call = {"x86_64": 217, "aarch64": 61}.get(os.uname().machine)
    if system_call is None or not base.is_dir():
        return False
    try:
        with tempfile.TemporaryDirectory(prefix=".d-type-probe-", dir=base) as directory:
            Path(directory, "regular").touch(mode=0o600)
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                buffer = ctypes.create_string_buffer(8192)
                length = ctypes.CDLL(None, use_errno=True).syscall(
                    system_call, descriptor, buffer, len(buffer)
                )
            finally:
                os.close(descriptor)
            if length <= 0:
                return False
            offset = 0
            while offset < length:
                record_length = int.from_bytes(buffer.raw[offset + 16 : offset + 18], "little")
                if record_length < 20 or offset + record_length > length:
                    return False
                entry_type = buffer.raw[offset + 18]
                name = buffer.raw[offset + 19 : offset + record_length].split(b"\0", 1)[0]
                if name == b"regular":
                    return entry_type == 8
                offset += record_length
    except OSError:
        return False
    return False


def filesystem_facts() -> dict[str, object]:
    filesystem = checked_output(["findmnt", "-n", "-o", "FSTYPE", "/"])
    options = checked_output(["findmnt", "-n", "-o", "OPTIONS", "/"]).split(",")
    overlay_supported = any(
        line.split()[-1] == "overlay"
        for line in read_text(Path("/proc/filesystems"), 65_536).splitlines()
        if line.split()
    )
    return {
        "type": filesystem,
        "read_only": "ro" in options,
        "overlayfs_supported": overlay_supported,
        "d_type": d_type_supported(Path("/srv/secpal-ci")),
    }


def required_tool_facts() -> dict[str, list[str]]:
    present = sorted(tool for tool in REQUIRED_TOOLS if shutil.which(tool))
    return {"present": present, "missing": sorted(REQUIRED_TOOLS - set(present))}


def version_tuple(text: str) -> tuple[int, int, int] | None:
    match = re.search(r"([0-9]+)\.([0-9]+)\.([0-9]+)", text)
    return tuple(int(value) for value in match.groups()) if match else None


def admission_failures(facts: dict[str, Any], profile_name: str) -> list[str]:
    platform = facts["platform"]
    apt = facts["apt"]
    host = facts["host"]
    runtime = facts["runtime"]
    podman = runtime["podman"]
    apparmor = runtime["apparmor_host"]
    failures: list[str] = []

    def reject(condition: bool, invariant: str) -> None:
        if condition and invariant not in failures:
            failures.append(invariant)

    os_facts = platform["os_release"]
    reject(
        (os_facts["ID"], os_facts["VERSION_ID"], os_facts["VERSION_CODENAME"])
        != ("debian", "13", "trixie"),
        "D1_OS_DEBIAN_13_TRIXIE",
    )
    reject(platform["architecture"] != "amd64", "D1_ARCHITECTURE_AMD64")
    kernel_release = str(platform["kernel"])
    reject(
        re.fullmatch(r"6\.12\.[0-9]+(?:[-+._][A-Za-z0-9+._-]+)?", kernel_release)
        is None
        or re.search(r"(?<![A-Za-z])rc(?:[0-9]+|(?=$|[-+._]))", kernel_release, re.IGNORECASE)
        is not None,
        "D1_KERNEL_DEBIAN_6_12",
    )
    kernel_package = host["kernel_package"]
    reject(
        not kernel_package["owned"]
        or not kernel_package["name"]
        or not kernel_package["version"]
        or kernel_package["architecture"] != platform["architecture"]
        or kernel_package["origin"] != "Debian"
        or kernel_package["suite"] not in {"trixie", "trixie-security"},
        "D1_KERNEL_PACKAGE_PROVENANCE",
    )
    reject(set(apt["configured_suites"]) != EXPECTED_SUITES, "D1_APT_CODENAME_SUITES")
    reject(apt["release_origins"] != ["Debian"], "D1_APT_RELEASE_ORIGIN")
    reject(set(apt["verified_release_suites"]) != EXPECTED_SUITES, "D1_APT_RELEASE_SUITES")
    reject(apt["release_signatures_verified"] is not True, "D1_APT_RELEASE_SIGNATURES")
    reject(not apt["debian_archive_keyring_version"], "D1_APT_ARCHIVE_KEYRING")
    reject(bool(apt["forbidden_packages_present"]), "D1_FORBIDDEN_RUNTIME_PACKAGES")
    package_facts = apt["runtime_packages"]
    reject(
        set(package_facts) != set(RUNTIME_PACKAGES)
        or any(
            not package["version"]
            or package["architecture"] not in {platform["architecture"], "all"}
            or package["origin"] != "Debian"
            or package["suite"] not in {"trixie", "trixie-security"}
            for package in package_facts.values()
        ),
        "D1_RUNTIME_PACKAGE_PROVENANCE",
    )
    security_updates = host["security_updates"]
    reject(
        security_updates != {
            "mechanism": "unattended-upgrades",
            "automatic": True,
            "timer_enabled": True,
            "security_suite": "trixie-security",
            "normal_updates_automatic": False,
            "major_release_upgrades_automatic": False,
            "automatic_reboot": False,
            "runtime_packages_excluded": True,
        },
        "D1_SECURITY_UPDATE_POLICY",
    )
    filesystem = host["filesystem"]
    reject(
        filesystem["type"] not in {"ext4", "xfs"}
        or filesystem["read_only"] is not False
        or filesystem["d_type"] is not True,
        "D1_LOCAL_FILESYSTEM",
    )
    reject(filesystem["overlayfs_supported"] is not True, "D1_OVERLAYFS")
    required_tools = host["required_tools"]
    reject(
        set(required_tools["present"]) != REQUIRED_TOOLS
        or bool(required_tools["missing"]),
        "D1_REQUIRED_TOOLS",
    )
    reject(host["clock"]["synchronized"] is not True, "D1_CLOCK_SYNCHRONIZED")
    reject(host["ssh"]["root_login_denied"] is not True, "D1_ROOT_SSH_DISABLED")
    version = version_tuple(str(podman["version"]))
    reject(version is None or not ((5, 4, 2) <= version < (6, 0, 0)), "D1_PODMAN_VERSION_5")
    reject(podman["rootless"] is not True, "D1_PODMAN_ROOTLESS")
    reject(podman["seccomp_enabled"] is not True, "D1_PODMAN_SECCOMP")
    reject(podman["oci_runtime"] != "crun", "D1_OCI_RUNTIME_CRUN")
    reject(podman["network_backend"] != "netavark", "D1_NETWORK_BACKEND_NETAVARK")
    reject(podman["rootless_network_command"] != "pasta", "D1_ROOTLESS_NETWORK_PASTA")
    reject(str(podman["cgroup_version"]).lower() not in {"v2", "2"}, "D1_CGROUP_V2")
    reject(
        apparmor["kernel_enabled"] is not True
        or not isinstance(apparmor["loaded_profiles"], int)
        or not isinstance(apparmor["enforcing_profiles"], int)
        or apparmor["loaded_profiles"] < 1
        or apparmor["enforcing_profiles"] < 1
        or apparmor["enforcing_profiles"] > apparmor["loaded_profiles"],
        "D1_HOST_APPARMOR",
    )
    uidmap = runtime["uidmap"]
    reject(
        not uidmap["newuidmap"]
        or not uidmap["newgidmap"]
        or uidmap["mapping_effective"] is not True
        or any(
            mapping["entry_count"] != 1
            or mapping["start"] < 65536
            or mapping["count"] != 65536
            or mapping["start"] + mapping["count"] > 4294967295
            or mapping["overlap"] is not False
            for mapping in (uidmap["subuid"], uidmap["subgid"])
        ),
        "D1_UIDMAP_EFFECTIVE",
    )
    systemd_user = runtime["systemd_user"]
    reject(
        any(
            systemd_user[name] is not True
            for name in (
                "manager_available",
                "starts_at_boot",
                "linger_enabled",
                "dbus_session_available",
            )
        )
        or systemd_user["runtime_directory"] != f"/run/user/{CI_OPERATOR_UID}"
        or systemd_user["runtime_directory_uid"] != CI_OPERATOR_UID
        or systemd_user["runtime_directory_gid"] < 0
        or systemd_user["runtime_directory_mode"] != "0700",
        "D1_SYSTEMD_USER_MANAGER",
    )
    quadlet = runtime["quadlet"]
    expected_quadlet_path = f"/etc/containers/systemd/users/{CI_OPERATOR_UID}"
    reject(
        quadlet["generator_path"] != "/usr/lib/systemd/user-generators/podman-user-generator"
        or quadlet["effective_search_paths"] != [expected_quadlet_path]
        or quadlet["definitions_uid"] != 0
        or quadlet["definitions_gid"] != 0
        or quadlet["definitions_mode"] != "0755"
        or quadlet["tree_symlinks_present"] is not False
        or quadlet["service_account_can_write"] is not False,
        "D1_QUADLET_TRUST_BOUNDARY",
    )
    storage = runtime["storage"]
    reject(storage["driver"] != "overlay", "D1_PODMAN_OVERLAY_STORAGE")
    reject(
        storage["graphroot"] != "/home/secpal-ci/.local/share/containers/storage"
        or storage["runroot"] != f"/run/user/{CI_OPERATOR_UID}/containers",
        "D1_PODMAN_STORAGE_PATHS",
    )
    reject(any(runtime["api"].values()), "D1_PODMAN_API_DISABLED")
    reject(any(runtime["updates"].values()), "D1_PODMAN_AUTO_UPDATE_DISABLED")
    registries = runtime["registries"]
    reject(
        registries["ghcr_insecure"] is not False
        or registries["secpal_mirrors"]
        or registries["secpal_location_rewrite"] is not False,
        "D1_REGISTRY_CONFIGURATION",
    )
    combined_cpu = f"{platform['cpu']['vendor']} {platform['cpu']['model']}".lower()
    reject(profile_name == "intel" and "intel" not in combined_cpu, "PROVIDER_CPU_PROFILE_INTEL")
    reject(profile_name == "amd" and "amd" not in combined_cpu, "PROVIDER_CPU_PROFILE_AMD")
    reject(platform["logical_cpu"] < 4, "D1_MINIMUM_LOGICAL_CPU")
    reject(platform["memory_bytes"] < 8 * 1024**3, "D1_MINIMUM_MEMORY_8_GIB")
    reject(platform["root_filesystem_bytes"] < 100 * 1024**3, "D1_MINIMUM_STORAGE_100_GIB")
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
    parser.add_argument("root_ssh_denied", choices=["true", "false"])
    arguments = parser.parse_args()
    if re.fullmatch(r"[0-9a-f]{40}", arguments.target_sha) is None:
        parser.error("target_sha must be a full lowercase SHA")

    os_facts = os_release()
    architecture = checked_output(["dpkg", "--print-architecture"])
    kernel = checked_output(["uname", "-r"])
    cpu = cpu_facts()
    apt = apt_sources(architecture)
    podman, store = podman_facts()
    apparmor = apparmor_facts()
    filesystem = filesystem_facts()
    stat = os.statvfs("/")
    disk_bytes = stat.f_frsize * stat.f_blocks
    memory_match = re.search(
        r"^MemTotal:\s+([0-9]+) kB$",
        read_text(Path("/proc/meminfo"), 65_536),
        re.MULTILINE,
    )
    memory_bytes = int(memory_match.group(1)) * 1024 if memory_match else 0
    systemd_user, user_environment = systemd_user_facts()
    facts: dict[str, Any] = {
        "platform": {
            "os_release": os_facts,
            "architecture": architecture,
            "uname": checked_output(["uname", "-a"]),
            "kernel": kernel,
            "cpu": cpu,
            "virtualization": output(["systemd-detect-virt"]),
            "logical_cpu": os.cpu_count() or 0,
            "memory_bytes": memory_bytes,
            "root_filesystem_bytes": disk_bytes,
        },
        "apt": apt,
        "host": {
            "kernel_package": kernel_package_facts(
                kernel, architecture, set(apt["verified_release_suites"])
            ),
            "filesystem": filesystem,
            "security_updates": security_update_facts(),
            "required_tools": required_tool_facts(),
            "clock": {
                "synchronized": checked_output(
                    ["timedatectl", "show", "-p", "NTPSynchronized", "--value"]
                ) == "yes"
            },
            "ssh": {"root_login_denied": arguments.root_ssh_denied == "true"},
        },
        "runtime": {
            "podman": podman,
            "crun_version": command_version("crun", "--version"),
            "crun_features": output(["crun", "features"]),
            "netavark_version": command_version("netavark", "--version"),
            "aardvark_version": command_version("aardvark-dns", "--version"),
            "pasta_version": command_version("pasta", "--version"),
            "passt_version": command_version("passt", "--version"),
            "uidmap": uidmap_facts(),
            "cgroup_version": "v2" if Path("/sys/fs/cgroup/cgroup.controllers").is_file() else "unknown",
            "systemd_version": output(["systemctl", "--version"]).splitlines()[0],
            "apparmor_host": apparmor,
            "systemd_user": systemd_user,
            "quadlet": quadlet_facts(user_environment),
            "storage": {
                "driver": store.get("graphDriverName", ""),
                "graphroot": store.get("graphRoot", ""),
                "runroot": store.get("runRoot", ""),
            },
            "api": podman_api_facts(),
            "updates": podman_update_facts(),
            "registries": registry_facts(),
        },
    }
    failures = admission_failures(facts, arguments.profile)
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
        **facts,
    }
    json.dump(document, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
