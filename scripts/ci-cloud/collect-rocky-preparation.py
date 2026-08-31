#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Observe Rocky host facts and hand them to the pure evidence contract."""

from __future__ import annotations

import argparse
import grp
import json
import os
import pwd
import subprocess
import sys
from enum import Enum
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rocky_preparation_contract as contract


RESPONSIBILITY = "observation,orchestration"
EXTERNAL_DOMAINS = frozenset({"host", "rpm", "podman", "systemd"})
COHERENT_EXTERNAL_CONTRACT = "rocky-preparation-evidence-v1"
PACKAGES = contract.PACKAGES
FIXTURE = contract.FIXTURE
ARM_CHILD = contract.ARM_CHILD
FIXTURE_REPOSITORY = contract.FIXTURE_REPOSITORY
FIXTURE_DIGEST_IDENTITY_MAX = contract.FIXTURE_DIGEST_IDENTITY_MAX
FIXTURE_DIGEST_METADATA_MAX_BYTES = contract.FIXTURE_DIGEST_METADATA_MAX_BYTES
ROCKY_FINGERPRINT = contract.ROCKY_FINGERPRINT
SHA = contract.SHA
CollectionError = contract.ContractError
AUTOMATIC_UNITS = (
    "dnf-automatic.timer",
    "dnf-automatic-install.timer",
    "dnf-automatic-download.timer",
    "dnf-automatic-notifyonly.timer",
)


class ObservationOperation(str, Enum):
    OS_RELEASE = "read-os-release"
    ARCHITECTURE = "query-architecture"
    DNF_VERSION = "query-dnf-version"
    RELEASEVER = "query-releasever"
    SELINUX_MODE = "query-selinux-mode"
    SELINUX_ENABLED = "query-selinux-enabled"
    SELINUX_POLICY = "query-selinux-policy"
    REPOSITORIES = "query-enabled-repositories"
    SERVICE_ACCOUNT = "resolve-service-account"
    SUBUID = "read-subuid"
    SUBGID = "read-subgid"
    EFFECTIVE_IDS = "query-effective-identities"
    SUPPLEMENTARY_GROUPS = "query-supplementary-groups"
    PODMAN_INFO = "query-podman-info"
    RESOLVE_GRAPHROOT = "resolve-rootless-graphroot"
    RESOLVE_ACCOUNT_HOME = "resolve-service-account-home"
    FIXTURE_REPO_DIGESTS = "inspect-fixture-repo-digests"
    BOOT_ID = "read-boot-id"
    MEMORY = "read-memory-info"
    ROOT_FILESYSTEM = "query-root-filesystem"
    CPU_COUNT = "query-cpu-count"
    UPDATE_UNIT = "query-update-unit"
    CONTAINER_CONFIG = "read-container-config"
    CGROUP_FILESYSTEM = "query-cgroup-filesystem"
    SYSTEMD_USER = "query-systemd-user"
    PODMAN_SOCKET = "query-podman-socket"
    SOCKET_PATH = "query-podman-socket-path"
    ENVIRONMENT_AUTHORITY = "query-environment-authority"
    SUDO_AUTHORITY = "query-sudo-authority"
    QUADLET_AUTHORITY = "query-quadlet-authority"
    LINGER = "query-linger"
    FIXTURE_PRESENT = "verify-fixture-present"
    CLOUD_IDENTITY = "query-cloud-identity-marker"
    PACKAGE_NEVRA = "query-package-nevra"
    PACKAGE_REPOSITORY = "resolve-package-repository"
    PACKAGE_SIGNED_HEADER = "inspect-installed-signed-header"
    ROCKY_KEY = "inspect-rocky-signing-key"
    WRITE_EVIDENCE = "write-evidence"
    WRITE_DIAGNOSTIC = "write-collection-diagnostic"


class ObservationError(RuntimeError):
    def __init__(self, operation: ObservationOperation, reason: str, subject: str | None = None) -> None:
        super().__init__(operation.value)
        self.operation = operation.value
        self.reason = reason
        self.subject = subject


class Observer:
    """The sole owner of process/filesystem/environment observations."""

    PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

    def run(
        self,
        operation: ObservationOperation,
        arguments: list[str],
        *, user: str | None = None,
        subject: str | None = None,
        accepted: frozenset[int] = frozenset({0}),
        maximum: int = 262_144,
    ) -> tuple[int, str, str]:
        command = arguments
        if user is not None:
            try:
                account = pwd.getpwnam(user)
            except KeyError as error:
                raise ObservationError(operation, "observation-failed", subject) from error
            command = [
                "runuser", "--user", user, "--", "env",
                f"HOME={account.pw_dir}", f"XDG_RUNTIME_DIR=/run/user/{account.pw_uid}",
                f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{account.pw_uid}/bus",
                *arguments,
            ]
        try:
            completed = subprocess.run(
                command, check=False, capture_output=True, timeout=60,
                env={"PATH": self.PATH},
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ObservationError(operation, "command-failed", subject) from error
        if completed.returncode not in accepted:
            raise ObservationError(operation, "command-failed", subject)
        if len(completed.stdout) > maximum or len(completed.stderr) > maximum:
            raise ObservationError(operation, "observation-limit-exceeded", subject)
        try:
            stdout = completed.stdout.decode("utf-8").strip()
            stderr = completed.stderr.decode("utf-8").strip()
        except UnicodeDecodeError as error:
            raise ObservationError(operation, "representation-invalid", subject) from error
        return completed.returncode, stdout, stderr

    def text(self, operation: ObservationOperation, path: Path, *, maximum: int = 262_144, encoding: str = "utf-8") -> str:
        try:
            payload = path.read_bytes()
        except OSError as error:
            raise ObservationError(operation, "observation-failed") from error
        if len(payload) > maximum:
            raise ObservationError(operation, "observation-limit-exceeded")
        try:
            return payload.decode(encoding).strip()
        except UnicodeDecodeError as error:
            raise ObservationError(operation, "representation-invalid") from error

    def account(self) -> dict[str, Any]:
        try:
            account = pwd.getpwnam("secpal-runtime")
        except KeyError as error:
            raise ObservationError(ObservationOperation.SERVICE_ACCOUNT, "observation-failed") from error
        return {"name": account.pw_name, "uid": account.pw_uid, "gid": account.pw_gid, "home": account.pw_dir, "shell": account.pw_shell}

    def effective_ids(self) -> list[int]:
        try:
            users, groups = pwd.getpwall(), grp.getgrall()
        except OSError as error:
            raise ObservationError(ObservationOperation.EFFECTIVE_IDS, "observation-failed") from error
        values = {entry.pw_uid for entry in users}
        values.update(entry.pw_gid for entry in users)
        values.update(entry.gr_gid for entry in groups)
        return sorted(values)

    def supplementary_groups(self, account: dict[str, Any]) -> list[int]:
        try:
            return os.getgrouplist(account["name"], account["gid"])
        except OSError as error:
            raise ObservationError(ObservationOperation.SUPPLEMENTARY_GROUPS, "observation-failed") from error

    def resolved(self, operation: ObservationOperation, path: str) -> str:
        try:
            return str(Path(path).resolve(strict=True))
        except OSError as error:
            raise ObservationError(operation, "observation-failed") from error

    def podman_graphroot(self, raw: str) -> str:
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as error:
            raise ObservationError(
                ObservationOperation.PODMAN_INFO, "representation-invalid"
            ) from error
        if (
            not isinstance(value, dict)
            or not isinstance(value.get("store"), dict)
            or not isinstance(value["store"].get("graphRoot"), str)
        ):
            raise ObservationError(
                ObservationOperation.PODMAN_INFO, "representation-invalid"
            )
        return value["store"]["graphRoot"]

    def exists(self, operation: ObservationOperation, path: Path) -> bool:
        try:
            return path.exists()
        except OSError as error:
            raise ObservationError(operation, "observation-failed") from error

    def is_regular_file(self, operation: ObservationOperation, path: Path) -> bool:
        try:
            return path.is_file()
        except OSError as error:
            raise ObservationError(operation, "observation-failed") from error

    def cpu_count(self) -> int | None:
        result = os.cpu_count()
        if result is None:
            raise ObservationError(ObservationOperation.CPU_COUNT, "observation-failed")
        return result

    def filesystem_bytes(self) -> int:
        try:
            facts = os.statvfs("/")
        except OSError as error:
            raise ObservationError(ObservationOperation.ROOT_FILESYSTEM, "observation-failed") from error
        return facts.f_blocks * facts.f_frsize

    def environment_present(self, name: str) -> bool:
        if name not in {"CONTAINER_HOST", "GOOGLE_APPLICATION_CREDENTIALS"}:
            raise ObservationError(ObservationOperation.ENVIRONMENT_AUTHORITY, "subject-invalid")
        return bool(os.environ.get(name))

    def unit_status(self, unit: str) -> int:
        allowed = set(AUTOMATIC_UNITS) | {"podman.socket"}
        if unit not in allowed:
            raise ObservationError(ObservationOperation.UPDATE_UNIT, "subject-invalid")
        operation = ObservationOperation.PODMAN_SOCKET if unit == "podman.socket" else ObservationOperation.UPDATE_UNIT
        status, _, _ = self.run(operation, ["systemctl", "is-enabled", unit], subject=unit, accepted=frozenset(range(6)), maximum=4096)
        return status

    def systemd_user_state(self, uid: int) -> str:
        _, state, _ = self.run(
            ObservationOperation.SYSTEMD_USER,
            ["systemctl", "is-active", f"user@{uid}.service"],
            accepted=frozenset({0, 3}),
            maximum=4096,
        )
        return state

    def sudo_observation(self, account: str) -> dict[str, Any]:
        status, stdout, stderr = self.run(
            ObservationOperation.SUDO_AUTHORITY, ["sudo", "-l", "-U", account],
            accepted=frozenset(range(256)), maximum=8192,
        )
        return {"status": status, "output": f"{stdout}\n{stderr}"}

    def quadlet_status(self, account: dict[str, Any]) -> int:
        status, _, _ = self.run(
            ObservationOperation.QUADLET_AUTHORITY,
            ["runuser", "--user", account["name"], "--", "test", "-w", f"/etc/containers/systemd/users/{account['uid']}"],
            accepted=frozenset({0, 1}), maximum=4096,
        )
        return status

    def container_configs(self, home: str) -> list[str]:
        result: list[str] = []
        for path in (Path("/etc/containers/containers.conf"), Path(home) / ".config/containers/containers.conf"):
            if self.exists(ObservationOperation.CONTAINER_CONFIG, path):
                result.append(self.text(ObservationOperation.CONTAINER_CONFIG, path, maximum=65_536))
        return result

    @staticmethod
    def package_repository_query(nevra: str) -> list[str]:
        """Select one exact NEVRA while formatting its repository identity."""
        return [
            "dnf4",
            "--quiet",
            "--disablerepo=*",
            "--enablerepo=baseos,appstream,extras",
            "repoquery-nevra",
            "--qf",
            "%{repoid}",
            nevra,
        ]

    def package(self, name: str) -> dict[str, Any]:
        if name not in PACKAGES:
            raise ObservationError(ObservationOperation.PACKAGE_NEVRA, "subject-invalid")
        _, identity, _ = self.run(
            ObservationOperation.PACKAGE_NEVRA,
            [
                "rpm", "-q", "--qf",
                "%{NAME}\\n%{EPOCHNUM}\\n%{VERSION}\\n%{RELEASE}\\n%{ARCH}\\n%{NEVRA}\\n",
                name,
            ],
            subject=name,
        )
        identity_lines = identity.splitlines()
        if len(identity_lines) != 6:
            raise ObservationError(
                ObservationOperation.PACKAGE_NEVRA,
                "representation-invalid",
                name,
            )
        package_name, epoch, version, release, architecture, nevra = identity_lines
        _, repositories, _ = self.run(
            ObservationOperation.PACKAGE_REPOSITORY,
            self.package_repository_query(nevra),
            subject=name,
        )
        _, signed_header, verification = self.run(
            ObservationOperation.PACKAGE_SIGNED_HEADER,
            [
                "rpm", "-qvv", "--qf",
                "%{NAME}\\n%{EPOCHNUM}\\n%{VERSION}\\n%{RELEASE}\\n%{ARCH}\\n"
                "%{NEVRA}\\n%{PAYLOADDIGEST}\\n%{PAYLOADDIGESTALGO}\\n"
                "%{SHA256HEADER}\\n%{RSAHEADER:pgpsig}\\n",
                nevra,
            ],
            subject=name,
            maximum=4096,
        )
        return {
            "name": package_name,
            "epoch": epoch,
            "version": version,
            "release": release,
            "architecture": architecture,
            "nevra": nevra,
            "repositories": repositories.splitlines(),
            "signed_header": signed_header,
            "verification": verification,
        }

    def rocky_signing_key(self) -> str:
        _, key, _ = self.run(
            ObservationOperation.ROCKY_KEY,
            [
                "rpm", "-q", "--qf", "%{VERSION}\\n%{PUBKEYS}\\n",
                contract.ROCKY_KEY_PACKAGE,
            ],
            maximum=4096,
        )
        return key

    def write(
        self,
        operation: ObservationOperation,
        path: Path,
        document: dict[str, Any],
    ) -> None:
        try:
            path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            path.chmod(0o600)
        except OSError as error:
            raise ObservationError(operation, "observation-failed") from error


def admitted_fixture_arm64_child(repo_digests_metadata: str) -> str:
    """Compatibility name; the pure contract remains the authoritative owner."""
    return contract.admit_fixture_repo_digests(repo_digests_metadata)


def diagnostic_document(error: ObservationError | contract.ContractError) -> dict[str, str]:
    layer = "observation" if isinstance(error, ObservationError) else error.layer
    return contract.assemble_collection_diagnostic(
        layer, error.operation, error.reason, error.subject
    )


def collect(observer: Observer, options: argparse.Namespace) -> dict[str, Any]:
    account = observer.account()
    _, architecture, _ = observer.run(ObservationOperation.ARCHITECTURE, ["uname", "-m"])
    _, dnf_version, _ = observer.run(ObservationOperation.DNF_VERSION, ["dnf4", "--version"])
    _, releasever, _ = observer.run(ObservationOperation.RELEASEVER, ["rpm", "--eval", "%{rhel}"])
    _, getenforce, _ = observer.run(ObservationOperation.SELINUX_MODE, ["getenforce"])
    observer.run(ObservationOperation.SELINUX_ENABLED, ["selinuxenabled"])
    _, sestatus, _ = observer.run(ObservationOperation.SELINUX_POLICY, ["sestatus"])
    _, repositories, _ = observer.run(ObservationOperation.REPOSITORIES, ["dnf4", "--quiet", "repolist", "--enabled"])
    _, podman_info, _ = observer.run(ObservationOperation.PODMAN_INFO, ["podman", "info", "--format", "json"], user=account["name"])
    graphroot_raw = observer.podman_graphroot(podman_info)
    _, fixture_repo_digests, _ = observer.run(ObservationOperation.FIXTURE_REPO_DIGESTS, ["podman", "image", "inspect", "--format", "{{json .RepoDigests}}", FIXTURE], user=account["name"], maximum=FIXTURE_DIGEST_METADATA_MAX_BYTES)
    _, cgroup_filesystem, _ = observer.run(ObservationOperation.CGROUP_FILESYSTEM, ["stat", "-fc", "%T", "/sys/fs/cgroup"])
    systemd_user = observer.systemd_user_state(account["uid"])
    raw = {
        "os_release": observer.text(ObservationOperation.OS_RELEASE, Path("/etc/os-release"), maximum=65_536),
        "architecture": architecture, "dnf_version": dnf_version, "releasever": releasever,
        "getenforce": getenforce, "selinux_enabled": True, "sestatus": sestatus,
        "repositories": repositories, "account": account,
        "subuid": observer.text(ObservationOperation.SUBUID, Path("/etc/subuid"), maximum=262_144),
        "subgid": observer.text(ObservationOperation.SUBGID, Path("/etc/subgid"), maximum=262_144),
        "effective_ids": observer.effective_ids(), "supplementary_groups": observer.supplementary_groups(account),
        "podman_info": podman_info,
        "graphroot": observer.resolved(ObservationOperation.RESOLVE_GRAPHROOT, graphroot_raw),
        "account_home": observer.resolved(ObservationOperation.RESOLVE_ACCOUNT_HOME, account["home"]),
        "fixture_repo_digests": fixture_repo_digests,
        "automatic_unit_statuses": [observer.unit_status(unit) for unit in AUTOMATIC_UNITS],
        "boot_id": observer.text(ObservationOperation.BOOT_ID, Path("/proc/sys/kernel/random/boot_id"), maximum=128, encoding="ascii"),
        "meminfo": observer.text(ObservationOperation.MEMORY, Path("/proc/meminfo"), maximum=65_536, encoding="ascii"),
        "root_filesystem_bytes": observer.filesystem_bytes(), "cpu_count": observer.cpu_count(),
        "packages": [observer.package(name) for name in PACKAGES],
        "rocky_signing_key": observer.rocky_signing_key(),
        "container_configs": observer.container_configs(account["home"]),
        "cgroup_filesystem": cgroup_filesystem, "systemd_user": systemd_user,
        "socket_exists": observer.exists(ObservationOperation.SOCKET_PATH, Path(f"/run/user/{account['uid']}/podman/podman.sock")),
        "podman_socket_status": observer.unit_status("podman.socket"),
        "container_host_present": observer.environment_present("CONTAINER_HOST"),
        "sudo_observation": observer.sudo_observation(account["name"]),
        "quadlet_status": observer.quadlet_status(account),
        "linger": observer.exists(ObservationOperation.LINGER, Path(f"/var/lib/systemd/linger/{account['name']}")),
        "fixture_present": observer.run(ObservationOperation.FIXTURE_PRESENT, ["podman", "image", "exists", FIXTURE], user=account["name"])[0] == 0,
        "cloud_identity_marker": observer.is_regular_file(ObservationOperation.CLOUD_IDENTITY, Path("/var/lib/secpal-rocky/cloud-identity-absent")),
        "google_credentials_present": observer.environment_present("GOOGLE_APPLICATION_CREDENTIALS"),
    }
    return contract.normalize_and_admit(raw, vars(options))


def collect_native_package_admission(
    observer: Observer, options: argparse.Namespace
) -> dict[str, Any]:
    _, architecture, _ = observer.run(
        ObservationOperation.ARCHITECTURE, ["uname", "-m"]
    )
    raw = {
        "os_release": observer.text(
            ObservationOperation.OS_RELEASE,
            Path("/etc/os-release"),
            maximum=65_536,
        ),
        "architecture": architecture,
        "packages": [observer.package(name) for name in PACKAGES],
        "rocky_signing_key": observer.rocky_signing_key(),
    }
    return contract.normalize_and_admit_native_packages(raw, vars(options))


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--native-package-admission", action="store_true")
    result.add_argument("--target-sha", required=True)
    result.add_argument("--control-sha", required=True)
    result.add_argument("--run-id", required=True)
    result.add_argument("--run-attempt", required=True)
    result.add_argument("--expires-at", type=int)
    result.add_argument("--image")
    result.add_argument("--first-boot-id")
    result.add_argument("--output", required=True, type=Path)
    result.add_argument("--diagnostic-output", required=True, type=Path)
    return result


def main() -> int:
    if sys.argv[1:] == ["--admit-fixture-repo-digests"]:
        try:
            raw = sys.stdin.read(FIXTURE_DIGEST_METADATA_MAX_BYTES + 1)
            contract.admit_fixture_repo_digests(raw)
        except contract.ContractError:
            return 1
        return 0
    options = parser().parse_args()
    observer = Observer()
    try:
        document = (
            collect_native_package_admission(observer, options)
            if options.native_package_admission
            else collect(observer, options)
        )
        observer.write(
            ObservationOperation.WRITE_EVIDENCE,
            options.output,
            document,
        )
    except (ObservationError, contract.ContractError) as error:
        try:
            observer.write(
                ObservationOperation.WRITE_DIAGNOSTIC,
                options.diagnostic_output,
                diagnostic_document(error),
            )
        except ObservationError:
            pass
        return 1
    except (AttributeError, KeyError, TypeError, ValueError, OSError):
        try:
            observer.write(
                ObservationOperation.WRITE_DIAGNOSTIC,
                options.diagnostic_output,
                contract.assemble_collection_diagnostic(
                    "assembly", "assemble-evidence", "internal-error"
                ),
            )
        except ObservationError:
            pass
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
