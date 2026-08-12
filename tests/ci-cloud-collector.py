#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Admission regressions for effective disposable Debian host facts."""

from __future__ import annotations

import copy
import importlib.util
import stat
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
COLLECTOR_PATH = ROOT / "scripts" / "ci-cloud" / "collect-host-evidence.py"
REQUIRED_TOOLS = {
    "aa-status", "apt-cache", "apt-config", "bash", "curl", "df", "dpkg",
    "dpkg-query", "findmnt", "getent", "gh", "git", "id", "install",
    "jq", "loginctl", "lscpu", "mktemp", "newgidmap", "newuidmap", "podman",
    "python3", "realpath", "sha256sum", "ss", "stat",
    "systemd-detect-virt", "systemctl", "timedatectl", "uname",
}
RUNTIME_PACKAGES = {
    "podman", "conmon", "crun", "netavark", "aardvark-dns", "passt",
    "uidmap", "dbus-user-session",
}
BOOTSTRAP_PACKAGES = {
    "aardvark-dns", "apparmor", "apparmor-utils", "crun", "curl",
    "dbus-user-session", "git", "gh", "jq", "netavark", "passt", "podman",
    "python3", "python3-jsonschema", "python3-yaml", "uidmap",
    "unattended-upgrades",
}


def load_collector():
    spec = importlib.util.spec_from_file_location("ci_cloud_collector", COLLECTOR_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load cloud host collector")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def valid_facts() -> dict[str, object]:
    packages = {
        name: {
            "version": "1.0-1",
            "architecture": "amd64",
            "origin": "Debian",
            "suite": "trixie",
        }
        for name in RUNTIME_PACKAGES | BOOTSTRAP_PACKAGES
    }
    packages["dbus-user-session"]["architecture"] = "all"
    return {
        "platform": {
            "os_release": {
                "ID": "debian",
                "VERSION_ID": "13",
                "VERSION_CODENAME": "trixie",
                "PRETTY_NAME": "Debian GNU/Linux 13 (trixie)",
            },
            "architecture": "amd64",
            "kernel": "6.12.42+deb13-amd64",
            "cpu": {"vendor": "GenuineIntel", "model": "synthetic Intel"},
            "logical_cpu": 8,
            "memory_bytes": 16 * 1024**3,
            "root_filesystem_bytes": 160 * 1024**3,
        },
        "apt": {
            "source_files": ["/etc/apt/sources.list.d/debian.sources"],
            "source_hosts": ["deb.debian.org", "security.debian.org"],
            "configured_suites": ["trixie", "trixie-security", "trixie-updates"],
            "release_origins": ["Debian"],
            "verified_release_suites": ["trixie", "trixie-security", "trixie-updates"],
            "release_signatures_verified": True,
            "debian_archive_keyring_version": "2025.1",
            "runtime_packages": {
                name: copy.deepcopy(packages[name]) for name in RUNTIME_PACKAGES
            },
            "bootstrap_packages": {
                name: copy.deepcopy(packages[name]) for name in BOOTSTRAP_PACKAGES
            },
            "forbidden_packages_present": [],
        },
        "host": {
            "kernel_package": {
                "name": "linux-image-6.12.42+deb13-amd64",
                "version": "6.12.42-1",
                "architecture": "amd64",
                "origin": "Debian",
                "suite": "trixie-security",
                "owned": True,
            },
            "filesystem": {
                "type": "ext4",
                "read_only": False,
                "overlayfs_supported": True,
                "d_type": True,
            },
            "security_updates": {
                "mechanism": "unattended-upgrades",
                "automatic": True,
                "timer_enabled": True,
                "security_suite": "trixie-security",
                "normal_updates_automatic": False,
                "major_release_upgrades_automatic": False,
                "automatic_reboot": False,
                "runtime_packages_excluded": True,
            },
            "required_tools": {
                "present": sorted(REQUIRED_TOOLS),
                "missing": [],
            },
            "clock": {"synchronized": True},
            "ssh": {"root_login_denied": True},
            "cloud_identity": {
                "probe_supported": False,
                "probe_succeeded": False,
                "identity_present": False,
            },
        },
        "runtime": {
            "podman": {
                "version": "podman version 5.4.2",
                "rootless": True,
                "seccomp_enabled": True,
                "apparmor_enabled": False,
                "oci_runtime": "crun",
                "network_backend": "netavark",
                "rootless_network_command": "pasta",
                "cgroup_version": "v2",
            },
            "apparmor_host": {
                "kernel_enabled": True,
                "loaded_profiles": 10,
                "enforcing_profiles": 4,
            },
            "uidmap": {
                "newuidmap": "/usr/bin/newuidmap",
                "newgidmap": "/usr/bin/newgidmap",
                "subuid": {"start": 200000, "count": 65536, "entry_count": 1, "overlap": False},
                "subgid": {"start": 200000, "count": 65536, "entry_count": 1, "overlap": False},
                "mapping_effective": True,
            },
            "systemd_user": {
                "manager_available": True,
                "starts_at_boot": True,
                "linger_enabled": True,
                "dbus_session_available": True,
                "runtime_directory": "/run/user/20000",
                "runtime_directory_uid": 20000,
                "runtime_directory_gid": 20000,
                "runtime_directory_mode": "0700",
            },
            "quadlet": {
                "generator_path": "/usr/lib/systemd/user-generators/podman-user-generator",
                "effective_search_paths": ["/etc/containers/systemd/users/20000"],
                "definitions_uid": 0,
                "definitions_gid": 0,
                "definitions_mode": "0755",
                "tree_symlinks_present": False,
                "service_account_can_write": False,
            },
            "storage": {
                "driver": "overlay",
                "graphroot": "/home/secpal-ci/.local/share/containers/storage",
                "runroot": "/run/user/20000/containers",
            },
            "api": {
                "system_service_active": False,
                "system_service_enabled": False,
                "system_socket_active": False,
                "system_socket_enabled": False,
                "user_service_active": False,
                "user_service_enabled": False,
                "user_socket_active": False,
                "user_socket_enabled": False,
                "tcp_listener": False,
                "unix_listener": False,
                "service_process": False,
                "process_scan_incomplete": False,
                "listener_scan_incomplete": False,
                "remote_connection": False,
            },
            "updates": {
                "auto_update_timer_enabled": False,
                "auto_update_timer_active": False,
            },
            "registries": {
                "ghcr_insecure": False,
                "secpal_mirrors": [],
                "secpal_location_rewrite": False,
            },
        },
    }


class CloudHostAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.collector = load_collector()

    def test_gcp_metadata_probe_records_only_bounded_identity_booleans(self) -> None:
        probe = self.collector.subprocess.CompletedProcess(
            args=[], returncode=0, stdout="200", stderr=""
        )
        absent_identity = self.collector.subprocess.CompletedProcess(
            args=[], returncode=0, stdout="404", stderr=""
        )
        with mock.patch.object(
            self.collector.subprocess,
            "run",
            side_effect=[probe, absent_identity],
        ) as run:
            self.assertEqual(
                {
                    "probe_supported": True,
                    "probe_succeeded": True,
                    "identity_present": False,
                },
                self.collector.cloud_identity_facts("gcp"),
            )
        self.assertEqual(["curl", "--disable"], run.call_args.args[0][:2])
        self.assertEqual(2, run.call_count)

    def test_package_origin_is_bound_to_the_selected_policy_entry(self) -> None:
        policy = """podman:
  Installed: 1.0-1
  Candidate: 1.0-1
  Version table:
 *** 1.0-1 500
        500 https://packages.example.invalid/debian trixie/main amd64 Packages
           release o=Example,n=trixie,l=Example,c=main,b=amd64
        100 /var/lib/dpkg/status
"""

        def checked_output(arguments: list[str], timeout: int = 15) -> str:
            del timeout
            if arguments[:3] == ["dpkg-query", "-W", "-f"]:
                return "amd64"
            if arguments == ["apt-cache", "policy", "podman"]:
                return policy
            return ""

        with (
            mock.patch.object(self.collector, "package_version", return_value="1.0-1"),
            mock.patch.object(self.collector, "checked_output", side_effect=checked_output),
        ):
            self.assertEqual(
                {
                    "version": "1.0-1",
                    "architecture": "amd64",
                    "origin": "",
                    "suite": "trixie",
                },
                self.collector.package_metadata("podman", "amd64", {"trixie"}),
            )

    def test_package_origin_accepts_the_selected_debian_release(self) -> None:
        policy = """podman:
  Installed: 1.0-1
  Candidate: 1.0-1
  Version table:
 *** 1.0-1 500
        500 https://deb.debian.org/debian trixie/main amd64 Packages
           release o=Debian,n=trixie,l=Debian,c=main,b=amd64
        100 /var/lib/dpkg/status
"""
        with mock.patch.object(
            self.collector, "checked_output", return_value=policy
        ):
            self.assertEqual(
                ("Debian", "trixie"),
                self.collector.package_policy_provenance("podman", "1.0-1"),
            )

    def test_package_origin_accepts_real_debian_policy_without_release_line(self) -> None:
        policy = """podman:
  Installed: 5.4.2+ds1-2+b2
  Candidate: 5.4.2+ds1-2+b2
  Version table:
 *** 5.4.2+ds1-2+b2 500
        500 http://deb.debian.org/debian trixie/main amd64 Packages
        100 /var/lib/dpkg/status
"""
        with mock.patch.object(
            self.collector, "checked_output", return_value=policy
        ):
            self.assertEqual(
                ("Debian", "trixie"),
                self.collector.package_policy_provenance(
                    "podman", "5.4.2+ds1-2+b2"
                ),
            )

    def test_package_origin_rejects_external_source_spoofing_debian_release(self) -> None:
        policy = """podman:
  Installed: 5.4.2+ds1-2+b2
  Candidate: 5.4.2+ds1-2+b2
  Version table:
 *** 5.4.2+ds1-2+b2 500
        500 https://packages.example.invalid/debian trixie/main amd64 Packages
           release o=Debian,n=trixie,l=Debian,c=main,b=amd64
        100 /var/lib/dpkg/status
"""
        with mock.patch.object(
            self.collector, "checked_output", return_value=policy
        ):
            self.assertEqual(
                ("", "trixie"),
                self.collector.package_policy_provenance(
                    "podman", "5.4.2+ds1-2+b2"
                ),
            )

    def test_verified_releases_ignore_stale_inactive_backports_metadata(self) -> None:
        release_files = [
            f"/var/lib/apt/lists/debian_dists_{suite}_InRelease"
            for suite in (
                "trixie",
                "trixie-security",
                "trixie-updates",
                "trixie-backports",
            )
        ]

        def read_text(path: Path, limit: int = 8192) -> str:
            del limit
            suite = path.name.removeprefix("debian_dists_").removesuffix(
                "_InRelease"
            )
            origin = "Debian Backports" if suite == "trixie-backports" else "Debian"
            return f"Origin: {origin}\nCodename: {suite}\n"

        metadata = mock.Mock(st_uid=0, st_mode=stat.S_IFREG | 0o644)
        with (
            mock.patch.object(self.collector.glob, "glob", return_value=release_files),
            mock.patch.object(self.collector, "read_text", side_effect=read_text),
            mock.patch.object(Path, "stat", return_value=metadata),
        ):
            self.assertEqual(
                (
                    ["Debian"],
                    ["trixie", "trixie-security", "trixie-updates"],
                    True,
                ),
                self.collector.verified_releases(
                    {"trixie", "trixie-security", "trixie-updates"}
                ),
            )

    def test_gcp_metadata_probe_detects_an_attached_identity(self) -> None:
        responses = [
            self.collector.subprocess.CompletedProcess(
                args=[], returncode=0, stdout="200", stderr=""
            ),
            self.collector.subprocess.CompletedProcess(
                args=[], returncode=0, stdout="200", stderr=""
            ),
        ]
        with mock.patch.object(
            self.collector.subprocess, "run", side_effect=responses
        ):
            self.assertEqual(
                {
                    "probe_supported": True,
                    "probe_succeeded": True,
                    "identity_present": True,
                },
                self.collector.cloud_identity_facts("gcp"),
            )

    def test_registry_wildcard_matching_ghcr_is_admitted_as_effective(self) -> None:
        self.assertTrue(
            self.collector.registry_prefix_matches("*.io", "ghcr.io/secpal/api")
        )
        self.assertFalse(
            self.collector.registry_prefix_matches(
                "*.example.com", "ghcr.io/secpal/api"
            )
        )

    def test_registry_facts_detect_matching_wildcard_override(self) -> None:
        document = """
[[registry]]
prefix = "*.io"
location = "mirror.example.invalid"
insecure = true
[[registry.mirror]]
location = "backup.example.invalid"
"""
        with (
            mock.patch.object(Path, "is_file", return_value=True),
            mock.patch.object(self.collector, "read_text", return_value=document),
            mock.patch.object(self.collector.glob, "glob", return_value=[]),
        ):
            self.assertEqual(
                {
                    "ghcr_insecure": True,
                    "secpal_mirrors": ["backup.example.invalid"],
                    "secpal_location_rewrite": True,
                },
                self.collector.registry_facts(),
            )

    def test_arm_cpu_model_uses_effective_lscpu_facts(self) -> None:
        lscpu = {
            "lscpu": [
                {"field": "Vendor ID:", "data": "ARM"},
                {"field": "Model name:", "data": "Neoverse-V2"},
            ]
        }
        with (
            mock.patch.object(self.collector, "json_output", return_value=lscpu),
            mock.patch.object(
                self.collector,
                "read_text",
                return_value="CPU implementer\t: 0x41\nCPU part\t: 0xd4f\n",
            ),
        ):
            self.assertEqual(
                {"vendor": "ARM", "model": "Neoverse-V2"},
                self.collector.cpu_facts(),
            )

    def assert_failure(self, path: tuple[str, ...], value: object, invariant: str) -> None:
        facts = copy.deepcopy(valid_facts())
        target = facts
        for name in path[:-1]:
            target = target[name]
        target[path[-1]] = value
        failures = self.collector.admission_failures(facts, "intel")
        self.assertIn(invariant, failures)

    def test_complete_effective_facts_pass(self) -> None:
        self.assertEqual([], self.collector.admission_failures(valid_facts(), "intel"))

    def test_required_tools_cover_security_fact_collectors(self) -> None:
        self.assertTrue(
            {
                "aa-status",
                "apt-cache",
                "apt-config",
                "dpkg",
                "dpkg-query",
                "git",
                "jq",
                "ss",
                "systemd-detect-virt",
                "uname",
            }.issubset(self.collector.REQUIRED_TOOLS)
        )

    def test_rejects_unverified_apt_release(self) -> None:
        self.assert_failure(("apt", "release_signatures_verified"), False, "D1_APT_RELEASE_SIGNATURES")

    def test_rejects_missing_archive_keyring(self) -> None:
        self.assert_failure(("apt", "debian_archive_keyring_version"), "", "D1_APT_ARCHIVE_KEYRING")

    def test_rejects_unowned_kernel(self) -> None:
        self.assert_failure(("host", "kernel_package", "owned"), False, "D1_KERNEL_PACKAGE_PROVENANCE")

    def test_rejects_release_candidate_kernel(self) -> None:
        self.assert_failure(("platform", "kernel"), "6.12.0-rc4-amd64", "D1_KERNEL_DEBIAN_6_12")

    def test_rejects_runtime_package_from_backports(self) -> None:
        facts = valid_facts()
        facts["apt"]["runtime_packages"]["podman"]["suite"] = "trixie-backports"
        self.assertIn("D1_RUNTIME_PACKAGE_PROVENANCE", self.collector.admission_failures(facts, "intel"))

    def test_rejects_bootstrap_package_without_debian_provenance(self) -> None:
        facts = valid_facts()
        facts["apt"]["bootstrap_packages"]["apparmor"]["origin"] = ""
        self.assertIn(
            "D1_BOOTSTRAP_PACKAGE_PROVENANCE",
            self.collector.admission_failures(facts, "intel"),
        )

    def test_rejects_incomplete_security_update_policy(self) -> None:
        self.assert_failure(("host", "security_updates", "automatic"), False, "D1_SECURITY_UPDATE_POLICY")

    def test_guest_memory_is_evidence_not_an_unmeasured_admission_floor(self) -> None:
        facts = valid_facts()
        facts["platform"]["memory_bytes"] = 4 * 1024**3
        self.assertNotIn(
            "D1_MINIMUM_MEMORY_8_GIB",
            self.collector.admission_failures(facts, "intel"),
        )

    def test_rejects_missing_required_tool(self) -> None:
        self.assert_failure(("host", "required_tools", "missing"), ["gh"], "D1_REQUIRED_TOOLS")

    def test_rejects_unsupported_filesystem(self) -> None:
        self.assert_failure(("host", "filesystem", "type"), "fuse", "D1_LOCAL_FILESYSTEM")

    def test_rejects_ineffective_subordinate_mapping(self) -> None:
        self.assert_failure(("runtime", "uidmap", "mapping_effective"), False, "D1_UIDMAP_EFFECTIVE")

    def test_rejects_subordinate_mapping_past_kernel_id_limit(self) -> None:
        self.assert_failure(("runtime", "uidmap", "subuid", "start"), 4294901760, "D1_UIDMAP_EFFECTIVE")

    def test_rejects_unrestricted_quadlet_search_path(self) -> None:
        self.assert_failure(("runtime", "quadlet", "effective_search_paths"), ["/home/secpal-ci/.config/containers/systemd"], "D1_QUADLET_TRUST_BOUNDARY")

    def test_rejects_unbounded_podman_storage_path(self) -> None:
        self.assert_failure(("runtime", "storage", "runroot"), "/tmp/containers", "D1_PODMAN_STORAGE_PATHS")

    def test_rejects_user_runtime_directory_with_weak_mode(self) -> None:
        self.assert_failure(("runtime", "systemd_user", "runtime_directory_mode"), "0755", "D1_SYSTEMD_USER_MANAGER")

    def test_rejects_active_podman_api_socket(self) -> None:
        self.assert_failure(
            ("runtime", "api", "system_socket_active"),
            True,
            "D1_PODMAN_API_DISABLED",
        )

    def test_rejects_manually_launched_podman_api_process(self) -> None:
        self.assert_failure(
            ("runtime", "api", "service_process"),
            True,
            "D1_PODMAN_API_DISABLED",
        )

    def test_recognizes_podman_system_service_command(self) -> None:
        self.assertTrue(
            self.collector.is_podman_service_command(
                ["/usr/bin/podman", "system", "service", "unix:///tmp/api.sock"]
            )
        )
        self.assertFalse(
            self.collector.is_podman_service_command(
                ["/usr/bin/podman", "system", "connection", "list"]
            )
        )

    def test_parses_root_owned_app_armor_snapshot(self) -> None:
        self.assertEqual(
            {"loaded_profiles": 10, "enforcing_profiles": 4},
            self.collector.parse_apparmor_snapshot(
                "loaded_profiles=10\nenforcing_profiles=4\n"
            ),
        )

    def test_rejects_malformed_app_armor_snapshot(self) -> None:
        self.assertEqual(
            {"loaded_profiles": None, "enforcing_profiles": None},
            self.collector.parse_apparmor_snapshot(
                "loaded_profiles=ten\nenforcing_profiles=4\n"
            ),
        )

    def test_detects_system_scope_podman_api_socket(self) -> None:
        def command_result(arguments: list[str], timeout: int = 15) -> tuple[int, str]:
            del timeout
            if arguments == ["systemctl", "is-active", "podman.socket"]:
                return 0, "active"
            return 1, "inactive"

        with (
            mock.patch.object(self.collector, "command_result", side_effect=command_result),
            mock.patch.object(self.collector, "output", return_value=""),
            mock.patch.object(self.collector, "json_array_output", return_value=[]),
        ):
            facts = self.collector.podman_api_facts()
        self.assertTrue(facts["system_socket_active"])

    def test_detects_enabled_system_scope_podman_api_service(self) -> None:
        def command_result(arguments: list[str], timeout: int = 15) -> tuple[int, str]:
            del timeout
            if arguments == ["systemctl", "is-enabled", "podman.service"]:
                return 0, "enabled"
            return 1, "disabled"

        with (
            mock.patch.object(self.collector, "command_result", side_effect=command_result),
            mock.patch.object(self.collector, "output", return_value=""),
            mock.patch.object(self.collector, "json_array_output", return_value=[]),
        ):
            facts = self.collector.podman_api_facts()
        self.assertTrue(facts["system_service_enabled"])

    def test_static_system_scope_podman_service_is_not_enabled(self) -> None:
        def command_result(arguments: list[str], timeout: int = 15) -> tuple[int, str]:
            del timeout
            if arguments == ["systemctl", "is-enabled", "podman.service"]:
                return 0, "static"
            if "is-enabled" in arguments:
                return 1, "disabled"
            return 1, "inactive"

        with (
            mock.patch.object(self.collector, "command_result", side_effect=command_result),
            mock.patch.object(self.collector, "output", return_value=""),
            mock.patch.object(self.collector, "json_array_output", return_value=[]),
        ):
            facts = self.collector.podman_api_facts()
        self.assertFalse(facts["system_service_enabled"])

    def test_unknown_podman_service_enablement_fails_closed(self) -> None:
        def command_result(arguments: list[str], timeout: int = 15) -> tuple[int, str]:
            del timeout
            if arguments == ["systemctl", "is-enabled", "podman.service"]:
                return 1, "unexpected state"
            if "is-enabled" in arguments:
                return 1, "disabled"
            return 1, "inactive"

        with (
            mock.patch.object(self.collector, "command_result", side_effect=command_result),
            mock.patch.object(self.collector, "output", return_value=""),
            mock.patch.object(self.collector, "json_array_output", return_value=[]),
        ):
            facts = self.collector.podman_api_facts()
        self.assertTrue(facts["system_service_enabled"])

    def test_static_podman_auto_update_timer_is_not_enabled(self) -> None:
        def command_result(arguments: list[str], timeout: int = 15) -> tuple[int, str]:
            del timeout
            if arguments == [
                "systemctl", "--user", "is-enabled", "podman-auto-update.timer"
            ]:
                return 0, "static"
            return 1, "inactive"

        with mock.patch.object(
            self.collector, "command_result", side_effect=command_result
        ):
            facts = self.collector.podman_update_facts()
        self.assertFalse(facts["auto_update_timer_enabled"])

    def test_unknown_podman_auto_update_enablement_fails_closed(self) -> None:
        with mock.patch.object(
            self.collector,
            "command_result",
            return_value=(1, "unexpected state"),
        ):
            facts = self.collector.podman_update_facts()
        self.assertTrue(facts["auto_update_timer_enabled"])

    def test_static_security_upgrade_timer_is_not_enabled(self) -> None:
        config = '''APT::Periodic::Enable "1";
APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade::Origins-Pattern:: "origin=Debian,codename=trixie-security";
Unattended-Upgrade::Automatic-Reboot "false";
'''
        with (
            mock.patch.object(self.collector, "checked_output", return_value=config),
            mock.patch.object(self.collector, "package_version", return_value="1.0-1"),
            mock.patch.object(self.collector, "command_result", return_value=(0, "static")),
        ):
            facts = self.collector.security_update_facts()
        self.assertFalse(facts["timer_enabled"])

    def test_security_update_policy_reads_complete_large_apt_configuration(self) -> None:
        config = "X" * 9000 + '''
APT::Periodic::Enable "1";
APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade::Origins-Pattern:: "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Package-Blacklist:: "podman";
Unattended-Upgrade::Package-Blacklist:: "conmon";
Unattended-Upgrade::Package-Blacklist:: "crun";
Unattended-Upgrade::Package-Blacklist:: "netavark";
Unattended-Upgrade::Package-Blacklist:: "aardvark-dns";
Unattended-Upgrade::Package-Blacklist:: "passt";
Unattended-Upgrade::Package-Blacklist:: "uidmap";
Unattended-Upgrade::Package-Blacklist:: "dbus-user-session";
'''

        def checked_output(
            arguments: list[str], timeout: int = 15, output_limit: int = 8192
        ) -> str:
            del timeout
            self.assertEqual(["apt-config", "dump"], arguments)
            self.assertGreaterEqual(output_limit, len(config))
            return config[:output_limit]

        with (
            mock.patch.object(
                self.collector, "checked_output", side_effect=checked_output
            ),
            mock.patch.object(self.collector, "package_version", return_value="2.12"),
            mock.patch.object(
                self.collector, "systemd_unit_enabled", return_value=True
            ),
        ):
            self.assertEqual(
                {
                    "mechanism": "unattended-upgrades",
                    "automatic": True,
                    "timer_enabled": True,
                    "security_suite": "trixie-security",
                    "normal_updates_automatic": False,
                    "major_release_upgrades_automatic": False,
                    "automatic_reboot": False,
                    "runtime_packages_excluded": True,
                },
                self.collector.security_update_facts(),
            )

    def test_detects_manually_launched_unix_podman_api(self) -> None:
        def command_result(
            arguments: list[str], timeout: int = 15
        ) -> tuple[int, str]:
            del timeout
            if arguments == ["ss", "-lxnp"]:
                return (
                    0,
                    'u_str LISTEN 0 4096 /tmp/fixture.sock '
                    'users:(("podman",pid=42,fd=3))',
                )
            if arguments == ["ss", "-ltnp"]:
                return 0, ""
            return 1, "inactive"

        with (
            mock.patch.object(
                self.collector, "command_result", side_effect=command_result
            ),
            mock.patch.object(self.collector, "json_array_output", return_value=[]),
        ):
            facts = self.collector.podman_api_facts()
        self.assertTrue(facts["unix_listener"])

    def test_stale_known_podman_socket_is_not_an_active_listener(self) -> None:
        def command_result(
            arguments: list[str], timeout: int = 15
        ) -> tuple[int, str]:
            del timeout
            if arguments in (["ss", "-lxnp"], ["ss", "-ltnp"]):
                return 0, ""
            return 1, "inactive"

        with (
            mock.patch.object(
                self.collector, "command_result", side_effect=command_result
            ),
            mock.patch.object(self.collector, "json_array_output", return_value=[]),
            mock.patch.object(Path, "is_socket", return_value=True),
        ):
            facts = self.collector.podman_api_facts()
        self.assertFalse(facts["unix_listener"])
        self.assertFalse(facts["listener_scan_incomplete"])

    def test_rejects_missing_effective_root_ssh_denial(self) -> None:
        self.assert_failure(("host", "ssh", "root_login_denied"), False, "D1_ROOT_SSH_DISABLED")


if __name__ == "__main__":
    unittest.main()
