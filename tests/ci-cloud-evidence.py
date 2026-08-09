#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Negative tests for bounded non-secret cloud evidence."""

from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path

import jsonschema


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = ROOT / "scripts" / "ci-cloud" / "validate-evidence.py"


def load_validator():
    spec = importlib.util.spec_from_file_location("ci_cloud_evidence", VALIDATOR_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load evidence validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def valid_document() -> dict[str, object]:
    packages = {
        name: "1.0-1"
        for name in (
            "podman",
            "conmon",
            "crun",
            "netavark",
            "aardvark-dns",
            "passt",
            "uidmap",
            "dbus-user-session",
        )
    }
    return {
        "schema_version": 1,
        "workflow": {
            "repository": "SecPal/deployment",
            "run_id": "12345",
            "run_attempt": "1",
            "target_sha": "a" * 40,
        },
        "test": {
            "provider": "digitalocean",
            "region": "fra1",
            "profile": "amd",
            "started_at": "2026-08-09T12:00:00Z",
            "ended_at": "2026-08-09T12:10:00Z",
            "target_exit_status": 0,
            "result": "passed",
            "failed_admission_invariants": [],
        },
        "platform": {
            "os_release": {
                "ID": "debian",
                "VERSION_ID": "13",
                "VERSION_CODENAME": "trixie",
                "PRETTY_NAME": "Debian GNU/Linux 13 (trixie)",
            },
            "architecture": "amd64",
            "uname": "Linux fixture 6.12.0-amd64 x86_64 GNU/Linux",
            "kernel": "6.12.0-amd64",
            "cpu": {"vendor": "AuthenticAMD", "model": "DO-Premium-AMD"},
            "virtualization": "kvm",
            "logical_cpu": 8,
            "memory_bytes": 17179869184,
            "root_filesystem_bytes": 171798691840,
        },
        "apt": {
            "source_files": ["/etc/apt/sources.list.d/debian.sources"],
            "source_hosts": ["deb.debian.org", "security.debian.org"],
            "configured_suites": ["trixie", "trixie-security", "trixie-updates"],
            "debian_archive_keyring_version": "2025.1",
            "runtime_packages": packages,
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
            "crun_version": "crun version 1.18",
            "crun_features": "seccomp systemd",
            "netavark_version": "netavark 1.14",
            "aardvark_version": "aardvark-dns 1.14",
            "pasta_version": "pasta 0.0",
            "passt_version": "passt 0.0",
            "uidmap": {"newuidmap": "/usr/bin/newuidmap", "newgidmap": "/usr/bin/newgidmap"},
            "cgroup_version": "v2",
            "systemd_version": "systemd 257",
            "apparmor_host": {"kernel_enabled": True, "loaded_profiles": 10, "enforcing_profiles": 4},
        },
    }


class EvidenceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.validator = load_validator()

    def test_complete_evidence_accepts_host_apparmor_with_podman_capability_false(self) -> None:
        document = valid_document()
        schema = json.loads(
            (ROOT / "schemas" / "ci-cloud-evidence.schema.json").read_text(
                encoding="utf-8"
            )
        )
        jsonschema.Draft202012Validator(schema).validate(document)
        self.assertEqual(document, self.validator.validate_document(document))

    def test_incomplete_evidence_is_rejected(self) -> None:
        document = valid_document()
        del document["runtime"]
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self.validator.validate_document(document)

    def test_credential_like_field_is_rejected(self) -> None:
        document = valid_document()
        document["runtime"]["access_token"] = "synthetic"
        with self.assertRaisesRegex(ValueError, "credential-like field"):
            self.validator.validate_document(document)

    def test_credential_like_value_is_rejected(self) -> None:
        document = valid_document()
        document["runtime"]["crun_features"] = "Authorization: Bearer syntheticvalue"
        with self.assertRaisesRegex(ValueError, "credential-like value"):
            self.validator.validate_document(document)

    def test_result_cannot_hide_failed_admission(self) -> None:
        document = valid_document()
        document["test"]["failed_admission_invariants"] = ["D1_HOST_APPARMOR"]
        with self.assertRaisesRegex(ValueError, "contradicts"):
            self.validator.validate_document(document)

    def test_unknown_nested_field_is_rejected(self) -> None:
        document = copy.deepcopy(valid_document())
        document["runtime"]["podman"]["cloud_identity"] = "none"
        with self.assertRaisesRegex(ValueError, "unknown"):
            self.validator.validate_document(document)


if __name__ == "__main__":
    unittest.main()
