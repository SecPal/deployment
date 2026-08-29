#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Contract evidence for provider-neutral capacity qualification."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

import jsonschema


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas/capacity-qualification.schema.json"
VALIDATOR = ROOT / "scripts/validate-capacity-qualification.py"
EVALUATION_TIME = "2026-08-15T00:00:00Z"
SHA_A = "a" * 40
SHA_B = "b" * 40
HASH_A = "a" * 64
HASH_B = "b" * 64


def provider_evidence() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "capability": {
            "capacity_profile": "M",
            "compute_isolation": "dedicated-vcpu",
            "cpu_architecture": "amd64",
            "storage_capability": "persistent-posix",
            "topology": "single",
        },
        "subject": {
            "kind": "provider-product",
            "target_identity_sha256": HASH_A,
            "provider_product": {
                "provider": "example-cloud",
                "product_id": "compute-dedicated-4",
                "catalog_record_sha256": HASH_B,
                "catalog_observed_at": "2026-08-01T00:00:00Z",
            },
        },
        "observations": {
            "compute_isolation": {
                "classification": "dedicated-vcpu",
                "basis": "dedicated-vcpu-entitlement",
            },
            "cpu": {
                "architecture": "amd64",
                "instruction_set_level": "x86-64-v3",
                "vendor": "Example CPU Vendor",
                "model": "Example CPU Model",
            },
            "resources": {
                "usable_cpu_millicores": 4000,
                "online_logical_cpus": 4,
                "usable_memory_bytes": 8589934592,
                "total_storage_bytes": 107374182400,
                "free_storage_bytes": 75161927680,
                "total_inodes": 1000000,
                "free_inodes": 700000,
            },
            "workload": {
                "probe_id": "secpal-capacity-workload-v1",
                "probe_revision": SHA_A,
                "duration_seconds": 900,
                "completed_iterations": 3,
                "failed_iterations": 0,
                "deadline_misses": 0,
                "oom_events": 0,
                "peak_cpu_millicores": 2500,
                "peak_memory_bytes": 5368709120,
            },
            "storage": {
                "attachment": "network-block",
                "persistence": "persistent",
                "filesystem": "xfs",
                "fsync_supported": True,
                "performance": {
                    "probe_id": "secpal-capacity-storage-v1",
                    "probe_revision": SHA_A,
                    "duration_seconds": 300,
                    "random_read_iops": 5000,
                    "random_write_iops": 3000,
                    "sequential_read_bytes_per_second": 200000000,
                    "sequential_write_bytes_per_second": 100000000,
                    "fsync_p95_microseconds": 2500,
                },
            },
        },
        "qualification": {
            "target_sha": SHA_A,
            "trusted_control_sha": SHA_B,
            "observed_at": "2026-08-01T00:00:00Z",
            "valid_until": "2026-08-31T00:00:00Z",
            "freshness_seconds": 2592000,
            "result": "PASS",
            "source_evidence_sha256": HASH_A,
            "cleanup": {"required": True, "status": "complete"},
        },
    }


def self_host_evidence() -> dict[str, Any]:
    evidence = provider_evidence()
    evidence["capability"]["compute_isolation"] = "dedicated-host"
    evidence["capability"]["cpu_architecture"] = "arm64"
    evidence["subject"] = {
        "kind": "self-host",
        "target_identity_sha256": HASH_B,
        "hardware_description": "Operator-owned ARM64 host",
    }
    evidence["observations"]["compute_isolation"] = {
        "classification": "dedicated-host",
        "basis": "exclusive-physical-host",
    }
    evidence["observations"]["cpu"] = {
        "architecture": "arm64",
        "instruction_set_level": "arm64",
        "vendor": "Example CPU Vendor",
        "model": "Example ARM CPU",
    }
    evidence["observations"]["storage"]["attachment"] = "local-block"
    evidence["qualification"]["cleanup"] = {
        "required": False,
        "status": "not-required",
    }
    return evidence


class CapacityCapabilityContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(cls.schema)
        cls.validator = jsonschema.Draft202012Validator(
            cls.schema, format_checker=jsonschema.FormatChecker()
        )

    def assert_schema_rejects(self, evidence: dict[str, Any]) -> None:
        with self.assertRaises(jsonschema.ValidationError):
            self.validator.validate(evidence)

    def run_validator(
        self, evidence: dict[str, Any], evaluation_time: str = EVALUATION_TIME
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "evidence.json"
            path.write_text(json.dumps(evidence), encoding="utf-8")
            return subprocess.run(
                [
                    sys.executable,
                    str(VALIDATOR),
                    "--evidence",
                    str(path),
                    "--evaluation-time",
                    evaluation_time,
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

    def test_provider_and_self_host_can_qualify_the_same_profile(self) -> None:
        for evidence in (provider_evidence(), self_host_evidence()):
            with self.subTest(kind=evidence["subject"]["kind"]):
                self.validator.validate(evidence)
                result = self.run_validator(evidence)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("QUALIFIED", result.stdout)
        self.assertNotIn("provider_product", self_host_evidence()["subject"])

    def test_provider_product_is_evidence_not_capacity_identity(self) -> None:
        evidence = provider_evidence()
        evidence["capability"]["capacity_profile"] = "compute-dedicated-4"
        self.assert_schema_rejects(evidence)

        evidence = provider_evidence()
        del evidence["subject"]["provider_product"]["catalog_record_sha256"]
        self.assert_schema_rejects(evidence)

        evidence = provider_evidence()
        evidence["subject"]["provider_product"][
            "catalog_observed_at"
        ] = "2026-06-01T00:00:00Z"
        result = self.run_validator(evidence)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("catalog evidence is stale", result.stderr)

    def test_closed_capability_vocabularies_fail_unknown(self) -> None:
        mutations = {
            "isolation": ("compute_isolation", "burstable"),
            "architecture": ("cpu_architecture", "riscv64"),
            "storage": ("storage_capability", "fast-disk"),
            "topology": ("topology", "large"),
        }
        for name, (field, value) in mutations.items():
            with self.subTest(name=name):
                evidence = provider_evidence()
                evidence["capability"][field] = value
                self.assert_schema_rejects(evidence)

    def test_isolation_architecture_and_topology_are_independent(self) -> None:
        shared = provider_evidence()
        shared["capability"]["compute_isolation"] = "shared"
        shared["observations"]["compute_isolation"] = {
            "classification": "shared",
            "basis": "shared-scheduler",
        }
        self.validator.validate(shared)
        self.validator.validate(self_host_evidence())
        self.assertEqual(shared["capability"]["capacity_profile"], "M")
        self.assertEqual(self_host_evidence()["capability"]["capacity_profile"], "M")

    def test_claims_must_match_effective_observations(self) -> None:
        for field in ("compute_isolation", "cpu_architecture"):
            with self.subTest(field=field):
                evidence = provider_evidence()
                if field == "compute_isolation":
                    evidence["observations"]["compute_isolation"] = {
                        "classification": "shared",
                        "basis": "shared-scheduler",
                    }
                else:
                    evidence["observations"]["cpu"] = {
                        "architecture": "arm64",
                        "instruction_set_level": "arm64",
                        "vendor": "Example CPU Vendor",
                        "model": "Example ARM CPU",
                    }
                result = self.run_validator(evidence)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("does not match", result.stderr)

        evidence = provider_evidence()
        evidence["observations"]["workload"]["probe_revision"] = SHA_B
        result = self.run_validator(evidence)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not bound to target revision", result.stderr)

    def test_profile_floors_and_operational_headroom_are_enforced(self) -> None:
        evidence = provider_evidence()
        evidence["observations"]["resources"]["usable_memory_bytes"] = 8589934591
        self.assert_schema_rejects(evidence)
        evidence["qualification"]["result"] = "FAIL"
        self.validator.validate(evidence)

        evidence = provider_evidence()
        evidence["observations"]["workload"]["peak_cpu_millicores"] = 3000
        result = self.run_validator(evidence)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("CPU operational headroom", result.stderr)

    def test_missing_unknown_stale_or_unclean_evidence_is_not_qualified(self) -> None:
        missing = provider_evidence()
        del missing["observations"]
        self.assert_schema_rejects(missing)

        unknown = provider_evidence()
        del unknown["observations"]
        unknown["qualification"]["result"] = "UNKNOWN"
        self.validator.validate(unknown)
        result = self.run_validator(unknown)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("result is UNKNOWN", result.stderr)

        stale = provider_evidence()
        result = self.run_validator(stale, "2026-09-01T00:00:00Z")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("stale", result.stderr)

        unclean = provider_evidence()
        unclean["qualification"]["cleanup"]["status"] = "incomplete"
        result = self.run_validator(unclean)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cleanup", result.stderr)


if __name__ == "__main__":
    unittest.main()
