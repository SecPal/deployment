#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Contract evidence for provider-neutral capacity qualification."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
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
PROBE_PATH = ROOT / "config/capacity-probes-v1.json"
VALIDATOR = ROOT / "scripts/validate-capacity-qualification.py"
EVALUATION_TIME = "2026-08-15T00:00:00Z"
SHA_A, SHA_B = "a" * 40, "b" * 40
HASH_A, HASH_B = "a" * 64, "b" * 64
MAX_EVIDENCE_BYTES = 262_144


def canonical_digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
    ).hexdigest()


def probe_revisions() -> tuple[str, str]:
    manifest = json.loads(PROBE_PATH.read_text(encoding="utf-8"))
    return canonical_digest(manifest["workload"]), canonical_digest(manifest["storage"])


def provider_evidence() -> dict[str, Any]:
    workload_revision, storage_revision = probe_revisions()
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
                "probe_revision_sha256": workload_revision,
                "duration_seconds": 900,
                "completed_iterations": 1,
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
                    "probe_revision_sha256": storage_revision,
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
            "workload_probe_revision_sha256": workload_revision,
            "storage_probe_revision_sha256": storage_revision,
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
    evidence["capability"].update(
        compute_isolation="dedicated-host", cpu_architecture="arm64"
    )
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


def source_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    qualification = evidence["qualification"]
    workload = evidence["observations"]["workload"]
    return {
        "schema_version": 1,
        "authority": {
            "collector": "trusted-controller",
            "target_sha": qualification["target_sha"],
            "trusted_control_sha": qualification["trusted_control_sha"],
            "target_identity_sha256": evidence["subject"]["target_identity_sha256"],
            "workload_probe_revision_sha256": qualification[
                "workload_probe_revision_sha256"
            ],
            "storage_probe_revision_sha256": qualification[
                "storage_probe_revision_sha256"
            ],
            "observed_at": qualification["observed_at"],
        },
        "capability": copy.deepcopy(evidence["capability"]),
        "subject": copy.deepcopy(evidence["subject"]),
        "observations": copy.deepcopy(evidence["observations"]),
        "cleanup": copy.deepcopy(qualification["cleanup"]),
        "collection": {
            "workload": {
                "observer": "trusted-controller",
                "controller_observed_duration_seconds": workload["duration_seconds"],
                "maximum_iteration_duration_seconds": 600,
                "controller_observed_completed_iterations": workload[
                    "completed_iterations"
                ],
                "controller_observed_failed_iterations": workload[
                    "failed_iterations"
                ],
                "controller_observed_deadline_misses": workload["deadline_misses"],
                "controller_observed_oom_events": workload["oom_events"],
                "cpu_reservation_requested_millicores": 1200,
                "cpu_reservation_delivered_millicores": 1200,
                "cpu_reservation_observed_seconds": workload["duration_seconds"],
                "memory_reservation_bytes": 2576980378,
                "memory_reservation_held_seconds": workload["duration_seconds"],
                "target_results_authoritative": False,
            },
            "storage": {
                "observer": "trusted-controller",
                "controller_observed_cycles_completed": 5,
                "controller_observed_deadline_misses": 0,
                "maximum_cycle_duration_microseconds": 100000000,
                "same_persistent_filesystem_observed": True,
            },
        },
    }


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
        self,
        evidence: dict[str, Any] | None = None,
        *,
        source: dict[str, Any] | None = None,
        evaluation_time: str = EVALUATION_TIME,
        evidence_payload: bytes | None = None,
        source_payload: bytes | None = None,
        expected_target_sha: str = SHA_A,
        expected_control_sha: str = SHA_B,
        expected_target_identity: str | None = None,
        include_trusted_inputs: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        evidence = provider_evidence() if evidence is None else evidence
        source = source_evidence(evidence) if source is None else source
        if source_payload is None:
            source_payload = json.dumps(
                source, ensure_ascii=False, separators=(",", ":"), sort_keys=True
            ).encode()
        if evidence_payload is None:
            evidence["qualification"]["source_evidence_sha256"] = hashlib.sha256(
                source_payload
            ).hexdigest()
            evidence_payload = json.dumps(evidence).encode()
        workload_revision, storage_revision = probe_revisions()
        expected_target_identity = (
            evidence["subject"]["target_identity_sha256"]
            if expected_target_identity is None
            else expected_target_identity
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            evidence_path, source_path = directory / "evidence.json", directory / "source.json"
            evidence_path.write_bytes(evidence_payload)
            source_path.write_bytes(source_payload)
            command = [
                sys.executable,
                str(VALIDATOR),
                "--evidence",
                str(evidence_path),
                "--evaluation-time",
                evaluation_time,
            ]
            if include_trusted_inputs:
                command += [
                    "--source-evidence",
                    str(source_path),
                    "--expected-target-sha",
                    expected_target_sha,
                    "--expected-control-sha",
                    expected_control_sha,
                    "--expected-target-identity-sha256",
                    expected_target_identity,
                    "--expected-workload-probe-revision",
                    workload_revision,
                    "--expected-storage-probe-revision",
                    storage_revision,
                ]
            return subprocess.run(
                command, cwd=ROOT, check=False, capture_output=True, text=True
            )

    def assert_not_qualified(
        self, result: subprocess.CompletedProcess[str], message: str = ""
    ) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertNotIn("Traceback", result.stderr)
        if message:
            self.assertIn(message, result.stderr)

    def test_provider_and_provider_free_self_host_use_identical_trust(self) -> None:
        for evidence in (provider_evidence(), self_host_evidence()):
            with self.subTest(kind=evidence["subject"]["kind"]):
                self.validator.validate(evidence)
                result = self.run_validator(evidence)
                self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("provider_product", self_host_evidence()["subject"])

    def test_closed_provider_neutral_vocabularies(self) -> None:
        for profile in ("S", "L", "XL", "compute-dedicated-4"):
            evidence = provider_evidence()
            evidence["capability"]["capacity_profile"] = profile
            self.assert_schema_rejects(evidence)
        for field, value in (
            ("compute_isolation", "burstable"),
            ("cpu_architecture", "riscv64"),
            ("storage_capability", "fast-disk"),
            ("topology", "large"),
        ):
            evidence = provider_evidence()
            evidence["capability"][field] = value
            self.assert_schema_rejects(evidence)

    def test_capability_and_effective_observations_must_agree(self) -> None:
        evidence = provider_evidence()
        evidence["observations"]["compute_isolation"] = {
            "classification": "shared",
            "basis": "shared-scheduler",
        }
        self.assert_not_qualified(self.run_validator(evidence), "does not match")
        evidence = provider_evidence()
        evidence["observations"]["cpu"].update(
            architecture="arm64", instruction_set_level="arm64"
        )
        self.assert_not_qualified(self.run_validator(evidence), "does not match")

    def test_trusted_identity_probe_and_source_bindings(self) -> None:
        for kwargs in (
            {"expected_target_sha": "c" * 40},
            {"expected_control_sha": "c" * 40},
            {"expected_target_identity": "c" * 64},
        ):
            self.assert_not_qualified(self.run_validator(**kwargs), "trusted expected")
        for field, message in (
            ("workload_probe_revision_sha256", "workload probe"),
            ("storage_probe_revision_sha256", "storage probe"),
        ):
            evidence = provider_evidence()
            evidence["qualification"][field] = "c" * 64
            self.assert_not_qualified(self.run_validator(evidence), message)
        evidence = provider_evidence()
        source = source_evidence(evidence)
        source_payload = json.dumps(source, sort_keys=True).encode()
        evidence["qualification"]["source_evidence_sha256"] = "c" * 64
        self.assert_not_qualified(
            self.run_validator(
                evidence,
                evidence_payload=json.dumps(evidence).encode(),
                source_payload=source_payload,
            ),
            "source evidence digest",
        )
        workload_revision, storage_revision = probe_revisions()
        self.assertEqual(len({SHA_A, SHA_B, workload_revision, storage_revision}), 4)

    def test_target_authored_pass_and_source_mutation_cannot_qualify(self) -> None:
        self.assert_not_qualified(self.run_validator(include_trusted_inputs=False), "required")
        evidence = provider_evidence()
        source = source_evidence(evidence)
        source["observations"]["workload"]["peak_cpu_millicores"] = 1
        self.assert_not_qualified(self.run_validator(evidence, source=source), "source evidence")
        evidence = provider_evidence()
        source = source_evidence(evidence)
        evidence["qualification"]["observed_at"] = "2026-08-02T00:00:00Z"
        self.assert_not_qualified(
            self.run_validator(evidence, source=source), "source observed_at"
        )

    def test_shared_cpu_requires_delivered_reservation_and_deadlines(self) -> None:
        evidence = provider_evidence()
        evidence["capability"]["compute_isolation"] = "shared"
        evidence["observations"]["compute_isolation"] = {
            "classification": "shared",
            "basis": "shared-scheduler",
        }
        source = source_evidence(evidence)
        source["collection"]["workload"]["cpu_reservation_delivered_millicores"] = 1199
        self.assert_not_qualified(self.run_validator(evidence, source=source), "CPU reservation")
        source = source_evidence(evidence)
        source["collection"]["workload"]["controller_observed_deadline_misses"] = 1
        self.assert_not_qualified(self.run_validator(evidence, source=source), "deadline")
        source = source_evidence(evidence)
        source["collection"]["workload"]["maximum_iteration_duration_seconds"] = 631
        self.assert_not_qualified(
            self.run_validator(evidence, source=source), "reviewed duration"
        )

    def test_pathological_storage_cannot_pass_reviewed_probe(self) -> None:
        evidence = provider_evidence()
        evidence["observations"]["storage"]["performance"].update(
            random_read_iops=1,
            random_write_iops=1,
            sequential_read_bytes_per_second=1,
            sequential_write_bytes_per_second=1,
            fsync_p95_microseconds=86_400_000_000,
        )
        self.assert_not_qualified(self.run_validator(evidence), "storage probe")

    def test_cpu_consistency_and_exact_headroom_boundaries(self) -> None:
        evidence = provider_evidence()
        evidence["observations"]["resources"]["usable_cpu_millicores"] = 8000
        self.assert_not_qualified(self.run_validator(evidence), "logical CPUs")
        exact = provider_evidence()
        exact["observations"]["workload"].update(
            peak_cpu_millicores=2800, peak_memory_bytes=6012954214
        )
        source = source_evidence(exact)
        source["collection"]["workload"]["memory_reservation_bytes"] = 2576980378
        self.assertEqual(self.run_validator(exact, source=source).returncode, 0)
        for field, value in (
            ("peak_cpu_millicores", 2801),
            ("peak_memory_bytes", 6012954215),
        ):
            evidence = provider_evidence()
            evidence["observations"]["workload"][field] = value
            self.assert_not_qualified(self.run_validator(evidence), "operational headroom")

    def test_storage_inode_and_profile_floors_fail_closed(self) -> None:
        for field, value, message in (
            ("free_storage_bytes", 107374182401, "free storage exceeds"),
            ("free_inodes", 1000001, "free inodes exceeds"),
            ("free_storage_bytes", 21474836479, "schema validation"),
            ("free_inodes", 199999, "schema validation"),
        ):
            evidence = provider_evidence()
            evidence["observations"]["resources"][field] = value
            self.assert_not_qualified(self.run_validator(evidence), message)
        evidence = provider_evidence()
        evidence["observations"]["resources"].update(
            total_storage_bytes=200000000000, free_storage_bytes=39999999999
        )
        self.assert_not_qualified(self.run_validator(evidence), "storage operational")
        evidence = provider_evidence()
        evidence["observations"]["resources"].update(
            total_inodes=2000000, free_inodes=399999
        )
        self.assert_not_qualified(self.run_validator(evidence), "inode operational")

        for field, value in (
            ("usable_cpu_millicores", 3999),
            ("online_logical_cpus", 3),
            ("usable_memory_bytes", 8589934591),
            ("total_storage_bytes", 107374182399),
            ("total_inodes", 999999),
        ):
            evidence = provider_evidence()
            evidence["observations"]["resources"][field] = value
            self.assert_not_qualified(self.run_validator(evidence), "schema validation")

        for result_name in ("FAIL", "UNAVAILABLE", "UNKNOWN"):
            evidence = provider_evidence()
            source = source_evidence(evidence)
            evidence.pop("observations")
            evidence["qualification"]["result"] = result_name
            self.assert_not_qualified(
                self.run_validator(evidence, source=source), "not PASS"
            )

    def test_freshness_future_cleanup_and_catalog_decision_time(self) -> None:
        future = provider_evidence()
        future["qualification"]["observed_at"] = "2026-08-16T00:00:00Z"
        invalid = provider_evidence()
        invalid["qualification"]["observed_at"] = "2026-07-01T00:00:00Z"
        invalid["qualification"]["valid_until"] = "2026-08-16T00:00:00Z"
        cases = [
            (future, EVALUATION_TIME, "future"),
            (provider_evidence(), "2026-09-01T00:00:00Z", "stale"),
            (invalid, EVALUATION_TIME, "freshness window"),
        ]
        for status in ("incomplete", "unknown"):
            evidence = provider_evidence()
            evidence["qualification"]["cleanup"]["status"] = status
            cases.append((evidence, EVALUATION_TIME, "cleanup"))
        for evidence, evaluation, message in cases:
            self.assert_not_qualified(
                self.run_validator(evidence, evaluation_time=evaluation), message
            )
        current = provider_evidence()
        current["subject"]["provider_product"]["catalog_observed_at"] = "2026-07-16T00:00:00Z"
        self.assertEqual(self.run_validator(current).returncode, 0)
        stale = provider_evidence()
        stale["subject"]["provider_product"]["catalog_observed_at"] = "2026-07-15T23:59:59Z"
        self.assert_not_qualified(self.run_validator(stale), "catalog evidence is stale")

    def test_strict_bounded_json_utf8_and_hashes(self) -> None:
        evidence = provider_evidence()
        source_payload = json.dumps(source_evidence(evidence), sort_keys=True).encode()
        duplicate = json.dumps(evidence).replace(
            '"result": "PASS"', '"result": "FAIL", "result": "PASS"'
        ).encode()
        for evidence_payload, message in (
            (duplicate, "duplicate object key"),
            (b"\xff", "UTF-8"),
            (b"{", "malformed JSON"),
            (b" " * (MAX_EVIDENCE_BYTES + 1), "too large"),
        ):
            self.assert_not_qualified(
                self.run_validator(
                    evidence,
                    evidence_payload=evidence_payload,
                    source_payload=source_payload,
                ),
                message,
            )
        for source_payload, message in (
            (b"\xff", "source evidence is not strict UTF-8"),
            (b"{", "source evidence contains malformed JSON"),
            (b" " * (MAX_EVIDENCE_BYTES + 1), "source evidence is too large"),
            (
                source_payload.replace(
                    b'{"authority":', b'{"schema_version":0,"authority":', 1
                ),
                "duplicate object key",
            ),
        ):
            self.assert_not_qualified(
                self.run_validator(evidence, source_payload=source_payload), message
            )
        for field in ("target_sha", "trusted_control_sha"):
            evidence = provider_evidence()
            evidence["qualification"][field] += "\n"
            self.assert_not_qualified(self.run_validator(evidence), "schema validation")
        self.assert_not_qualified(
            self.run_validator(expected_target_sha=SHA_A + "\n"),
            "trusted expected target SHA is malformed",
        )
        evidence = provider_evidence()
        evidence["subject"]["target_identity_sha256"] += "x"
        self.assert_not_qualified(
            self.run_validator(evidence, expected_target_identity=HASH_A),
            "schema validation",
        )
        evidence = provider_evidence()
        evidence["subject"]["provider_product"]["provider"] = "example-cloud\n"
        self.assert_not_qualified(self.run_validator(evidence), "schema validation")

    def test_rfc3339_and_malformed_schema_are_bounded(self) -> None:
        evidence = provider_evidence()
        evidence["qualification"]["observed_at"] = "2026-08-01 00:00:00Z"
        self.assert_not_qualified(self.run_validator(evidence), "RFC 3339")
        specification = importlib.util.spec_from_file_location("capacity_validator", VALIDATOR)
        assert specification is not None and specification.loader is not None
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as temporary_directory:
            malformed = Path(temporary_directory) / "schema.json"
            malformed.write_text('{"type": 7}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "schema"):
                module.load_schema(malformed)
            malformed_probe = Path(temporary_directory) / "probe.json"
            malformed_probe.write_text('{"schema_version": 1}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "probe contract"):
                module.load_probe_contract(malformed_probe)


if __name__ == "__main__":
    unittest.main()
