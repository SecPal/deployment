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
ASSEMBLER_PATH = ROOT / "scripts" / "ci-cloud" / "assemble-evidence.py"
WORKLOAD_TEST_PATH = ROOT / "tests" / "ci-cloud-workload-evidence.py"


def load_validator():
    spec = importlib.util.spec_from_file_location("ci_cloud_evidence", VALIDATOR_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load evidence validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_assembler():
    spec = importlib.util.spec_from_file_location("ci_cloud_assembler", ASSEMBLER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load evidence assembler")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def valid_workload() -> dict[str, object]:
    spec = importlib.util.spec_from_file_location(
        "ci_cloud_workload_test_fixtures", WORKLOAD_TEST_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load workload evidence fixture")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.valid_observations()


def valid_document() -> dict[str, object]:
    return load_assembler().assemble(
        {"repository": "SecPal/deployment", "run_id": "12345",
         "run_attempt": "1", "target_sha": "a" * 40},
        valid_workload()["baseline"], valid_workload()["live"],
        valid_workload()["post_cleanup"],
        {mode: {"mode": mode, "status": 0, "stage": "complete",
                "failure_reason": None, "command_status": None}
         for mode in ("live", "cleanup")},
        {name: 0 for name in ("workload_prepare_start", "workload_cleanup",
                             "trusted_quadlet_normalize_live", "trusted_quadlet_normalize_cleanup")},
        {name: 0 for name in ("baseline", "live", "post_cleanup")},
    )


class EvidenceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.validator = load_validator()

    def test_complete_current_workload_evidence_is_accepted(self) -> None:
        document = valid_document()
        schema = json.loads(
            (ROOT / "schemas" / "ci-cloud-evidence.schema.json").read_text(
                encoding="utf-8"
            )
        )
        jsonschema.Draft202012Validator(schema).validate(document)
        self.assertEqual(document, self.validator.validate_document(document))

    def test_canonical_systemd_escapes_cross_the_evidence_boundary(self) -> None:
        document = valid_document()
        escaped_unit = "dev-disk-by\\x2ddiskseq-1.device"
        escaped_job = "secpal\\x2dmaintenance.service"
        for phase in ("baseline", "live", "post_cleanup"):
            user_work = document["workload"][phase]["user_work"]
            user_work["active_units"].append(escaped_unit)
            user_work["jobs"].append(escaped_job)

        schema = json.loads(
            (ROOT / "schemas" / "ci-cloud-evidence.schema.json").read_text(
                encoding="utf-8"
            )
        )
        jsonschema.Draft202012Validator(schema).validate(document)
        self.assertEqual(document, self.validator.validate_document(document))

        for malformed in (
            "dev-disk-by\\xZZescape.device",
            "dev-disk-by\\x2Descape.device",
            "dev-disk-by\\escape.device",
            "a" * 125 + "\\x2d",
            "dev-disk-by-diskseq-1.device\n",
        ):
            with self.subTest(malformed=malformed):
                invalid = valid_document()
                for phase in ("baseline", "live", "post_cleanup"):
                    invalid["workload"][phase]["user_work"][
                        "active_units"
                    ].append(malformed)
                with self.assertRaises(jsonschema.ValidationError):
                    jsonschema.Draft202012Validator(schema).validate(invalid)
                with self.assertRaisesRegex(ValueError, "declared schema"):
                    self.validator.validate_document(invalid)


    def test_schema_forbids_passed_workload_with_invalid_live_or_cleanup_state(self) -> None:
        schema = json.loads(
            (ROOT / "schemas" / "ci-cloud-evidence.schema.json").read_text(
                encoding="utf-8"
            )
        )
        for mutate in (
            lambda document: document["workload"]["live"].__setitem__(
                "complete", False
            ),
            lambda document: document["workload"]["post_cleanup"].__setitem__(
                "containers", ["secpal-int-aaaaaaaaaaaa-api"]
            ),
            lambda document: document["workload"]["post_cleanup"][
                "control_resources"
            ].__setitem__("network_present", False),
        ):
            with self.subTest(mutate=mutate):
                document = valid_document()
                mutate(document)
                errors = list(
                    jsonschema.Draft202012Validator(schema).iter_errors(document)
                )
                self.assertTrue(errors)

    def test_target_controlled_status_cannot_replace_independent_workload_facts(self) -> None:
        document = valid_document()
        document["workload"] = {
            "protocol_version": 1,
            "instance": "aaaaaaaaaaaa",
            "target_status": "passed",
        }
        with self.assertRaisesRegex(ValueError, "workload|incomplete|declared schema"):
            self.validator.validate_document(document)

    def test_workload_evidence_cannot_claim_production_authority(self) -> None:
        for field, value in (
            ("claim_scope", "production-installation"),
            ("database_scope", "production-postgresql-container"),
        ):
            with self.subTest(field=field):
                document = valid_document()
                document["workload"][field] = value
                with self.assertRaisesRegex(
                    ValueError, "declared schema|integration-only authority"
                ):
                    self.validator.validate_document(document)

    def test_workload_instance_is_bound_to_the_exact_target_sha(self) -> None:
        document = valid_document()

        def replace_instance(value: object) -> object:
            if isinstance(value, str):
                return value.replace("aaaaaaaaaaaa", "bbbbbbbbbbbb")
            if isinstance(value, list):
                return [replace_instance(item) for item in value]
            if isinstance(value, dict):
                return {
                    key: replace_instance(item) for key, item in value.items()
                }
            return value

        document["workload"] = replace_instance(document["workload"])
        with self.assertRaisesRegex(ValueError, "workload instance"):
            self.validator.validate_document(document)

    def test_phase_failure_is_preserved_and_forces_workload_failure(self) -> None:
        document = valid_document()
        document["test"]["phase_exit_statuses"]["workload_prepare_start"] = 7
        document["test"]["result"] = "failed"
        document["test"]["failed_admission_invariants"] = [
            "TARGET_WORKLOAD_PREPARE_START"
        ]
        document["workload"]["result"] = "failed"
        document["workload"]["failed_admission_invariants"] = [
            "TARGET_WORKLOAD_PREPARE_START"
        ]
        self.assertEqual(document, self.validator.validate_document(document))

    def test_normalization_failure_is_closed_and_bound_to_phase_status(self) -> None:
        document = valid_document()
        document["test"]["phase_exit_statuses"][
            "trusted_quadlet_normalize_live"
        ] = 1
        document["test"]["normalization_diagnostics"]["live"] = {
            "mode": "live",
            "status": 1,
            "stage": "daemon-reload",
            "failure_reason": "command-exit",
            "command_status": 1,
        }
        invariant = "TRUSTED_QUADLET_NORMALIZE_LIVE"
        document["test"]["result"] = "failed"
        document["test"]["failed_admission_invariants"] = [invariant]
        document["workload"]["result"] = "failed"
        document["workload"]["failed_admission_invariants"] = [invariant]
        self.assertEqual(document, self.validator.validate_document(document))

    def test_current_schema_rejects_obsolete_normalization_stages(self) -> None:
        from tempfile import TemporaryDirectory

        for stage in (
            "manager-environment-admission",
            "post-manager-environment-read",
            "user-environment-generator-admission",
        ):
            with self.subTest(stage=stage):
                document = valid_document()
                document["test"]["phase_exit_statuses"][
                    "trusted_quadlet_normalize_cleanup"
                ] = 1
                document["test"]["normalization_diagnostics"]["cleanup"] = {
                    "mode": "cleanup",
                    "status": 1,
                    "stage": stage,
                    "failure_reason": "contract-rejected",
                    "command_status": None,
                }
                invariant = "TRUSTED_QUADLET_NORMALIZE_CLEANUP"
                document["test"]["result"] = "failed"
                document["test"]["failed_admission_invariants"] = [invariant]
                document["workload"]["result"] = "failed"
                document["workload"]["failed_admission_invariants"] = [invariant]
                with self.assertRaises(ValueError):
                    self.validator.validate_document(document)

                with TemporaryDirectory() as directory:
                    diagnostic = Path(directory) / "normalization.json"
                    diagnostic.write_text(
                        json.dumps(
                            document["test"]["normalization_diagnostics"][
                                "cleanup"
                            ]
                        ),
                        encoding="utf-8",
                    )
                    with self.assertRaises(ValueError):
                        load_assembler().read_normalization_diagnostic(
                            diagnostic, "cleanup", 1
                        )

    def test_normalization_stage_sets_match_current_schema(self) -> None:
        collector = self.validator.load_trusted_module(
            self.validator.WORKLOAD_COLLECTOR_PATH,
            "ci_cloud_normalization_stage_contract",
        )
        schema = json.loads(
            self.validator.SCHEMA_PATH.read_text(encoding="utf-8")
        )
        schema_stages = set(
            schema["$defs"]["normalizationDiagnostic"]["properties"]["stage"][
                "enum"
            ]
        )
        self.assertEqual(
            schema_stages - {"complete"},
            set(collector.NORMALIZATION_STAGES),
        )

    def test_normalization_diagnostic_rejects_open_or_inconsistent_values(self) -> None:
        mutations = (
            lambda document: document["test"]["normalization_diagnostics"][
                "live"
            ].__setitem__("mode", "cleanup"),
            lambda document: document["test"]["normalization_diagnostics"][
                "live"
            ].__setitem__("stage", "target-controlled-stage"),
            lambda document: document["test"]["normalization_diagnostics"][
                "live"
            ].__setitem__("failure_reason", "target-controlled-reason"),
            lambda document: document["test"]["normalization_diagnostics"][
                "live"
            ].__setitem__("failure_reason", ["command-exit"]),
            lambda document: document["test"]["normalization_diagnostics"][
                "live"
            ].__setitem__("status", True),
            lambda document: document["test"]["normalization_diagnostics"][
                "live"
            ].__setitem__("command_status", 7),
            lambda document: document["test"]["normalization_diagnostics"][
                "live"
            ].__setitem__("unknown", "field"),
            lambda document: document["test"]["normalization_diagnostics"].pop(
                "cleanup"
            ),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                document = valid_document()
                mutate(document)
                with self.assertRaisesRegex(
                    ValueError,
                    "normalization|unknown|incomplete|declared schema",
                ):
                    self.validator.validate_document(document)

    def test_summary_contains_normalization_diagnostics(self) -> None:
        document = self.validator.validate_document(valid_document())
        with self.subTest("summary"):
            from tempfile import TemporaryDirectory

            with TemporaryDirectory() as directory:
                summary = Path(directory) / "summary.md"
                self.validator.write_summary(document, summary)
                contents = summary.read_text(encoding="utf-8")
        self.assertIn("Trusted Quadlet normalization diagnostics", contents)
        self.assertIn('"stage":"complete"', contents)


    def test_cleanup_collection_failure_cannot_report_conformance(self) -> None:
        document = valid_document()
        document["test"]["collection_exit_statuses"]["post_cleanup"] = 124
        with self.assertRaisesRegex(ValueError, "result|admission failures"):
            self.validator.validate_document(document)

    def test_unknown_workload_field_is_rejected(self) -> None:
        document = valid_document()
        document["workload"]["live"]["target_claimed_ready"] = True
        with self.assertRaisesRegex(ValueError, "unknown|declared schema"):
            self.validator.validate_document(document)

    def test_schema_rejects_missing_or_state_contradictory_user_namespace_facts(self) -> None:
        schema = json.loads(
            (ROOT / "schemas" / "ci-cloud-evidence.schema.json").read_text(
                encoding="utf-8"
            )
        )
        schema_validator = jsonschema.Draft202012Validator(schema)
        mutations = (
            lambda namespace: namespace.pop("process_identity"),
            lambda namespace: namespace.__setitem__("uid_map", []),
            lambda namespace: namespace.__setitem__("podman_uid_map", []),
            lambda namespace: namespace["uid_map"][0].__setitem__(
                "target_claimed_safe", True
            ),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                document = valid_document()
                mutate(
                    document["workload"]["live"]["containers"][4][
                        "user_namespace"
                    ]
                )
                with self.assertRaises(jsonschema.ValidationError):
                    schema_validator.validate(document)
                with self.assertRaises(ValueError):
                    self.validator.validate_document(document)

        document = valid_document()
        exited = document["workload"]["live"]["containers"][2]
        exited["user_namespace"]["process_identity"] = "user:[4026540999]"
        with self.assertRaises(jsonschema.ValidationError):
            schema_validator.validate(document)
        with self.assertRaises(ValueError):
            self.validator.validate_document(document)

    def test_validator_recomputes_namespace_identity_separation(self) -> None:
        document = valid_document()
        namespace = document["workload"]["live"]["containers"][4][
            "user_namespace"
        ]
        namespace["process_identity"] = namespace["collector_identity"]
        with self.assertRaisesRegex(ValueError, "workload admission failures"):
            self.validator.validate_document(document)

    def test_validator_recomputes_configured_mapping_consistency(self) -> None:
        document = valid_document()
        namespace = document["workload"]["live"]["containers"][4][
            "user_namespace"
        ]
        inconsistent = [
            {"container_id": 0, "host_id": 3_000_000_000, "size": 65_536}
        ]
        namespace["configured_uid_map"] = copy.deepcopy(inconsistent)
        namespace["configured_gid_map"] = copy.deepcopy(inconsistent)
        with self.assertRaisesRegex(ValueError, "workload admission failures"):
            self.validator.validate_document(document)

    def test_service_environment_evidence_cannot_contain_values(self) -> None:
        document = valid_document()
        document["workload"]["live"]["generated_services"][0]["environment"] = [
            "DB_PASSWORD=synthetic-placeholder"
        ]
        with self.assertRaises(ValueError):
            self.validator.validate_document(document)

    def test_unprefixed_resource_cannot_survive_validator_recomputation(self) -> None:
        document = valid_document()
        document["workload"]["live"]["all_containers"].append(
            "target-created-rogue"
        )
        with self.assertRaisesRegex(ValueError, "workload admission failures"):
            self.validator.validate_document(document)


    def test_incomplete_evidence_is_rejected(self) -> None:
        document = valid_document()
        del document["workload"]
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self.validator.validate_document(document)

    def test_credential_like_field_is_rejected(self) -> None:
        document = valid_document()
        document["workload"]["access_token"] = "synthetic"
        with self.assertRaisesRegex(ValueError, "credential-like field"):
            self.validator.validate_document(document)

    def test_credential_like_value_is_rejected(self) -> None:
        document = valid_document()
        document["workload"]["live"]["oci_runtime"] = "Authorization: Bearer syntheticvalue"
        with self.assertRaisesRegex(ValueError, "credential-like value"):
            self.validator.validate_document(document)

    def test_result_cannot_hide_failed_admission(self) -> None:
        document = valid_document()
        document["test"]["failed_admission_invariants"] = ["WORKLOAD_ROOTLESS"]
        with self.assertRaisesRegex(ValueError, "contradicts"):
            self.validator.validate_document(document)


    def test_unknown_nested_field_is_rejected(self) -> None:
        document = copy.deepcopy(valid_document())
        document["workload"]["live"]["cloud_identity"] = "none"
        with self.assertRaisesRegex(ValueError, "unknown"):
            self.validator.validate_document(document)

    def test_declared_schema_rejects_invalid_run_identity(self) -> None:
        document = valid_document()
        document["workflow"]["run_id"] = "0"
        with self.assertRaisesRegex(ValueError, "declared schema"):
            self.validator.validate_document(document)

    def test_declared_schema_rejects_duplicate_array_values(self) -> None:
        document = valid_document()
        document["workload"]["failed_admission_invariants"] = ["WORKLOAD_ROOTLESS"] * 2
        with self.assertRaisesRegex(ValueError, "declared schema|admission failures"):
            self.validator.validate_document(document)


if __name__ == "__main__":
    unittest.main()
