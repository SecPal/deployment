#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Contract tests for exact closed Rocky failure replay witnesses."""

from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
CLASSIFIER = ROOT / "scripts/ci-cloud/classify-rocky-target-qualification-failure.py"
VERIFIER = ROOT / "scripts/ci-cloud/verify-rocky-target-qualification-replay.py"
SCHEMA = ROOT / "schemas/rocky-cloud-target-qualification-failure.schema.json"
RUNNER = ROOT / "scripts/ci-cloud/run-rocky-target-qualification.sh"
HARNESS = ROOT / "scripts/qualify-production-host.sh"
HISTORICAL_NATIVE_REPLAY = (
    ROOT / "tests/fixtures/rocky-target-qualification-replay-34767598359.json"
)
LEGACY_CONTROL = "f7a298d19bf4a0957d6b3db383a1f1bb2eeb309e"
CURRENT_CONTROL = "c" * 40
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def load(path: Path, name: str):
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise RuntimeError(f"cannot load {path.name}")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


class RockyReplayWitnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.classifier = load(CLASSIFIER, "rocky_failure_classifier")
        cls.verifier = load(VERIFIER, "rocky_replay_verifier")
        cls.control = load(ROOT / "scripts/ci-cloud/rocky-control.py", "rocky_control")
        cls.start_producer = load(
            ROOT / "scripts/ci-cloud/rocky-start-runuser.py", "rocky_start_producer"
        )
        cls.active_producer = load(
            ROOT / "scripts/ci-cloud/rocky-active-runuser.py", "rocky_active_producer"
        )
        cls.primary_producer = load(
            ROOT / "scripts/ci-cloud/rocky-primary-runuser.py", "rocky_primary_producer"
        )
        cls.schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        cls.schema_validator = Draft202012Validator(cls.schema)

    @staticmethod
    def canonical_json(document: object) -> bytes:
        return (
            json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("ascii")

    def sources(self, **overrides: tuple[bool, bytes]) -> dict[str, tuple[bool, bytes]]:
        sources = {
            name: (False, b"") for name in self.classifier.REPLAY_COMPONENT_ORDER
        }
        sources["qualification_stdout"] = (True, b"")
        sources["target_qualification_trace"] = (True, b"")
        sources.update(overrides)
        return sources

    def witness(
        self,
        *,
        sources: dict[str, tuple[bool, bytes]] | None = None,
        exit_status: int = 3,
        representation_invalid: bool = True,
    ) -> dict[str, object]:
        return self.classifier.build_replay_witness(
            self.sources() if sources is None else sources,
            exit_status=exit_status,
            representation_invalid=representation_invalid,
            bindings={
                "target_sha": self.classifier.EXPECTED_TARGET_SHA,
                "trusted_control_sha": CURRENT_CONTROL,
                "qualification_run_id": "12345",
                "qualification_run_attempt": "1",
            },
        )

    def document(self, witness: dict[str, object]) -> dict[str, object]:
        components = witness["components"]
        assert isinstance(components, dict)
        replayed = []
        total = 0
        for name in self.classifier.REPLAY_COMPONENT_ORDER:
            component = components[name]
            assert isinstance(component, dict)
            encoded = component["content_base64"]
            payload = b"" if encoded is None else base64.b64decode(encoded)
            replayed.append(payload)
            total += len(payload)
        aggregate = b"\0".join(replayed)
        return {
            "schema_version": 2,
            "phase": "target-qualification",
            "target_sha": self.classifier.EXPECTED_TARGET_SHA,
            "trusted_control_sha": CURRENT_CONTROL,
            "qualification_run_id": "12345",
            "qualification_run_attempt": "1",
            "harness_sha256": self.classifier.EXPECTED_HARNESS_SHA256,
            "operation": "qualification-harness",
            "reason": "representation-invalid",
            "exit_status": witness["exit_status"],
            "diagnostic_input_sha256": hashlib.sha256(aggregate).hexdigest(),
            "diagnostic_input_bytes": total,
            "replay_witness": witness,
        }

    def assert_rejected(self, document: dict[str, object]) -> None:
        with self.assertRaises(ValueError):
            self.verifier.verify_replay_witness(document, self.classifier)

    @classmethod
    def success_observations(cls) -> dict[str, dict[str, object]]:
        def protocol(*records: dict[str, object]) -> bytes:
            return b"".join(cls.canonical_json(record) for record in records)

        return {
            "start_observation": cls.start_producer.parse_protocol(
                protocol(
                    {"kind": "env", "schema_version": 1, "stage": "env-entered"},
                    {
                        "kind": "systemctl",
                        "schema_version": 1,
                        "stage": "success",
                        "systemctl_client_status": 0,
                        "service_result": None,
                        "exec_main_code": None,
                        "exec_main_status": None,
                    },
                ),
                0,
            ),
            "active_observation": cls.active_producer.parse_protocol(
                protocol(
                    {"kind": "env", "schema_version": 1, "stage": "env-entered"},
                    {
                        "kind": "systemctl",
                        "schema_version": 1,
                        "stage": "success",
                        "systemctl_client_status": 0,
                    },
                ),
                0,
            ),
            "primary_observation": cls.primary_producer.parse_protocol(
                protocol(
                    {
                        "kind": "runtime",
                        "schema_version": 1,
                        "stage": "runtime-entered",
                    },
                    {
                        "kind": "runtime",
                        "schema_version": 1,
                        "stage": "success",
                        "podman_status": 0,
                    },
                ),
                0,
            ),
        }

    def test_historical_digest_and_count_cannot_reconstruct_or_authorize_guess(self) -> None:
        historical = {
            "schema_version": 1,
            "phase": "target-qualification",
            "target_sha": self.classifier.HISTORICAL_PRE_269_TARGET_SHA,
            "trusted_control_sha": "a4a4ff415f01421af4f3ddfe0a3542815df42414",
            "qualification_run_id": "34876534431",
            "qualification_run_attempt": "1",
            "harness_sha256": self.classifier.HISTORICAL_PRE_269_HARNESS_SHA256,
            "operation": "qualify-avc-correlation",
            "reason": "command-failed",
            "exit_status": 3,
            "diagnostic_input_sha256": (
                "d10b32d994b4056611561d93638db15a768122053e25f5d0bae32af45ee8f355"
            ),
            "diagnostic_input_bytes": 85,
        }
        historical_bytes = self.classifier.canonical_json_bytes(historical)
        self.assertEqual(
            "7e19cdf446ed44dde82a45cc6b73fe96e3717f84f7f027788f0d847c124af492",
            hashlib.sha256(historical_bytes).hexdigest(),
        )
        self.assertEqual([], list(self.schema_validator.iter_errors(historical)))
        self.assertNotIn("avc_correlation_diagnostic", historical)
        self.assert_rejected(historical)
        guessed = copy.deepcopy(historical)
        guessed["replay_witness"] = {
            "schema_version": 1,
            "available": False,
            "representation_invalid": True,
            "exit_status": 3,
            "component_order": list(self.classifier.REPLAY_COMPONENT_ORDER),
            "separator": "NUL",
            "components": {
                name: {
                    "present": name in {
                        "qualification_stdout",
                        "target_qualification_trace",
                    },
                    "byte_count": 85 if name == "qualification_stdout" else 0,
                    "sha256": (
                        historical["diagnostic_input_sha256"]
                        if name == "qualification_stdout"
                        else EMPTY_SHA256
                    ),
                    "replayability": "unavailable",
                    "content_base64": None,
                }
                for name in self.classifier.REPLAY_COMPONENT_ORDER
            },
        }
        self.assert_rejected(guessed)

    def test_consumed_259_unavailable_witness_remains_immutable_history(self) -> None:
        metadata = {
            "qualification_stdout": (
                True,
                0,
                EMPTY_SHA256,
                "exact",
                "",
            ),
            "target_qualification_trace": (
                True,
                85,
                "046e1ab89605315c3522ee06939db5b41bb6a0920a231df1d1921df9cab22ef2",
                "unavailable",
                None,
            ),
            "trusted_marker": (False, 0, EMPTY_SHA256, "exact", None),
            "reload_adjacency": (False, 0, EMPTY_SHA256, "exact", None),
            "start_observation": (
                True,
                154,
                "34a6ae288bbc737caaac9a85b267effb44cae97568a0c6c2c46aceb4df5c3ec1",
                "unavailable",
                None,
            ),
            "active_observation": (
                True,
                86,
                "7d080f4a0b4aded43a6b947066b5cbe6c026958ef8920f3265687c2ddcddcdb2",
                "unavailable",
                None,
            ),
            "primary_observation": (
                True,
                76,
                "b9cf904d71ed3821a6a0dd8571a1b1e91d3b495ad29c0903047ccd8bc6d7190a",
                "unavailable",
                None,
            ),
        }
        witness = {
            "schema_version": 1,
            "available": False,
            "representation_invalid": True,
            "exit_status": 3,
            "component_order": list(self.classifier.REPLAY_COMPONENT_ORDER),
            "separator": "NUL",
            "components": {
                name: {
                    "present": values[0],
                    "byte_count": values[1],
                    "sha256": values[2],
                    "replayability": values[3],
                    "content_base64": values[4],
                }
                for name, values in metadata.items()
            },
        }
        document = {
            "schema_version": 2,
            "phase": "target-qualification",
            "target_sha": self.classifier.EXPECTED_TARGET_SHA,
            "trusted_control_sha": "fbe3ea0b732e46f70202db963e9154e431409e01",
            "qualification_run_id": "34760025768",
            "qualification_run_attempt": "1",
            "harness_sha256": self.classifier.EXPECTED_HARNESS_SHA256,
            "operation": "qualification-harness",
            "reason": "representation-invalid",
            "exit_status": 3,
            "diagnostic_input_sha256": (
                "e6a7b09efc09d9d2fd312a39dc9da77024cc4dd09389bda72ad8422de935e855"
            ),
            "diagnostic_input_bytes": 401,
            "replay_witness": witness,
        }
        self.assertEqual([], list(self.schema_validator.iter_errors(document)))
        self.assertIsNone(
            self.verifier.validate_replay_witness(document, self.classifier)
        )
        self.assert_rejected(document)

    def test_historical_native_witness_has_valid_nested_trace_semantics(self) -> None:
        fixture_bytes = HISTORICAL_NATIVE_REPLAY.read_bytes()
        self.assertEqual(
            "f67bb1f4e431dd08d917895d4976cf724872adfd717240b4041231af34ef4042",
            hashlib.sha256(fixture_bytes).hexdigest(),
        )
        document = json.loads(fixture_bytes)
        self.assertEqual(
            self.classifier.HISTORICAL_PRE_265_TARGET_SHA, document["target_sha"]
        )
        self.assertEqual(
            self.classifier.HISTORICAL_PRE_265_HARNESS_SHA256,
            document["harness_sha256"],
        )
        self.assertEqual([], list(self.schema_validator.iter_errors(document)))
        self.assertEqual(401, document["diagnostic_input_bytes"])
        self.assertEqual(
            "e6a7b09efc09d9d2fd312a39dc9da77024cc4dd09389bda72ad8422de935e855",
            document["diagnostic_input_sha256"],
        )

        witness = document["replay_witness"]
        self.assertTrue(witness["available"])
        self.assertFalse(witness["representation_invalid"])
        self.assertEqual(
            list(self.classifier.REPLAY_COMPONENT_ORDER), witness["component_order"]
        )
        decoded = {}
        component_bytes = 0
        for name in self.classifier.REPLAY_COMPONENT_ORDER:
            component = witness["components"][name]
            self.assertEqual("exact", component["replayability"])
            encoded = component["content_base64"]
            payload = b"" if encoded is None else base64.b64decode(encoded)
            decoded[name] = payload
            component_bytes += len(payload)
            self.assertEqual(component["byte_count"], len(payload))
            self.assertEqual(component["sha256"], hashlib.sha256(payload).hexdigest())
            if component["present"]:
                self.verifier.validate_component_payload(
                    name,
                    payload,
                    document,
                    self.classifier,
                    decoded["qualification_stdout"],
                )

        replayed = b"\0".join(
            decoded[name] for name in self.classifier.REPLAY_COMPONENT_ORDER
        )
        self.assertEqual(401, component_bytes)
        self.assertEqual(407, len(replayed))
        self.assertEqual(
            document["diagnostic_input_sha256"], hashlib.sha256(replayed).hexdigest()
        )
        traced_operations, trace_valid = self.classifier.trace_operations(
            decoded["target_qualification_trace"].decode("ascii"),
            document["exit_status"],
            self.classifier.replay_line_rules(
                document["target_sha"], document["harness_sha256"]
            ),
        )
        self.assertTrue(trace_valid)
        self.assertEqual({"qualify-avc-correlation"}, traced_operations)
        self.assertEqual(
            ("qualify-avc-correlation", "command-failed"),
            self.classifier.classify_failure(
                decoded["qualification_stdout"],
                decoded["target_qualification_trace"],
                document["exit_status"],
                target_bound=True,
                trusted_marker=None,
                representation_invalid=witness["representation_invalid"],
                line_rules=self.classifier.replay_line_rules(
                    document["target_sha"], document["harness_sha256"]
                ),
            ),
        )
        self.assert_rejected(document)
        with self.assertRaises(self.control.ControlError):
            self.control.validate_target_qualification_failure(
                HISTORICAL_NATIVE_REPLAY,
                document["target_sha"],
                document["trusted_control_sha"],
                document["qualification_run_id"],
                document["qualification_run_attempt"],
            )

    def test_historical_native_witness_cannot_acquire_current_classifier_authority(
        self,
    ) -> None:
        source = json.loads(HISTORICAL_NATIVE_REPLAY.read_bytes())
        witness = source["replay_witness"]
        components = witness["components"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = {}
            for name in self.classifier.REPLAY_COMPONENT_ORDER:
                component = components[name]
                if not component["present"]:
                    continue
                path = root / name
                path.write_bytes(base64.b64decode(component["content_base64"]))
                paths[name] = path
            output = root / "classified.json"
            completed = subprocess.run(
                [
                    CLASSIFIER,
                    "--target-sha",
                    source["target_sha"],
                    "--control-sha",
                    source["trusted_control_sha"],
                    "--run-id",
                    source["qualification_run_id"],
                    "--run-attempt",
                    source["qualification_run_attempt"],
                    "--harness",
                    HARNESS,
                    "--stdout",
                    paths["qualification_stdout"],
                    "--trace",
                    paths["target_qualification_trace"],
                    "--start-observation",
                    paths["start_observation"],
                    "--active-observation",
                    paths["active_observation"],
                    "--primary-observation",
                    paths["primary_observation"],
                    "--exit-status",
                    str(source["exit_status"]),
                    "--output",
                    output,
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            classified = json.loads(output.read_bytes())
            self.assertEqual(
                ("qualification-harness", "representation-invalid"),
                (classified["operation"], classified["reason"]),
            )
            self.assertEqual(1, classified["schema_version"])
            self.assertNotIn("replay_witness", classified)
            self.assertEqual(85, classified["diagnostic_input_bytes"])
            causative_replay = b"\0".join(
                (
                    paths["qualification_stdout"].read_bytes(),
                    paths["target_qualification_trace"].read_bytes(),
                    b"",
                    b"",
                    b"",
                    b"",
                    b"",
                )
            )
            self.assertEqual(
                hashlib.sha256(causative_replay).hexdigest(),
                classified["diagnostic_input_sha256"],
            )
            self.control.validate_target_qualification_failure(
                output,
                source["target_sha"],
                source["trusted_control_sha"],
                source["qualification_run_id"],
                source["qualification_run_attempt"],
            )

    def test_runner_deletes_every_ephemeral_classifier_source(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        for source in (
            '"$stdout"',
            '"$qualification_trace"',
            '"$qualification_marker"',
            '"$reload_adjacency"',
            '"$start_observation"',
            '"$active_observation"',
            '"$primary_observation"',
        ):
            self.assertRegex(runner, r"rm -f --(?s:.*?)" + re.escape(source))
        self.assertLess(
            runner.index("secpal-classify-rocky-target-failure"),
            runner.index('rm -f -- "$stdout"'),
        )

    def test_bounded_producer_trace_grammar_replays_exactly(self) -> None:
        traces = (
            b"SECPAL_TARGET_ERR_V2:3:667\n",
            (
                b"SECPAL_TARGET_ERR_V2:3:667,662\n"
                b"SECPAL_TARGET_ERR_V2:3:637,626,619\n"
            ),
            (
                b"SECPAL_TARGET_ERR_V2:3:667,662\n"
                b"SECPAL_TARGET_ERR_V2:1:637,626,619\n"
            ),
            b"SECPAL_TARGET_ERR_V2:255:1,2,3,4,5,6,7,9999\n",
        )
        for trace in traces:
            with self.subTest(trace=trace):
                witness = self.witness(
                    sources=self.sources(target_qualification_trace=(True, trace))
                )
                document = self.document(witness)
                self.assertTrue(witness["available"])
                replayed = self.verifier.verify_replay_witness(
                    document, self.classifier
                )
                self.assertEqual(b"\0" + trace + b"\0\0\0\0\0", replayed)
                self.assertEqual(
                    document["diagnostic_input_sha256"],
                    hashlib.sha256(replayed).hexdigest(),
                )

    def test_retained_273_pair_replays_but_mixed_authority_fails_closed(self) -> None:
        witness = self.witness()
        historical = self.document(witness)
        historical["target_sha"] = self.classifier.HISTORICAL_273_TARGET_SHA
        self.verifier.verify_replay_witness(historical, self.classifier)

        mixed = copy.deepcopy(historical)
        mixed["harness_sha256"] = self.classifier.HISTORICAL_PRE_269_HARNESS_SHA256
        self.assert_rejected(mixed)

    def test_conflicting_statuses_replay_as_semantic_representation_invalid(self) -> None:
        trace = (
            b"SECPAL_TARGET_ERR_V2:3:667,662\n"
            b"SECPAL_TARGET_ERR_V2:1:637,626,619\n"
        )
        classification = self.classifier.classify_failure(
            b"",
            trace,
            3,
            target_bound=True,
            representation_invalid=False,
        )
        self.assertEqual(
            ("qualification-harness", "representation-invalid"), classification
        )
        witness = self.witness(
            sources=self.sources(target_qualification_trace=(True, trace)),
            representation_invalid=False,
        )
        self.assertTrue(witness["available"])
        document = self.document(witness)
        self.verifier.verify_replay_witness(document, self.classifier)
        after_replay = self.classifier.classify_failure(
            b"",
            trace,
            3,
            target_bound=True,
            representation_invalid=False,
        )
        self.assertEqual(classification, after_replay)

    def test_stdout_is_replayable_only_when_complete_bytes_are_finite(self) -> None:
        exact = b"ERROR: SELinux is not Enforcing.\n"
        witness = self.witness(
            sources=self.sources(qualification_stdout=(True, exact))
        )
        self.assertTrue(witness["available"])
        self.verifier.verify_replay_witness(self.document(witness), self.classifier)
        for arbitrary in (
            exact + b"secret suffix\n",
            b"token=arbitrary\n",
            b"ERROR: SELinux is not Enforcing.",
        ):
            with self.subTest(arbitrary=arbitrary):
                rejected = self.witness(
                    sources=self.sources(qualification_stdout=(True, arbitrary))
                )
                self.assertFalse(rejected["available"])
                self.assertIsNone(
                    rejected["components"]["qualification_stdout"]["content_base64"]
                )

    def test_malformed_extra_non_ascii_and_oversized_trace_are_unavailable(self) -> None:
        for trace in (
            b"SECPAL_TARGET_ERR_V2:3:667",
            b"SECPAL_TARGET_ERR_V2:3:667\r\n",
            b"SECPAL_TARGET_ERR_V1:3:667\n",
            b"SECPAL_TARGET_ERR_V2:3:not-a-number\n",
            b"SECPAL_TARGET_ERR_V2:0:667\n",
            b"SECPAL_TARGET_ERR_V2:256:667\n",
            b"SECPAL_TARGET_ERR_V2:3:0\n",
            b"SECPAL_TARGET_ERR_V2:3:10000\n",
            b"SECPAL_TARGET_ERR_V2:3:" + b",".join([b"667"] * 9) + b"\n",
            b"SECPAL_TARGET_ERR_V2:3:667\nextra text\n",
            b"SECPAL_TARGET_ERR_V2:3:667\n\xff",
            b"SECPAL_TARGET_ERR_V2:3:667\n" * 200,
        ):
            with self.subTest(length=len(trace)):
                witness = self.witness(
                    sources=self.sources(target_qualification_trace=(True, trace))
                )
                self.assertFalse(witness["available"])
                self.assertIsNone(
                    witness["components"]["target_qualification_trace"][
                        "content_base64"
                    ]
                )

    def test_trusted_marker_requires_exact_finite_bytes(self) -> None:
        valid = b"qualification-harness representation-invalid\n"
        witness = self.witness(
            sources=self.sources(trusted_marker=(True, valid))
        )
        self.assertTrue(witness["available"])
        self.verifier.verify_replay_witness(self.document(witness), self.classifier)
        for invalid in (valid + b"suffix", b"arbitrary marker\n", b"\xff"):
            with self.subTest(invalid=invalid):
                rejected = self.witness(
                    sources=self.sources(trusted_marker=(True, invalid))
                )
                self.assertFalse(rejected["available"])

    def test_noncanonical_closed_failure_observation_is_replayable(self) -> None:
        facts = {
            "exec_main_code": None,
            "exec_main_status": None,
            "runuser_status": 3,
            "schema_version": 1,
            "service_result": None,
            "stage": "systemctl-request-failed",
            "systemctl_client_status": 3,
        }
        self.assertTrue(
            self.classifier.admit_quadlet_start_observation(facts, 3)[2][
                "observation_complete"
            ]
        )
        observation = json.dumps(facts, indent=2).encode("ascii")
        witness = self.witness(
            sources=self.sources(start_observation=(True, observation))
        )
        self.assertTrue(witness["available"])
        self.verifier.verify_replay_witness(self.document(witness), self.classifier)

    def test_all_closed_success_observations_accept_legal_json_formatting(self) -> None:
        for name, facts in self.success_observations().items():
            representations = (
                self.canonical_json(facts),
                json.dumps(facts, separators=(",", ":")).encode("ascii"),
                (json.dumps(facts, indent=2) + "\n").encode("ascii"),
                ("\t" + json.dumps(dict(reversed(list(facts.items())))) + " \n").encode(
                    "ascii"
                ),
            )
            for payload in representations:
                with self.subTest(name=name, payload=payload):
                    witness = self.witness(
                        sources=self.sources(**{name: (True, payload)})
                    )
                    self.assertTrue(witness["available"])
                    document = self.document(witness)
                    replayed = self.verifier.verify_replay_witness(
                        document, self.classifier
                    )
                    component = witness["components"][name]
                    self.assertEqual(len(payload), component["byte_count"])
                    self.assertEqual(
                        hashlib.sha256(payload).hexdigest(), component["sha256"]
                    )
                    self.assertIn(payload, replayed)

    def test_observation_schema_semantics_and_bound_remain_closed(self) -> None:
        for name, facts in self.success_observations().items():
            invalid_documents = (
                dict(facts, arbitrary_payload="secret"),
                dict(facts, stage="caller-selected"),
                dict(facts, runuser_status=3),
                dict(facts, runuser_status=False),
                dict(facts, schema_version=True),
                dict(facts, stage={"payload": "secret"}),
            )
            payloads = [
                json.dumps(document).encode("ascii")
                for document in invalid_documents
            ]
            payloads.extend(
                (
                    b'{"schema_version":1,',
                    b'{"schema_version":1,"schema_version":1}',
                    b'{"schema_version":1,"stage":NaN}',
                    b"[" * 1_001 + b"0" + b"]" * 1_001,
                    self.canonical_json(facts)
                    + b" "
                    * (
                        self.classifier.REPLAY_EXACT_COMPONENT_BOUNDS[name]
                        - len(self.canonical_json(facts))
                        + 1
                    ),
                )
            )
            for payload in payloads:
                with self.subTest(name=name, payload=payload[:80]):
                    rejected = self.witness(
                        sources=self.sources(**{name: (True, payload)})
                    )
                    self.assertFalse(rejected["available"])
                    self.assertIsNone(
                        rejected["components"][name]["content_base64"]
                    )

    def test_unhashable_start_service_result_is_unavailable(self) -> None:
        for service_result in ([], {}):
            with self.subTest(service_result=service_result):
                observation = self.canonical_json(
                    {
                        "exec_main_code": None,
                        "exec_main_status": None,
                        "runuser_status": 3,
                        "schema_version": 1,
                        "service_result": service_result,
                        "stage": "systemctl-request-failed",
                        "systemctl_client_status": 3,
                    }
                )
                witness = self.witness(
                    sources=self.sources(start_observation=(True, observation))
                )
                self.assertFalse(witness["available"])
                self.assertEqual(
                    "unavailable",
                    witness["components"]["start_observation"]["replayability"],
                )
                self.assertIsNone(
                    witness["components"]["start_observation"]["content_base64"]
                )

    def test_changed_json_format_has_its_own_digest_and_cannot_be_substituted(self) -> None:
        facts = self.success_observations()["active_observation"]
        compact = self.canonical_json(facts)
        spaced = (json.dumps(facts, indent=2) + "\n").encode("ascii")
        self.assertNotEqual(
            hashlib.sha256(compact).digest(), hashlib.sha256(spaced).digest()
        )
        compact_document = self.document(
            self.witness(
                sources=self.sources(active_observation=(True, compact))
            )
        )
        spaced_document = self.document(
            self.witness(
                sources=self.sources(active_observation=(True, spaced))
            )
        )
        self.verifier.verify_replay_witness(compact_document, self.classifier)
        self.verifier.verify_replay_witness(spaced_document, self.classifier)
        altered = copy.deepcopy(compact_document)
        altered["replay_witness"]["components"]["active_observation"][
            "content_base64"
        ] = base64.b64encode(spaced).decode("ascii")
        self.assert_rejected(altered)

    def test_partial_witness_and_all_exact_replay_mutations_fail_closed(self) -> None:
        document = self.document(self.witness())
        self.verifier.verify_replay_witness(document, self.classifier)
        mutations: list[tuple[str, dict[str, object]]] = []

        partial = copy.deepcopy(document)
        partial["replay_witness"]["available"] = False
        component = partial["replay_witness"]["components"]["qualification_stdout"]
        component["replayability"] = "unavailable"
        component["content_base64"] = None
        mutations.append(("partial", partial))

        byte_count = copy.deepcopy(document)
        byte_count["replay_witness"]["components"]["qualification_stdout"][
            "byte_count"
        ] = 1
        mutations.append(("component byte count", byte_count))

        component_digest = copy.deepcopy(document)
        component_digest["replay_witness"]["components"]["qualification_stdout"][
            "sha256"
        ] = "a" * 64
        mutations.append(("component digest", component_digest))

        ordering = copy.deepcopy(document)
        ordering["replay_witness"]["component_order"][0:2] = reversed(
            ordering["replay_witness"]["component_order"][0:2]
        )
        mutations.append(("ordering", ordering))

        separator = copy.deepcopy(document)
        separator["replay_witness"]["separator"] = "none"
        mutations.append(("separator", separator))

        aggregate_count = copy.deepcopy(document)
        aggregate_count["diagnostic_input_bytes"] += 1
        mutations.append(("aggregate byte count", aggregate_count))

        aggregate_digest = copy.deepcopy(document)
        aggregate_digest["diagnostic_input_sha256"] = "a" * 64
        mutations.append(("aggregate digest", aggregate_digest))

        result = copy.deepcopy(document)
        result["replay_witness"]["representation_invalid"] = False
        mutations.append(("classifier result", result))

        exit_result = copy.deepcopy(document)
        exit_result["replay_witness"]["exit_status"] = 4
        mutations.append(("exit result", exit_result))

        stale_target = copy.deepcopy(document)
        stale_target["target_sha"] = "a" * 40
        mutations.append(("stale target", stale_target))

        stale_harness = copy.deepcopy(document)
        stale_harness["harness_sha256"] = "a" * 64
        mutations.append(("stale harness", stale_harness))

        historical_control = copy.deepcopy(document)
        historical_control["trusted_control_sha"] = LEGACY_CONTROL
        mutations.append(("mixed historical control", historical_control))

        positive = copy.deepcopy(document)
        positive["operation"] = "qualify-seccomp"
        positive["reason"] = "invariant-failed"
        mutations.append(("positive authority", positive))

        for name, mutation in mutations:
            with self.subTest(name=name):
                self.assert_rejected(mutation)

    def test_schema_preserves_history_and_requires_closed_v2_witness(self) -> None:
        self.assertEqual(
            sum(self.classifier.REPLAY_COMPONENT_BOUNDS.values()),
            self.schema["properties"]["diagnostic_input_bytes"]["maximum"],
        )
        self.assertEqual(
            max(self.classifier.REPLAY_COMPONENT_BOUNDS.values()),
            self.schema["$defs"]["replayComponent"]["properties"]["byte_count"][
                "maximum"
            ],
        )
        current = self.document(self.witness())
        self.assertEqual([], list(self.schema_validator.iter_errors(current)))
        self.assertTrue(
            list(self.schema_validator.iter_errors(dict(current, stderr="forbidden")))
        )
        for forbidden in ("journal", "environment", "provider_output"):
            with self.subTest(forbidden=forbidden):
                self.assertTrue(
                    list(
                        self.schema_validator.iter_errors(
                            dict(current, **{forbidden: "forbidden"})
                        )
                    )
                )
        no_witness = dict(current)
        no_witness.pop("replay_witness")
        self.assertTrue(list(self.schema_validator.iter_errors(no_witness)))
        historical = dict(no_witness, schema_version=1, trusted_control_sha=LEGACY_CONTROL)
        self.assertEqual([], list(self.schema_validator.iter_errors(historical)))
        mixed = dict(current, schema_version=1)
        self.assertTrue(list(self.schema_validator.iter_errors(mixed)))
        self.assert_rejected(mixed)
        mixed_without_witness = dict(
            no_witness, schema_version=1, trusted_control_sha=CURRENT_CONTROL
        )
        self.assertEqual(
            [], list(self.schema_validator.iter_errors(mixed_without_witness))
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "failure.json"
            path.write_text(json.dumps(mixed_without_witness), encoding="utf-8")
            with self.assertRaises(self.control.ControlError):
                self.control.validate_target_qualification_failure(
                    path,
                    mixed_without_witness["target_sha"],
                    mixed_without_witness["trusted_control_sha"],
                    mixed_without_witness["qualification_run_id"],
                    mixed_without_witness["qualification_run_attempt"],
                )

    def test_classifier_emits_replay_witness_only_for_new_current_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stdout = root / "stdout"
            trace = root / "trace"
            stdout.write_bytes(b"")
            trace.write_bytes(b"SECPAL_TARGET_ERR_V2:3:667\n")
            for control, expected_version in (
                (CURRENT_CONTROL, 2),
                (LEGACY_CONTROL, 1),
            ):
                output = root / f"failure-{expected_version}.json"
                completed = subprocess.run(
                    [
                        CLASSIFIER,
                        "--target-sha",
                        self.classifier.EXPECTED_TARGET_SHA,
                        "--control-sha",
                        control,
                        "--run-id",
                        "12345",
                        "--run-attempt",
                        "1",
                        "--harness",
                        HARNESS,
                        "--stdout",
                        stdout,
                        "--trace",
                        trace,
                        "--exit-status",
                        "3",
                        "--representation-invalid",
                        "--output",
                        output,
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(0, completed.returncode, completed.stderr)
                document = json.loads(output.read_text(encoding="utf-8"))
                self.assertEqual(expected_version, document["schema_version"])
                self.assertEqual(expected_version == 2, "replay_witness" in document)
                if expected_version == 2:
                    self.verifier.verify_replay_witness(document, self.classifier)

    def test_representation_failure_reads_existing_observation_sources(self) -> None:
        observation = self.canonical_json(
            {
                "exec_main_code": None,
                "exec_main_status": None,
                "runuser_status": 3,
                "schema_version": 1,
                "service_result": None,
                "stage": "systemctl-request-failed",
                "systemctl_client_status": 3,
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stdout = root / "stdout"
            trace = root / "trace"
            start = root / "start.json"
            output = root / "failure.json"
            stdout.write_bytes(b"")
            trace.write_bytes(b"SECPAL_TARGET_ERR_V2:3:667\n")
            start.write_bytes(observation)
            completed = subprocess.run(
                [
                    CLASSIFIER,
                    "--target-sha",
                    self.classifier.EXPECTED_TARGET_SHA,
                    "--control-sha",
                    CURRENT_CONTROL,
                    "--run-id",
                    "12345",
                    "--run-attempt",
                    "1",
                    "--harness",
                    HARNESS,
                    "--stdout",
                    stdout,
                    "--trace",
                    trace,
                    "--start-observation",
                    start,
                    "--exit-status",
                    "3",
                    "--representation-invalid",
                    "--output",
                    output,
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            document = json.loads(output.read_text(encoding="utf-8"))
            component = document["replay_witness"]["components"]["start_observation"]
            self.assertTrue(component["present"])
            self.assertEqual(len(observation), component["byte_count"])
            self.assertEqual(
                hashlib.sha256(observation).hexdigest(), component["sha256"]
            )
            self.assertEqual(
                base64.b64encode(observation).decode("ascii"),
                component["content_base64"],
            )
            self.verifier.verify_replay_witness(document, self.classifier)

    def test_present_empty_observations_make_witness_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stdout = root / "stdout"
            trace = root / "trace"
            output = root / "failure.json"
            observations = [root / name for name in ("start", "active", "primary")]
            stdout.write_bytes(b"")
            trace.write_bytes(b"SECPAL_TARGET_ERR_V2:3:667\n")
            for observation in observations:
                observation.write_bytes(b"")
            completed = subprocess.run(
                [
                    CLASSIFIER,
                    "--target-sha",
                    self.classifier.EXPECTED_TARGET_SHA,
                    "--control-sha",
                    CURRENT_CONTROL,
                    "--run-id",
                    "12345",
                    "--run-attempt",
                    "1",
                    "--harness",
                    HARNESS,
                    "--stdout",
                    stdout,
                    "--trace",
                    trace,
                    "--start-observation",
                    observations[0],
                    "--active-observation",
                    observations[1],
                    "--primary-observation",
                    observations[2],
                    "--exit-status",
                    "3",
                    "--representation-invalid",
                    "--output",
                    output,
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            witness = json.loads(output.read_text(encoding="utf-8"))["replay_witness"]
            self.assertFalse(witness["available"])
            for name in ("start_observation", "active_observation", "primary_observation"):
                component = witness["components"][name]
                self.assertTrue(component["present"])
                self.assertEqual("unavailable", component["replayability"])
                self.assertIsNone(component["content_base64"])

    def test_stdout_overflow_sentinel_emits_unavailable_witness(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stdout = root / "stdout"
            trace = root / "trace"
            output = root / "failure.json"
            overflow = b"x" * (self.classifier.MAX_STDOUT_BYTES + 1)
            stdout.write_bytes(overflow)
            trace.write_bytes(b"SECPAL_TARGET_ERR_V2:3:667\n")
            completed = subprocess.run(
                [
                    CLASSIFIER,
                    "--target-sha",
                    self.classifier.EXPECTED_TARGET_SHA,
                    "--control-sha",
                    CURRENT_CONTROL,
                    "--run-id",
                    "12345",
                    "--run-attempt",
                    "1",
                    "--harness",
                    HARNESS,
                    "--stdout",
                    stdout,
                    "--trace",
                    trace,
                    "--exit-status",
                    "3",
                    "--representation-invalid",
                    "--output",
                    output,
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            encoded = output.read_bytes()
            document = json.loads(encoded)
            component = document["replay_witness"]["components"][
                "qualification_stdout"
            ]
            self.assertFalse(document["replay_witness"]["available"])
            self.assertEqual(len(overflow), component["byte_count"])
            self.assertEqual(hashlib.sha256(overflow).hexdigest(), component["sha256"])
            self.assertEqual("unavailable", component["replayability"])
            self.assertIsNone(component["content_base64"])
            self.assertNotIn(overflow, encoded)

    def test_verifier_cli_loads_extensionless_installed_classifier(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            classifier = root / "secpal-classify-rocky-target-failure"
            shutil.copyfile(CLASSIFIER, classifier)
            classifier.chmod(0o755)
            failure = root / "failure.json"
            failure.write_bytes(self.canonical_json(self.document(self.witness())))
            completed = subprocess.run(
                [VERIFIER, failure, "--classifier", classifier],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)

    def test_unavailable_witness_retains_no_arbitrary_raw_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stdout = root / "stdout"
            trace = root / "trace"
            output = root / "failure.json"
            arbitrary = b"credential-shaped-but-not-exported\n"
            stdout.write_bytes(arbitrary)
            trace.write_bytes(b"SECPAL_TARGET_ERR_V1:3:667\n")
            completed = subprocess.run(
                [
                    CLASSIFIER,
                    "--target-sha",
                    self.classifier.EXPECTED_TARGET_SHA,
                    "--control-sha",
                    CURRENT_CONTROL,
                    "--run-id",
                    "12345",
                    "--run-attempt",
                    "1",
                    "--harness",
                    HARNESS,
                    "--stdout",
                    stdout,
                    "--trace",
                    trace,
                    "--exit-status",
                    "3",
                    "--output",
                    output,
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            encoded = output.read_bytes()
            document = json.loads(encoded)
            self.assertFalse(document["replay_witness"]["available"])
            self.assertNotIn(arbitrary, encoded)
            self.assertNotIn(base64.b64encode(arbitrary), encoded)
            self.verifier.validate_replay_witness(document, self.classifier)
            self.assert_rejected(document)
            self.control.validate_target_qualification_failure(
                output,
                self.classifier.EXPECTED_TARGET_SHA,
                CURRENT_CONTROL,
                "12345",
                "1",
            )
            disguised = copy.deepcopy(document)
            component = disguised["replay_witness"]["components"][
                "qualification_stdout"
            ]
            component["replayability"] = "exact"
            component["content_base64"] = base64.b64encode(arbitrary).decode("ascii")
            self.assert_rejected(disguised)


if __name__ == "__main__":
    unittest.main()
