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
            "exit_status": 3,
            "diagnostic_input_sha256": hashlib.sha256(aggregate).hexdigest(),
            "diagnostic_input_bytes": total,
            "replay_witness": witness,
        }

    def assert_rejected(self, document: dict[str, object]) -> None:
        with self.assertRaises(ValueError):
            self.verifier.verify_replay_witness(document, self.classifier)

    def test_historical_digest_and_count_cannot_reconstruct_or_authorize_guess(self) -> None:
        historical = {
            "schema_version": 1,
            "phase": "target-qualification",
            "target_sha": self.classifier.EXPECTED_TARGET_SHA,
            "trusted_control_sha": LEGACY_CONTROL,
            "qualification_run_id": "34726109991",
            "qualification_run_attempt": "1",
            "harness_sha256": self.classifier.EXPECTED_HARNESS_SHA256,
            "operation": "qualification-harness",
            "reason": "representation-invalid",
            "exit_status": 3,
            "diagnostic_input_sha256": (
                "d10b32d994b4056611561d93638db15a768122053e25f5d0bae32af45ee8f355"
            ),
            "diagnostic_input_bytes": 85,
        }
        self.assertEqual([], list(self.schema_validator.iter_errors(historical)))
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

    def test_empty_stdout_and_bounded_numeric_trace_replay_exactly(self) -> None:
        trace = b"SECPAL_TARGET_ERR_V2:3:667\n"
        witness = self.witness(
            sources=self.sources(target_qualification_trace=(True, trace))
        )
        document = self.document(witness)
        self.assertTrue(witness["available"])
        replayed = self.verifier.verify_replay_witness(document, self.classifier)
        self.assertEqual(b"\0" + trace + b"\0\0\0\0\0", replayed)
        self.assertEqual(
            document["diagnostic_input_sha256"], hashlib.sha256(replayed).hexdigest()
        )

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

    def test_malformed_and_oversized_trace_are_unavailable(self) -> None:
        for trace in (
            b"SECPAL_TARGET_ERR_V1:3:667\n",
            b"SECPAL_TARGET_ERR_V2:1:667\n",
            b"SECPAL_TARGET_ERR_V2:3:not-a-number\n",
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

    def test_closed_observation_replays_but_malformed_and_oversized_do_not(self) -> None:
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
        witness = self.witness(
            sources=self.sources(start_observation=(True, observation))
        )
        self.assertTrue(witness["available"])
        self.verifier.verify_replay_witness(self.document(witness), self.classifier)
        malformed = observation.replace(b'"schema_version":1', b'"unknown":"secret"')
        oversized = observation + b" " * (
            self.classifier.MAX_START_OBSERVATION_BYTES - len(observation) + 1
        )
        for payload in (malformed, oversized):
            rejected = self.witness(
                sources=self.sources(start_observation=(True, payload))
            )
            self.assertFalse(rejected["available"])
            self.assertIsNone(
                rejected["components"]["start_observation"]["content_base64"]
            )

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
