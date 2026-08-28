#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Behavioral contract for bounded Rocky target-qualification failures."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
CLASSIFIER = ROOT / "scripts/ci-cloud/classify-rocky-target-qualification-failure.py"
SCHEMA = ROOT / "schemas/rocky-cloud-target-qualification-failure.schema.json"
WORKFLOW = ROOT / ".github/workflows/rocky-cloud-qualification.yml"
CONTROL = ROOT / "scripts/ci-cloud/rocky-control.py"
RUNNER = ROOT / "scripts/ci-cloud/run-rocky-target-qualification.sh"
TRACE = ROOT / "scripts/ci-cloud/rocky-target-qualification-trace.sh"


def load_classifier():
    specification = importlib.util.spec_from_file_location(
        "rocky_target_qualification_failure", CLASSIFIER
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("cannot load target qualification classifier")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


class RockyTargetQualificationDiagnosticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.classifier = load_classifier()

    def classify(
        self,
        output: str = "",
        trace: str = "",
        status: int = 1,
        *,
        target_bound: bool = True,
        marker: str | None = None,
    ) -> tuple[str, str]:
        return self.classifier.classify_failure(
            output.encode(),
            trace.encode(),
            status,
            target_bound=target_bound,
            trusted_marker=marker,
        )

    def run_traced_bash(
        self, script: str
    ) -> tuple[subprocess.CompletedProcess[bytes], str]:
        with tempfile.TemporaryDirectory() as directory:
            trace = Path(directory) / "trace"
            with trace.open("wb") as descriptor:
                result = subprocess.run(
                    ["bash", "-c", script],
                    check=False,
                    env={**os.environ, "BASH_ENV": str(TRACE)},
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    pass_fds=(descriptor.fileno(),),
                    close_fds=True,
                    preexec_fn=lambda: os.dup2(descriptor.fileno(), 3),
                )
            return result, trace.read_text(encoding="ascii")

    def test_real_bash_trace_retains_bounded_semantic_call_stack(self) -> None:
        cases = (
            ("set -eEuo pipefail\nfalse\n", (2,)),
            (
                "set -eEuo pipefail\nhelper() {\n  false\n}\nhelper\n",
                (3, 5),
            ),
            (
                "set -eEuo pipefail\ninner() {\n  false\n}\n"
                "outer() {\n  inner\n}\nouter\n",
                (3, 6, 8),
            ),
        )
        for script, required_lines in cases:
            with self.subTest(required_lines=required_lines):
                result, trace = self.run_traced_bash(script)
                self.assertEqual(1, result.returncode)
                match = self.classifier.TRACE_PATTERN.fullmatch(trace.strip())
                self.assertIsNotNone(match)
                self.assertEqual(1, int(match.group(1)))
                frames = tuple(int(value) for value in match.group(2).split(","))
                self.assertLessEqual(len(frames), self.classifier.MAX_TRACE_FRAMES)
                for line in required_lines:
                    self.assertIn(line, frames)

    def test_real_bash_helper_failures_classify_by_outer_semantic_call_site(self) -> None:
        definitions = {
            27: "read_os_release_value() {",
            28: "  false",
            29: "}",
            39: "run_as_service_account() {",
            40: "  false",
            41: "}",
            48: "rootless_podman() {",
            49: "  run_as_service_account",
            50: "}",
            52: "user_systemctl() {",
            53: "  false",
            54: "}",
        }
        cases = (
            (117, 'value="$(read_os_release_value)"', "qualify-host-identity"),
            (183, "rootless_podman", "qualify-rootless-runtime"),
            (243, "user_systemctl", "qualify-quadlet-runtime"),
            (257, "rootless_podman", "qualify-workload-primary"),
            (269, "rootless_podman", "qualify-workload-secondary"),
            (271, "rootless_podman", "qualify-selinux-storage"),
        )
        for call_line, command, operation in cases:
            lines = ["set -eEuo pipefail"] + [""] * (call_line - 1)
            for line_number, source in definitions.items():
                lines[line_number - 1] = source
            lines[call_line - 1] = command
            with self.subTest(operation=operation):
                result, trace = self.run_traced_bash("\n".join(lines) + "\n")
                self.assertEqual(1, result.returncode)
                self.assertEqual(
                    (operation, "command-failed"),
                    self.classify(trace=trace),
                )

    def test_reachable_bash_control_constructs_preserve_closed_diagnostics(self) -> None:
        definitions = {
            39: "run_as_service_account() {",
            40: "  false",
            41: "}",
            48: "rootless_podman() {",
            49: "  run_as_service_account",
            50: "}",
        }
        for call_line, command, operation in (
            (183, 'value="$(rootless_podman)"', "qualify-rootless-runtime"),
            (271, "rootless_podman | cat", "qualify-selinux-storage"),
        ):
            lines = ["set -eEuo pipefail"] + [""] * (call_line - 1)
            for line_number, source in definitions.items():
                lines[line_number - 1] = source
            lines[call_line - 1] = command
            with self.subTest(operation=operation):
                result, trace = self.run_traced_bash("\n".join(lines) + "\n")
                self.assertEqual(1, result.returncode)
                self.assertEqual(
                    (operation, "command-failed"),
                    self.classify(trace=trace),
                )

        conditional = (
            "set -eEuo pipefail\nhelper() { false; }\n"
            "if ! helper; then\n"
            "  printf 'ERROR: service-account home is not usable by secpal-runtime\\n'\n"
            "  exit 1\n"
            "fi\n"
        )
        result, trace = self.run_traced_bash(conditional)
        self.assertEqual(1, result.returncode)
        self.assertEqual("", trace)
        self.assertEqual(
            ("qualify-service-account", "invariant-failed"),
            self.classify(result.stdout.decode("utf-8"), trace),
        )

    def test_every_reviewed_semantic_surface_has_an_exact_failure_identity(self) -> None:
        cases = (
            ("NOT RUN: Rocky Linux 10.2 native qualification requires ID=rocky", "", "qualify-host-identity", "invariant-failed"),
            ("ERROR: native qualification must run as an administrator on the disposable qualification host.", "", "qualify-administrator-execution", "invariant-failed"),
            ("ERROR: --image must be a fully qualified, pre-staged digest reference.", "", "qualify-fixture-reference", "invariant-failed"),
            ("ERROR: required service account does not exist: secpal-runtime", "", "qualify-service-account", "invariant-failed"),
            ("ERROR: SELinux is not Enforcing.", "", "qualify-selinux-host", "invariant-failed"),
            ("", "SECPAL_TARGET_ERR_V2:1:162", "qualify-package-prerequisites", "command-failed"),
            ("ERROR: unsupported native architecture: ppc64le", "", "qualify-native-architecture", "invariant-failed"),
            ("ERROR: unified cgroup v2 is not effective.", "", "qualify-cgroup", "invariant-failed"),
            ("ERROR: rootless Podman does not select crun.", "", "qualify-rootless-runtime", "invariant-failed"),
            ("ERROR: digest-only fixture image is not pre-staged for the service account.", "", "qualify-fixture-presence", "invariant-failed"),
            ("", "SECPAL_TARGET_ERR_V2:1:196", "qualify-fixture-setup", "command-failed"),
            ("ERROR: service account can write the administrator Quadlet directory.", "", "qualify-quadlet-authority", "invariant-failed"),
            ("", "SECPAL_TARGET_ERR_V2:1:243", "qualify-quadlet-runtime", "command-failed"),
            ("", "SECPAL_TARGET_ERR_V2:1:251", "qualify-selinux-storage", "command-failed"),
            ("", "SECPAL_TARGET_ERR_V2:1:257", "qualify-workload-primary", "command-failed"),
            ("ERROR: representative rootless workload is not effectively seccomp-confined.", "", "qualify-seccomp", "invariant-failed"),
            ("", "SECPAL_TARGET_ERR_V2:1:269", "qualify-workload-secondary", "command-failed"),
            ("ERROR: representative SELinux MCS boundaries are not distinct and effective.", "", "qualify-mcs-relationship", "invariant-failed"),
            ("ERROR: cross-boundary read unexpectedly succeeded.", "", "qualify-cross-mcs-denial", "invariant-failed"),
            ("ERROR: cross-boundary failure lacks a matching SELinux AVC denial.", "", "qualify-avc-correlation", "invariant-failed"),
            ("ERROR: unable to restore SELinux dontaudit policy.", "", "qualify-selinux-policy-restoration", "command-failed"),
            ("ERROR: effective runtime facts contain a forbidden security fallback.", "", "qualify-runtime-fallback-absence", "invariant-failed"),
            ("", "", "qualify-fixture-cleanup", "cleanup-failed", "qualify-fixture-cleanup cleanup-failed"),
        )
        observed = set()
        for case in cases:
            with self.subTest(operation=case[2]):
                output, trace, operation, reason, *marker = case
                result = self.classify(
                    output,
                    trace,
                    marker=marker[0] if marker else None,
                )
                self.assertEqual((operation, reason), result)
                observed.add(operation)
        self.assertEqual(self.classifier.OPERATIONS - {"qualification-harness"}, observed)

    def test_unknown_ambiguous_and_unbound_failures_are_never_guessed(self) -> None:
        self.assertEqual(
            ("qualification-harness", "unclassified-target-failure"),
            self.classify("unexpected target failure"),
        )
        self.assertEqual(
            ("qualification-harness", "unclassified-target-failure"),
            self.classify(
                "ERROR: SELinux is not Enforcing.\n"
                "ERROR: unified cgroup v2 is not effective."
            ),
        )
        self.assertEqual(
            ("qualification-harness", "representation-invalid"),
            self.classify(target_bound=False),
        )
        self.assertEqual(
            ("qualification-harness", "unclassified-target-failure"),
            self.classify(trace="SECPAL_TARGET_ERR_V2:1:243,257"),
        )

    def test_timeout_and_malformed_representations_fail_closed(self) -> None:
        self.assertEqual(
            ("qualification-harness", "timeout"),
            self.classify(status=124),
        )
        self.assertEqual(
            ("qualification-harness", "representation-invalid"),
            self.classifier.classify_failure(
                b"\xff", b"", 1, target_bound=True, trusted_marker=None
            ),
        )

    def test_every_reviewed_message_and_call_site_has_a_closed_mapping(self) -> None:
        for prefix, operation, reason in self.classifier.EXPLICIT_RULES:
            with self.subTest(prefix=prefix):
                self.assertEqual((operation, reason), self.classify(prefix))
        for first, last, operation in self.classifier.LINE_RULES:
            with self.subTest(line=first):
                self.assertEqual(
                    (operation, "command-failed"),
                    self.classify(trace=f"SECPAL_TARGET_ERR_V2:1:{first}"),
                )
                self.assertLessEqual(first, last)

    def test_bash_env_trace_records_only_numeric_failure_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            harness = root / "harness.sh"
            trace = root / "trace"
            harness.write_text("set -euo pipefail\nfalse\n", encoding="utf-8")
            with trace.open("wb") as descriptor:
                result = subprocess.run(
                    ["bash", harness],
                    check=False,
                    env={**os.environ, "BASH_ENV": str(TRACE)},
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    pass_fds=(descriptor.fileno(),),
                    close_fds=True,
                    preexec_fn=lambda: os.dup2(descriptor.fileno(), 3),
                )
            self.assertEqual(1, result.returncode)
            self.assertRegex(
                trace.read_text(encoding="ascii"),
                r"^SECPAL_TARGET_ERR_V2:1:[0-9]+(?:,[0-9]+){0,7}\n$",
            )

    def test_helper_frames_resolve_only_through_reviewed_outer_call_sites(self) -> None:
        cases = (
            ("qualify-rootless-runtime", (40, 49, 183)),
            ("qualify-quadlet-runtime", (53, 243)),
            ("qualify-workload-primary", (40, 49, 257)),
            ("qualify-workload-secondary", (40, 49, 269)),
            ("qualify-selinux-storage", (40, 49, 271)),
        )
        for operation, frames in cases:
            with self.subTest(operation=operation):
                trace = "SECPAL_TARGET_ERR_V2:1:" + ",".join(map(str, frames))
                self.assertEqual(
                    (operation, "command-failed"), self.classify(trace=trace)
                )
                for helper_line in frames[:-1]:
                    self.assertIsNone(self.classifier.operation_for_line(helper_line))

        self.assertEqual(
            ("qualify-service-account", "invariant-failed"),
            self.classify("ERROR: service-account home is not usable by secpal-runtime"),
        )
        explicit_conditionals = (
            (
                "ERROR: digest-only fixture image is not pre-staged",
                "qualify-fixture-presence",
            ),
            (
                "ERROR: cross-boundary read unexpectedly succeeded.",
                "qualify-cross-mcs-denial",
            ),
            (
                "ERROR: cross-boundary failure lacks a matching SELinux AVC denial.",
                "qualify-avc-correlation",
            ),
            (
                "ERROR: effective runtime facts contain a forbidden security fallback.",
                "qualify-runtime-fallback-absence",
            ),
        )
        for message, operation in explicit_conditionals:
            self.assertEqual(
                (operation, "invariant-failed"), self.classify(message)
            )

    def test_same_operation_frames_agree_but_different_operations_are_ambiguous(self) -> None:
        self.assertEqual(
            ("qualify-rootless-runtime", "command-failed"),
            self.classify(trace="SECPAL_TARGET_ERR_V2:1:40,49,183,187"),
        )
        self.assertEqual(
            ("qualification-harness", "unclassified-target-failure"),
            self.classify(trace="SECPAL_TARGET_ERR_V2:1:183,243"),
        )

    def test_explicit_message_and_stack_must_agree(self) -> None:
        self.assertEqual(
            ("qualify-selinux-host", "invariant-failed"),
            self.classify(
                "ERROR: SELinux is not Enforcing.",
                "SECPAL_TARGET_ERR_V2:1:153",
            ),
        )
        self.assertEqual(
            ("qualification-harness", "unclassified-target-failure"),
            self.classify(
                "ERROR: SELinux is not Enforcing.",
                "SECPAL_TARGET_ERR_V2:1:179",
            ),
        )

    def test_v2_trace_bounds_and_unknown_frames_fail_closed(self) -> None:
        self.assertEqual(
            ("qualification-harness", "unclassified-target-failure"),
            self.classify(trace="SECPAL_TARGET_ERR_V2:1:40,49,9999"),
        )
        malformed = (
            "SECPAL_TARGET_ERR_V1:183:1",
            "SECPAL_TARGET_ERR_V2:0:183",
            "SECPAL_TARGET_ERR_V2:2:183",
            "SECPAL_TARGET_ERR_V2:1:183,command",
            "SECPAL_TARGET_ERR_V2:1:" + ",".join(["183"] * 9),
        )
        for trace in malformed:
            with self.subTest(trace=trace):
                self.assertEqual(
                    ("qualification-harness", "representation-invalid"),
                    self.classify(trace=trace),
                )
        self.assertEqual(
            ("qualification-harness", "representation-invalid"),
            self.classify(
                "ERROR: SELinux is not Enforcing.",
                "SECPAL_TARGET_ERR_V1:153:1",
            ),
        )

    def test_failure_schema_is_closed_bounded_and_run_bound(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        self.assertEqual(
            self.classifier.OPERATIONS,
            set(schema["properties"]["operation"]["enum"]),
        )
        self.assertEqual(
            self.classifier.REASONS,
            set(schema["properties"]["reason"]["enum"]),
        )
        document = {
            "schema_version": 1,
            "phase": "target-qualification",
            "target_sha": "d" * 40,
            "trusted_control_sha": "c" * 40,
            "qualification_run_id": "12345",
            "qualification_run_attempt": "1",
            "harness_sha256": self.classifier.EXPECTED_HARNESS_SHA256,
            "operation": "qualify-seccomp",
            "reason": "invariant-failed",
            "exit_status": 1,
            "diagnostic_input_sha256": "b" * 64,
            "diagnostic_input_bytes": 100,
        }
        self.assertEqual([], list(validator.iter_errors(document)))
        for mutation in (
            dict(document, stdout="untrusted"),
            dict(document, operation="arbitrary-command"),
            dict(document, reason="some-error-text"),
            dict(document, qualification_run_id="0"),
            dict(document, diagnostic_input_bytes=131_329),
        ):
            self.assertTrue(list(validator.iter_errors(mutation)))
        unbound = dict(
            document,
            harness_sha256="a" * 64,
            operation="qualification-harness",
            reason="representation-invalid",
        )
        self.assertEqual([], list(validator.iter_errors(unbound)))
        self.assertTrue(
            list(
                validator.iter_errors(
                    dict(unbound, operation="qualify-seccomp", reason="invariant-failed")
                )
            )
        )

    def test_trusted_validator_binds_the_exact_control_target_and_run(self) -> None:
        document = {
            "schema_version": 1,
            "phase": "target-qualification",
            "target_sha": "d" * 40,
            "trusted_control_sha": "c" * 40,
            "qualification_run_id": "12345",
            "qualification_run_attempt": "1",
            "harness_sha256": self.classifier.EXPECTED_HARNESS_SHA256,
            "operation": "qualify-seccomp",
            "reason": "invariant-failed",
            "exit_status": 1,
            "diagnostic_input_sha256": "b" * 64,
            "diagnostic_input_bytes": 100,
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "failure.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            command = [
                CONTROL,
                "validate-target-qualification-failure",
                path,
                "--target-sha",
                "d" * 40,
                "--control-sha",
                "c" * 40,
                "--run-id",
                "12345",
                "--run-attempt",
                "1",
            ]
            self.assertEqual(
                0,
                subprocess.run(command, check=False, capture_output=True).returncode,
            )
            command[-1] = "2"
            self.assertNotEqual(
                0,
                subprocess.run(command, check=False, capture_output=True).returncode,
            )

    def test_success_and_failure_transport_are_disjoint(self) -> None:
        workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
        steps = {
            step["name"]: step
            for step in workflow["jobs"]["qualify_target"]["steps"]
            if "name" in step
        }
        failure = steps["Retrieve and validate bounded target-qualification failure"]
        success = steps["Retrieve and validate target-owned qualification evidence"]
        self.assertIn("qualification_failure_expected == 'true'", failure["if"])
        self.assertEqual(
            "${{ steps.target_execution.outcome == 'success' }}", success["if"]
        )
        self.assertNotIn("qualification.json", failure["run"])
        self.assertNotIn("target-qualification-failure.json", success["run"])
        self.assertIn("head -c 2049", failure["run"])
        self.assertIn("-le 2048", failure["run"])

        runner = RUNNER.read_text(encoding="utf-8")
        direct_failure = runner.split('if [[ "$status" -ne 0 ]]; then', 1)[1].split(
            "fi", 1
        )[0]
        self.assertNotIn("--trusted-marker", direct_failure)
        self.assertIn(
            'rm -f -- "$source_failure" "$qualification_failure" '
            '"$qualification_trace" "$qualification_marker"',
            runner,
        )
        self.assertIn(
            'exit 91\nfi\n\n# The target cannot pre-seed the trusted admission marker.',
            runner,
        )
        self.assertIn('rm -f -- "$qualification_marker"\nset +e\npython3 -', runner)
        self.assertIn("representation_option=(--representation-invalid)", runner)

    def test_trace_overflow_and_unsafe_inputs_fail_closed(self) -> None:
        self.assertEqual(
            ("qualification-harness", "representation-invalid"),
            self.classifier.classify_failure(
                b"",
                b"x" * (self.classifier.MAX_TRACE_BYTES + 1),
                1,
                target_bound=True,
                representation_invalid=True,
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            missing = root / "missing"
            with self.assertRaises(ValueError):
                self.classifier.bounded_bytes(missing, 1)
            target = root / "target"
            target.write_bytes(b"ok")
            link = root / "link"
            link.symlink_to(target)
            with self.assertRaises(ValueError):
                self.classifier.bounded_bytes(link, 2)
            with self.assertRaises(ValueError):
                self.classifier.bounded_bytes(target, 1)

    def test_trace_helper_is_inert_without_its_dedicated_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            harness = Path(directory) / "harness.sh"
            harness.write_text("set -euo pipefail\nfalse\n", encoding="utf-8")
            result = subprocess.run(
                ["bash", harness],
                check=False,
                env={**os.environ, "BASH_ENV": str(TRACE)},
                capture_output=True,
                text=True,
            )
            self.assertEqual(1, result.returncode)
            self.assertNotIn("Bad file descriptor", result.stderr)


if __name__ == "__main__":
    unittest.main()
