#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "scripts/selinux_isolation_contract.py"
SCHEMA_PATH = ROOT / "schemas/rocky-cloud-qualification-evidence.schema.json"
CONTROL = ROOT / "scripts/ci-cloud/rocky-control.py"
QUADLET_AUTHORITY_PATH = ROOT / "scripts/quadlet_authority_contract.py"


def load_contract():
    specification = importlib.util.spec_from_file_location(
        "selinux_isolation_contract", CONTRACT_PATH
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


CONTRACT = load_contract()
PROCESS_A = "system_u:system_r:container_t:s0:c0"
PROCESS_B = "system_u:system_r:container_t:s0:c1023"
STORAGE_A = "system_u:object_r:container_file_t:s0:c0"
PID = 4242


def event(
    *,
    serial: str = "41",
    permission: str = "read",
    pid: int = PID,
    syscall_pid: int | None = None,
    name: str = "marker",
    source: str = PROCESS_B,
    target: str = STORAGE_A,
    target_class: str = "file",
    permissive: int = 0,
    path: str = "/foreign/marker",
) -> str:
    if syscall_pid is None:
        syscall_pid = pid
    identity = f"msg=audit(08/31/26 00:43:39.673:{serial}) :"
    return "\n".join(
        (
            f"type=AVC {identity} avc: denied {{ {permission} }} "
            f'pid={pid} name="{name}" scontext={source} tcontext={target} '
            f"tclass={target_class} permissive={permissive}",
            f"type=PROCTITLE {identity} proctitle=cat {path}",
            f'type=SYSCALL {identity} pid={syscall_pid} comm="cat"',
        )
    )


def admitted_isolation(**changes):
    arguments = {
        "process_a": PROCESS_A,
        "process_b": PROCESS_B,
        "storage_a": STORAGE_A,
        "audit_text": event(),
    }
    arguments.update(changes)
    return CONTRACT.admit_selinux_isolation(**arguments)


class SelinuxIsolationContractTests(unittest.TestCase):
    def test_closed_mcs_boundaries_and_pairs(self) -> None:
        accepted = (
            (PROCESS_A, "container_t", [0]),
            (PROCESS_B, "container_t", [1023]),
            (
                "system_u:system_r:container_t:s0:c0,c1023",
                "container_t",
                [0, 1023],
            ),
        )
        for raw, expected_type, categories in accepted:
            with self.subTest(raw=raw):
                normalized = CONTRACT.normalize_context(raw, expected_type)
                self.assertEqual(categories, normalized["mcs_categories"])

        rejected = (
            "system_u:system_r:container_t:s0:c-1",
            "system_u:system_r:container_t:s0:c1024",
            "system_u:system_r:container_t:s0:c9999",
            "system_u:system_r:container_t:s0:c",
            "system_u:system_r:container_t:s0:c1,",
            "system_u:system_r:container_t:s0:c1,c2,c3",
            "system_u:system_r:container_t:s0:c1,c1",
            "system_u:system_r:container_t:s0:c01",
        )
        for raw in rejected:
            with self.subTest(raw=raw), self.assertRaises(CONTRACT.IsolationError):
                CONTRACT.normalize_context(raw, "container_t")

    def test_unique_enforcing_avc_correlation(self) -> None:
        accepted = admitted_isolation()
        self.assertEqual(PID, accepted["denial"]["pid"])
        self.assertEqual("41", accepted["denial"]["serial"])
        self.assertEqual("file", accepted["denial"]["target_class"])
        self.assertEqual(CONTRACT.INVARIANT_OWNER, accepted["invariant_owner"])

        rejected = {
            "permissive": event(permissive=1),
            "unrelated-marker": event(pid=999, source="system_u:system_r:other_t:s0:c3"),
            "wrong-source": event(source=PROCESS_A),
            "wrong-target": event(target="system_u:object_r:container_file_t:s0:c9"),
            "wrong-path": event(path="/foreign/other"),
            "wrong-operation": event(permission="write"),
            "wrong-process": event(pid=999, syscall_pid=PID),
            "wrong-class": event(target_class="dir"),
            "incomplete": event().splitlines()[0],
        }
        for name, audit_text in rejected.items():
            with self.subTest(name=name), self.assertRaises(CONTRACT.IsolationError):
                admitted_isolation(audit_text=audit_text)

        avc, proctitle, syscall = event().splitlines()
        cross_serial = "\n".join(
            (avc, proctitle.replace(":41) :", ":42) :"), syscall)
        )
        with self.assertRaises(CONTRACT.IsolationError):
            admitted_isolation(audit_text=cross_serial)
        with self.assertRaisesRegex(CONTRACT.IsolationError, "ambiguous"):
            admitted_isolation(
                audit_text="\n".join((event(), event(serial="42")))
            )

    def test_closed_diagnostic_identifies_avc_rejection_predicate(self) -> None:
        diagnostic = CONTRACT.diagnose_avc_correlation(
            process_a=PROCESS_A,
            process_b=PROCESS_B,
            storage_a=STORAGE_A,
            audit_text=event(permission="write"),
            attempt=1,
        )
        self.assertEqual("no-match", diagnostic["correlation_outcome"])
        self.assertIn("permission-mismatch", diagnostic["rejection_facts"])
        CONTRACT.validate_avc_correlation_diagnostic(diagnostic)

    def test_closed_diagnostic_distinguishes_complete_rejection_family(self) -> None:
        avc, proctitle, syscall = event().splitlines()
        cases = {
            "no-avc-records-observed": "",
            "permission-mismatch": event(permission="write"),
            "target-class-mismatch": event(target_class="dir"),
            "target-name-mismatch": event(name="other"),
            "source-context-mismatch": event(source=PROCESS_A),
            "target-context-mismatch": event(
                target="system_u:object_r:container_file_t:s0:c9"
            ),
            "permissive-mismatch": event(permissive=1),
            "avc-pid-invalid-or-missing": avc.replace("pid=4242 ", "")
            + "\n"
            + proctitle
            + "\n"
            + syscall,
            "avc-duplicate": "\n".join((avc, avc, proctitle, syscall)),
            "proctitle-absent": "\n".join((avc, syscall)),
            "proctitle-mismatch": event(path="/foreign/other"),
            "proctitle-duplicate": "\n".join((avc, proctitle, proctitle, syscall)),
            "syscall-absent": "\n".join((avc, proctitle)),
            "syscall-mismatch": event(syscall_pid=999),
            "syscall-duplicate": "\n".join((avc, proctitle, syscall, syscall)),
            "cross-event-separation": "\n".join(
                (avc, *event(serial="42").splitlines()[1:])
            ),
            "multiple-candidate-events": "\n".join((event(), event(serial="42"))),
        }
        for rejection, audit_text in cases.items():
            with self.subTest(rejection=rejection):
                diagnostic = CONTRACT.diagnose_avc_correlation(
                    process_a=PROCESS_A,
                    process_b=PROCESS_B,
                    storage_a=STORAGE_A,
                    audit_text=audit_text,
                    attempt=12,
                )
                self.assertIn(rejection, diagnostic["rejection_facts"])
                CONTRACT.validate_avc_correlation_diagnostic(diagnostic)

        malformed = CONTRACT.diagnose_avc_correlation(
            process_a=PROCESS_A,
            process_b=PROCESS_B,
            storage_a=STORAGE_A,
            audit_text=event().replace("08/31/26", "13/31/26"),
            attempt=1,
        )
        self.assertEqual(
            ["event-id-parse-mismatch", "observation-malformed"],
            malformed["rejection_facts"],
        )
        malformed_record = CONTRACT.diagnose_avc_correlation(
            process_a=PROCESS_A,
            process_b=PROCESS_B,
            storage_a=STORAGE_A,
            audit_text="unrestricted audit record",
            attempt=1,
        )
        self.assertEqual(
            ["record-representation-malformed", "observation-malformed"],
            malformed_record["rejection_facts"],
        )
        oversized = CONTRACT.diagnose_avc_correlation_bytes(
            process_a=PROCESS_A,
            process_b=PROCESS_B,
            storage_a=STORAGE_A,
            payload=b"x" * (CONTRACT.MAX_AUDIT_OBSERVATION_BYTES + 1),
            attempt=1,
        )
        self.assertEqual(["observation-oversized"], oversized["rejection_facts"])

    def test_capture_diagnostics_and_mutations_fail_closed(self) -> None:
        no_result = CONTRACT.capture_avc_correlation_diagnostic(
            process_a=PROCESS_A,
            process_b=PROCESS_B,
            storage_a=STORAGE_A,
            payload=b"",
            attempt=12,
            capture_outcome="ausearch-no-result",
            ausearch_status=1,
            capture_status=0,
        )
        self.assertEqual("no-match", no_result["correlation_outcome"])
        execution_error = CONTRACT.capture_avc_correlation_diagnostic(
            process_a=PROCESS_A,
            process_b=PROCESS_B,
            storage_a=STORAGE_A,
            payload=b"",
            attempt=1,
            capture_outcome="capture-execution-error",
            ausearch_status=125,
            capture_status=0,
        )
        self.assertEqual(
            ["capture-execution-error"], execution_error["rejection_facts"]
        )
        for diagnostic in (no_result, execution_error):
            CONTRACT.validate_avc_correlation_diagnostic(diagnostic)

        admitted = CONTRACT.diagnose_avc_correlation(
            process_a=PROCESS_A,
            process_b=PROCESS_B,
            storage_a=STORAGE_A,
            audit_text=event(),
            attempt=1,
        )
        mutations = []
        wrong_reason = deepcopy(admitted)
        wrong_reason["rejection_facts"] = ["permission-mismatch"]
        mutations.append(wrong_reason)
        wrong_count = deepcopy(admitted)
        wrong_count["candidate_event_count"] = 0
        mutations.append(wrong_count)
        wrong_mcs = deepcopy(admitted)
        wrong_mcs["process_contexts"][0]["mcs_categories"] = [1024]
        mutations.append(wrong_mcs)
        wrong_event = deepcopy(admitted)
        wrong_event["events"][0]["serial"] = "0"
        mutations.append(wrong_event)
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(
                CONTRACT.IsolationError
            ):
                CONTRACT.validate_avc_correlation_diagnostic(mutation)

    def test_schema_and_owner_agree_after_normalization(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        isolation_schema = {
            "$ref": "#/$defs/selinux_isolation",
            "$defs": schema["$defs"],
        }
        document = admitted_isolation()
        self.assertEqual([], list(Draft202012Validator(isolation_schema).iter_errors(document)))
        self.assertEqual(
            CONTRACT.INVARIANT_OWNER,
            schema["$defs"]["selinux_isolation"]["properties"]
            ["invariant_owner"]["const"],
        )
        self.assertEqual(
            CONTRACT.SCHEMA_CONTEXT_PATTERN,
            schema["$defs"]["normalized_context"]["properties"]["raw"]["pattern"],
        )
        contradictory = deepcopy(document)
        contradictory["process_contexts"][0]["mcs_categories"] = [1]
        with self.assertRaisesRegex(CONTRACT.IsolationError, "contradict"):
            CONTRACT.validate_isolation_evidence(contradictory)
        out_of_range = deepcopy(document)
        out_of_range["process_contexts"][0] = {
            "raw": "system_u:system_r:container_t:s0:c1024",
            "selinux_type": "container_t",
            "mcs_categories": [1024],
        }
        self.assertTrue(list(Draft202012Validator(isolation_schema).iter_errors(out_of_range)))

    def test_realistic_denial_traverses_schema_and_trusted_admission(self) -> None:
        schema = json.loads(
            (ROOT / "schemas/rocky-cloud-preparation-evidence.schema.json").read_text(
                encoding="utf-8"
            )
        )
        names = [
            branch["contains"]["properties"]["name"]["const"]
            for branch in schema["properties"]["packages"]["allOf"]
        ]
        packages = []
        for name in names:
            version = "5.8.2" if name == "podman" else "1.0"
            packages.append(
                {
                    "name": name,
                    "epoch": "0",
                    "version": version,
                    "release": "1.el10_2",
                    "architecture": "aarch64",
                    "nevra": f"{name}-{version}-1.el10_2.aarch64",
                    "resolved_repository": "appstream",
                    "signature_verified": True,
                    "signer_fingerprint": "fc226859c0860bf0ddb95b085b106c736fedfc85",
                    "payload_digest": "a" * 64,
                }
            )
        isolation = admitted_isolation()
        isolation_digest = hashlib.sha256(CONTRACT.canonical_bytes(isolation)).hexdigest()
        authority_specification = importlib.util.spec_from_file_location(
            "quadlet_authority_contract", QUADLET_AUTHORITY_PATH
        )
        assert (
            authority_specification is not None
            and authority_specification.loader is not None
        )
        authority_contract = importlib.util.module_from_spec(
            authority_specification
        )
        authority_specification.loader.exec_module(authority_contract)
        unit_name = "secpal-host-qualification-Ab12Cd"
        fragment = f"/run/user/991/systemd/generator/{unit_name}.service"
        source = f"/etc/containers/systemd/users/991/{unit_name}.container"
        authority = authority_contract.admit_quadlet_authority(
            "\n".join(
                (
                    f"FragmentPath={fragment}",
                    f"SourcePath={source}",
                    "DropInPaths=",
                    f"ExecStart={authority_contract.expected_exec_start(unit_name)}",
                )
            )
            + "\n",
            fragment,
            source,
        )
        authority_encoded = base64.b64encode(
            authority_contract.canonical_bytes(authority)
        ).decode("ascii")
        stdout = (
            f"selinux_isolation_sha256={isolation_digest}\n"
            f"quadlet_authority_base64={authority_encoded}\n"
            "PASS: Rocky Linux 10.2 target workload contract\n"
        ).encode()
        observation = {
            "schema_version": 1,
            "target_sha": "b76c24fe59fbe2406d8b84094fc9e6694c57f0c6",
            "trusted_control_sha": "a" * 40,
            "qualification_run_id": "12345",
            "qualification_run_attempt": "1",
            "host": {"id": "rocky", "version_id": "10.2", "architecture": "aarch64"},
            "podman_version": "5.8.2",
            "packages": packages,
        }
        evidence = {
            "schema_version": 3,
            "target_sha": "b76c24fe59fbe2406d8b84094fc9e6694c57f0c6",
            "native_observation": observation,
            "quadlet_authority": authority,
            "exit_status": 0,
            "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
            "stdout_bytes": len(stdout),
            "selinux_isolation": isolation,
            "seccomp_enforced": True,
            "cleanup_complete": True,
            "classification": "PASS",
        }

        def validate(candidate):
            with tempfile.TemporaryDirectory() as directory:
                temporary = Path(directory)
                evidence_path = temporary / "qualification.json"
                stdout_path = temporary / "qualification.stdout"
                observation_path = temporary / "native.json"
                evidence_path.write_text(json.dumps(candidate), encoding="utf-8")
                stdout_path.write_bytes(stdout)
                observation_path.write_text(json.dumps(observation), encoding="utf-8")
                return subprocess.run(
                    [
                        CONTROL,
                        "validate-native-qualification",
                        evidence_path,
                        "--stdout",
                        stdout_path,
                        "--native-observation",
                        observation_path,
                        "--target-sha",
                        "b76c24fe59fbe2406d8b84094fc9e6694c57f0c6",
                        "--control-sha",
                        "a" * 40,
                        "--run-id",
                        "12345",
                        "--run-attempt",
                        "1",
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )

        self.assertEqual(0, validate(evidence).returncode)
        for field, value in (
            ("source_context", PROCESS_A),
            ("target_context", "system_u:object_r:container_file_t:s0:c9"),
            ("permission", "write"),
            ("target_path", "/foreign/other"),
            ("permissive", 1),
            ("pid", 999),
            ("serial", "0"),
        ):
            mutated = deepcopy(evidence)
            mutated["selinux_isolation"]["denial"][field] = value
            with self.subTest(field=field):
                self.assertNotEqual(0, validate(mutated).returncode)


if __name__ == "__main__":
    unittest.main()
