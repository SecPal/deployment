#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Contract tests for the trusted Rocky ephemeral-cloud control plane."""

from __future__ import annotations

import json
import re
import base64
import gzip
import importlib.util
import os
from copy import deepcopy
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import yaml
from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "config/ci-cloud/gcp-rocky-10-2-arm64.json"
WORKFLOW = ROOT / ".github/workflows/rocky-cloud-qualification.yml"
TF_ROOT = ROOT / "infra/ci-cloud/gcp-rocky"
SCHEMA_NAMES = (
    "rocky-cloud-discovery-evidence.schema.json",
    "rocky-cloud-continuation.schema.json",
    "rocky-cloud-preparation-evidence.schema.json",
    "rocky-cloud-preparation-failure-evidence.schema.json",
    "rocky-cloud-qualification-evidence.schema.json",
    "rocky-cloud-qualification-readiness-failure.schema.json",
    "rocky-cloud-target-source-failure.schema.json",
    "rocky-cloud-target-qualification-failure.schema.json",
)


def load_rocky_preparation_collector():
    path = ROOT / "scripts/ci-cloud/collect-rocky-preparation.py"
    specification = importlib.util.spec_from_file_location(
        "rocky_preparation_collector", path
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("unable to load Rocky preparation collector")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


class RockyCloudControlTests(unittest.TestCase):
    def test_gce_metadata_policy_separates_dns_from_metadata_api(self) -> None:
        preparation = (ROOT / "scripts/ci-cloud/prepare-rocky-host.sh").read_text(
            encoding="utf-8"
        )
        function = preparation.split("block_metadata_credentials() {", 1)[1].split(
            "\n}\n\nconfigure_subids() {", 1
        )[0]
        udp_dns = "ip daddr 169.254.169.254 udp dport 53 accept"
        tcp_dns = "ip daddr 169.254.169.254 tcp dport 53 accept"
        metadata_reject = "ip daddr 169.254.169.254 reject"
        self.assertIn(udp_dns, function)
        self.assertIn(tcp_dns, function)
        self.assertIn(metadata_reject, function)
        self.assertNotIn("8.8.8.8", function)
        self.assertNotIn("1.1.1.1", function)

        policy = [
            line.strip()
            for line in function.splitlines()
            if line.strip().startswith("ip daddr 169.254.169.254")
        ][-3:]
        self.assertEqual([udp_dns, tcp_dns, metadata_reject], policy)

        def decision(protocol: str, port: int) -> str:
            exact = f"ip daddr 169.254.169.254 {protocol} dport {port} accept"
            for rule in policy:
                if rule == exact:
                    return "accept"
                if rule == metadata_reject:
                    return "reject"
            return "accept"

        self.assertEqual("accept", decision("udp", 53))
        self.assertEqual("accept", decision("tcp", 53))
        self.assertEqual("reject", decision("tcp", 80))
        self.assertEqual("reject", decision("tcp", 443))
        self.assertEqual("reject", decision("udp", 123))
        self.assertEqual("reject", decision("tcp", 22))

    def test_target_source_resolution_has_a_closed_failure_contract(self) -> None:
        runner = (ROOT / "scripts/ci-cloud/run-rocky-target-qualification.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("getent ahostsv4 github.com", runner)
        self.assertIn("resolve-target-source", runner)
        self.assertIn("fetch-exact-target", runner)
        self.assertIn("checkout-exact-target", runner)
        self.assertIn("verify-target-sha", runner)
        schema = json.loads(
            (ROOT / "schemas/rocky-cloud-target-source-failure.schema.json").read_text(
                encoding="utf-8"
            )
        )
        validator = Draft202012Validator(schema)
        base = {
            "schema_version": 1,
            "phase": "qualify-target",
            "operation": "resolve-target-source",
            "reason": "command-failed",
            "exit_status": 1,
            "source_host": "github.com",
            "target_sha": "d89214795bc1bdf0e65d9bbf7c8b9647b7e1ebd6",
        }
        self.assertEqual([], list(validator.iter_errors(base)))
        for mutation in (
            dict(base, source_host="example.com"),
            dict(base, operation="arbitrary-command"),
            dict(base, stdout="untrusted"),
        ):
            self.assertTrue(list(validator.iter_errors(mutation)))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "failure.json"
            path.write_text(json.dumps(base), encoding="utf-8")
            command = [
                str(ROOT / "scripts/ci-cloud/rocky-control.py"),
                "validate-target-source-failure",
                str(path),
                "--target-sha",
                base["target_sha"],
            ]
            self.assertEqual(0, subprocess.run(command, check=False).returncode)
            command[-1] = "a" * 40
            self.assertNotEqual(0, subprocess.run(command, check=False).returncode)

    def test_access_request_validation_is_exact_bound_and_order_independent(self) -> None:
        control = ROOT / "scripts/ci-cloud/rocky-control.py"
        target_sha = "d89214795bc1bdf0e65d9bbf7c8b9647b7e1ebd6"
        run_id = "33123855032"
        run_attempt = "1"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key = root / "id_ed25519"
            subprocess.run(
                [
                    "ssh-keygen",
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-C",
                    f"secpal-rocky-{run_id}-{run_attempt}",
                    "-f",
                    key,
                ],
                check=True,
            )
            public_key = key.with_suffix(".pub").read_text(encoding="utf-8").strip()
            request = {
                "runner_ipv4": "8.8.8.8",
                "run_attempt": run_attempt,
                "run_id": run_id,
                "ssh_public_key": public_key,
                "target_sha": target_sha,
            }
            command = [
                control,
                "validate-access-request",
                root / "access-request.json",
                "--target-sha",
                target_sha,
                "--run-id",
                run_id,
                "--run-attempt",
                run_attempt,
            ]
            with (root / "access-request.json").open("wb") as output:
                subprocess.run(
                    [
                        "jq",
                        "-n",
                        "--arg",
                        "runner_ipv4",
                        request["runner_ipv4"],
                        "--arg",
                        "ssh_public_key",
                        request["ssh_public_key"],
                        "--arg",
                        "target_sha",
                        request["target_sha"],
                        "--arg",
                        "run_id",
                        request["run_id"],
                        "--arg",
                        "run_attempt",
                        request["run_attempt"],
                        "{runner_ipv4: $runner_ipv4, ssh_public_key: $ssh_public_key, "
                        "target_sha: $target_sha, run_id: $run_id, "
                        "run_attempt: $run_attempt}",
                    ],
                    check=True,
                    stdout=output,
                )
            completed = subprocess.run(command, check=False, capture_output=True)
            self.assertEqual(0, completed.returncode, completed.stderr)
            for fields in (
                tuple(request),
                tuple(reversed(request)),
                ("target_sha", "runner_ipv4", "ssh_public_key", "run_id", "run_attempt"),
            ):
                with self.subTest(fields=fields):
                    (root / "access-request.json").write_text(
                        json.dumps({field: request[field] for field in fields}),
                        encoding="utf-8",
                    )
                    completed = subprocess.run(command, check=False, capture_output=True)
                    self.assertEqual(0, completed.returncode, completed.stderr)

    def test_access_request_validation_rejects_every_closed_contract_mismatch(self) -> None:
        control = ROOT / "scripts/ci-cloud/rocky-control.py"
        target_sha = "d89214795bc1bdf0e65d9bbf7c8b9647b7e1ebd6"
        run_id = "33123855032"
        run_attempt = "1"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key = root / "id_ed25519"
            subprocess.run(
                [
                    "ssh-keygen",
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-C",
                    f"secpal-rocky-{run_id}-{run_attempt}",
                    "-f",
                    key,
                ],
                check=True,
            )
            public_key = key.with_suffix(".pub").read_text(encoding="utf-8").strip()
            valid = {
                "runner_ipv4": "8.8.8.8",
                "run_attempt": run_attempt,
                "run_id": run_id,
                "ssh_public_key": public_key,
                "target_sha": target_sha,
            }
            request = root / "access-request.json"
            command = [
                control,
                "validate-access-request",
                request,
                "--target-sha",
                target_sha,
                "--run-id",
                run_id,
                "--run-attempt",
                run_attempt,
            ]
            mutations = {
                "missing": {key: value for key, value in valid.items() if key != "runner_ipv4"},
                "extra": {**valid, "unexpected": "value"},
                "wrong-target": {**valid, "target_sha": "a" * 40},
                "wrong-run": {**valid, "run_id": "33123855033"},
                "wrong-attempt": {**valid, "run_attempt": "2"},
                "empty-key": {**valid, "ssh_public_key": ""},
                "wrong-key-type": {**valid, "ssh_public_key": "ssh-rsa AAAA comment"},
                "wrong-key-comment": {
                    **valid,
                    "ssh_public_key": public_key.rsplit(" ", 1)[0] + " wrong-comment",
                },
                "malformed-ipv4": {**valid, "runner_ipv4": "999.1.1.1"},
                "non-public-ipv4": {**valid, "runner_ipv4": "192.0.2.1"},
                "ipv6": {**valid, "runner_ipv4": "2001:4860:4860::8888"},
                "wrong-type": {**valid, "run_attempt": 1},
                "scalar": "access-request",
                "list": list(valid),
                "null": None,
            }
            for name, document in mutations.items():
                with self.subTest(name=name):
                    request.write_text(json.dumps(document), encoding="utf-8")
                    self.assertNotEqual(
                        0,
                        subprocess.run(command, check=False, capture_output=True).returncode,
                    )
            request.write_text(
                '{"runner_ipv4":"8.8.8.8","runner_ipv4":"1.1.1.1",'
                f'"run_attempt":"{run_attempt}","run_id":"{run_id}",'
                f'"ssh_public_key":{json.dumps(public_key)},'
                f'"target_sha":"{target_sha}"}}',
                encoding="utf-8",
            )
            duplicate = subprocess.run(
                command, check=False, capture_output=True, text=True
            )
            self.assertNotEqual(0, duplicate.returncode)
            self.assertIn("duplicate object key", duplicate.stderr)
            request.write_text(json.dumps(valid) + " " * 1024, encoding="utf-8")
            self.assertNotEqual(
                0, subprocess.run(command, check=False, capture_output=True).returncode
            )

    def test_access_request_contract_has_one_owner_before_resume_oidc(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        canonical_call = "rocky-control.py validate-access-request"
        self.assertEqual(2, workflow.count(canonical_call))
        self.assertNotIn(
            'keys == ["runner_ipv4", "run_attempt", "run_id", "ssh_public_key", "target_sha"]',
            workflow,
        )
        resume = workflow.index("Wait for the uncredentialed target runner access request")
        resume_validation = workflow.index(canonical_call, resume)
        resume_oidc = workflow.index("google-github-actions/auth@", resume_validation)
        self.assertLess(resume_validation, resume_oidc)
        producer = workflow.index("Generate runner-local SSH key and public access request")
        producer_validation = workflow.index(canonical_call, producer)
        producer_upload = workflow.index("Upload only the public access request", producer)
        self.assertLess(producer_validation, producer_upload)

    def test_inactive_systemd_user_state_reaches_runtime_admission(self) -> None:
        collector = load_rocky_preparation_collector()
        observed: dict[str, object] = {}

        class RecordingObserver(collector.Observer):
            def run(self, operation, arguments, **options):
                observed["operation"] = operation
                observed["arguments"] = arguments
                observed["accepted"] = options.get("accepted")
                return 3, "inactive", ""

        self.assertEqual("inactive", RecordingObserver().systemd_user_state(991))
        self.assertEqual(collector.ObservationOperation.SYSTEMD_USER, observed["operation"])
        self.assertEqual(
            ["systemctl", "is-active", "user@991.service"], observed["arguments"]
        )
        self.assertEqual(frozenset({0, 3}), observed["accepted"])

    def test_package_repository_observation_uses_exact_nevra_query(self) -> None:
        collector = load_rocky_preparation_collector()
        nevra = "podman-5.6.0-12.el10_2.aarch64"

        self.assertEqual(
            [
                "dnf4",
                "--quiet",
                "--disablerepo=*",
                "--enablerepo=baseos,appstream,extras",
                "repoquery-nevra",
                "--qf",
                "%{repoid}",
                nevra,
            ],
            collector.Observer.package_repository_query(nevra),
        )

        observer = collector.Observer()
        signed_header = "\n".join(
            (
                nevra,
                "a" * 64,
                "8",
                "b" * 64,
                "RSA/SHA256, Wed May 21 13:19:52 2025, Key ID 5b106c736fedfc85",
            )
        )
        with mock.patch.object(
            observer,
            "run",
            side_effect=(
                (0, nevra, ""),
                (0, "appstream", ""),
                (
                    0,
                    signed_header,
                    "Header V4 RSA/SHA256 Signature, key ID 6fedfc85: OK\n"
                    "Header SHA256 digest: OK\nHeader SHA1 digest: OK",
                ),
            ),
        ) as run:
            observed = observer.package("podman")
        self.assertEqual(nevra, observed["nevra"])
        self.assertEqual(nevra, run.call_args_list[1].args[1][-1])
        self.assertEqual(nevra, run.call_args_list[2].args[1][-1])

    def test_rendered_rocky_startup_script_is_bounded_valid_bash(self) -> None:
        template = (ROOT / "scripts/ci-cloud/bootstrap-rocky-host.tftpl").read_text(
            encoding="utf-8"
        )
        sources = {
            "prepare_script_base64gzip": ROOT / "scripts/ci-cloud/prepare-rocky-host.sh",
            "readiness_publisher_base64gzip": ROOT
            / "scripts/ci-cloud/publish-rocky-qualification-readiness.py",
            "target_runner_base64gzip": ROOT / "scripts/ci-cloud/run-rocky-target-qualification.sh",
            "target_failure_classifier_base64gzip": ROOT
            / "scripts/ci-cloud/classify-rocky-target-qualification-failure.py",
            "target_trace_base64gzip": ROOT
            / "scripts/ci-cloud/rocky-target-qualification-trace.sh",
            "reload_observer_base64gzip": ROOT
            / "scripts/ci-cloud/observe-rocky-quadlet-reload-adjacency.py",
            "allocator_base64gzip": ROOT / "scripts/ci-cloud/allocate-rocky-subids.py",
            "collector_base64gzip": ROOT / "scripts/ci-cloud/collect-rocky-preparation.py",
            "preparation_contract_base64gzip": ROOT / "scripts/ci-cloud/rocky_preparation_contract.py",
            "control_utility_base64gzip": ROOT / "scripts/ci-cloud/rocky-control.py",
            "discovery_schema_base64gzip": ROOT / "schemas/rocky-cloud-discovery-evidence.schema.json",
            "continuation_schema_base64gzip": ROOT / "schemas/rocky-cloud-continuation.schema.json",
            "preparation_schema_base64gzip": ROOT / "schemas/rocky-cloud-preparation-evidence.schema.json",
            "preparation_failure_schema_base64gzip": ROOT / "schemas/rocky-cloud-preparation-failure-evidence.schema.json",
            "qualification_schema_base64gzip": ROOT / "schemas/rocky-cloud-qualification-evidence.schema.json",
            "target_source_failure_schema_base64gzip": ROOT
            / "schemas/rocky-cloud-target-source-failure.schema.json",
            "target_qualification_failure_schema_base64gzip": ROOT
            / "schemas/rocky-cloud-target-qualification-failure.schema.json",
            "profile_base64gzip": PROFILE,
        }
        rendered = template
        for name, path in sources.items():
            encoded = base64.b64encode(gzip.compress(path.read_bytes(), mtime=0)).decode(
                "ascii"
            )
            rendered = rendered.replace("${" + name + "}", encoded)
        rendered = rendered.replace("$${", "${")
        self.assertLessEqual(len(rendered.encode("utf-8")), (256 * 1024) - 256)
        self.assertNotRegex(rendered, r"\$\{[a-z_]+_base64gzip\}")
        self.assertIn(
            "decode_script '${target_failure_classifier_base64gzip}' "
            "/usr/local/sbin/secpal-classify-rocky-target-failure",
            template,
        )
        self.assertIn('chmod 0700 "$destination"', template)
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as script:
            script.write(rendered)
            script.flush()
            completed = subprocess.run(
                ["bash", "-n", script.name],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(0, completed.returncode, completed.stderr)

    def test_profile_is_one_closed_reviewed_arm64_contract(self) -> None:
        profile = json.loads(PROFILE.read_text(encoding="utf-8"))
        self.assertEqual(
            {
                "schema_version": 1,
                "profile": "gcp-rocky-10-2-arm64",
                "provider": "google",
                "project": "secpal-dev",
                "region": "europe-west3",
                "zone": "europe-west3-a",
                "machine_type": "c4a-standard-4",
                "architecture": "aarch64",
                "disk": {"type": "hyperdisk-balanced", "size_gib": 120},
                "instance_count": 1,
                "image": {
                    "project": "rocky-linux-cloud",
                    "discovery_family": "rocky-linux-10-arm64",
                },
                "guest": {"id": "rocky", "version_id": "10.2"},
                "repositories": {
                    "final_enabled_repositories": ["appstream", "baseos", "extras"],
                    "pre_admission_provider_repositories": [
                        "google-cloud-sdk",
                        "google-compute-engine"
                    ],
                },
                "ttl_seconds": 10800,
                "fixture": {
                    "input": "docker.io/library/alpine@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1",
                    "arm64_child": "sha256:4562b419adf48c5f3c763995d6014c123b3ce1d2e0ef2613b189779caa787192",
                },
            },
            profile,
        )

    def test_workflow_has_only_closed_operations_and_profile(self) -> None:
        document = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
        inputs = document["on"]["workflow_dispatch"]["inputs"]
        self.assertEqual(
            ["discover", "provision-and-prepare", "qualify", "destroy"],
            inputs["operation"]["options"],
        )
        self.assertEqual(
            ["gcp-rocky-10-2-arm64"], inputs["provider_profile"]["options"]
        )
        self.assertIn("^[0-9a-fA-F]{40}$", WORKFLOW.read_text(encoding="utf-8"))

    def test_target_execution_job_has_no_cloud_authority(self) -> None:
        document = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
        target = document["jobs"]["qualify_target"]
        self.assertEqual({"actions": "read", "contents": "read"}, target["permissions"])
        self.assertNotIn("environment", target)
        target_text = json.dumps(target, sort_keys=True)
        for forbidden in (
            "id-token",
            "google-github-actions/auth",
            "GOOGLE_OAUTH_ACCESS_TOKEN",
            "GCP_SERVICE_ACCOUNT",
            "credentials_file",
        ):
            self.assertNotIn(forbidden, target_text)

    def test_target_source_failure_is_wrapper_owned_and_bounded(self) -> None:
        document = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
        steps = {
            step["name"]: step
            for step in document["jobs"]["qualify_target"]["steps"]
            if "name" in step
        }
        execution = steps[
            "Execute exact target SHA once on the ready identity-free guest"
        ]
        retrieval = steps["Retrieve and validate bounded target-source failure"]
        publication = steps["Publish bounded target-source failure"]
        execution_run = execution["run"]
        retrieval_run = retrieval["run"]
        self.assertIn("81|82|83|84)", execution_run)
        self.assertIn("source_failure_expected=true", execution_run)
        self.assertIn("91)", execution_run)
        self.assertIn("qualification_failure_expected=true", execution_run)
        self.assertIn(
            "steps.target_execution.outputs.source_failure_expected == 'true'",
            retrieval["if"],
        )
        self.assertIn(
            "steps.target_execution.outputs.source_failure_expected == 'true'",
            publication["if"],
        )
        self.assertIn("test ! -L", retrieval_run)
        self.assertIn("head -c 1025", retrieval_run)
        self.assertIn("stat -c %s", retrieval_run)
        self.assertIn("-le 1024", retrieval_run)

        runner = (
            ROOT / "scripts/ci-cloud/run-rocky-target-qualification.sh"
        ).read_text(encoding="utf-8")
        for status in (81, 82, 83, 84):
            self.assertIn(f"exit {status}", runner)
        self.assertIn('if [[ "$status" -ne 0 ]]; then', runner)
        self.assertIn("validate-target-qualification-failure", runner)
        self.assertIn("exit 91", runner)

    def test_opentofu_consumes_only_exact_image_identity(self) -> None:
        main = (TF_ROOT / "main.tf").read_text(encoding="utf-8")
        variables = (TF_ROOT / "variables.tf").read_text(encoding="utf-8")
        self.assertNotIn("data \"google_compute_image\"", main)
        self.assertNotIn("family", main)
        self.assertRegex(main, r"image\s*=\s*var\.exact_image_self_link")
        self.assertIn("rocky-linux-cloud/global/images/", variables)
        self.assertIsNone(re.search(r"\bcount\s*=", main))
        self.assertEqual(1, main.count('resource "google_compute_instance"'))

    def test_rocky_contract_does_not_reuse_debian_admission(self) -> None:
        rocky_files = [WORKFLOW, PROFILE, *TF_ROOT.glob("*.tf")]
        text = "\n".join(path.read_text(encoding="utf-8") for path in rocky_files)
        for forbidden in ("debian-cloud", "apt-get", "AppArmor", "apparmor"):
            self.assertNotIn(forbidden, text)

    def test_schemas_are_closed_and_valid(self) -> None:
        for name in SCHEMA_NAMES:
            with self.subTest(name=name):
                document = json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
                Draft202012Validator.check_schema(document)
                self.assertFalse(document["additionalProperties"])

    def test_profile_validator_rejects_every_unreviewed_selector(self) -> None:
        valid = json.loads(PROFILE.read_text(encoding="utf-8"))
        mutations = (
            (("project",), "other-project"),
            (("zone",), "us-central1-a"),
            (("machine_type",), "c4a-standard-8"),
            (("instance_count",), 2),
            (("ttl_seconds",), 10801),
            (("disk", "size_gib"), 240),
            (("image", "project"), "other-images"),
            (("image", "discovery_family"), "rocky-linux-10"),
            (("repositories", "final_enabled_repositories"), ["baseos"]),
            (("repositories", "pre_admission_provider_repositories"), ["epel"]),
        )
        validator = ROOT / "scripts/ci-cloud/rocky-control.py"
        for path, value in mutations:
            with self.subTest(path=path), tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", suffix=".json"
            ) as candidate:
                mutated = deepcopy(valid)
                owner = mutated
                for key in path[:-1]:
                    owner = owner[key]
                owner[path[-1]] = value
                json.dump(mutated, candidate)
                candidate.flush()
                completed = subprocess.run(
                    [validator, "validate-profile", candidate.name],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(0, completed.returncode)

    def test_discovery_schema_rejects_moving_or_non_arm_image_identity(self) -> None:
        schema = json.loads(
            (ROOT / "schemas/rocky-cloud-discovery-evidence.schema.json").read_text(
                encoding="utf-8"
            )
        )
        validator = Draft202012Validator(schema)
        valid = {
            "schema_version": 1,
            "trusted_control_sha": "a" * 40,
            "provider": "google",
            "profile": "gcp-rocky-10-2-arm64",
            "image_project": "rocky-linux-cloud",
            "discovery_family": "rocky-linux-10-arm64",
            "exact_image_name": "rocky-linux-10-2-20260801-arm64",
            "exact_image_self_link": "https://www.googleapis.com/compute/v1/projects/rocky-linux-cloud/global/images/rocky-linux-10-2-20260801-arm64",
            "architecture": "ARM64",
            "image_creation_timestamp": "2026-08-01T00:00:00Z",
            "discovered_at": "2026-08-25T00:00:00Z",
        }
        self.assertFalse(list(validator.iter_errors(valid)))
        mutations = (
            ("exact_image_self_link", "https://www.googleapis.com/compute/v1/projects/rocky-linux-cloud/global/images/family/rocky-linux-10-arm64"),
            ("image_project", "debian-cloud"),
            ("architecture", "X86_64"),
            ("exact_image_name", ""),
            ("exact_image_self_link", "projects/user/global/images/custom"),
        )
        for key, value in mutations:
            with self.subTest(key=key, value=value):
                candidate = dict(valid)
                candidate[key] = value
                self.assertTrue(list(validator.iter_errors(candidate)))

    def test_preparation_schema_rejects_guest_and_security_drift(self) -> None:
        schema = json.loads(
            (ROOT / "schemas/rocky-cloud-preparation-evidence.schema.json").read_text(
                encoding="utf-8"
            )
        )
        properties = schema["properties"]
        self.assertEqual("10.2", properties["guest"]["properties"]["version_id"]["const"])
        self.assertEqual("aarch64", properties["guest"]["properties"]["uname_machine"]["const"])
        self.assertEqual("Enforcing", properties["selinux"]["properties"]["mode"]["const"])
        self.assertEqual(False, properties["repositories"]["properties"]["external_enabled"]["const"])
        self.assertEqual(False, properties["updates"]["properties"]["automatic"]["const"])
        self.assertEqual(True, properties["runtime"]["properties"]["socket_absent"]["const"])
        self.assertEqual(False, properties["service_account"]["properties"]["sudo"]["const"])
        self.assertEqual(False, properties["service_account"]["properties"]["quadlet_authority_writable"]["const"])

        package_names = [
            branch["contains"]["properties"]["name"]["const"]
            for branch in properties["packages"]["allOf"]
        ]
        document = {
            "schema_version": 1,
            "target_sha": "b" * 40,
            "run": {
                "repository": "SecPal/deployment",
                "trusted_control_sha": "a" * 40,
                "profile": "gcp-rocky-10-2-arm64",
                "run_id": "12345",
                "run_attempt": "1",
                "expires_at": 1800010800,
            },
            "image": {
                "project": "rocky-linux-cloud",
                "exact_self_link": "https://www.googleapis.com/compute/v1/projects/rocky-linux-cloud/global/images/rocky-linux-10-2-20260801-arm64",
            },
            "guest": {"id": "rocky", "version_id": "10.2", "uname_machine": "aarch64"},
            "hardware": {"cpu_count": 4, "memory_bytes": 16000000000, "root_filesystem_bytes": 120000000000},
            "repositories": {"enabled": ["baseos", "appstream", "extras"], "external_enabled": False},
            "updates": {"mechanism": "dnf4", "releasever": "10", "automatic": False, "automatic_reboot": False},
            "packages": [
                {"name": name, "nevra": f"{name}-1-1.aarch64", "resolved_repository": "baseos", "signature_verified": True, "signer_fingerprint": "fc226859c0860bf0ddb95b085b106c736fedfc85", "payload_digest": "a" * 64}
                for name in package_names
            ],
            "selinux": {"enabled": True, "mode": "Enforcing", "policy": "targeted", "container_selinux_installed": True, "label_disable_absent": True},
            "runtime": {"podman": "podman version 5.8.2", "rootless": True, "graphroot": "/home/secpal-runtime/.local/share/containers/storage", "oci_runtime": "crun", "cgroup_version": 2, "systemd_user": True, "network_backend": "netavark", "seccomp_available": True, "socket_absent": True, "api_dependency_absent": True},
            "service_account": {"name": "secpal-runtime", "uid": 991, "gid": 991, "home": "/home/secpal-runtime", "shell": "/usr/sbin/nologin", "sudo": False, "privileged_supplementary_groups": False, "subuid_start": 1048576, "subuid_count": 65536, "subgid_start": 1048576, "subgid_count": 65536, "subids_non_overlapping": True, "linger": True, "quadlet_authority_writable": False},
            "fixture": {"input": "docker.io/library/alpine@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1", "resolved_arm64_child": "sha256:4562b419adf48c5f3c763995d6014c123b3ce1d2e0ef2613b189779caa787192", "pre_staged": True},
            "persistence": {"rebooted": True, "boot_id_changed": True, "survived_reboot": True},
            "cloud_identity": {"control_service_account_absent": True, "credential_file_absent": True, "metadata_token_unavailable": True, "useful_project_authority_absent": True},
        }
        validator = Draft202012Validator(schema)
        self.assertFalse(list(validator.iter_errors(document)))
        mutations = (
            (("guest", "id"), "almalinux"),
            (("guest", "version_id"), "10.3"),
            (("guest", "uname_machine"), "x86_64"),
            (("selinux", "mode"), "Permissive"),
            (("repositories", "external_enabled"), True),
            (("updates", "automatic"), True),
            (("runtime", "socket_absent"), False),
            (("runtime", "api_dependency_absent"), False),
            (("service_account", "sudo"), True),
            (("service_account", "quadlet_authority_writable"), True),
            (("cloud_identity", "credential_file_absent"), False),
        )
        for path, value in mutations:
            with self.subTest(path=path):
                candidate = deepcopy(document)
                candidate[path[0]][path[1]] = value
                self.assertTrue(list(validator.iter_errors(candidate)))

    def test_preparation_failure_schema_is_closed_and_run_bound(self) -> None:
        schema = json.loads(
            (ROOT / "schemas/rocky-cloud-preparation-failure-evidence.schema.json").read_text(
                encoding="utf-8"
            )
        )
        validator = Draft202012Validator(schema)
        evidence = {
            "schema_version": 1,
            "target_sha": "b" * 40,
            "trusted_control_sha": "a" * 40,
            "run_id": "12345",
            "run_attempt": "1",
            "phase": "guest-identity",
            "exit_status": 1,
            "guest": {"id": "rocky", "version_id": "10.3", "uname_machine": "aarch64"},
        }
        self.assertFalse(list(validator.iter_errors(evidence)))
        control = ROOT / "scripts/ci-cloud/rocky-control.py"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "preparation-failure.json"
            path.write_text(json.dumps(evidence), encoding="utf-8")
            self.assertEqual(
                0,
                subprocess.run(
                    [control, "validate-evidence", "preparation-failure", path],
                    check=False,
                    capture_output=True,
                ).returncode,
            )
        mutations = (
            ("phase", "arbitrary-command"),
            ("target_sha", "short"),
            ("exit_status", "1"),
            ("diagnostic", "arbitrary stderr"),
        )
        for key, value in mutations:
            with self.subTest(key=key):
                candidate = dict(evidence)
                candidate[key] = value
                self.assertTrue(list(validator.iter_errors(candidate)))

    def test_runtime_admission_diagnostics_are_closed_and_controller_validated(self) -> None:
        schema = json.loads(
            (ROOT / "schemas/rocky-cloud-preparation-failure-evidence.schema.json").read_text(
                encoding="utf-8"
            )
        )
        validator = Draft202012Validator(schema)
        control = ROOT / "scripts/ci-cloud/rocky-control.py"
        operations = (
            "admit-runtime-rootless",
            "admit-runtime-oci-runtime",
            "admit-runtime-network-backend",
            "admit-runtime-seccomp",
            "admit-runtime-cgroup",
            "admit-runtime-systemd-user",
            "admit-runtime-socket-path-absence",
            "admit-runtime-socket-unit-disabled",
            "admit-runtime-container-host-absence",
            "admit-runtime-service-locality",
            "admit-runtime-podman-version",
        )
        base = {
            "schema_version": 1,
            "target_sha": "b" * 40,
            "trusted_control_sha": "a" * 40,
            "run_id": "12345",
            "run_attempt": "1",
            "phase": "evidence-collection",
            "exit_status": 1,
            "guest": {
                "id": "rocky",
                "version_id": "10.2",
                "uname_machine": "aarch64",
            },
            "collection_diagnostic": {
                "layer": "admission",
                "operation": "admit-runtime-rootless",
                "reason": "invariant-failed",
            },
        }
        for operation in operations:
            with self.subTest(operation=operation):
                document = deepcopy(base)
                document["collection_diagnostic"]["operation"] = operation
                self.assertFalse(list(validator.iter_errors(document)))
                with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as path:
                    json.dump(document, path)
                    path.flush()
                    completed = subprocess.run(
                        [control, "validate-evidence", "preparation-failure", path.name],
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                self.assertEqual(0, completed.returncode, completed.stderr)

        collapsed = deepcopy(base)
        collapsed["collection_diagnostic"]["operation"] = "admit-runtime"
        self.assertTrue(list(validator.iter_errors(collapsed)))
        with_subject = deepcopy(base)
        with_subject["collection_diagnostic"]["subject"] = "podman"
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as path:
            json.dump(with_subject, path)
            path.flush()
            completed = subprocess.run(
                [control, "validate-evidence", "preparation-failure", path.name],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(0, completed.returncode)

    def test_repository_failure_observation_is_bounded_and_phase_scoped(self) -> None:
        schema = json.loads(
            (ROOT / "schemas/rocky-cloud-preparation-failure-evidence.schema.json").read_text(
                encoding="utf-8"
            )
        )
        validator = Draft202012Validator(schema)
        base = {
            "schema_version": 1,
            "target_sha": "b" * 40,
            "trusted_control_sha": "a" * 40,
            "run_id": "12345",
            "run_attempt": "1",
            "phase": "repositories",
            "exit_status": 1,
            "guest": {"id": "rocky", "version_id": "10.2", "uname_machine": "aarch64"},
            "repositories": {
                "stage": "pre-admission",
                "enabled": ["appstream", "baseos", "epel", "extras"],
                "unexpected_enabled": ["epel"],
                "missing_required": [],
            },
            "repository_diagnostic": {
                "operation": "validate-initial-pre-admission",
                "reason": "postcondition-failed",
            },
        }
        self.assertFalse(list(validator.iter_errors(base)))
        mutations = (
            (("repositories", "enabled"), ["https://example.invalid/repo"]),
            (("repositories", "enabled"), ["a" for _ in range(17)]),
            (("repositories", "enabled"), ["bad repo id"]),
            (("repositories", "diagnostic"), "arbitrary command output"),
            (("repository_diagnostic", "operation"), "arbitrary-command"),
            (("repository_diagnostic", "reason"), "arbitrary stderr"),
            (("phase",), "packages"),
        )
        for path, value in mutations:
            with self.subTest(path=path):
                candidate = deepcopy(base)
                owner = candidate
                for key in path[:-1]:
                    owner = owner[key]
                owner[path[-1]] = value
                self.assertTrue(list(validator.iter_errors(candidate)))

    def test_repository_failure_diagnostic_is_closed_and_independently_validated(self) -> None:
        control = ROOT / "scripts/ci-cloud/rocky-control.py"

        def validate(diagnostic: dict[str, object]) -> int:
            document = {
                "schema_version": 1,
                "target_sha": "b" * 40,
                "trusted_control_sha": "a" * 40,
                "run_id": "12345",
                "run_attempt": "1",
                "phase": "repositories",
                "exit_status": 1,
                "guest": {"id": "rocky", "version_id": "10.2", "uname_machine": "aarch64"},
                "repository_diagnostic": diagnostic,
            }
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as path:
                json.dump(document, path)
                path.flush()
                return subprocess.run(
                    [control, "validate-evidence", "preparation-failure", path.name],
                    check=False,
                    capture_output=True,
                ).returncode

        self.assertEqual(
            0,
            validate(
                {
                    "operation": "install-repository-management-prerequisite",
                    "reason": "package-transaction-failed",
                }
            ),
        )
        self.assertEqual(
            0,
            validate(
                {
                    "operation": "validate-required-repository-definitions",
                    "reason": "required-repository-definition-unavailable",
                    "repository_id": "extras",
                }
            ),
        )
        self.assertEqual(
            0,
            validate(
                {
                    "operation": "enable-required-rocky-repository",
                    "reason": "repository-mutation-failed",
                    "repository_id": "extras",
                }
            ),
        )
        self.assertEqual(
            0,
            validate(
                {
                    "operation": "disable-reviewed-provider-repository",
                    "reason": "repository-mutation-failed",
                    "repository_id": "google-cloud-sdk",
                }
            ),
        )
        rejected = (
            {"operation": "arbitrary-command", "reason": "command-failed"},
            {"operation": "install-repository-management-prerequisite", "reason": "command-failed"},
            {
                "operation": "validate-required-repository-definitions",
                "reason": "required-repository-definition-unavailable",
            },
            {
                "operation": "validate-required-repository-definitions",
                "reason": "required-repository-definition-unavailable",
                "repository_id": "google-cloud-sdk",
            },
            {
                "operation": "validate-required-repository-definitions",
                "reason": "required-repository-definition-unavailable",
                "repository_id": "evil-external",
            },
            {
                "operation": "enable-required-rocky-repository",
                "reason": "repository-mutation-failed",
                "repository_id": "google-cloud-sdk",
            },
            {
                "operation": "disable-reviewed-provider-repository",
                "reason": "repository-mutation-failed",
                "repository_id": "evil-external",
            },
            {
                "operation": "observe-final-repository-state",
                "reason": "command-failed",
                "repository_id": "google-cloud-sdk",
            },
        )
        for diagnostic in rejected:
            with self.subTest(diagnostic=diagnostic):
                self.assertNotEqual(0, validate(diagnostic))

    def test_fixture_failure_diagnostic_is_closed_and_independently_validated(self) -> None:
        control = ROOT / "scripts/ci-cloud/rocky-control.py"

        def validate(
            diagnostic: dict[str, object] | None, *, phase: str = "fixture"
        ) -> int:
            document = {
                "schema_version": 1,
                "target_sha": "b" * 40,
                "trusted_control_sha": "a" * 40,
                "run_id": "12345",
                "run_attempt": "1",
                "phase": phase,
                "exit_status": 1,
                "guest": {"id": "rocky", "version_id": "10.2", "uname_machine": "aarch64"},
            }
            if diagnostic is not None:
                document["fixture_diagnostic"] = diagnostic
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as path:
                json.dump(document, path)
                path.flush()
                return subprocess.run(
                    [control, "validate-evidence", "preparation-failure", path.name],
                    check=False,
                    capture_output=True,
                ).returncode

        accepted = (
            {"operation": "pull-immutable-fixture", "reason": "command-failed"},
            {"operation": "verify-immutable-fixture-present", "reason": "command-failed"},
            {"operation": "inspect-resolved-arm64-child", "reason": "command-failed"},
            {"operation": "validate-resolved-arm64-child", "reason": "postcondition-failed"},
        )
        for diagnostic in accepted:
            with self.subTest(diagnostic=diagnostic):
                self.assertEqual(0, validate(diagnostic))
        rejected = (
            {"operation": "arbitrary-command", "reason": "command-failed"},
            {"operation": "pull-immutable-fixture", "reason": "postcondition-failed"},
            {"operation": "validate-resolved-arm64-child", "reason": "command-failed"},
            {
                "operation": "pull-immutable-fixture",
                "reason": "command-failed",
                "stderr": "arbitrary podman output",
            },
        )
        for diagnostic in rejected:
            with self.subTest(diagnostic=diagnostic):
                self.assertNotEqual(0, validate(diagnostic))
        self.assertNotEqual(0, validate(None))
        self.assertNotEqual(0, validate(accepted[0], phase="repositories"))

        preparation = (ROOT / "scripts/ci-cloud/prepare-rocky-host.sh").read_text(
            encoding="utf-8"
        )
        helper_start = preparation.index("set_fixture_diagnostic()")
        helper_end = preparation.index("\n}\n", helper_start) + len("\n}\n")
        helper = preparation[helper_start:helper_end]
        invalid_writer_pair = subprocess.run(
            [
                "bash",
                "-c",
                "set -euo pipefail\nfixture_diagnostic_evidence=''\n"
                + helper
                + "\nset_fixture_diagnostic pull-immutable-fixture postcondition-failed",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(0, invalid_writer_pair.returncode)

    def _run_fixture_admission(
        self,
        *,
        fail_pattern: str = "",
        inspected_digest: str = "sha256:" + "2" * 64,
        repo_digests: object | None = None,
    ) -> subprocess.CompletedProcess[str]:
        preparation = (ROOT / "scripts/ci-cloud/prepare-rocky-host.sh").read_text(
            encoding="utf-8"
        )
        preparation = preparation.replace(
            "/usr/local/sbin/secpal-collect-rocky-preparation",
            str(ROOT / "scripts/ci-cloud/collect-rocky-preparation.py"),
        )
        helper_start = preparation.index("set_fixture_diagnostic()")
        helper_end = preparation.index("\n}\n", helper_start) + len("\n}\n")
        helper = preparation[helper_start:helper_end]
        block_start = preparation.index('  current_phase="fixture"')
        block_end = preparation.index("\n\n  cat >/etc/sudoers.d/", block_start)
        block = preparation[block_start:block_end]
        fixture_contract = json.loads(PROFILE.read_text(encoding="utf-8"))["fixture"]
        fixture = fixture_contract["input"]
        arm_child = fixture_contract["arm64_child"]
        if repo_digests is None:
            repo_digests = [f"docker.io/library/alpine@{arm_child}"]
        script = (
            "set -euo pipefail\n"
            f"readonly fixture={fixture}\n"
            f"readonly arm_child={arm_child}\n"
            "readonly fixture_digest_identity_max=8\n"
            "readonly fixture_digest_metadata_max_bytes=1024\n"
            "fixture_diagnostic_evidence=''\n"
            + helper
            + "\nrun_as_runtime() {\n"
            + "  if [[ -n \"$FAIL_PATTERN\" && \"$*\" == *\"$FAIL_PATTERN\"* ]]; then printf '%s\\n' 'untrusted fixture stderr' >&2; return 1; fi\n"
            + "  if [[ \"$*\" == *'podman image inspect'*RepoDigests* ]]; then printf '%s\\n' \"$REPO_DIGESTS_JSON\";\n"
            + "  elif [[ \"$*\" == *'podman image inspect'* ]]; then printf '%s\\n' \"$INSPECTED_DIGEST\"; fi\n"
            + "}\n"
            + "set +e\n(\n  set -euo pipefail\n"
            + "  trap 'status=$?; printf \"STATUS=%s\\nDIAGNOSTIC=%s\\n\" \"$status\" \"$fixture_diagnostic_evidence\"; exit \"$status\"' EXIT\n"
            + block
            + "\n)\nstatus=$?\nset -e\nexit \"$status\"\n"
        )
        environment = dict(os.environ)
        environment.update(
            {
                "FAIL_PATTERN": fail_pattern,
                "INSPECTED_DIGEST": inspected_digest,
                "REPO_DIGESTS_JSON": json.dumps(repo_digests, separators=(",", ":")),
            }
        )
        return subprocess.run(
            ["bash", "-c", script],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )

    def test_fixture_failure_diagnostic_tracks_each_operation_without_untrusted_output(self) -> None:
        expected_child = json.loads(PROFILE.read_text(encoding="utf-8"))["fixture"]["arm64_child"]
        expected_reference = f"docker.io/library/alpine@{expected_child}"
        wrong_reference = "docker.io/library/alpine@sha256:" + "3" * 64
        cases = (
            (
                "podman pull",
                expected_child,
                [expected_reference],
                {"operation": "pull-immutable-fixture", "reason": "command-failed"},
            ),
            (
                "podman image exists",
                expected_child,
                [expected_reference],
                {"operation": "verify-immutable-fixture-present", "reason": "command-failed"},
            ),
            (
                "podman image inspect",
                expected_child,
                [expected_reference],
                {"operation": "inspect-resolved-arm64-child", "reason": "command-failed"},
            ),
            (
                "",
                "sha256:" + "3" * 64,
                [wrong_reference],
                {"operation": "validate-resolved-arm64-child", "reason": "postcondition-failed"},
            ),
        )
        for fail_pattern, digest, repo_digests, expected in cases:
            with self.subTest(operation=expected["operation"]):
                completed = self._run_fixture_admission(
                    fail_pattern=fail_pattern,
                    inspected_digest=digest,
                    repo_digests=repo_digests,
                )
                self.assertNotEqual(0, completed.returncode)
                diagnostic_line = next(
                    line
                    for line in completed.stdout.splitlines()
                    if line.startswith("DIAGNOSTIC=")
                )
                self.assertEqual(
                    expected, json.loads(diagnostic_line.removeprefix("DIAGNOSTIC="))
                )
                document = {
                    "schema_version": 1,
                    "target_sha": "b" * 40,
                    "trusted_control_sha": "a" * 40,
                    "run_id": "12345",
                    "run_attempt": "1",
                    "phase": "fixture",
                    "exit_status": completed.returncode,
                    "guest": {
                        "id": "rocky",
                        "version_id": "10.2",
                        "uname_machine": "aarch64",
                    },
                    "fixture_diagnostic": expected,
                }
                with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as path:
                    json.dump(document, path)
                    path.flush()
                    self.assertEqual(
                        0,
                        subprocess.run(
                            [
                                ROOT / "scripts/ci-cloud/rocky-control.py",
                                "validate-evidence",
                                "preparation-failure",
                                path.name,
                            ],
                            check=False,
                            capture_output=True,
                        ).returncode,
                    )
                if fail_pattern:
                    self.assertIn("untrusted fixture stderr", completed.stderr)
                self.assertNotIn("untrusted fixture stderr", completed.stdout)
        successful = self._run_fixture_admission()
        self.assertEqual(0, successful.returncode, successful.stderr)
        self.assertIn("DIAGNOSTIC=", successful.stdout)
        self.assertNotIn('DIAGNOSTIC={"operation"', successful.stdout)

    def test_fixture_child_admission_uses_complete_bounded_digest_membership(self) -> None:
        repository = "docker.io/library/alpine"
        parent_digest = "sha256:" + "1" * 64
        child_digest = json.loads(PROFILE.read_text(encoding="utf-8"))["fixture"]["arm64_child"]
        wrong_child_digest = "sha256:" + "3" * 64
        parent_reference = f"{repository}@{parent_digest}"
        child_reference = f"{repository}@{child_digest}"
        wrong_child_reference = f"{repository}@{wrong_child_digest}"

        accepted = (
            # Real run 33015901180: singular Digest may identify the parent while
            # RepoDigests still carries the exact locally associated ARM64 child.
            (parent_digest, [parent_reference, child_reference]),
            (child_digest, [child_reference]),
            (child_digest, [child_reference, parent_reference]),
        )
        for singular_digest, repo_digests in accepted:
            with self.subTest(accepted=repo_digests):
                completed = self._run_fixture_admission(
                    inspected_digest=singular_digest, repo_digests=repo_digests
                )
                self.assertEqual(0, completed.returncode, completed.stderr)

        rejected = (
            [parent_reference, wrong_child_reference],
            [parent_reference],
            [f"{repository}@sha256:" + "2" * 63 + "3"],
            [],
            [child_reference, child_reference],
            ["untrusted podman metadata"],
            {"digest": child_reference},
            [
                f"{repository}@sha256:{index:064x}"
                for index in range(1, 10)
            ],
            ["x" * 1100],
        )
        for repo_digests in rejected:
            with self.subTest(rejected=repo_digests):
                completed = self._run_fixture_admission(
                    inspected_digest=parent_digest, repo_digests=repo_digests
                )
                self.assertNotEqual(0, completed.returncode)
                diagnostic_line = next(
                    line
                    for line in completed.stdout.splitlines()
                    if line.startswith("DIAGNOSTIC=")
                )
                self.assertEqual(
                    {
                        "operation": "validate-resolved-arm64-child",
                        "reason": "postcondition-failed",
                    },
                    json.loads(diagnostic_line.removeprefix("DIAGNOSTIC=")),
                )
                self.assertNotIn("untrusted podman metadata", completed.stdout)

        preparation = (ROOT / "scripts/ci-cloud/prepare-rocky-host.sh").read_text(
            encoding="utf-8"
        )
        fixture_block = preparation[
            preparation.index('  current_phase="fixture"') : preparation.index(
                "\n\n  cat >/etc/sudoers.d/", preparation.index('  current_phase="fixture"')
            )
        ]
        self.assertIn(".RepoDigests", fixture_block)
        self.assertNotIn("{{.Digest}}", fixture_block)
        self.assertIn("--admit-fixture-repo-digests", fixture_block)
        self.assertIn("readonly fixture_digest_metadata_max_bytes=1024", preparation)

    def test_preparation_collector_uses_the_same_complete_fixture_digest_membership(self) -> None:
        collector = load_rocky_preparation_collector()
        collector_source = (
            ROOT / "scripts/ci-cloud/collect-rocky-preparation.py"
        ).read_text(encoding="utf-8")
        preparation = (ROOT / "scripts/ci-cloud/prepare-rocky-host.sh").read_text(
            encoding="utf-8"
        )
        schema = json.loads(
            (ROOT / "schemas/rocky-cloud-preparation-evidence.schema.json").read_text(
                encoding="utf-8"
            )
        )

        self.assertIn("{{json .RepoDigests}}", collector_source)
        self.assertNotIn("{{.Digest}}", collector_source)
        self.assertEqual(8, collector.FIXTURE_DIGEST_IDENTITY_MAX)
        self.assertEqual(1024, collector.FIXTURE_DIGEST_METADATA_MAX_BYTES)
        self.assertIn("--admit-fixture-repo-digests", preparation)
        self.assertIn("readonly fixture_digest_metadata_max_bytes=1024", preparation)
        self.assertEqual(
            collector.FIXTURE,
            schema["properties"]["fixture"]["properties"]["input"]["const"],
        )
        self.assertEqual(
            collector.ARM_CHILD,
            schema["properties"]["fixture"]["properties"]["resolved_arm64_child"][
                "const"
            ],
        )

        repository = collector.FIXTURE_REPOSITORY
        parent = f"{repository}@sha256:" + "1" * 64
        expected = f"{repository}@{collector.ARM_CHILD}"
        wrong_child = f"{repository}@sha256:" + "3" * 64

        # Run 33018858593: a singular Digest may be the parent/list identity,
        # while the complete local identities contain the reviewed ARM64 child.
        singular_digest = parent.removeprefix(f"{repository}@")
        self.assertNotEqual(collector.ARM_CHILD, singular_digest)
        accepted = (
            [parent, expected],
            [expected],
            [expected, parent],
        )
        for identities in accepted:
            with self.subTest(accepted=identities):
                self.assertEqual(
                    collector.ARM_CHILD,
                    collector.admitted_fixture_arm64_child(
                        json.dumps(identities, separators=(",", ":"))
                    ),
                )

        metadata_over_bound = json.dumps([expected], separators=(",", ":")) + " " * 1024
        rejected = (
            [parent],
            [parent, wrong_child],
            [expected + "0"],
            [f"docker.io/library/other@{collector.ARM_CHILD}"],
            ["untrusted podman output"],
            [],
            [expected, expected],
            [f"{repository}@sha256:{value:064x}" for value in range(1, 10)],
        )
        for identities in rejected:
            with self.subTest(rejected=identities):
                with self.assertRaises(collector.CollectionError) as error:
                    collector.admitted_fixture_arm64_child(
                        json.dumps(identities, separators=(",", ":"))
                    )
                self.assertNotIn("untrusted podman output", str(error.exception))
        with self.assertRaises(collector.CollectionError):
            collector.admitted_fixture_arm64_child(metadata_over_bound)

    def _run_repository_admission(
        self,
        enabled_states: list[list[str]],
        *,
        all_repositories: list[str] | None = None,
        fail_enabled_attempts: set[int] | None = None,
        fail_all_observation: bool = False,
        fail_install: bool = False,
        failure_noise: str = "",
        fail_config_command: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        preparation = (ROOT / "scripts/ci-cloud/prepare-rocky-host.sh").read_text(
            encoding="utf-8"
        )
        start = preparation.index("read_repository_ids()")
        end = preparation.index("\ninstall_policy()", start)
        functions = preparation[start:end]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = root / "profile.json"
            profile.write_text(PROFILE.read_text(encoding="utf-8"), encoding="utf-8")
            functions = functions.replace(
                "/opt/secpal-control/config/ci-cloud/gcp-rocky-10-2-arm64.json",
                str(profile),
            )
            state_file = root / "enabled-states"
            state_file.write_text(
                "\n".join(",".join(state) for state in enabled_states) + "\n",
                encoding="utf-8",
            )
            available = all_repositories or [
                "appstream",
                "baseos",
                "extras",
                "google-cloud-sdk",
                "google-compute-engine",
            ]
            fake_bin = root / "bin"
            fake_bin.mkdir()
            (fake_bin / "dnf4").write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "printf '%s\\n' \"$*\" >>\"$DNF_LOG\"\n"
                "if [[ \"$*\" == *\"--version\"* ]]; then printf '4.20.0\\n'; exit 0; fi\n"
                "if [[ \"$*\" == *\"repolist --enabled\"* ]]; then\n"
                "  count=0; [[ -f \"$DNF_COUNT\" ]] && count=$(cat \"$DNF_COUNT\")\n"
                "  count=$((count + 1)); printf '%s' \"$count\" >\"$DNF_COUNT\"\n"
                "  if [[ \",${DNF_FAIL_ENABLED_ATTEMPTS},\" == *\",${count},\"* ]]; then printf '%s\\n' \"$DNF_FAILURE_NOISE\" >&2; exit 1; fi\n"
                "  state=$(sed -n \"${count}p\" \"$DNF_STATES\")\n"
                "  printf 'repo id repo name\\n'; tr ',' '\\n' <<<\"$state\" | awk 'NF {print $1 \" test\"}'\n"
                "  exit 0\n"
                "fi\n"
                "if [[ \"$*\" == *\"repolist --all\"* ]]; then\n"
                "  [[ \"${DNF_FAIL_ALL_OBSERVATION}\" == true ]] && exit 1\n"
                "  printf 'repo id repo name\\n'; tr ',' '\\n' <<<\"$DNF_ALL\" | awk 'NF {print $1 \" test\"}'; exit 0\n"
                "fi\n"
                "if [[ \"$*\" == *\" install dnf-plugins-core\"* ]] && [[ \"${DNF_FAIL_INSTALL}\" == true ]]; then printf '%s\\n' \"$DNF_FAILURE_NOISE\" >&2; exit 1; fi\n"
                "if [[ -n \"${DNF_FAIL_CONFIG_COMMAND:-}\" && \"$*\" == *\"${DNF_FAIL_CONFIG_COMMAND}\"* ]]; then printf '%s\\n' \"$DNF_FAILURE_NOISE\" >&2; exit 1; fi\n"
                "exit 0\n",
                encoding="utf-8",
            )
            (fake_bin / "dnf4").chmod(0o700)
            script = (
                "set -euo pipefail\n"
                "readonly profile_path='" + str(profile) + "'\n"
                "readonly final_repositories=(appstream baseos extras)\n"
                "readonly enabled_repository_max=16\n"
                "readonly available_repository_definition_max=64\n"
                "repository_failure_evidence=''\n"
                "repository_diagnostic_evidence=''\n"
                + functions
                + "\nset +e\n(\n"
                + "  set -euo pipefail\n"
                + "  trap 'status=$?; printf \"FAILURE=%s\\nDIAGNOSTIC=%s\\n\" \"$repository_failure_evidence\" \"$repository_diagnostic_evidence\" >\"$DNF_RESULT\"; exit \"$status\"' EXIT\n"
                + "  admit_repositories\n"
                + ")\nstatus=$?\nset -e\n"
                + "printf 'STATUS=%s\\n' \"$status\"\ncat \"$DNF_RESULT\"\n"
                + "exit \"$status\"\n"
            )
            environment = dict(os.environ)
            environment.update(
                {
                    "PATH": f"{fake_bin}:{environment['PATH']}",
                    "DNF_LOG": str(root / "dnf.log"),
                    "DNF_RESULT": str(root / "result"),
                    "DNF_COUNT": str(root / "dnf.count"),
                    "DNF_STATES": str(state_file),
                    "DNF_ALL": ",".join(available),
                    "DNF_FAIL_ENABLED_ATTEMPTS": ",".join(
                        str(item) for item in sorted(fail_enabled_attempts or set())
                    ),
                    "DNF_FAIL_ALL_OBSERVATION": "true" if fail_all_observation else "false",
                    "DNF_FAIL_INSTALL": "true" if fail_install else "false",
                    "DNF_FAILURE_NOISE": failure_noise,
                    "DNF_FAIL_CONFIG_COMMAND": fail_config_command or "",
                }
            )
            completed = subprocess.run(
                ["bash", "-c", script], check=False, capture_output=True, text=True, env=environment
            )
            completed.dnf_log = (root / "dnf.log").read_text(encoding="utf-8")  # type: ignore[attr-defined]
            return completed

    def test_repository_admission_normalizes_only_the_reviewed_gcp_bootstrap_repositories(self) -> None:
        baseline = self._run_repository_admission([["appstream", "baseos", "extras"]])
        self.assertEqual(0, baseline.returncode, baseline.stderr)
        self.assertIn("FAILURE=", baseline.stdout)
        self.assertNotIn("config-manager", baseline.dnf_log)  # type: ignore[attr-defined]
        provider_sets = (
            ("google-cloud-sdk",),
            ("google-compute-engine",),
            ("google-cloud-sdk", "google-compute-engine"),
        )
        for providers in provider_sets:
            with self.subTest(providers=providers):
                initial = ["appstream", "baseos", "extras", *providers]
                normalized = self._run_repository_admission(
                    [initial, initial, ["appstream", "baseos", "extras"]]
                )
                self.assertEqual(0, normalized.returncode, normalized.stderr)
                log = normalized.dnf_log  # type: ignore[attr-defined]
                for provider in providers:
                    self.assertIn(f"config-manager --set-disabled {provider}", log)
                for transaction in (line for line in log.splitlines() if " install " in line):
                    self.assertIn("--disablerepo=*", transaction)
                    self.assertIn("--enablerepo=baseos,appstream,extras", transaction)

    def test_real_observed_provider_repositories_are_closed_and_unknown_repositories_fail(self) -> None:
        real_observed = self._run_repository_admission(
            [
                [
                    "appstream",
                    "baseos",
                    "extras",
                    "google-cloud-sdk",
                    "google-compute-engine",
                ],
                [
                    "appstream",
                    "baseos",
                    "extras",
                    "google-cloud-sdk",
                    "google-compute-engine",
                ],
                ["appstream", "baseos", "extras"],
            ]
        )
        self.assertEqual(0, real_observed.returncode, real_observed.stderr)
        for provider in ("google-cloud-sdk", "google-compute-engine"):
            self.assertIn(
                f"config-manager --set-disabled {provider}",
                real_observed.dnf_log,  # type: ignore[attr-defined]
            )
        unknown = self._run_repository_admission(
            [["appstream", "baseos", "evil-external", "extras", "google-cloud-sdk"]]
        )
        self.assertNotEqual(0, unknown.returncode)
        self.assertIn('"unexpected_enabled":["evil-external"]', unknown.stdout)
        self.assertNotIn(" install ", unknown.dnf_log)  # type: ignore[attr-defined]
        self.assertNotIn("config-manager --set-disabled", unknown.dnf_log)  # type: ignore[attr-defined]

    def test_available_repository_definitions_have_a_separate_bounded_cardinality(self) -> None:
        initial = [
            "appstream",
            "baseos",
            "extras",
            "google-cloud-sdk",
            "google-compute-engine",
        ]
        available = [
            "appstream",
            "baseos",
            "extras",
            *(f"disabled-definition-{index:02d}" for index in range(14)),
        ]
        normalized = self._run_repository_admission(
            [initial, initial, ["appstream", "baseos", "extras"]],
            all_repositories=available,
        )
        self.assertEqual(0, normalized.returncode, normalized.stderr)
        over_limit = self._run_repository_admission(
            [initial],
            all_repositories=[
                "appstream",
                "baseos",
                "extras",
                *(f"disabled-definition-{index:02d}" for index in range(62)),
            ],
        )
        self.assertNotEqual(0, over_limit.returncode)
        self.assertIn("repository observation exceeds the bounded limit", over_limit.stderr)

    def test_missing_rocky_repository_without_provider_staging_fails_closed(self) -> None:
        for repository in ("appstream", "baseos", "extras"):
            with self.subTest(repository=repository):
                enabled = [
                    item
                    for item in ("appstream", "baseos", "extras")
                    if item != repository
                ]
                failed = self._run_repository_admission([enabled])
                self.assertNotEqual(0, failed.returncode)
                self.assertIn(f'"missing_required":["{repository}"]', failed.stdout)
                self.assertNotIn(" install ", failed.dnf_log)  # type: ignore[attr-defined]

    def test_repository_admission_fails_closed_for_unknown_or_unobservable_state(self) -> None:
        unknown = self._run_repository_admission(
            [["appstream", "baseos", "epel", "extras"]]
        )
        self.assertNotEqual(0, unknown.returncode)
        self.assertIn('"unexpected_enabled":["epel"]', unknown.stdout)
        self.assertNotIn(" install ", unknown.dnf_log)  # type: ignore[attr-defined]
        dnf_failure = self._run_repository_admission(
            [["appstream", "baseos", "extras"]], fail_enabled_attempts={1}
        )
        self.assertNotEqual(0, dnf_failure.returncode)
        self.assertIn("dnf4 repository observation failed", dnf_failure.stderr)
        self.assertNotIn(" install ", dnf_failure.dnf_log)  # type: ignore[attr-defined]

    def test_repository_failure_diagnostics_identify_the_semantic_operation(self) -> None:
        def diagnostic(completed: subprocess.CompletedProcess[str]) -> dict[str, object]:
            line = next(line for line in completed.stdout.splitlines() if line.startswith("DIAGNOSTIC="))
            return json.loads(line.removeprefix("DIAGNOSTIC="))

        initial = ["appstream", "baseos", "extras", "google-cloud-sdk", "google-compute-engine"]
        cases = (
            (
                "all-observation",
                self._run_repository_admission([initial], fail_all_observation=True),
                {
                    "operation": "observe-available-repository-definitions",
                    "reason": "command-failed",
                },
            ),
            (
                "required-definition",
                self._run_repository_admission([initial], all_repositories=["appstream", "baseos"]),
                {
                    "operation": "validate-required-repository-definitions",
                    "reason": "required-repository-definition-unavailable",
                    "repository_id": "extras",
                },
            ),
            (
                "plugin-transaction",
                self._run_repository_admission([initial], fail_install=True),
                {
                    "operation": "install-repository-management-prerequisite",
                    "reason": "package-transaction-failed",
                },
            ),
            (
                "enable-mutation",
                self._run_repository_admission(
                    [["appstream", "baseos", "google-compute-engine"]],
                    fail_config_command="config-manager --set-enabled extras",
                ),
                {
                    "operation": "enable-required-rocky-repository",
                    "reason": "repository-mutation-failed",
                    "repository_id": "extras",
                },
            ),
            (
                "disable-mutation",
                self._run_repository_admission(
                    [initial, initial],
                    fail_config_command="config-manager --set-disabled google-cloud-sdk",
                ),
                {
                    "operation": "disable-reviewed-provider-repository",
                    "reason": "repository-mutation-failed",
                    "repository_id": "google-cloud-sdk",
                },
            ),
            (
                "final-postcondition",
                self._run_repository_admission([initial, initial, initial]),
                {
                    "operation": "validate-final-repository-state",
                    "reason": "postcondition-failed",
                },
            ),
        )
        for name, completed, expected in cases:
            with self.subTest(name=name):
                self.assertNotEqual(0, completed.returncode)
                self.assertEqual(expected, diagnostic(completed))

    def test_generated_missing_required_repository_diagnostic_is_trusted(self) -> None:
        failed = self._run_repository_admission(
            [["appstream", "baseos", "extras", "google-cloud-sdk", "google-compute-engine"]],
            all_repositories=["appstream", "baseos"],
        )
        self.assertNotEqual(0, failed.returncode)

        def output_record(name: str) -> dict[str, object]:
            line = next(
                line for line in failed.stdout.splitlines() if line.startswith(f"{name}=")
            )
            return json.loads(line.removeprefix(f"{name}="))

        document = {
            "schema_version": 1,
            "target_sha": "b" * 40,
            "trusted_control_sha": "a" * 40,
            "run_id": "12345",
            "run_attempt": "1",
            "phase": "repositories",
            "exit_status": 1,
            "guest": {"id": "rocky", "version_id": "10.2", "uname_machine": "aarch64"},
            "repositories": output_record("FAILURE"),
            "repository_diagnostic": output_record("DIAGNOSTIC"),
        }
        self.assertEqual(
            {
                "operation": "validate-required-repository-definitions",
                "reason": "required-repository-definition-unavailable",
                "repository_id": "extras",
            },
            document["repository_diagnostic"],
        )
        control = ROOT / "scripts/ci-cloud/rocky-control.py"
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as path:
            json.dump(document, path)
            path.flush()
            self.assertEqual(
                0,
                subprocess.run(
                    [control, "validate-evidence", "preparation-failure", path.name],
                    check=False,
                    capture_output=True,
                ).returncode,
            )

    def test_repository_failure_diagnostic_does_not_retain_stale_operation_context(self) -> None:
        failed = self._run_repository_admission(
            [
                ["appstream", "baseos", "extras", "google-compute-engine"],
                ["appstream", "baseos", "extras", "google-compute-engine"],
            ],
            fail_enabled_attempts={3},
            failure_noise="untrusted dnf stderr is not evidence",
        )
        self.assertNotEqual(0, failed.returncode)
        diagnostic_line = next(
            line for line in failed.stdout.splitlines() if line.startswith("DIAGNOSTIC=")
        )
        self.assertEqual(
            {
                "operation": "observe-final-repository-state",
                "reason": "command-failed",
            },
            json.loads(diagnostic_line.removeprefix("DIAGNOSTIC=")),
        )
        self.assertIn("untrusted dnf stderr is not evidence", failed.stderr)
        self.assertNotIn("untrusted dnf stderr is not evidence", failed.stdout)

    def test_repository_admission_requires_final_state_after_provider_normalization(self) -> None:
        missing_extras = self._run_repository_admission(
            [
                ["appstream", "baseos", "google-compute-engine"],
                ["appstream", "baseos", "extras", "google-compute-engine"],
                ["appstream", "baseos", "extras"],
            ]
        )
        self.assertEqual(0, missing_extras.returncode, missing_extras.stderr)
        self.assertIn("config-manager --set-enabled extras", missing_extras.dnf_log)  # type: ignore[attr-defined]
        still_enabled = self._run_repository_admission(
            [
                ["appstream", "baseos", "extras", "google-compute-engine"],
                ["appstream", "baseos", "extras", "google-compute-engine"],
                ["appstream", "baseos", "extras", "google-compute-engine"],
            ]
        )
        self.assertNotEqual(0, still_enabled.returncode)
        self.assertIn('"stage":"final-admission"', still_enabled.stdout)
        self.assertIn('"unexpected_enabled":["google-compute-engine"]', still_enabled.stdout)

    def test_repository_mutation_order_and_reentry_are_restart_safe(self) -> None:
        interrupted_enable = self._run_repository_admission(
            [["appstream", "baseos", "google-compute-engine"]],
            fail_config_command="config-manager --set-enabled extras",
        )
        self.assertNotEqual(0, interrupted_enable.returncode)
        self.assertIn("config-manager --set-enabled extras", interrupted_enable.dnf_log)  # type: ignore[attr-defined]
        self.assertNotIn("config-manager --set-disabled google-compute-engine", interrupted_enable.dnf_log)  # type: ignore[attr-defined]
        ordered = self._run_repository_admission(
            [
                ["appstream", "baseos", "google-compute-engine"],
                ["appstream", "baseos", "extras", "google-compute-engine"],
                ["appstream", "baseos", "extras"],
            ]
        )
        self.assertEqual(0, ordered.returncode, ordered.stderr)
        ordered_log = ordered.dnf_log  # type: ignore[attr-defined]
        self.assertLess(
            ordered_log.index("config-manager --set-enabled extras"),
            ordered_log.index("config-manager --set-disabled google-compute-engine"),
        )
        resumed = self._run_repository_admission(
            [
                ["appstream", "baseos", "extras", "google-compute-engine"],
                ["appstream", "baseos", "extras", "google-compute-engine"],
                ["appstream", "baseos", "extras"],
            ]
        )
        self.assertEqual(0, resumed.returncode, resumed.stderr)
        self.assertIn(
            "config-manager --set-disabled google-compute-engine",
            resumed.dnf_log,  # type: ignore[attr-defined]
        )

    def test_repository_snapshot_is_cleared_before_failed_post_mutation_observation(self) -> None:
        failed = self._run_repository_admission(
            [
                ["appstream", "baseos", "extras", "google-compute-engine"],
                ["appstream", "baseos", "extras", "google-compute-engine"],
            ],
            fail_enabled_attempts={3},
        )
        self.assertNotEqual(0, failed.returncode)
        self.assertIn("config-manager --set-disabled google-compute-engine", failed.dnf_log)  # type: ignore[attr-defined]
        self.assertIn("FAILURE=", failed.stdout)
        self.assertNotIn('"stage"', failed.stdout)

    def test_preparation_failure_repository_classification_is_recomputed_by_trusted_control(self) -> None:
        control = ROOT / "scripts/ci-cloud/rocky-control.py"

        def validate(repositories: dict[str, object]) -> int:
            document = {
                "schema_version": 1,
                "target_sha": "b" * 40,
                "trusted_control_sha": "a" * 40,
                "run_id": "12345",
                "run_attempt": "1",
                "phase": "repositories",
                "exit_status": 1,
                "guest": {"id": "rocky", "version_id": "10.2", "uname_machine": "aarch64"},
                "repositories": repositories,
            }
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as path:
                json.dump(document, path)
                path.flush()
                return subprocess.run(
                    [control, "validate-evidence", "preparation-failure", path.name],
                    check=False,
                    capture_output=True,
                ).returncode

        self.assertEqual(
            0,
            validate(
                {
                    "stage": "pre-admission",
                    "enabled": ["appstream", "baseos", "extras", "google-cloud-sdk", "google-compute-engine"],
                    "unexpected_enabled": [],
                    "missing_required": [],
                }
            ),
        )
        self.assertEqual(
            0,
            validate(
                {
                    "stage": "pre-admission",
                    "enabled": ["appstream", "baseos", "epel", "extras", "zrepo"],
                    "unexpected_enabled": ["epel", "zrepo"],
                    "missing_required": [],
                }
            ),
        )
        self.assertEqual(
            0,
            validate(
                {
                    "stage": "final-admission",
                    "enabled": ["appstream", "baseos", "extras", "google-compute-engine"],
                    "unexpected_enabled": ["google-compute-engine"],
                    "missing_required": [],
                }
            ),
        )
        rejected = (
            {"stage": "pre-admission", "enabled": ["epel"], "unexpected_enabled": [], "missing_required": []},
            {"stage": "pre-admission", "enabled": ["appstream", "baseos", "google-cloud-sdk", "google-compute-engine"], "unexpected_enabled": [], "missing_required": []},
            {"stage": "pre-admission", "enabled": ["appstream", "baseos", "epel", "extras", "zrepo"], "unexpected_enabled": ["epel"], "missing_required": []},
            {"stage": "pre-admission", "enabled": ["extras", "baseos", "appstream"], "unexpected_enabled": [], "missing_required": []},
        )
        for repositories in rejected:
            with self.subTest(repositories=repositories):
                self.assertNotEqual(0, validate(repositories))

    def test_failure_evidence_maximum_payload_and_defensive_fallback_are_bounded(self) -> None:
        maximum_ids = sorted(
            f"x{index:02d}" + "a" * 61 for index in range(16)
        )
        document = (
            '{"schema_version":1,"target_sha":"' + "a" * 40
            + '","trusted_control_sha":"' + "b" * 40
            + '","run_id":"' + "9" * 20
            + '","run_attempt":"999","phase":"repositories","exit_status":255,'
            + '"guest":{"id":"' + "c" * 64
            + '","version_id":"' + "d" * 64
            + '","uname_machine":"' + "e" * 64
            + '"},"repositories":{"stage":"pre-admission","enabled":'
            + json.dumps(maximum_ids, separators=(",", ":"))
            + ',"unexpected_enabled":'
            + json.dumps(maximum_ids, separators=(",", ":"))
            + ',"missing_required":'
            + json.dumps(["appstream", "baseos", "extras"], separators=(",", ":"))
            + '},"repository_diagnostic":{"operation":"validate-initial-pre-admission",'
            + '"reason":"postcondition-failed"}}\n'
        ).encode("utf-8")
        schema = json.loads(
            (ROOT / "schemas/rocky-cloud-preparation-failure-evidence.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertFalse(list(Draft202012Validator(schema).iter_errors(json.loads(document))))
        self.assertLessEqual(len(document), 4096)
        fixture_document = {
            "schema_version": 1,
            "target_sha": "a" * 40,
            "trusted_control_sha": "b" * 40,
            "run_id": "9" * 20,
            "run_attempt": "999",
            "phase": "fixture",
            "exit_status": 255,
            "guest": {
                "id": "c" * 64,
                "version_id": "d" * 64,
                "uname_machine": "e" * 64,
            },
            "fixture_diagnostic": {
                "operation": "validate-resolved-arm64-child",
                "reason": "postcondition-failed",
            },
        }
        fixture_payload = (
            json.dumps(fixture_document, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        self.assertFalse(list(Draft202012Validator(schema).iter_errors(fixture_document)))
        self.assertLessEqual(len(fixture_payload), 4096)
        with tempfile.NamedTemporaryFile(mode="wb") as path:
            path.write(document)
            path.flush()
            self.assertEqual(
                0,
                subprocess.run(
                    [
                        ROOT / "scripts/ci-cloud/rocky-control.py",
                        "validate-evidence",
                        "preparation-failure",
                        path.name,
                    ],
                    check=False,
                    capture_output=True,
                ).returncode,
            )
        preparation = (ROOT / "scripts/ci-cloud/prepare-rocky-host.sh").read_text(encoding="utf-8")
        start = preparation.index("write_failure_document()")
        end = preparation.index("\nclear_repository_failure()", start)
        function = preparation[start:end]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "failure.json"
            completed = subprocess.run(
                [
                    "bash",
                    "-c",
                    "failure_evidence_max_bytes=20\n"
                    + function
                    + "\nwrite_failure_document '{\"base\":1}' '{\"repositories\":\"oversized\"}' '{\"operation\":\"install-repository-management-prerequisite\",\"reason\":\"package-transaction-failed\"}' '' '' \"$1\"\ncat \"$1\"",
                    "bash",
                    str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual('{"base":1}\n', completed.stdout)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "fixture-failure.json"
            completed = subprocess.run(
                [
                    "bash",
                    "-c",
                    "failure_evidence_max_bytes=20\n"
                    + function
                    + "\nwrite_failure_document '{\"base\":1}' '' '' '{\"operation\":\"validate-resolved-arm64-child\",\"reason\":\"postcondition-failed\"}' '' \"$1\"\ncat \"$1\"",
                    "bash",
                    str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual('{"base":1}\n', completed.stdout)

    def test_preparation_failure_transport_is_closed_and_reboot_safe(self) -> None:
        preparation = (ROOT / "scripts/ci-cloud/prepare-rocky-host.sh").read_text(
            encoding="utf-8"
        )
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('current_phase="guest-identity"', preparation)
        self.assertIn("preparation-failure.json", preparation)
        self.assertIn("trap 'preparation_exit", preparation)
        self.assertIn("reboot_requested=true", preparation)
        self.assertIn("preparation-failure.json", workflow)
        self.assertIn("ROCKY_PREPARATION_EVIDENCE_TIMEOUT", workflow)
        self.assertIn("rocky-cloud-preparation-failure-${{ github.run_id }}-${{ github.run_attempt }}", workflow)
        self.assertIn("validate-evidence preparation-failure", workflow)
        self.assertIn("repository_operation=", workflow)
        self.assertIn("repository_reason=", workflow)
        self.assertIn("fixture_operation=", workflow)
        self.assertIn("fixture_reason=", workflow)
        self.assertIn("steps.preparation.outputs.failure == 'true'", workflow)
        self.assertIn('install -d -o root -g secpal-cloud -m 0710 "$state_root"', preparation)
        self.assertIn('install -d -o root -g secpal-cloud -m 0750 "$state_root/evidence"', preparation)
        self.assertIn('chown root:secpal-cloud "$evidence_output"', preparation)
        self.assertIn('chmod 0440 "$evidence_output"', preparation)
        self.assertNotIn('chmod 0400 "$evidence_output"', preparation)
        self.assertIn('chown root:secpal-cloud "$temporary" && chmod 0440', preparation)

    def _run_workflow_preparation_poll(
        self, states: list[str], *, include_timeout: bool = False
    ) -> subprocess.CompletedProcess[str]:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        start = workflow.index("          preparation_state=none")
        if include_timeout:
            end = workflow.index("\n\n      - name: Publish bounded preparation failure evidence", start)
        else:
            end = workflow.index('          if [[ "$preparation_state" == failure ]]', start)
        block = "\n".join(
            line[10:] if line.startswith("          ") else line
            for line in workflow[start:end].splitlines()
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            states_path = root / "states"
            states_path.write_text("\n".join(states) + "\n", encoding="utf-8")
            (fake_bin / "ssh").write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "count=0\n"
                "[[ -f \"$POLL_COUNTER\" ]] && count=$(cat \"$POLL_COUNTER\")\n"
                "count=$((count + 1))\n"
                "printf '%s' \"$count\" >\"$POLL_COUNTER\"\n"
                "printf 'FAKE_SSH_ATTEMPT=%s\\n' \"$count\" >&2\n"
                "state=$(sed -n \"${count}p\" \"$POLL_STATES\")\n"
                "[[ \"$state\" == transport ]] && exit 255\n"
                "printf '%s' \"$state\"\n",
                encoding="utf-8",
            )
            (fake_bin / "sleep").write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
            for executable in fake_bin.iterdir():
                executable.chmod(0o700)
            script = (
                "set -euo pipefail\n"
                "ip=198.51.100.10\n"
                "RUNNER_TEMP=$(mktemp -d)\n"
                "mkdir -p \"$RUNNER_TEMP/rocky-cloud\"\n"
                "touch \"$RUNNER_TEMP/rocky-cloud/id_ed25519\"\n"
                f"{block}\n"
                "printf 'FINAL_STATE=%s\\n' \"$preparation_state\"\n"
            )
            environment = dict(os.environ)
            environment.update(
                {
                    "PATH": f"{fake_bin}:{environment['PATH']}",
                    "POLL_COUNTER": str(root / "counter"),
                    "POLL_STATES": str(states_path),
                    "GITHUB_OUTPUT": str(root / "github-output"),
                }
            )
            return subprocess.run(
                ["bash", "-c", script],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
            )

    def test_preparation_poll_retries_transport_failures_then_reaches_evidence(self) -> None:
        failure = self._run_workflow_preparation_poll(
            ["transport", "transport", "failure"]
        )
        self.assertEqual(0, failure.returncode, failure.stderr)
        self.assertIn("FINAL_STATE=failure", failure.stdout)
        self.assertEqual(3, failure.stderr.count("FAKE_SSH_ATTEMPT="))
        success = self._run_workflow_preparation_poll(["transport", "success"])
        self.assertEqual(0, success.returncode, success.stderr)
        self.assertIn("FINAL_STATE=success", success.stdout)
        self.assertEqual(2, success.stderr.count("FAKE_SSH_ATTEMPT="))

    def test_preparation_poll_rejects_malformed_and_both_evidence_state(self) -> None:
        for state in ("garbage", "both"):
            with self.subTest(state=state):
                completed = self._run_workflow_preparation_poll([state])
                self.assertNotEqual(0, completed.returncode)
                self.assertNotIn("FINAL_STATE=success", completed.stdout)

    def test_preparation_poll_attempt_ninety_reaches_timeout_diagnostic(self) -> None:
        completed = self._run_workflow_preparation_poll(["transport"] * 90, include_timeout=True)
        self.assertNotEqual(0, completed.returncode)
        self.assertIn("ROCKY_PREPARATION_EVIDENCE_TIMEOUT", completed.stderr)
        self.assertEqual(90, completed.stderr.count("FAKE_SSH_ATTEMPT="))

    def test_continuation_rejects_expiry_target_mismatch_and_instance_only(self) -> None:
        validator = ROOT / "scripts/ci-cloud/rocky-control.py"
        with tempfile.TemporaryDirectory() as directory:
            continuation = Path(directory) / "continuation.json"
            subprocess.run(
                [
                    validator,
                    "create-continuation",
                    "--control-sha",
                    "a" * 40,
                    "--target-sha",
                    "b" * 40,
                    "--run-id",
                    "12345",
                    "--run-attempt",
                    "1",
                    "--image",
                    "https://www.googleapis.com/compute/v1/projects/rocky-linux-cloud/global/images/rocky-linux-10-2-20260801-arm64",
                    "--instance-id",
                    "987654",
                    "--instance-name",
                    "sprk-12345-1-instance",
                    "--created-at",
                    "1800000000",
                    "--expires-at",
                    "1800010800",
                    "--output",
                    continuation,
                ],
                check=True,
            )
            base = [
                validator,
                "validate-continuation",
                continuation,
                "--control-sha",
                "a" * 40,
                "--target-sha",
                "b" * 40,
                "--source-run-id",
                "12345",
                "--source-run-attempt",
                "1",
                "--now",
                "1800000000",
            ]
            self.assertEqual(
                0, subprocess.run(base, check=False, capture_output=True).returncode
            )
            expired = [*base[:-1], "1800010800"]
            mismatch = list(base)
            mismatch[mismatch.index("b" * 40)] = "c" * 40
            self.assertNotEqual(
                0, subprocess.run(expired, check=False, capture_output=True).returncode
            )
            self.assertNotEqual(
                0, subprocess.run(mismatch, check=False, capture_output=True).returncode
            )
            document = json.loads(continuation.read_text(encoding="utf-8"))
            continuation.write_text(json.dumps({"instance_name": document["instance_name"]}), encoding="utf-8")
            self.assertNotEqual(
                0, subprocess.run(base, check=False, capture_output=True).returncode
            )

    def test_trusted_preparation_is_rocky_selinux_and_dnf_only(self) -> None:
        preparation = (
            ROOT / "scripts/ci-cloud/prepare-rocky-host.sh"
        ).read_text(encoding="utf-8")
        for required in (
            "VERSION_ID=10.2",
            "uname -m",
            "aarch64",
            "dnf4",
            "baseos,appstream,extras",
            "getenforce",
            "Enforcing",
            "selinux-policy-targeted",
            "container-selinux",
            "65536",
            "/usr/sbin/nologin",
            "loginctl enable-linger",
            "podman.socket",
        ):
            self.assertIn(required, preparation)
        for forbidden in ("apt-get", "AppArmor", "setenforce 0", "label=disable"):
            self.assertNotIn(forbidden, preparation)
        self.assertIn(
            "systemctl mask --now podman.socket podman.service", preparation
        )
        self.assertIn(
            "run_as_runtime systemctl --user mask --now podman.socket podman.service",
            preparation,
        )
        self.assertIn("-u CONTAINER_HOST", preparation)
        self.assertIn("-u CONTAINER_CONNECTION", preparation)

    def test_repository_staging_preserves_provider_guest_environment_and_final_contract(self) -> None:
        preparation = (ROOT / "scripts/ci-cloud/prepare-rocky-host.sh").read_text(
            encoding="utf-8"
        )
        collector = (ROOT / "scripts/ci-cloud/collect-rocky-preparation.py").read_text(
            encoding="utf-8"
        )
        self.assertEqual(
            ["google-cloud-sdk", "google-compute-engine"],
            json.loads(PROFILE.read_text(encoding="utf-8"))["repositories"]["pre_admission_provider_repositories"],
        )
        self.assertIn("config-manager --set-disabled", preparation)
        self.assertNotIn("remove google-guest-agent", preparation)
        self.assertNotIn("disable google-guest-agent", preparation)
        self.assertIn("dnf-plugins-core", preparation)
        self.assertIn("dnf-plugins-core", (ROOT / "scripts/ci-cloud/rocky_preparation_contract.py").read_text(encoding="utf-8"))
        self.assertIn("--disablerepo='*'", preparation)
        self.assertIn("--enablerepo=baseos,appstream,extras", preparation)
        evidence_contract = (
            ROOT / "scripts/ci-cloud/rocky_preparation_contract.py"
        ).read_text(encoding="utf-8")
        self.assertIn("if set(repositories) != REPOSITORIES or len(repositories) != 3", evidence_contract)

    def test_cleanup_is_exact_state_and_janitor_never_uses_prefix(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        janitor = (ROOT / "scripts/ci-cloud/gcp-rocky-janitor.py").read_text(encoding="utf-8")
        self.assertIn("tofu destroy --auto-approve --input=false", workflow)
        self.assertIn("rocky-cloud-continuation", workflow)
        self.assertNotIn("startswith", janitor)
        self.assertNotIn("namePrefix", janitor)

    def test_qualification_admission_is_observation_derived_and_pass_only(self) -> None:
        schema = json.loads((ROOT / "schemas/rocky-cloud-qualification-evidence.schema.json").read_text(encoding="utf-8"))
        self.assertNotIn("positive_access", schema["required"])
        runner = (ROOT / "scripts/ci-cloud/run-rocky-target-qualification.sh").read_text(encoding="utf-8")
        for required in ("duplicate", "MCS relationship", "seccomp mode", "ausearch", "correlated enforcing AVC", "cleanup is incomplete"):
            self.assertIn(required, runner)
        self.assertNotIn('"mcs_distinct": passed', runner)
        self.assertNotIn('"classification": "PASS" if passed', runner)

    def test_transition_rejects_replacement_with_same_name_and_labels(self) -> None:
        transition_path = ROOT / "scripts/ci-cloud/rocky-gcp-transition.py"
        spec = importlib.util.spec_from_file_location("rocky_transition", transition_path)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        options = SimpleNamespace(instance="sprk-12345-1-instance", instance_id="987654", target_sha="b" * 40, control_sha="a" * 40, created_at="1800000000", expires_at="1800010800")
        labels = {"secpal_ci_owner": "rocky-host-qualification", "repository": "secpal-deployment", "github_run_id": "12345", "github_run_attempt": "1", "target_sha": "b" * 40, "control_sha": "a" * 40, "provider_profile": "gcp-rocky-10-2-arm64", "created_at": "1800000000", "expires_at": "1800010800"}
        accepted = {"name": options.instance, "id": "987654", "labels": labels, "serviceAccounts": []}
        module.validate_instance(accepted, options)
        replaced = dict(accepted, id="987655")
        with self.assertRaises(module.TransitionError):
            module.validate_instance(replaced, options)

    def test_bootstrap_identity_admission_normalizes_only_empty_scope_forms(self) -> None:
        transition_path = ROOT / "scripts/ci-cloud/rocky-gcp-transition.py"
        spec = importlib.util.spec_from_file_location("rocky_transition", transition_path)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        bootstrap = "secpal-ci-bootstrap@secpal-dev.iam.gserviceaccount.com"
        accepted = (
            {},
            {"serviceAccounts": []},
            {"serviceAccounts": [{"email": bootstrap, "scopes": []}]},
            {"serviceAccounts": [{"email": bootstrap}]},
            {"serviceAccounts": [{"email": bootstrap, "scopes": None}]},
        )
        for instance in accepted:
            with self.subTest(instance=instance):
                module.validate_service_accounts(instance)
        rejected = (
            {"serviceAccounts": None},
            {"serviceAccounts": {}},
            {"serviceAccounts": [{"email": bootstrap}, {"email": bootstrap}]},
            {"serviceAccounts": [{"email": "other@secpal-dev.iam.gserviceaccount.com"}]},
            {"serviceAccounts": [{"email": "123-compute@developer.gserviceaccount.com"}]},
            {"serviceAccounts": [{"email": "gcp-service-account@secpal-dev.iam.gserviceaccount.com"}]},
            {"serviceAccounts": [{"email": bootstrap, "scopes": ["https://www.googleapis.com/auth/cloud-platform"]}]},
            {"serviceAccounts": [{"email": bootstrap, "scopes": ["arbitrary"]}]},
            {"serviceAccounts": [{"email": bootstrap, "scopes": ""}]},
            {"serviceAccounts": [{"email": bootstrap, "scopes": {}}]},
            {"serviceAccounts": [{"email": bootstrap, "scopes": True}]},
            {"serviceAccounts": [{"email": bootstrap, "scopes": 0}]},
        )
        for instance in rejected:
            with self.subTest(instance=instance), self.assertRaises(module.TransitionError):
                module.validate_service_accounts(instance)

    def test_transition_binds_each_boot_to_the_current_access_run(self) -> None:
        transition_path = ROOT / "scripts/ci-cloud/rocky-gcp-transition.py"
        spec = importlib.util.spec_from_file_location("rocky_transition", transition_path)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        instance = {
            "metadata": {
                "fingerprint": "exact-fingerprint",
                "items": [
                    {"key": "startup-script", "value": "trusted"},
                    {"key": "secpal-rocky-access-run-id", "value": "old"},
                    {"key": "secpal-rocky-access-run-attempt", "value": "old"},
                ],
            }
        }
        payload = module.metadata_payload(
            instance,
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJg27OkflrkqeiB5KIy9PTGqXLI22JkP42HA2U5zAF6n secpal-rocky-33146182082-1",
            "33146182082",
            "1",
        )
        items = {item["key"]: item["value"] for item in payload["items"]}
        self.assertEqual("33146182082", items["secpal-rocky-access-run-id"])
        self.assertEqual("1", items["secpal-rocky-access-run-attempt"])
        self.assertEqual("true", items["secpal-rocky-cloud-identity-admitted"])
        self.assertEqual("trusted", items["startup-script"])
        self.assertEqual(len(items), len(payload["items"]))
    def test_runner_firewall_rotation_uses_classic_patch_without_fingerprint(self) -> None:
        transition_path = ROOT / "scripts/ci-cloud/rocky-gcp-transition.py"
        spec = importlib.util.spec_from_file_location("rocky_transition", transition_path)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        labels = {
            "secpal_ci_owner": "rocky-host-qualification",
            "repository": "secpal-deployment",
            "github_run_id": "12345",
            "github_run_attempt": "1",
            "target_sha": "b" * 40,
            "control_sha": "a" * 40,
            "provider_profile": "gcp-rocky-10-2-arm64",
            "created_at": "1800000000",
            "expires_at": "1800010800",
        }
        name = "sprk-12345-1-ssh"
        expected_description = {
            "o": labels["secpal_ci_owner"], "r": labels["repository"],
            "i": labels["github_run_id"], "a": labels["github_run_attempt"],
            "t": labels["target_sha"], "c": labels["control_sha"],
            "p": labels["provider_profile"], "n": labels["created_at"],
            "x": labels["expires_at"],
        }

        def firewall(source_ranges: list[str]) -> dict[str, object]:
            return {
                "name": name,
                "description": json.dumps(expected_description, separators=(",", ":")),
                "network": "https://www.googleapis.com/compute/v1/projects/secpal-dev/global/networks/sprk-12345-1-network",
                "priority": 1000,
                "direction": "INGRESS",
                "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
                "targetTags": ["sprk-12345-1"],
                "sourceRanges": source_ranges,
            }

        class FakeClient:
            def __init__(self, responses: list[dict[str, object]]) -> None:
                self.responses = responses
                self.requests: list[tuple[str, str]] = []
                self.mutations: list[tuple[str, dict[str, object], bool, str]] = []

            def request(self, method: str, path: str) -> dict[str, object]:
                self.requests.append((method, path))
                return deepcopy(self.responses.pop(0))

            def mutate(self, path: str, payload: dict[str, object], *, global_operation: bool, method: str) -> None:
                self.mutations.append((path, payload, global_operation, method))

        client = FakeClient([firewall(["198.51.100.10/32"]), firewall(["203.0.113.10/32"])])
        module.update_runner_firewall(client, "sprk-12345-1-instance", "203.0.113.10", labels)
        self.assertEqual(
            [("global/firewalls/sprk-12345-1-ssh", {"sourceRanges": ["203.0.113.10/32"]}, True, "PATCH")],
            client.mutations,
        )
        self.assertNotIn("fingerprint", client.mutations[0][1])
        self.assertEqual(
            [("GET", "global/firewalls/sprk-12345-1-ssh"), ("GET", "global/firewalls/sprk-12345-1-ssh")],
            client.requests,
        )

    def test_runner_firewall_rotation_rejects_unreviewed_pre_or_post_patch_state(self) -> None:
        transition_path = ROOT / "scripts/ci-cloud/rocky-gcp-transition.py"
        spec = importlib.util.spec_from_file_location("rocky_transition", transition_path)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        labels = {
            "secpal_ci_owner": "rocky-host-qualification", "repository": "secpal-deployment",
            "github_run_id": "12345", "github_run_attempt": "1", "target_sha": "b" * 40,
            "control_sha": "a" * 40, "provider_profile": "gcp-rocky-10-2-arm64",
            "created_at": "1800000000", "expires_at": "1800010800",
        }
        name = "sprk-12345-1-ssh"
        description = {"o": labels["secpal_ci_owner"], "r": labels["repository"], "i": labels["github_run_id"], "a": labels["github_run_attempt"], "t": labels["target_sha"], "c": labels["control_sha"], "p": labels["provider_profile"], "n": labels["created_at"], "x": labels["expires_at"]}

        def valid() -> dict[str, object]:
            return {"name": name, "description": json.dumps(description), "network": "https://www.googleapis.com/compute/v1/projects/secpal-dev/global/networks/sprk-12345-1-network", "priority": 1000, "direction": "INGRESS", "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}], "targetTags": ["sprk-12345-1"], "sourceRanges": ["198.51.100.10/32"]}

        class FakeClient:
            def __init__(self, responses: list[dict[str, object]]) -> None:
                self.responses, self.mutations = responses, []

            def request(self, method: str, path: str) -> dict[str, object]:
                return deepcopy(self.responses.pop(0))

            def mutate(self, path: str, payload: dict[str, object], *, global_operation: bool, method: str) -> None:
                self.mutations.append((path, payload, global_operation, method))

        pre_mutations: list[tuple[str, object]] = [
            ("name", "sprk-99999-1-ssh"), ("description", "{}"), ("network", "wrong"),
            ("direction", "EGRESS"), ("priority", 999), ("disabled", True),
            ("allowed", [{"IPProtocol": "tcp", "ports": ["2222"]}]),
            ("targetTags", ["other"]), ("targetTags", ["sprk-12345-1", "other"]),
            ("denied", [{"IPProtocol": "tcp"}]), ("sourceTags", ["source"]),
            ("sourceServiceAccounts", ["source@example.com"]),
            ("targetServiceAccounts", ["target@example.com"]), ("sourceRanges", None),
            ("sourceRanges", ["198.51.100.10/32", "203.0.113.10/32"]),
            ("sourceRanges", ["0.0.0.0/0"]), ("sourceRanges", ["198.51.100.0/24"]),
            ("sourceRanges", "198.51.100.10/32"),
        ]
        for key, value in pre_mutations:
            with self.subTest(pre_field=key, pre_value=value):
                candidate = valid()
                candidate[key] = value
                client = FakeClient([candidate])
                with self.assertRaises(module.TransitionError):
                    module.update_runner_firewall(client, "sprk-12345-1-instance", "203.0.113.10", labels)
                self.assertEqual([], client.mutations)
        for label_key in ("o", "r", "i", "a", "t", "c", "p"):
            with self.subTest(description_key=label_key):
                candidate = valid()
                changed = dict(description)
                changed[label_key] = "wrong"
                candidate["description"] = json.dumps(changed)
                client = FakeClient([candidate])
                with self.assertRaises(module.TransitionError):
                    module.update_runner_firewall(client, "sprk-12345-1-instance", "203.0.113.10", labels)
                self.assertEqual([], client.mutations)
        post_mutations: list[tuple[str, object]] = [
            ("sourceRanges", ["198.51.100.10/32"]), ("description", "{}"), ("network", "wrong"),
            ("direction", "EGRESS"), ("allowed", [{"IPProtocol": "tcp", "ports": ["2222"]}]),
            ("targetTags", ["other"]), ("disabled", True),
        ]
        for key, value in post_mutations:
            with self.subTest(post_field=key, post_value=value):
                before, after = valid(), valid()
                after["sourceRanges"] = ["203.0.113.10/32"]
                after[key] = value
                client = FakeClient([before, after])
                with self.assertRaises(module.TransitionError):
                    module.update_runner_firewall(client, "sprk-12345-1-instance", "203.0.113.10", labels)
                self.assertEqual(1, len(client.mutations))

    def test_every_rocky_wif_auth_has_a_same_job_identity_gate(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        auth = "uses: google-github-actions/auth@"
        self.assertEqual(4, workflow.count(auth))
        self.assertGreaterEqual(workflow.count('[[ "$GCP_PROJECT_ID" == secpal-dev ]]'), 4)
        self.assertGreaterEqual(workflow.count("gcp-service-account@secpal-dev.iam.gserviceaccount.com"), 4)

    def test_rpm_provenance_uses_installed_signed_header_identity(self) -> None:
        collector = (ROOT / "scripts/ci-cloud/collect-rocky-preparation.py").read_text(encoding="utf-8")
        for required in (
            "-qvv",
            "PAYLOADDIGEST",
            "PAYLOADDIGESTALGO",
            "SHA256HEADER",
            "%{RSAHEADER:pgpsig}",
            "%{PUBKEYS}",
            "repoquery-nevra",
        ):
            self.assertIn(required, collector)
        for forbidden in (
            "rpmkeys",
            "--checksig",
            '"dnf4", "download"',
            "TemporaryDirectory",
        ):
            self.assertNotIn(forbidden, collector)


if __name__ == "__main__":
    unittest.main()
