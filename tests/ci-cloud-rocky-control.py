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
from copy import deepcopy
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

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
    "rocky-cloud-qualification-evidence.schema.json",
)


class RockyCloudControlTests(unittest.TestCase):
    def test_rendered_rocky_startup_script_is_bounded_valid_bash(self) -> None:
        template = (ROOT / "scripts/ci-cloud/bootstrap-rocky-host.tftpl").read_text(
            encoding="utf-8"
        )
        sources = {
            "prepare_script_base64gzip": ROOT / "scripts/ci-cloud/prepare-rocky-host.sh",
            "target_runner_base64gzip": ROOT / "scripts/ci-cloud/run-rocky-target-qualification.sh",
            "allocator_base64gzip": ROOT / "scripts/ci-cloud/allocate-rocky-subids.py",
            "collector_base64gzip": ROOT / "scripts/ci-cloud/collect-rocky-preparation.py",
            "control_utility_base64gzip": ROOT / "scripts/ci-cloud/rocky-control.py",
            "discovery_schema_base64gzip": ROOT / "schemas/rocky-cloud-discovery-evidence.schema.json",
            "continuation_schema_base64gzip": ROOT / "schemas/rocky-cloud-continuation.schema.json",
            "preparation_schema_base64gzip": ROOT / "schemas/rocky-cloud-preparation-evidence.schema.json",
            "qualification_schema_base64gzip": ROOT / "schemas/rocky-cloud-qualification-evidence.schema.json",
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

    def test_every_rocky_wif_auth_has_a_same_job_identity_gate(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        auth = "uses: google-github-actions/auth@"
        self.assertEqual(4, workflow.count(auth))
        self.assertGreaterEqual(workflow.count('[[ "$GCP_PROJECT_ID" == secpal-dev ]]'), 4)
        self.assertGreaterEqual(workflow.count("gcp-service-account@secpal-dev.iam.gserviceaccount.com"), 4)

    def test_rpm_provenance_uses_verified_official_payload_identity(self) -> None:
        collector = (ROOT / "scripts/ci-cloud/collect-rocky-preparation.py").read_text(encoding="utf-8")
        for required in ("rpmkeys", "--checksig", "ROCKY_FINGERPRINT", "PAYLOADDIGEST", "dnf4", "download", "TemporaryDirectory"):
            self.assertIn(required, collector)
        self.assertNotIn("%{RSAHEADER:pgpsig}", collector)


if __name__ == "__main__":
    unittest.main()
