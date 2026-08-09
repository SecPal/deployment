#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Static and negative tests for the ephemeral cloud CI trust boundary."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts" / "validate-ci-cloud.py"


class CloudCIContractTests(unittest.TestCase):
    maxDiff = None

    def run_validator(self, root: Path = ROOT) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", str(VALIDATOR), str(root)],
            cwd=ROOT,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

    def mutated_root(self, relative_path: str, old: str, new: str) -> Path:
        temporary = Path(tempfile.mkdtemp(prefix="secpal-ci-cloud-contract-"))
        self.addCleanup(shutil.rmtree, temporary)
        for path in (
            ".github/workflows/cloud-conformance.yml",
            ".github/workflows/cloud-janitor.yml",
            "infra/ci-cloud/digitalocean",
            "scripts/ci-cloud",
        ):
            source = ROOT / path
            destination = temporary / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            if source.is_dir():
                shutil.copytree(source, destination)
            else:
                shutil.copy2(source, destination)

        target = temporary / relative_path
        document = target.read_text(encoding="utf-8")
        self.assertIn(old, document, f"mutation anchor missing in {relative_path}")
        target.write_text(document.replace(old, new, 1), encoding="utf-8")
        return temporary

    def assert_mutation_rejected(
        self, relative_path: str, old: str, new: str
    ) -> None:
        fixture = self.mutated_root(relative_path, old, new)
        result = self.run_validator(fixture)
        self.assertNotEqual(0, result.returncode, result.stdout)

    def test_repository_cloud_ci_contract_is_valid(self) -> None:
        result = self.run_validator()
        self.assertEqual(0, result.returncode, result.stdout)

    def test_rejects_non_full_target_sha_validation(self) -> None:
        self.assert_mutation_rejected(
            ".github/workflows/cloud-conformance.yml",
            "^[0-9a-fA-F]{40}$",
            "^[0-9a-fA-F]{7,40}$",
        )

    def test_rejects_branch_or_ref_input(self) -> None:
        self.assert_mutation_rejected(
            ".github/workflows/cloud-conformance.yml",
            "      provider_profile:\n",
            "      target_ref:\n"
            "        description: Arbitrary ref\n"
            "        required: false\n"
            "        type: string\n"
            "      provider_profile:\n",
        )

    def test_rejects_shell_interpolation_of_untrusted_input(self) -> None:
        self.assert_mutation_rejected(
            ".github/workflows/cloud-conformance.yml",
            '[[ ! "$RAW_TARGET_SHA" =~ ^[0-9a-fA-F]{40}$ ]]',
            '[[ ! "${{ inputs.target_sha }}" =~ ^[0-9a-fA-F]{40}$ ]]',
        )

    def test_rejects_resource_count_input(self) -> None:
        self.assert_mutation_rejected(
            ".github/workflows/cloud-conformance.yml",
            "      provider_profile:\n",
            "      resource_count:\n"
            "        description: Resource count\n"
            "        required: false\n"
            "        type: number\n"
            "      provider_profile:\n",
        )

    def test_rejects_arbitrary_provider_profile(self) -> None:
        self.assert_mutation_rejected(
            ".github/workflows/cloud-conformance.yml",
            "          - digitalocean-amd\n",
            "          - digitalocean-amd\n          - arbitrary-provider\n",
        )

    def test_rejects_machine_type_input(self) -> None:
        self.assert_mutation_rejected(
            ".github/workflows/cloud-conformance.yml",
            "      provider_profile:\n",
            "      machine_type:\n"
            "        description: Machine type\n"
            "        required: false\n"
            "        type: string\n"
            "      provider_profile:\n",
        )

    def test_rejects_arbitrary_cloud_image(self) -> None:
        self.assert_mutation_rejected(
            "infra/ci-cloud/digitalocean/main.tf",
            'image             = "debian-13-x64"',
            "image             = var.image",
        )

    def test_rejects_cloud_credential_in_remote_test_step(self) -> None:
        self.assert_mutation_rejected(
            ".github/workflows/cloud-conformance.yml",
            "      - name: Run uncredentialed remote conformance\n",
            "      - name: Run uncredentialed remote conformance\n"
            "        env:\n"
            "          DIGITALOCEAN_TOKEN: ${{ secrets.DIGITALOCEAN_ACCESS_TOKEN }}\n",
        )

    def test_rejects_target_script_in_credentialed_apply_step(self) -> None:
        self.assert_mutation_rejected(
            ".github/workflows/cloud-conformance.yml",
            "          tofu apply --auto-approve --input=false\n",
            "          tofu apply --auto-approve --input=false\n"
            "          bash scripts/ci-cloud/target-conformance.sh\n",
        )

    def test_rejects_ssh_private_key_in_opentofu(self) -> None:
        self.assert_mutation_rejected(
            "infra/ci-cloud/digitalocean/main.tf",
            'resource "digitalocean_ssh_key" "ephemeral" {',
            'resource "tls_private_key" "forbidden" {\n'
            '  algorithm = "ED25519"\n'
            '}\n\nresource "digitalocean_ssh_key" "ephemeral" {',
        )

    def test_rejects_missing_ci_owner_metadata(self) -> None:
        self.assert_mutation_rejected(
            "infra/ci-cloud/digitalocean/main.tf",
            "    local.owner_tag,\n",
            "",
        )

    def test_rejects_missing_ttl_metadata(self) -> None:
        self.assert_mutation_rejected(
            "infra/ci-cloud/digitalocean/main.tf",
            "    local.expires_tag,\n",
            "",
        )

    def test_rejects_non_exact_cleanup(self) -> None:
        self.assert_mutation_rejected(
            ".github/workflows/cloud-conformance.yml",
            "tofu destroy --auto-approve --input=false",
            "doctl compute droplet delete --force --tag-name secpal-ci",
        )

    def test_rejects_broad_janitor_deletion(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/digitalocean-janitor.py",
            'client.delete(f"/v2/droplets/{candidate.resource_id}")',
            'client.delete("/v2/droplets?tag_name=secpal-ci")',
        )

    def test_rejects_unpinned_external_action(self) -> None:
        self.assert_mutation_rejected(
            ".github/workflows/cloud-conformance.yml",
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            "actions/checkout@v7",
        )

    def test_rejects_mutable_provider_constraint(self) -> None:
        self.assert_mutation_rejected(
            "infra/ci-cloud/digitalocean/versions.tf",
            'version = "= 2.99.1"',
            'version = "~> 2.0"',
        )


if __name__ == "__main__":
    unittest.main()
