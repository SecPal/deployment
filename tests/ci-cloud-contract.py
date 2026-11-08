#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Static and negative tests for the ephemeral cloud CI trust boundary."""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts" / "validate-ci-cloud.py"


class CloudCIContractTests(unittest.TestCase):
    def test_cleanup_authenticates_the_original_native_github_run(self):
        workflow = yaml.load(
            (ROOT / '.github/workflows/rocky-cloud-qualification.yml').read_text(),
            Loader=yaml.BaseLoader,
        )
        steps = workflow['jobs']['cleanup']['steps']
        step = next((s for s in steps if s['name'] == 'Authenticate retained source before cleanup authority'), None)
        self.assertIsNotNone(step, 'native retained-run provenance must precede cleanup credentials')
        self.assertLess(steps.index(step), next(i for i, s in enumerate(steps) if s.get('id') == 'cleanup_auth'))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = root / 'github.json'
            gh = root / 'gh'
            gh.write_text(
                '#!/usr/bin/env python3\n'
                'import argparse\n'
                'import json\n'
                'import os\n'
                '\n'
                'parser = argparse.ArgumentParser()\n'
                'parser.add_argument("command", choices=["api"])\n'
                'parser.add_argument("endpoint")\n'
                'parser.add_argument("-H", "--header", action="append")\n'
                'parser.add_argument("-X", "--method", choices=["GET"], default="GET")\n'
                'args = parser.parse_args()\n'
                'with open(os.environ["SECPAL_SOURCE_FIXTURE"], encoding="utf-8") as fixture:\n'
                '    responses = json.load(fixture)\n'
                'endpoint = args.endpoint.removeprefix("/")\n'
                'if endpoint not in responses:\n'
                '    parser.error("unexpected cleanup API endpoint")\n'
                'print(json.dumps(responses[endpoint]))\n',
                encoding="utf-8",
            )
            gh.chmod(0o700)
            # Public native representation: historical successful preparation.
            source = 'bd5e667ddad55a91a7101e9f602ba3e5291de7f9'
            run = dict(id=34953572359, run_attempt=1, event='workflow_dispatch', status='completed',
                       head_branch='main', head_sha=source, head_repository=dict(full_name='SecPal/deployment'),
                       path='.github/workflows/rocky-cloud-qualification.yml')
            for field, value in [(None, None), ('event', 'pull_request'), ('head_branch', 'candidate'),
                                 ('head_sha', 'c' * 40), ('run_attempt', 2), ('id', 999),
                                 ('head_repository', dict(full_name='other/deployment')), ('status', 'in_progress'),
                                 ('verified', False), ('ancestor', 'c' * 40)]:
                data = dict(run=dict(run), commit={'commit': {'verification': {'verified': True, 'reason': 'valid'}}},
                            compare={'merge_base_commit': {'sha': source}})
                if field == 'verified':
                    data['commit']['commit']['verification']['verified'] = value
                elif field == 'ancestor':
                    data['compare']['merge_base_commit']['sha'] = value
                elif field:
                    data['run'][field] = value
                fixture.write_text(json.dumps({
                    'repos/SecPal/deployment/actions/runs/34953572359/attempts/1': data['run'],
                    f'repos/SecPal/deployment/commits/{source}': data['commit'],
                    f'repos/SecPal/deployment/compare/{source}...{"b" * 40}': data['compare'],
                }))
                env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'],
                           SECPAL_SOURCE_FIXTURE=str(fixture), SOURCE_RUN_ID='34953572359',
                           SOURCE_RUN_ATTEMPT='1', SOURCE_CONTROL_SHA=source, GITHUB_SHA='b' * 40)
                for position in ('none', 'before', 'after', 'leading-slash'):
                    command = step['run']
                    flags = '-H "Accept: application/vnd.github+json" --method GET'
                    if position == 'before':
                        command = command.replace('gh api', f'gh api {flags}')
                    elif position == 'after':
                        command = re.sub(r'(gh api "[^"\n]+")', rf'\1 {flags}', command)
                    elif position == 'leading-slash':
                        command = command.replace('"repos/SecPal/', '"/repos/SecPal/')
                    with self.subTest(field=field, position=position):
                        result = subprocess.run(
                            ['bash', '-euo', 'pipefail', '-c', command], env=env,
                            text=True, capture_output=True,
                        )
                        self.assertEqual(result.returncode == 0, field is None, result.stderr)

    def test_gcp_creation_is_retired_without_losing_retained_state_cleanup(self):
        workflow = yaml.load(
            (ROOT / '.github/workflows/rocky-cloud-qualification.yml').read_text(),
            Loader=yaml.BaseLoader,
        )
        self.assertEqual(workflow['on']['workflow_dispatch']['inputs']['operation']['options'], ['destroy'])
        self.assertEqual(set(workflow['jobs']), {'validate', 'cleanup'})
        for name in ('main.tf', 'metadata.tf', 'variables.tf', 'outputs.tf'):
            self.assertFalse((ROOT / 'infra/ci-cloud/gcp-rocky' / name).exists(), name)
        for directory in ('gcp-rocky', 'gcp', 'digitalocean'):
            self.assertTrue((ROOT / 'infra/ci-cloud' / directory / 'versions.tf').is_file())
            self.assertTrue((ROOT / 'infra/ci-cloud' / directory / '.terraform.lock.hcl').is_file())
        commands = '\n'.join(step.get('run', '') for step in workflow['jobs']['cleanup']['steps'])
        self.assertIn('tofu destroy --auto-approve --input=false', commands)
        self.assertIn('--exact-action verify', commands)
        self.assertNotIn('tofu apply', commands)

    def test_openssh_account_smoke_ignores_global_known_hosts(self) -> None:
        smoke = (ROOT / "tests/ci-cloud-openssh-account.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn("-o GlobalKnownHostsFile=/dev/null \\\n", smoke)

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
            ".gitignore",
            ".github/workflows/cloud-janitor.yml",
            ".github/workflows/rocky-cloud-qualification.yml",
            "config/ci-cloud/gcp-rocky-10-2-arm64.json",
            "config/ci-cloud/gcp-rocky-10-2-x86-64.json",
            "infra/ci-cloud/gcp/iam-role.yaml",
            "infra/ci-cloud/digitalocean/versions.tf",
            "infra/ci-cloud/digitalocean/.terraform.lock.hcl",
            "infra/ci-cloud/gcp/versions.tf",
            "infra/ci-cloud/gcp/.terraform.lock.hcl",
            "infra/ci-cloud/gcp-rocky",
            "schemas",
            "scripts/ci-cloud",
            "scripts/fetch-oci-attestation.py",
            "scripts/qualify-production-host.sh",
            "scripts/selinux_isolation_contract.py",
            "scripts/quadlet_authority_contract.py",
            "scripts/quadlet-integration.py",
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

    def test_retirement_and_cleanup_still_fail_closed(self):
        for old, new in (
            ('          - destroy', '          - provision-and-prepare'),
            ('--exact-action verify', '--exact-action omit-verification'),
            ('rocky-control.py validate-continuation', 'rocky-control.py skip-admission'),
        ):
            with self.subTest(boundary=old):
                self.assert_mutation_rejected(
                    '.github/workflows/rocky-cloud-qualification.yml', old, new,
                )

    def test_destroy_cleanup_authenticates_retained_target_before_oidc(self) -> None:
        workflow = (
            ROOT / ".github/workflows/rocky-cloud-qualification.yml"
        ).read_text(encoding="utf-8")
        validation = workflow.split(
            "      - name: Validate immutable inputs\n", 1
        )[1].split("\n  cleanup:\n", 1)[0]
        cleanup = workflow.split("\n  cleanup:\n", 1)[1]
        self.assertIn(
            'destroy)\n              [[ "${RAW_TARGET_SHA,,}" == '
            '"$expected_target_sha" ||\n                "${RAW_TARGET_SHA,,}" == '
            '"$historical_cleanup_target_sha" ]]',
            validation,
        )
        self.assertIn(
            "readonly historical_cleanup_target_sha="
            "293977ae93408a7bb812619de58649ab8a92d438",
            validation,
        )
        self.assert_mutation_rejected(
            ".github/workflows/rocky-cloud-qualification.yml",
            '[[ "${RAW_TARGET_SHA,,}" == "$expected_target_sha" ||\n'
            '                "${RAW_TARGET_SHA,,}" == '
            '"$historical_cleanup_target_sha" ]]',
            '[[ -n "${RAW_TARGET_SHA,,}" ]]',
        )
        admission = cleanup.index("Admit continuation before cross-run cleanup")
        provider_authentication = cleanup.index(
            "Authenticate separate exact cleanup authority through OIDC"
        )
        self.assertLess(admission, provider_authentication)
        self.assertIn(
            '--target-sha "$TARGET_SHA"',
            cleanup[admission:provider_authentication],
        )

    def test_preflight_prunes_generated_opentofu_cache(self) -> None:
        preflight = (ROOT / "scripts" / "preflight.sh").read_text(encoding="utf-8")
        self.assertEqual(
            3,
            preflight.count("-name .terraform"),
            "Markdown, YAML, and Prettier discovery must prune OpenTofu caches",
        )
        self.assertIn("python3 tests/ci-cloud-gcp-janitor.py", preflight)
        self.assertNotIn("required_tools=(actionlint cloud-init", preflight)

    def test_repository_contract_requires_every_cloud_provider_root_and_janitor(self) -> None:
        repository_contract = (ROOT / "tests" / "repository-contract.sh").read_text(
            encoding="utf-8"
        )
        for relative in (
            "infra/ci-cloud/gcp/iam-role.yaml",
            "infra/ci-cloud/gcp-rocky/.terraform.lock.hcl",
            "infra/ci-cloud/gcp-rocky/versions.tf",
            "scripts/ci-cloud/gcp-rocky-janitor.py",
            "scripts/ci-cloud/rocky-control.py",
            "scripts/ci-cloud/rocky-start-runuser.py",
            "scripts/ci-cloud/rocky-start-env.py",
            "scripts/ci-cloud/rocky-start-systemctl.py",
            "scripts/ci-cloud/rocky-active-runuser.py",
            "scripts/ci-cloud/rocky-active-env.py",
            "scripts/ci-cloud/rocky-active-systemctl.py",
            "tests/ci-cloud-gcp-rocky-janitor.py",
            "tests/ci-cloud-rocky-control.py",
            "tests/ci-cloud-rocky-target-diagnostics.py",
            "scripts/ci-cloud/gcp-janitor.py",
            "tests/ci-cloud-gcp-janitor.py",
        ):
            with self.subTest(relative=relative):
                self.assertIn(relative, repository_contract)

    def test_workflow_bash_uses_explicit_strict_mode(self) -> None:
        strict_shell = "shell: bash --noprofile --norc -euo pipefail {0}"
        for relative in (
            ".github/workflows/cloud-janitor.yml",
            ".github/workflows/rocky-cloud-qualification.yml",
        ):
            with self.subTest(relative=relative):
                self.assertIn(
                    strict_shell,
                    (ROOT / relative).read_text(encoding="utf-8"),
                )


    def test_quality_runs_real_openssh_account_admission_smoke(self) -> None:
        quality = (ROOT / ".github/workflows/quality.yml").read_text(
            encoding="utf-8"
        )
        repository_contract = (ROOT / "tests/repository-contract.sh").read_text(
            encoding="utf-8"
        )
        smoke = ROOT / "tests/ci-cloud-openssh-account.sh"

        self.assertTrue(smoke.is_file())
        self.assertIn("sudo bash tests/ci-cloud-openssh-account.sh", quality)
        self.assertIn("openssh-server", quality)
        self.assertIn("tests/ci-cloud-openssh-account.sh", repository_contract)
        document = smoke.read_text(encoding="utf-8")
        for required in (
            "unshare",
            "mount --bind",
            "/usr/sbin/sshd",
            "AuthenticationMethods publickey",
            "PasswordAuthentication no",
            "KbdInteractiveAuthentication no",
            "UsePAM no",
            "UsePAM yes",
            "*NP*",
            "!",
        ):
            self.assertIn(required, document)


    def test_static_contract_rejects_missing_quadlet_normalization_diagnostic(
        self,
    ) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/collect-workload-evidence.py",
            'NORMALIZATION_DIAGNOSTIC_PREFIX = "Trusted Quadlet '
            'normalization diagnostic: "',
            'NORMALIZATION_DIAGNOSTIC_PREFIX = ""',
        )

    def test_static_contract_rejects_broadened_capability_types(self) -> None:
        for field in ("EffectiveCaps", "BoundingCaps"):
            with self.subTest(field=field):
                self.assert_mutation_rejected(
                    "scripts/ci-cloud/collect-workload-evidence.py",
                    f'item["{field}"] is not None\n'
                    f'                and not isinstance(item["{field}"], list)',
                    "False",
                )

    def test_static_contract_rejects_broken_normalization_evidence_wiring(
        self,
    ) -> None:
        mutations = (
            (
                "scripts/ci-cloud/assemble-evidence.py",
                '"normalization_diagnostics": normalization_diagnostics',
                '"normalization_diagnostics": {}',
            ),
            (
                "schemas/ci-cloud-evidence.schema.json",
                '        "normalization_diagnostics",\n',
                "",
            ),
            (
                "scripts/ci-cloud/validate-evidence.py",
                "Trusted Quadlet normalization diagnostics",
                "Trusted normalization result",
            ),
        )
        for relative, old, new in mutations:
            with self.subTest(relative=relative, old=old):
                self.assert_mutation_rejected(relative, old, new)

    def test_static_contract_rejects_unadmitted_socket_trigger_services(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/collect-workload-evidence.py",
            '"systemctl", "--user", "show", trigger,',
            '"systemctl", "--user", "show", unit,',
        )
        self.assert_mutation_rejected(
            "scripts/ci-cloud/collect-workload-evidence.py",
            "or not root_owned_systemd_unit(service_fragment)",
            "or False",
        )


    def test_runtime_validator_enforces_declared_evidence_schema(self) -> None:
        validator = (
            ROOT / "scripts/ci-cloud/validate-evidence.py"
        ).read_text(encoding="utf-8")
        self.assertIn("Draft202012Validator", validator)
        self.assertIn("ci-cloud-evidence.schema.json", validator)


    def test_rejects_broad_janitor_deletion(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/digitalocean-janitor.py",
            'client.delete(f"/v2/droplets/{candidate.resource_id}")',
            'client.delete("/v2/droplets?tag_name=secpal-ci")',
        )


    def provider_pin(self, directory: str) -> str:
        versions = (ROOT / f"infra/ci-cloud/{directory}/versions.tf").read_text(
            encoding="utf-8"
        )
        match = re.search(r'^\s*version\s*=\s*"([^"]+)"',
                          versions, re.MULTILINE)
        self.assertIsNotNone(match, "provider must declare a version")
        return match.group(1)


    def cleanup_provider_version(self, directory: str) -> str:
        return self.provider_pin(directory).strip().removeprefix("=").strip()


    def test_accepts_equivalent_exact_version_constraints(self) -> None:
        specification = importlib.util.spec_from_file_location("cloud_validator", VALIDATOR)
        validator = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(validator)
        for directory, source in (("digitalocean", "digitalocean/digitalocean"),
                                  ("gcp", "hashicorp/google"),
                                  ("gcp-rocky", "hashicorp/google")):
            with tempfile.TemporaryDirectory(prefix="secpal-provider-pin-") as temporary:
                fixture = Path(temporary)
                provider = fixture / "infra/ci-cloud" / directory
                provider.mkdir(parents=True)
                for template in ("{}", "= {}", "={}", "  = {}  "):
                    with self.subTest(directory=directory, template=template):
                        (provider / "versions.tf").write_text(
                            f'required_version = "{template.format("1.12.5")}"\n'
                            f'source  = "{source}"\n'
                            f'version = "{template.format("8.7.0")}"\n',
                            encoding="utf-8",
                        )
                        (provider / ".terraform.lock.hcl").write_text(
                            f'provider "registry.opentofu.org/{source}" {{\n'
                            '  version = "8.7.0"\n'
                            f'  constraints = "{template.format("8.7.0")}"\n'
                            '}\n',
                            encoding="utf-8",
                        )
                        self.assertEqual(
                            "8.7.0", validator.validate_provider_pin(fixture, directory, source)
                        )

    def test_accepts_consistent_cleanup_provider_updates(self) -> None:
        # Static fixtures prove pin agreement, not provider package compatibility.
        for directory in ("digitalocean", "gcp"):
            with self.subTest(directory=directory):
                version = self.cleanup_provider_version(directory)
                major, minor, patch = map(int, version.split("."))
                updated = f"{major}.{minor}.{patch + 1}"
                fixture = self.mutated_root(
                    f"infra/ci-cloud/{directory}/versions.tf",
                    f'version = "{self.provider_pin(directory)}"',
                    f'version = "{updated}"',
                )
                lock = fixture / f"infra/ci-cloud/{directory}/.terraform.lock.hcl"
                document, count = re.subn(
                    r'(^\s*(?:version|constraints)\s*=\s*")' + re.escape(version) + r'(")',
                    lambda match: match.group(1) + updated + match.group(2),
                    lock.read_text(encoding="utf-8"),
                    flags=re.MULTILINE,
                )
                self.assertEqual(count, 2)
                lock.write_text(document, encoding="utf-8")
                result = self.run_validator(fixture)
                self.assertEqual(0, result.returncode, result.stdout)
                lock.write_text(document.replace(f'"{updated}"', f'"{version}"', 1),
                                encoding="utf-8")
                result = self.run_validator(fixture)
                self.assertNotEqual(0, result.returncode, result.stdout)
                self.assertIn("cleanup provider lock must match the pinned provider", result.stdout)

    def test_rocky_provider_drift_is_rejected_before_dispatch(self) -> None:
        specification = importlib.util.spec_from_file_location("cloud_validator", VALIDATOR)
        validator = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(validator)
        directory = "infra/ci-cloud/gcp-rocky"
        versions = (ROOT / directory / "versions.tf").read_text(encoding="utf-8")
        pin = re.search(r'^\s*version\s*=\s*"([^"]+)"', versions, re.MULTILINE).group(1)
        lock = (ROOT / directory / ".terraform.lock.hcl").read_text(encoding="utf-8")
        constraint = re.search(r'constraints\s*=\s*"([^"]+)"', lock).group(1)
        version = re.search(r'version\s*=\s*"([^"]+)"', lock).group(1)
        mutations = (
            (f"{directory}/versions.tf", f'version = "{pin}"', 'version = ">= 8.0.0"', "version must be exact"),
            (f"{directory}/versions.tf", 'source  = "hashicorp/google"', 'source  = "hashicorp/unrelated"', "provider source changed"),
            (f"{directory}/.terraform.lock.hcl", f'"{version}"', '"0.0.0"', "lock must match"),
            (f"{directory}/.terraform.lock.hcl", f'constraints = "{constraint}"', 'constraints = "0.0.0"', "lock constraints must match"),
        )
        for relative, old, new, diagnostic in mutations:
            with self.subTest(relative=relative, diagnostic=diagnostic):
                fixture = self.mutated_root(relative, old, new)
                with self.assertRaisesRegex(validator.ContractError, diagnostic):
                    validator.validate_opentofu(fixture)


    def test_rejects_mutable_provider_constraint(self) -> None:
        for directory in ("digitalocean", "gcp"):
            with self.subTest(directory=directory):
                version = self.cleanup_provider_version(directory)
                self.assert_mutation_rejected(
                    f"infra/ci-cloud/{directory}/versions.tf",
                    f'version = "{self.provider_pin(directory)}"',
                    f'version = "~> {version}"',
                )


    def test_rejects_cleanup_lock_constraint_drift(self) -> None:
        for directory in ("digitalocean", "gcp"):
            version = self.cleanup_provider_version(directory)
            for replacement in ('constraints = "0.0.0"', f'constraints = "~> {version}"', ''):
                with self.subTest(directory=directory, replacement=replacement):
                    fixture = self.mutated_root(
                        f"infra/ci-cloud/{directory}/.terraform.lock.hcl",
                        f'constraints = "{version}"',
                        replacement,
                    )
                    result = self.run_validator(fixture)
                    self.assertNotEqual(0, result.returncode, result.stdout)
                    self.assertIn(
                        "cleanup provider lock constraints must match the pinned provider",
                        result.stdout,
                    )


if __name__ == "__main__":
    unittest.main()
