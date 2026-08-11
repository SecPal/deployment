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

import yaml


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
            ".gitignore",
            ".github/workflows/cloud-conformance.yml",
            ".github/workflows/cloud-janitor.yml",
            "infra/ci-cloud/digitalocean",
            "infra/ci-cloud/gcp",
            "schemas",
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

    def test_preflight_prunes_generated_opentofu_cache(self) -> None:
        preflight = (ROOT / "scripts" / "preflight.sh").read_text(encoding="utf-8")
        self.assertEqual(
            3,
            preflight.count("-name .terraform"),
            "Markdown, YAML, and Prettier discovery must prune OpenTofu caches",
        )
        self.assertIn("python3 tests/ci-cloud-gcp-janitor.py", preflight)
        self.assertIn("python3 tests/ci-cloud-bootstrap-failure.py", preflight)
        self.assertIn("python3 tests/ci-cloud-config.py", preflight)
        self.assertIn("python3 tests/ci-cloud-host-setup-failure.py", preflight)
        self.assertIn("cloud-init", preflight)

    def test_repository_contract_requires_every_cloud_provider_root_and_janitor(self) -> None:
        repository_contract = (ROOT / "tests" / "repository-contract.sh").read_text(
            encoding="utf-8"
        )
        for relative in (
            "infra/ci-cloud/gcp/.terraform.lock.hcl",
            "infra/ci-cloud/gcp/cloud-init.tftpl",
            "infra/ci-cloud/gcp/iam-role.yaml",
            "infra/ci-cloud/gcp/main.tf",
            "infra/ci-cloud/gcp/outputs.tf",
            "infra/ci-cloud/gcp/variables.tf",
            "infra/ci-cloud/gcp/versions.tf",
            "schemas/ci-cloud-bootstrap-failure.schema.json",
            "scripts/ci-cloud/gcp-janitor.py",
            "tests/ci-cloud-gcp-janitor.py",
        ):
            with self.subTest(relative=relative):
                self.assertIn(relative, repository_contract)

    def test_gcp_provider_disables_automatic_attribution_label(self) -> None:
        versions = (ROOT / "infra/ci-cloud/gcp/versions.tf").read_text(
            encoding="utf-8"
        )
        self.assertIn("add_terraform_attribution_label = false", versions)

    def test_gcp_custom_role_can_attach_network_bound_resources(self) -> None:
        role = yaml.safe_load(
            (ROOT / "infra/ci-cloud/gcp/iam-role.yaml").read_text(
                encoding="utf-8"
            )
        )
        self.assertIn(
            "compute.networks.updatePolicy",
            role["includedPermissions"],
            "subnetwork and firewall network fields require updatePolicy",
        )

    def test_workflow_bash_uses_explicit_strict_mode(self) -> None:
        strict_shell = "shell: bash --noprofile --norc -euo pipefail {0}"
        for relative in (
            ".github/workflows/cloud-conformance.yml",
            ".github/workflows/cloud-janitor.yml",
        ):
            with self.subTest(relative=relative):
                self.assertIn(
                    strict_shell,
                    (ROOT / relative).read_text(encoding="utf-8"),
                )

    def test_cloud_init_uses_shellchecked_trusted_setup(self) -> None:
        cloud_init = (
            ROOT / "infra/ci-cloud/digitalocean/cloud-init.tftpl"
        ).read_text(encoding="utf-8")
        host_setup = (
            ROOT / "scripts/ci-cloud/configure-conformance-host.sh"
        ).read_text(encoding="utf-8")
        diagnostic_installer = (
            ROOT / "scripts/ci-cloud/install-diagnostic-ssh.sh"
        ).read_text(encoding="utf-8")
        self.assertIn("set -euo pipefail", host_setup)
        self.assertIn("set -euo pipefail", diagnostic_installer)
        self.assertEqual(1, cloud_init.count("- /bin/bash\n    - -c\n"))
        self.assertIn("${diagnostic_ssh_installer}", cloud_init)
        self.assertIn("/run/secpal-ci-evidence/apparmor-status", host_setup)
        self.assertIn(
            "systemctl disable --now podman.socket podman.service", host_setup
        )
        self.assertNotIn("groups: []", cloud_init)
        self.assertIn("${host_setup_failure_script}", cloud_init)
        self.assertIn(
            '[[ "$(id -G secpal-ci)" != "$(id -g secpal-ci)" ]]',
            host_setup,
        )

    def test_host_setup_failure_diagnostic_is_closed_and_uncredentialed(self) -> None:
        host_setup = (
            ROOT / "scripts/ci-cloud/configure-conformance-host.sh"
        ).read_text(encoding="utf-8")
        remote = (
            ROOT / "scripts/ci-cloud/run-remote-conformance.sh"
        ).read_text(encoding="utf-8")
        self.assertIn("secpal-ci-host-setup-failure", host_setup)
        for stage in (
            "initialize",
            "subordinate-ids",
            "service-policy",
            "apparmor",
            "ssh",
        ):
            self.assertIn(f'setup_stage="{stage}"', host_setup)
        self.assertIn("host-setup-failure.py", remote)
        self.assertIn("Trusted host setup failure", remote)
        self.assertNotIn("cloud-init-output.log", remote)

    def test_cloud_init_repairs_automatic_subordinate_ids(self) -> None:
        host_setup = (
            ROOT / "scripts/ci-cloud/configure-conformance-host.sh"
        ).read_text(encoding="utf-8")
        self.assertIn("--del-subuids", host_setup)
        self.assertIn("--del-subgids", host_setup)
        self.assertIn(
            "normalize_subordinate_ids /etc/subuid --add-subuids --del-subuids UID passwd",
            host_setup,
        )
        self.assertIn(
            "normalize_subordinate_ids /etc/subgid --add-subgids --del-subgids GID group",
            host_setup,
        )
        self.assertIn("overlaps the fixed secpal-ci range", host_setup)
        self.assertIn("fixed secpal-ci range overlaps a host identity", host_setup)

    def test_operator_ssh_key_is_deferred_until_host_setup_finishes(self) -> None:
        host_setup = (
            ROOT / "scripts/ci-cloud/configure-conformance-host.sh"
        ).read_text(encoding="utf-8")
        for provider in ("digitalocean", "gcp"):
            template = (
                ROOT / f"infra/ci-cloud/{provider}/cloud-init.tftpl"
            ).read_text(encoding="utf-8")
            variables = (
                ROOT / f"infra/ci-cloud/{provider}/variables.tf"
            ).read_text(encoding="utf-8")
            users_block = template.split("users:\n", 1)[1].split(
                "\ndisable_root:", 1
            )[0]
            self.assertNotIn("ssh_authorized_keys", users_block)
            self.assertIn("- path: /run/secpal-ci-authorized-key", template)
            staged_key = template.split(
                "- path: /run/secpal-ci-authorized-key", 1
            )[1].split("  - path:", 1)[0]
            self.assertIn("owner: root:root", staged_key)
            self.assertIn('permissions: "0600"', staged_key)
            self.assertIn("${ssh_public_key}", staged_key)
            self.assertIn(
                "AuthorizedKeysFile /var/lib/secpal-ci/authorized-keys/%u",
                template,
            )
            self.assertIn(
                "- path: /etc/ssh/sshd_config.d/00-secpal-ci.conf",
                template,
            )
            self.assertNotIn("sshd_config.d/90-secpal-ci.conf", template)
            self.assertIn("AuthenticationMethods publickey", template)
            self.assertIn("AuthorizedKeysCommand none", template)
            self.assertIn("AuthorizedPrincipalsCommand none", template)
            self.assertIn("AuthorizedPrincipalsFile none", template)
            self.assertIn("PermitRootLogin no", template)
            self.assertIn("TrustedUserCAKeys none", template)
            self.assertIn("UseDNS no", template)
            self.assertIn("AllowUsers secpal-ci", template)
            self.assertIn(
                "${diagnostic_ssh_installer}",
                template,
            )
            self.assertIn(
                " secpal-ci-${var.run_id}-${var.run_attempt}$",
                variables,
            )
            self.assertNotIn("( [A-Za-z0-9._@+-]+)?", variables)
            self.assertIn(
                "- [/usr/local/sbin/secpal-ci-configure-conformance-host, "
                '"${runner_ipv4}"]',
                template,
            )

        gcp_main = (ROOT / "infra/ci-cloud/gcp/main.tf").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("    ssh-keys                 =", gcp_main)
        self.assertIn("activate_operator_ssh", host_setup)
        failure_handler = host_setup.split("record_setup_failure() {", 1)[1].split(
            "\n}\n", 1
        )[0]
        self.assertIn("restore_diagnostic_ssh || true", failure_handler)
        self.assertNotIn("activate_operator_ssh", failure_handler)
        self.assertIn("validate_effective_sshd_config || return 1", host_setup)
        self.assertIn(
            "systemctl unmask ssh.service ssh.socket",
            host_setup,
        )
        self.assertIn("sshd -T -C", host_setup)
        for expected in (
            "authorizedkeyscommand none",
            "authorizedprincipalscommand none",
            "authorizedprincipalsfile none",
            "trustedusercakeys none",
            "usedns no",
        ):
            self.assertIn(expected, host_setup)
        self.assertIn('runner_ipv4="${1:-}"', host_setup)
        self.assertIn('ip -o -4 route get "$runner_ipv4"', host_setup)
        self.assertIn("addr=$runner_ipv4", host_setup)
        self.assertIn("host=$runner_ipv4", host_setup)
        self.assertIn("laddr=$local_ipv4", host_setup)
        self.assertIn("lport=22", host_setup)
        self.assertLess(
            host_setup.index('setup_stage="apparmor"'),
            host_setup.index('setup_stage="ssh"'),
        )
        ssh_stage = host_setup.split('setup_stage="ssh"', 1)[1]
        self.assertIn("activate_operator_ssh", ssh_stage)
        self.assertIn(
            'active_ssh_authorized_keys_dir="$active_ssh_root/authorized-keys"',
            host_setup,
        )
        self.assertIn(
            'active_ssh_authorized_keys="$active_ssh_authorized_keys_dir/secpal-ci"',
            host_setup,
        )
        self.assertNotIn("/home/secpal-ci/.ssh/authorized_keys", host_setup)
        self.assertIn(
            'mv -T -- "$authorized_keys_tmp_dir" \\\n'
            '    "$active_ssh_authorized_keys_dir"',
            host_setup,
        )
        private_install = (
            'install -o root -g root -m 0600 \\\n'
            '    "$staged_ssh_public_key" "$authorized_keys_tmp_dir/secpal-ci"'
        )
        publish = (
            'mv -T -- "$authorized_keys_tmp_dir" \\\n'
            '    "$active_ssh_authorized_keys_dir"'
        )
        expose_file = 'chmod 0644 "$active_ssh_authorized_keys"'
        expose_directory = 'chmod 0755 "$active_ssh_authorized_keys_dir"'
        self.assertIn(private_install, host_setup)
        self.assertIn(expose_file, host_setup)
        self.assertIn(expose_directory, host_setup)
        self.assertLess(host_setup.index(private_install), host_setup.index(publish))
        self.assertLess(host_setup.index(publish), host_setup.index(expose_file))
        self.assertLess(host_setup.index(expose_file), host_setup.index(expose_directory))
        self.assertLess(
            host_setup.index(expose_directory),
            host_setup.index("systemctl unmask ssh.service ssh.socket"),
        )
        self.assertLess(
            host_setup.index("systemctl unmask ssh.service ssh.socket"),
            host_setup.index("systemctl restart ssh.service"),
        )
        self.assertNotIn('chmod 0755 "$authorized_keys_tmp_dir"', host_setup)
        remote = (
            ROOT / "scripts/ci-cloud/run-remote-conformance.sh"
        ).read_text(encoding="utf-8")
        self.assertIn("operator_ssh_ready=false", remote)
        self.assertIn("for _ in {1..30}; do", remote)
        self.assertIn(
            "operator SSH access did not become ready; trusted host setup",
            remote,
        )
        self.assertIn(
            "network reachability, or sshd may have failed",
            remote,
        )
        self.assertNotIn(
            "operator SSH key was not activated by trusted host setup",
            remote,
        )
        self.assertIn("host_key_deadline=$((SECONDS + 15 * 60))", remote)
        self.assertIn("while ((SECONDS < host_key_deadline)); do", remote)

    def test_pre_runcmd_failure_keeps_restricted_diagnostic_ssh(self) -> None:
        installer = (
            ROOT / "scripts/ci-cloud/install-diagnostic-ssh.sh"
        ).read_text(encoding="utf-8")
        host_setup = (
            ROOT / "scripts/ci-cloud/configure-conformance-host.sh"
        ).read_text(encoding="utf-8")
        remote = (
            ROOT / "scripts/ci-cloud/run-remote-conformance.sh"
        ).read_text(encoding="utf-8")

        for provider in ("digitalocean", "gcp"):
            template = (
                ROOT / f"infra/ci-cloud/{provider}/cloud-init.tftpl"
            ).read_text(encoding="utf-8")
            main = (ROOT / f"infra/ci-cloud/{provider}/main.tf").read_text(
                encoding="utf-8"
            )
            self.assertIn("${diagnostic_ssh_installer}", template)
            self.assertIn('"${ssh_public_key}"', template)
            self.assertIn('"${runner_ipv4}"', template)
            self.assertIn('"${run_id}"', template)
            self.assertIn('"${run_attempt}"', template)
            self.assertIn(
                'file("${path.module}/../../../scripts/ci-cloud/'
                'install-diagnostic-ssh.sh")',
                main,
            )

        for required in (
            "systemctl mask --now ssh.service ssh.socket",
            "secpal-ci-diagnostic-sshd",
            "--on-active=10m",
            "ForceCommand /run/secpal-ci-cloud-init-diagnostic",
            "DisableForwarding yes",
            "PermitRootLogin no",
            "UsePAM yes",
            "AllowUsers secpal-ci-diagnostic@",
            "useradd --system",
            "SECPAL_CI_DIAGNOSTIC_SSH",
            "exit 125",
            '"$key_comment" != "secpal-ci-$3-$4"',
        ):
            self.assertIn(required, installer)
        self.assertNotIn("eval ", installer)
        self.assertNotIn("source ", installer)
        self.assertIn("secpal-ci-diagnostic-sshd.timer", host_setup)
        self.assertIn("secpal-ci-diagnostic-sshd.service", host_setup)
        restore_handler = host_setup.split("restore_diagnostic_ssh() {", 1)[1].split(
            "\n}\n", 1
        )[0]
        self.assertIn(
            'rm -f -- "$completion_marker" "$active_ssh_authorized_keys"',
            restore_handler,
        )
        self.assertLess(
            restore_handler.index(
                'rm -f -- "$completion_marker" "$active_ssh_authorized_keys"'
            ),
            restore_handler.index("systemctl mask --now ssh.service ssh.socket"),
        )
        stop_handler = host_setup.split("stop_diagnostic_ssh() {", 1)[1].split(
            "\n}\n", 1
        )[0]
        self.assertIn(
            '! systemctl is-active --quiet "$diagnostic_ssh_timer"',
            stop_handler,
        )
        self.assertIn(
            '! systemctl is-active --quiet "$diagnostic_ssh_service"',
            stop_handler,
        )
        self.assertIn(
            "SECPAL_CI_HOST_SETUP_FAILURE",
            installer,
        )
        self.assertIn(
            "/usr/local/sbin/secpal-ci-host-setup-failure read",
            installer,
        )
        self.assertIn("SECPAL_CI_HOST_SETUP_FAILURE", remote)
        self.assertIn("SECPAL_CI_DIAGNOSTIC_SSH", remote)
        self.assertIn("diagnostic_ssh_seen", remote)

    def test_diagnostic_identity_cleanup_is_idempotent(self) -> None:
        host_setup = (
            ROOT / "scripts/ci-cloud/configure-conformance-host.sh"
        ).read_text(encoding="utf-8")
        self.assertIn(
            'if getent group "$diagnostic_ssh_user" >/dev/null; then',
            host_setup,
        )
        self.assertNotIn(
            '! userdel "$diagnostic_ssh_user" ||\n'
            '    ! groupdel "$diagnostic_ssh_user"',
            host_setup,
        )

    def test_diagnostic_fallback_is_armed_before_primary_ssh_is_masked(self) -> None:
        installer = (
            ROOT / "scripts/ci-cloud/install-diagnostic-ssh.sh"
        ).read_text(encoding="utf-8")
        arm = "if ! systemd-run --quiet"
        mask = (
            "diagnostic_fallback_armed=true\n"
            "if ! systemctl mask --now ssh.service ssh.socket"
        )
        for preparation in (
            'if getent passwd "$diagnostic_user"',
            "ssh-keygen -A",
            'sshd -t -f "$config_tmp"',
            'chmod 0755 "$diagnostic_command"',
        ):
            with self.subTest(preparation=preparation):
                self.assertLess(installer.index(preparation), installer.index(arm))
        self.assertLess(
            installer.index("groupadd --system"),
            installer.index("diagnostic_identity_created=true"),
        )
        self.assertLess(
            installer.index("diagnostic_identity_created=true"),
            installer.index("useradd --system"),
        )
        self.assertLess(installer.index(arm), installer.index(mask))
        self.assertIn("diagnostic_fallback_armed=true", installer)
        cleanup = installer.split("cleanup() {", 1)[1].split("\n}\n", 1)[0]
        self.assertIn(
            'if [[ "$diagnostic_fallback_armed" == true ]]; then',
            cleanup,
        )
        self.assertIn(
            'systemctl start "$diagnostic_service"',
            cleanup,
        )
        self.assertIn(
            "systemctl mask --now ssh.service ssh.socket",
            cleanup,
        )
        self.assertNotIn("primary_ssh_masked", cleanup)

    def test_completed_setup_survives_cloud_init_bootcmd_on_reboot(self) -> None:
        installer = (
            ROOT / "scripts/ci-cloud/install-diagnostic-ssh.sh"
        ).read_text(encoding="utf-8")
        host_setup = (
            ROOT / "scripts/ci-cloud/configure-conformance-host.sh"
        ).read_text(encoding="utf-8")
        self.assertIn(
            'completion_marker="$active_operator_root/host-setup-complete"',
            installer,
        )
        self.assertIn(
            'active_operator_key="$active_operator_root/authorized-keys/secpal-ci"',
            installer,
        )
        completed_guard = "if completed_setup_is_valid; then"
        self.assertIn(completed_guard, installer)
        self.assertLess(
            installer.index(completed_guard),
            installer.index('groupadd --system "$diagnostic_user"'),
        )
        self.assertLess(
            installer.index(completed_guard),
            installer.index("if ! systemd-run --quiet"),
        )
        self.assertIn("stat -c '%u:%g:%a'", installer)
        self.assertIn('cmp -s -- - "$active_operator_key"', installer)
        self.assertIn("SECPAL_CI_HOST_SETUP_COMPLETE", installer)
        completed_validator = installer.split("completed_setup_is_valid() {", 1)[
            1
        ].split("\n}\n", 1)[0]
        self.assertIn(
            'systemctl is-enabled ssh.service',
            completed_validator,
        )
        self.assertIn('"$ssh_service_state" == enabled', completed_validator)
        self.assertNotIn("systemctl is-active", completed_validator)

        self.assertIn(
            'completion_marker="$active_ssh_root/host-setup-complete"',
            host_setup,
        )
        self.assertIn("publish_completion_marker", host_setup)
        self.assertLess(
            host_setup.index('systemctl restart ssh.service'),
            host_setup.index("if ! publish_completion_marker; then"),
        )
        self.assertLess(
            host_setup.index("systemctl enable ssh.service"),
            host_setup.index("systemctl restart ssh.service"),
        )
        self.assertIn('rm -f -- "$completion_marker"', host_setup)
        self.assertNotIn("/run/secpal-ci-authorized-keys", host_setup)

    def test_static_contract_rejects_missing_completed_setup_reboot_guard(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/install-diagnostic-ssh.sh",
            "if completed_setup_is_valid; then\n  exit 0\nfi\n",
            "",
        )

    def test_static_contract_rejects_masking_before_fallback_arm(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/install-diagnostic-ssh.sh",
            "diagnostic_fallback_armed=true\n"
            "if ! systemctl mask --now ssh.service ssh.socket",
            "if ! systemctl mask --now ssh.service ssh.socket",
        )

    def test_static_contract_rejects_short_masked_ssh_wait(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/run-remote-conformance.sh",
            "host_key_deadline=$((SECONDS + 15 * 60))",
            "host_key_deadline=$((SECONDS + 2 * 60))",
        )

    def test_static_contract_rejects_early_operator_ssh_key_release(self) -> None:
        self.assert_mutation_rejected(
            "infra/ci-cloud/digitalocean/cloud-init.tftpl",
            "/run/secpal-ci-authorized-key",
            "/home/secpal-ci/.ssh/authorized_keys",
        )

    def test_static_contract_rejects_unmasked_bootstrap_ssh(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/install-diagnostic-ssh.sh",
            "if ! systemctl mask --now ssh.service ssh.socket; then",
            "if ! true; then",
        )

    def test_static_contract_rejects_missing_diagnostic_ssh_timer(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/install-diagnostic-ssh.sh",
            "  --on-active=10m \\\n",
            "",
        )

    def test_static_contract_rejects_unrestricted_diagnostic_ssh(self) -> None:
        for old, new in (
            (
                "ForceCommand /run/secpal-ci-cloud-init-diagnostic",
                "ForceCommand internal-sftp",
            ),
            ("PermitRootLogin no", "PermitRootLogin yes"),
            ("DisableForwarding yes", "DisableForwarding no"),
            ("UsePAM yes", "UsePAM no"),
            (
                "AllowUsers secpal-ci-diagnostic@$runner_ipv4",
                "AllowUsers secpal-ci-diagnostic",
            ),
        ):
            with self.subTest(old=old):
                self.assert_mutation_rejected(
                    "scripts/ci-cloud/install-diagnostic-ssh.sh",
                    old,
                    new,
                )

    def test_static_contract_rejects_ignored_diagnostic_ssh_marker(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/run-remote-conformance.sh",
            "SECPAL_CI_DIAGNOSTIC_SSH",
            "UNRECOGNIZED_DIAGNOSTIC_SSH",
        )

    def test_static_contract_rejects_global_operator_key_path(self) -> None:
        self.assert_mutation_rejected(
            "infra/ci-cloud/digitalocean/cloud-init.tftpl",
            "AuthorizedKeysFile /var/lib/secpal-ci/authorized-keys/%u",
            "AuthorizedKeysFile /var/lib/secpal-ci/authorized-keys/key",
        )

    def test_static_contract_rejects_late_ssh_dropin(self) -> None:
        self.assert_mutation_rejected(
            "infra/ci-cloud/digitalocean/cloud-init.tftpl",
            "sshd_config.d/00-secpal-ci.conf",
            "sshd_config.d/90-secpal-ci.conf",
        )

    def test_static_contract_rejects_broadened_ssh_users(self) -> None:
        self.assert_mutation_rejected(
            "infra/ci-cloud/digitalocean/cloud-init.tftpl",
            "AllowUsers secpal-ci",
            "AllowUsers root secpal-ci",
        )

    def test_static_contract_rejects_root_key_login(self) -> None:
        self.assert_mutation_rejected(
            "infra/ci-cloud/digitalocean/cloud-init.tftpl",
            "PermitRootLogin no",
            "PermitRootLogin prohibit-password",
        )

    def test_static_contract_rejects_alternate_authentication_methods(self) -> None:
        self.assert_mutation_rejected(
            "infra/ci-cloud/digitalocean/cloud-init.tftpl",
            "AuthenticationMethods publickey",
            "AuthenticationMethods any",
        )

    def test_static_contract_rejects_alternate_public_key_sources(self) -> None:
        for directive in (
            "AuthorizedKeysCommand none\n",
            "AuthorizedPrincipalsCommand none\n",
            "AuthorizedPrincipalsFile none\n",
            "TrustedUserCAKeys none\n",
        ):
            with self.subTest(directive=directive):
                self.assert_mutation_rejected(
                    "infra/ci-cloud/digitalocean/cloud-init.tftpl",
                    f"      {directive}",
                    "",
                )

    def test_static_contract_rejects_synthetic_sshd_context(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/configure-conformance-host.sh",
            "host=$runner_ipv4,addr=$runner_ipv4,laddr=$local_ipv4,lport=22",
            "host=localhost,addr=127.0.0.1",
        )

    def test_static_contract_rejects_public_temporary_key_staging(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/configure-conformance-host.sh",
            'install -o root -g root -m 0600 \\\n'
            '    "$staged_ssh_public_key" "$authorized_keys_tmp_dir/secpal-ci"',
            'install -o root -g root -m 0644 \\\n'
            '    "$staged_ssh_public_key" "$authorized_keys_tmp_dir/secpal-ci"',
        )

    def test_static_contract_rejects_missing_effective_sshd_validation(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/configure-conformance-host.sh",
            "  validate_effective_sshd_config || return 1\n",
            "  true\n",
        )

    def test_setup_failure_trap_precedes_fallible_initialization(self) -> None:
        host_setup = (
            ROOT / "scripts/ci-cloud/configure-conformance-host.sh"
        ).read_text(encoding="utf-8")
        trap_index = host_setup.index("trap record_setup_failure EXIT")
        self.assertLess(
            trap_index,
            host_setup.index(
                'if [[ "$#" -ne 1 ]] || ! is_ipv4 "$runner_ipv4"; then'
            ),
        )
        self.assertLess(
            trap_index,
            host_setup.index(
                'install -d -o root -g root -m 0755 "$diagnostic_dir"'
            ),
        )
        self.assertLess(
            trap_index,
            host_setup.index(
                'rm -f -- "$diagnostic_dir/host-setup-failure.json"'
            ),
        )

    def test_static_contract_rejects_late_setup_failure_trap(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/configure-conformance-host.sh",
            'trap record_setup_failure EXIT\n'
            'if [[ "$#" -ne 1 ]] || ! is_ipv4 "$runner_ipv4"; then\n'
            "  printf 'ERROR: trusted runner IPv4 context is invalid.\\n' >&2\n"
            "  exit 1\n"
            "fi\n",
            'if [[ "$#" -ne 1 ]] || ! is_ipv4 "$runner_ipv4"; then\n'
            "  printf 'ERROR: trusted runner IPv4 context is invalid.\\n' >&2\n"
            "  exit 1\n"
            "fi\n"
            'trap record_setup_failure EXIT\n',
        )

    def test_static_contract_rejects_gcp_metadata_ssh_key_injection(self) -> None:
        self.assert_mutation_rejected(
            "infra/ci-cloud/gcp/main.tf",
            '    enable-oslogin           = "FALSE"\n',
            '    enable-oslogin           = "FALSE"\n'
            '    ssh-keys                 = "secpal-ci:${trimspace(var.ssh_public_key)}"\n',
        )

    def test_static_contract_rejects_unrestricted_setup_failure_access(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/configure-conformance-host.sh",
            "    restore_diagnostic_ssh || true\n",
            "    activate_operator_ssh || true\n",
        )

    def test_trusted_collector_ignores_target_owned_startup_configuration(self) -> None:
        remote = (
            ROOT / "scripts/ci-cloud/run-remote-conformance.sh"
        ).read_text(encoding="utf-8")
        self.assertIn("/usr/bin/env -i", remote)
        self.assertIn("/usr/bin/python3 -I -", remote)
        self.assertNotIn("\n  python3 - \"$provider\"", remote)

    def test_target_output_does_not_use_a_shared_temporary_path(self) -> None:
        remote = (
            ROOT / "scripts/ci-cloud/run-remote-conformance.sh"
        ).read_text(encoding="utf-8")
        self.assertNotIn("/tmp/secpal-target-conformance.log", remote)
        self.assertIn(") >/dev/null 2>&1", remote)

    def test_early_remote_failure_writes_bounded_structured_evidence(self) -> None:
        remote = (
            ROOT / "scripts/ci-cloud/run-remote-conformance.sh"
        ).read_text(encoding="utf-8")
        self.assertIn('bootstrap_stage="host-key"', remote)
        self.assertIn("orchestration_started_at", remote)
        self.assertIn("write-bootstrap-failure.py", remote)
        self.assertIn("cloud-init status --long", remote)
        self.assertIn("head -c 8192", remote)
        self.assertNotIn("cloud-init-output.log", remote)

    def test_remote_bash_programs_use_strict_mode(self) -> None:
        remote = (
            ROOT / "scripts/ci-cloud/run-remote-conformance.sh"
        ).read_text(encoding="utf-8")
        fixture = (
            ROOT / "tests/ci-cloud-remote-bootstrap.sh"
        ).read_text(encoding="utf-8")
        self.assertEqual(2, remote.count("<<'REMOTE'\nset -euo pipefail\n"))
        self.assertIn(
            "cat >\"$FAKE_BIN/sleep\" <<'EOF'\n"
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n",
            fixture,
        )

    def test_missing_provider_evidence_is_a_hard_upload_failure(self) -> None:
        workflow = (
            ROOT / ".github/workflows/cloud-conformance.yml"
        ).read_text(encoding="utf-8")
        self.assertEqual(2, workflow.count("if-no-files-found: error"))
        self.assertEqual(2, workflow.count("if-no-files-found: warn"))

    def test_static_contract_rejects_nonisolated_collector_python(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/run-remote-conformance.sh",
            "/usr/bin/python3 -I -",
            "/usr/bin/python3 -",
        )

    def test_static_contract_rejects_shared_target_log(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/run-remote-conformance.sh",
            ") >/dev/null 2>&1",
            ") >/tmp/secpal-target-conformance.log 2>&1",
        )

    def test_static_contract_rejects_warning_only_evidence_upload(self) -> None:
        self.assert_mutation_rejected(
            ".github/workflows/cloud-conformance.yml",
            "if-no-files-found: error",
            "if-no-files-found: warn",
        )

    def test_static_contract_rejects_missing_bootstrap_failure_writer(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/run-remote-conformance.sh",
            "scripts/ci-cloud/write-bootstrap-failure.py",
            "scripts/ci-cloud/missing-bootstrap-failure-writer.py",
        )

    def test_static_contract_rejects_missing_host_setup_failure_reader(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/run-remote-conformance.sh",
            "scripts/ci-cloud/host-setup-failure.py",
            "scripts/ci-cloud/missing-host-setup-failure.py",
        )

    def test_static_contract_rejects_unvalidated_bootstrap_failure_evidence(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/write-bootstrap-failure.py",
            "        validate_declared_schema(document)\n",
            "",
        )

    def test_static_contract_rejects_curl_user_configuration(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/collect-host-evidence.py",
            '                "--disable",\n',
            "",
        )

    def test_static_contract_rejects_missing_subordinate_id_repair(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/configure-conformance-host.sh",
            "normalize_subordinate_ids /etc/subuid --add-subuids --del-subuids UID passwd",
            "normalize_subordinate_ids /etc/subuid --add-subuids --add-subuids UID passwd",
        )

    def test_static_contract_rejects_missing_subordinate_overlap_guard(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/configure-conformance-host.sh",
            "elif ((start_value <= 265535 && end_value >= 200000)); then",
            "elif false; then",
        )

    def test_rendered_cloud_init_embeds_valid_host_setup(self) -> None:
        template = (
            ROOT / "infra/ci-cloud/digitalocean/cloud-init.tftpl"
        ).read_text(encoding="utf-8")
        host_setup = (
            ROOT / "scripts/ci-cloud/configure-conformance-host.sh"
        ).read_text(encoding="utf-8").strip()
        setup_lines = host_setup.splitlines()
        indented_setup = setup_lines[0] + "\n" + "\n".join(
            f"      {line}" for line in setup_lines[1:]
        )
        rendered = template.replace(
            "${ssh_public_key}",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAISynthetic fixture@example",
        ).replace("${host_setup_script}", indented_setup).replace(
            "${host_setup_failure_script}", "#!/usr/bin/env python3\n      pass"
        )
        document = yaml.safe_load(rendered)
        files = {entry["path"]: entry for entry in document["write_files"]}
        self.assertEqual(
            host_setup,
            files["/usr/local/sbin/secpal-ci-configure-conformance-host"][
                "content"
            ].strip(),
        )

    def test_runtime_validator_enforces_declared_evidence_schema(self) -> None:
        validator = (
            ROOT / "scripts/ci-cloud/validate-evidence.py"
        ).read_text(encoding="utf-8")
        self.assertIn("Draft202012Validator", validator)
        self.assertIn("ci-cloud-evidence.schema.json", validator)

    def test_dynamic_conformance_records_exact_resolved_inputs(self) -> None:
        main = (
            ROOT / "infra/ci-cloud/digitalocean/main.tf"
        ).read_text(encoding="utf-8")
        outputs = (
            ROOT / "infra/ci-cloud/digitalocean/outputs.tf"
        ).read_text(encoding="utf-8")
        workflow = (
            ROOT / ".github/workflows/cloud-conformance.yml"
        ).read_text(encoding="utf-8")
        collector = (
            ROOT / "scripts/ci-cloud/collect-host-evidence.py"
        ).read_text(encoding="utf-8")
        self.assertIn('data "digitalocean_image" "debian_13"', main)
        self.assertIn('slug = "debian-13-x64"', main)
        self.assertIn("image             = data.digitalocean_image.debian_13.id", main)
        self.assertIn('intel = "s-4vcpu-8gb-intel"', main)
        self.assertIn('amd   = "s-4vcpu-8gb-amd"', main)
        self.assertNotIn("s-8vcpu-16gb", main)
        self.assertIn('output "image_id"', outputs)
        self.assertIn("tofu output -raw image_id", workflow)
        self.assertIn("BOOTSTRAP_PACKAGES", collector)

        gcp_main = (ROOT / "infra/ci-cloud/gcp/main.tf").read_text(encoding="utf-8")
        gcp_outputs = (ROOT / "infra/ci-cloud/gcp/outputs.tf").read_text(
            encoding="utf-8"
        )
        self.assertIn('family  = "debian-13-arm64"', gcp_main)
        self.assertIn('project = "debian-cloud"', gcp_main)
        self.assertIn('machine_type = "c4a-standard-4"', gcp_main)
        self.assertIn('type   = "hyperdisk-balanced"', gcp_main)
        self.assertIn("size   = 120", gcp_main)
        self.assertIn('nic_type   = "GVNIC"', gcp_main)
        self.assertIn('output "image_id"', gcp_outputs)
        self.assertIn('output "machine_type"', gcp_outputs)

    def test_governance_exception_is_bounded_to_nonproduction_conformance(self) -> None:
        instructions = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        self.assertIn("non-production conformance", instructions)
        self.assertIn("resolved provider image ID", instructions)
        self.assertIn("exact installed package versions", instructions)

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

    def test_rejects_arbitrary_gcp_cloud_image(self) -> None:
        self.assert_mutation_rejected(
            "infra/ci-cloud/gcp/main.tf",
            'family  = "debian-13-arm64"',
            "family  = var.image",
        )

    def test_rejects_arbitrary_gcp_machine_type(self) -> None:
        self.assert_mutation_rejected(
            "infra/ci-cloud/gcp/main.tf",
            'machine_type = "c4a-standard-4"',
            "machine_type = var.machine_type",
        )

    def test_rejects_gcp_vm_service_account(self) -> None:
        self.assert_mutation_rejected(
            "infra/ci-cloud/gcp/main.tf",
            '  deletion_protection = false\n',
            '  deletion_protection = false\n\n  service_account {\n'
            '    email  = "default"\n'
            '    scopes = ["cloud-platform"]\n'
            "  }\n",
        )

    def test_rejects_missing_gcp_ci_owner_metadata(self) -> None:
        self.assert_mutation_rejected(
            "infra/ci-cloud/gcp/main.tf",
            '    secpal_ci_owner    = "deployment-conformance"\n',
            "",
        )

    def test_rejects_missing_gcp_ttl_metadata(self) -> None:
        self.assert_mutation_rejected(
            "infra/ci-cloud/gcp/main.tf",
            "    expires_at         = var.expires_at\n",
            "",
        )

    def test_rejects_gcp_access_token_in_remote_test_step(self) -> None:
        self.assert_mutation_rejected(
            ".github/workflows/cloud-conformance.yml",
            "      - name: Run uncredentialed GCP remote conformance\n",
            "      - name: Run uncredentialed GCP remote conformance\n"
            "        env:\n"
            "          GOOGLE_OAUTH_ACCESS_TOKEN: ${{ steps.auth.outputs.access_token }}\n",
        )

    def test_rejects_gcp_target_script_in_credentialed_apply_step(self) -> None:
        self.assert_mutation_rejected(
            ".github/workflows/cloud-conformance.yml",
            "          unset GOOGLE_OAUTH_ACCESS_TOKEN\n",
            "          bash scripts/ci-cloud/target-conformance.sh\n"
            "          unset GOOGLE_OAUTH_ACCESS_TOKEN\n",
        )

    def test_rejects_gcp_private_key_in_opentofu(self) -> None:
        self.assert_mutation_rejected(
            "infra/ci-cloud/gcp/main.tf",
            'data "google_compute_image" "debian_13" {',
            'resource "tls_private_key" "forbidden" {\n'
            '  algorithm = "ED25519"\n'
            '}\n\ndata "google_compute_image" "debian_13" {',
        )

    def test_rejects_broad_gcp_custom_role_permission(self) -> None:
        self.assert_mutation_rejected(
            "infra/ci-cloud/gcp/iam-role.yaml",
            "  - serviceusage.services.use\n",
            "  - serviceusage.services.use\n"
            "  - resourcemanager.projects.setIamPolicy\n",
        )

    def test_rejects_gcp_service_account_attachment_permission(self) -> None:
        self.assert_mutation_rejected(
            "infra/ci-cloud/gcp/iam-role.yaml",
            "  - serviceusage.services.use\n",
            "  - serviceusage.services.use\n"
            "  - iam.serviceAccounts.actAs\n",
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
            'slug = "debian-13-x64"',
            "slug = var.image",
        )

    def test_rejects_firewall_created_after_the_droplet(self) -> None:
        self.assert_mutation_rejected(
            "infra/ci-cloud/digitalocean/main.tf",
            "  tags = [digitalocean_tag.ownership[local.owner_tag].name]\n",
            "  droplet_ids = [digitalocean_droplet.conformance.id]\n",
        )

    def test_rejects_droplet_without_precreated_firewall_dependency(self) -> None:
        self.assert_mutation_rejected(
            "infra/ci-cloud/digitalocean/main.tf",
            "  depends_on        = [digitalocean_firewall.conformance]\n",
            "",
        )

    def test_rejects_missing_effective_root_ssh_denial_probe(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/run-remote-conformance.sh",
            "root_ssh_denied=true\n",
            "root_ssh_denied=false\n",
        )

    def test_rejects_incomplete_cloud_host_admission_policy(self) -> None:
        self.assert_mutation_rejected(
            "infra/ci-cloud/digitalocean/cloud-init.tftpl",
            "  - unattended-upgrades\n",
            "",
        )

    def test_rejects_appended_unattended_upgrade_origins(self) -> None:
        self.assert_mutation_rejected(
            "infra/ci-cloud/digitalocean/cloud-init.tftpl",
            "      #clear Unattended-Upgrade::Origins-Pattern;\n",
            "",
        )

    def test_rejects_cloud_credential_in_remote_test_step(self) -> None:
        self.assert_mutation_rejected(
            ".github/workflows/cloud-conformance.yml",
            "      - name: Run uncredentialed DigitalOcean remote conformance\n",
            "      - name: Run uncredentialed DigitalOcean remote conformance\n"
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
