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
    def test_provider_bootstrap_uses_documented_native_transports(self) -> None:
        digitalocean = (ROOT / "infra/ci-cloud/digitalocean/main.tf").read_text(
            encoding="utf-8"
        )
        gcp = (ROOT / "infra/ci-cloud/gcp/main.tf").read_text(encoding="utf-8")
        bootstrap = (
            ROOT / "scripts/ci-cloud/bootstrap-conformance-host.tftpl"
        ).read_text(encoding="utf-8")

        self.assertIn('user_data = templatefile(', digitalocean)
        self.assertIn("bootstrap-conformance-host.tftpl", digitalocean)
        self.assertIn('"startup-script" = templatefile(', gcp)
        self.assertNotIn("user-data", gcp)
        self.assertTrue(bootstrap.startswith("#!/usr/bin/env bash\n"))
        self.assertNotIn("#cloud-config", bootstrap)

    def test_ephemeral_public_key_is_bounded_before_provider_submission(self) -> None:
        for provider in ("digitalocean", "gcp"):
            variables = (
                ROOT / "infra" / "ci-cloud" / provider / "variables.tf"
            ).read_text(encoding="utf-8")
            self.assertIn(
                "length(trimspace(var.ssh_public_key)) <= 128", variables
            )
        host_setup = (
            ROOT / "scripts/ci-cloud/configure-conformance-host.sh"
        ).read_text(encoding="utf-8")
        self.assertIn("((file_size > 128))", host_setup)

    def test_provider_bootstrap_preserves_explicit_user_data_headroom(
        self,
    ) -> None:
        validator = VALIDATOR.read_text(encoding="utf-8")
        self.assertIn("BOOTSTRAP_USER_DATA_HEADROOM = 256", validator)
        self.assertIn(
            "(64 * 1024) - BOOTSTRAP_USER_DATA_HEADROOM",
            validator,
        )

    def test_static_contract_rejects_provider_bootstrap_transport_drift(self) -> None:
        for relative, old, new in (
            (
                "infra/ci-cloud/digitalocean/main.tf",
                "user_data = templatefile",
                "metadata = templatefile",
            ),
            (
                "infra/ci-cloud/gcp/main.tf",
                '"startup-script" = templatefile',
                "user-data = templatefile",
            ),
        ):
            with self.subTest(relative=relative):
                self.assert_mutation_rejected(relative, old, new)

    def test_static_contract_rejects_oversized_provider_bootstrap(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/bootstrap-conformance-host.tftpl",
            "#!/usr/bin/env bash\n",
            "#!/usr/bin/env bash\n# " + ("x" * (24 * 1024)) + "\n",
        )

    def test_static_contract_rejects_unbounded_provider_public_key(self) -> None:
        for provider in ("digitalocean", "gcp"):
            with self.subTest(provider=provider):
                self.assert_mutation_rejected(
                    f"infra/ci-cloud/{provider}/variables.tf",
                    "length(trimspace(var.ssh_public_key)) <= 128 &&\n",
                    "",
                )

    def test_native_bootstrap_installs_and_commits_trusted_host_setup(self) -> None:
        bootstrap = (
            ROOT / "scripts/ci-cloud/bootstrap-conformance-host.tftpl"
        ).read_text(encoding="utf-8")
        continuation = (
            ROOT / "scripts/ci-cloud/continue-conformance-bootstrap.sh"
        ).read_text(encoding="utf-8")

        self.assertIn("set -euo pipefail", bootstrap)
        self.assertIn("export LC_ALL=C", bootstrap)
        self.assertIn(
            'apt-get -o DPkg::Lock::Timeout=300 \\\n'
            '  -o "APT::Update::Pre-Invoke::=$apt_lists_cleanup" update',
            bootstrap,
        )
        self.assertIn(
            "apt-get -o DPkg::Lock::Timeout=300 install", bootstrap
        )
        self.assertIn("useradd", bootstrap)
        self.assertIn("${diagnostic_ssh_installer}", bootstrap)
        self.assertIn("${host_setup_script_base64gzip}", bootstrap)
        self.assertIn("${host_setup_failure_script}", bootstrap)
        self.assertIn("${bootstrap_continuation_script}", bootstrap)
        self.assertIn(
            '/usr/local/sbin/secpal-ci-configure-conformance-host "$runner_ipv4"',
            continuation,
        )

    def test_native_bootstrap_installs_required_catatonit_runtime(self) -> None:
        bootstrap = (
            ROOT / "scripts/ci-cloud/bootstrap-conformance-host.tftpl"
        ).read_text(encoding="utf-8")

        self.assertIn("  catatonit \\\n", bootstrap)

    def test_native_bootstrap_publishes_target_admitted_quadlet_policy(self) -> None:
        bootstrap = (
            ROOT / "scripts/ci-cloud/bootstrap-conformance-host.tftpl"
        ).read_text(encoding="utf-8")

        self.assertIn(
            "/etc/environment.d/90-secpal-quadlet.conf",
            bootstrap,
        )
        self.assertNotIn(
            "/etc/environment.d/90-secpal-ci-quadlet.conf",
            bootstrap,
        )

    def test_native_bootstrap_installs_closed_user_environment_generator(self) -> None:
        bootstrap = (
            ROOT / "scripts/ci-cloud/bootstrap-conformance-host.tftpl"
        ).read_text(encoding="utf-8")

        self.assertIn(
            "/etc/systemd/user-environment-generators/"
            "30-systemd-environment-d-generator",
            bootstrap,
        )
        self.assertIn('[[ "$(/usr/bin/id -u)" == 20000 ]] || exit 0', bootstrap)
        for assignment in (
            "CONTAINERS_CONF=/dev/null",
            "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/20000/bus",
            "HOME=/home/secpal-ci",
            "LANG=C.UTF-8",
            "LC_ALL=C.UTF-8",
            "LOGNAME=secpal-ci",
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "QUADLET_UNIT_DIRS=/etc/containers/systemd/users/20000",
            "SHELL=/bin/bash",
            "USER=secpal-ci",
            "XDG_RUNTIME_DIR=/run/user/20000",
        ):
            self.assertIn(f"'{assignment}'", bootstrap)

    def test_static_contract_rejects_unadmitted_quadlet_policy_path(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/bootstrap-conformance-host.tftpl",
            "/etc/environment.d/90-secpal-quadlet.conf",
            "/etc/environment.d/90-secpal-ci-quadlet.conf",
        )

    def test_static_contract_rejects_unadmitted_environment_generator_path(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/bootstrap-conformance-host.tftpl",
            (
                "/etc/systemd/user-environment-generators/"
                "30-systemd-environment-d-generator"
            ),
            (
                "/etc/systemd/user-environment-generators/"
                "31-unreviewed-environment-generator"
            ),
        )

    def test_static_contract_rejects_environment_generator_search_path_drift(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/bootstrap-conformance-host.tftpl",
            "'QUADLET_UNIT_DIRS=/etc/containers/systemd/users/20000'",
            "'QUADLET_UNIT_DIRS=/tmp/untrusted-quadlets'",
        )

    def test_static_contract_rejects_unterminated_quadlet_policy(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/bootstrap-conformance-host.tftpl",
            "\nSECPAL_QUADLET\n\ninstall -d -o root -g root -m 0755 ",
            "\n\ninstall -d -o root -g root -m 0755 ",
        )

    def test_native_bootstrap_reboots_once_into_authenticated_current_kernel(
        self,
    ) -> None:
        bootstrap = (
            ROOT / "scripts/ci-cloud/bootstrap-conformance-host.tftpl"
        ).read_text(encoding="utf-8")
        continuation = (
            ROOT / "scripts/ci-cloud/continue-conformance-bootstrap.sh"
        ).read_text(encoding="utf-8")

        self.assertIn("linux-image-cloud-amd64", bootstrap)
        self.assertIn("linux-image-cloud-arm64", bootstrap)
        self.assertIn("apt-cache policy", bootstrap)
        self.assertIn("/boot/vmlinuz-$expected_kernel", bootstrap)
        self.assertIn("meta_package_dependencies=", bootstrap)
        self.assertIn("expected_kernel_package_version=", bootstrap)
        self.assertNotIn("readlink -e /vmlinuz", bootstrap)
        self.assertIn("/proc/sys/kernel/random/boot_id", bootstrap)
        self.assertIn("secpal-ci-bootstrap-continue.service", bootstrap)
        self.assertEqual(1, bootstrap.count("systemctl reboot"))
        self.assertLess(
            bootstrap.index("secpal-ci-bootstrap-continue.service"),
            bootstrap.index("systemctl reboot"),
        )
        self.assertNotIn("systemctl reboot", continuation)
        self.assertIn("ConditionPathExists=", bootstrap)
        self.assertIn('validate_state_file "$context_file" 1024', continuation)
        self.assertIn('validate_state_file "$pending_file" 256', continuation)
        self.assertIn(
            '[[ "$(stat -c \'%u:%g:%a\' -- "$state_root")" == 0:0:700 ]]',
            bootstrap,
        )
        self.assertIn(
            '[[ ! -e "$state_root" && ! -L "$state_root" ]]', bootstrap
        )
        self.assertIn('mv -T -- "$context_tmp" "$state_root/context"', bootstrap)
        self.assertIn('mv -T -- "$pending_tmp" "$pending_file"', bootstrap)
        self.assertIn("uname -r", continuation)
        self.assertIn("/proc/sys/kernel/random/boot_id", continuation)
        self.assertIn("secpal-ci-install-diagnostic-ssh", continuation)
        self.assertIn("secpal-ci-configure-conformance-host", continuation)
        self.assertLess(
            continuation.index("secpal-ci-install-diagnostic-ssh"),
            continuation.index("secpal-ci-configure-conformance-host"),
        )
        self.assertIn("failure_marker_ready=true", continuation)
        self.assertIn(
            'rm -f -- "$pending_file" "$context_file" "$continuation_unit"',
            continuation,
        )
        self.assertLess(
            continuation.index(
                "/usr/local/sbin/secpal-ci-configure-conformance-host"
            ),
            continuation.index(
                'rm -f -- "$pending_file" "$context_file" "$continuation_unit"'
            ),
        )
        self.assertIn(
            '! "$failure_writer" read >/dev/null 2>&1', continuation
        )
        self.assertLess(
            continuation.index(
                "/usr/local/sbin/secpal-ci-configure-conformance-host"
            ),
            continuation.rindex("trap - EXIT"),
        )
        self.assertLess(
            continuation.rindex("trap - EXIT"),
            continuation.index(
                'rm -f -- "$pending_file" "$context_file" "$continuation_unit"'
            ),
        )

    def test_restricted_diagnostic_ssh_survives_the_kernel_reboot(self) -> None:
        installer = (
            ROOT / "scripts/ci-cloud/install-diagnostic-ssh.sh"
        ).read_text(encoding="utf-8")
        host_setup = (
            ROOT / "scripts/ci-cloud/configure-conformance-host.sh"
        ).read_text(encoding="utf-8")

        persistent_root = "/var/lib/secpal-ci-diagnostic"
        self.assertIn(f"diagnostic_root={persistent_root}", installer)
        self.assertIn(
            'diagnostic_key="$diagnostic_root/authorized-key"', installer
        )
        self.assertIn('diagnostic_home="$diagnostic_root/home"', installer)
        self.assertIn(
            'diagnostic_service_unit="/etc/systemd/system/$diagnostic_service"',
            installer,
        )
        self.assertIn(
            'diagnostic_timer_unit="/etc/systemd/system/$diagnostic_timer"',
            installer,
        )
        self.assertIn(f"diagnostic_root={persistent_root}", host_setup)
        self.assertIn(
            'diagnostic_ssh_key="$diagnostic_root/authorized-key"', host_setup
        )
        self.assertIn(
            'diagnostic_ssh_home="$diagnostic_root/home"', host_setup
        )
        self.assertIn(
            "diagnostic_ssh_service_unit=/etc/systemd/system/"
            "secpal-ci-diagnostic-sshd.service",
            host_setup,
        )
        self.assertIn(
            "diagnostic_ssh_timer_unit=/etc/systemd/system/"
            "secpal-ci-diagnostic-sshd.timer",
            host_setup,
        )

        self.assertNotIn("diagnostic_key=/run/", installer)
        self.assertNotIn("diagnostic_config=/run/", installer)
        self.assertNotIn("diagnostic_command=/run/", installer)
        self.assertIn("WantedBy=multi-user.target", installer)
        self.assertIn("RuntimeDirectory=sshd secpal-ci-evidence", installer)
        self.assertIn("RuntimeDirectoryMode=0755", installer)
        self.assertIn("RuntimeDirectoryPreserve=yes", installer)
        self.assertIn(
            "Before=secpal-ci-bootstrap-continue.service", installer
        )
        self.assertIn('systemctl enable "$diagnostic_service"', installer)
        self.assertLess(
            installer.index('systemctl enable "$diagnostic_service"'),
            installer.index('systemctl restart "$diagnostic_service"'),
        )
        activation = host_setup.split(
            "perform_operator_ssh_handoff() {", 1
        )[1].split("\n}\n", 1)[0]
        retirement = host_setup.split("retire_diagnostic_ssh() {", 1)[1].split(
            "\n}\n", 1
        )[0]
        self.assertNotIn(
            'systemctl disable "$diagnostic_ssh_service"', activation
        )
        self.assertIn('systemctl disable "$diagnostic_ssh_service"', retirement)
        self.assertIn('rm -f -- "$staged_ssh_public_key"', retirement)
        self.assertLess(
            retirement.index('systemctl disable "$diagnostic_ssh_service"'),
            retirement.index('rm -f -- "$staged_ssh_public_key"'),
        )
        self.assertIn('rmdir -- "$diagnostic_root"', host_setup)
        continuation = (
            ROOT / "scripts/ci-cloud/continue-conformance-bootstrap.sh"
        ).read_text(encoding="utf-8")
        diagnostic_init = (
            'install -d -o root -g root -m 0755 "$diagnostic_dir"'
        )
        self.assertIn("diagnostic_dir=/run/secpal-ci-evidence", continuation)
        self.assertIn(diagnostic_init, continuation)
        self.assertLess(
            continuation.index(diagnostic_init),
            continuation.index('validate_state_file "$context_file" 1024'),
        )
        self.assertLess(
            continuation.index("failure_marker_ready=true"),
            continuation.index('validate_state_file "$context_file" 1024'),
        )

        bootstrap = (
            ROOT / "scripts/ci-cloud/bootstrap-conformance-host.tftpl"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "Wants=network-online.target "
            "secpal-ci-diagnostic-sshd.service",
            bootstrap,
        )
        self.assertIn(
            "After=network-online.target "
            "secpal-ci-diagnostic-sshd.service",
            bootstrap,
        )

    def test_operator_handoff_cannot_reboot_two_port_22_listeners(self) -> None:
        installer = (
            ROOT / "scripts/ci-cloud/install-diagnostic-ssh.sh"
        ).read_text(encoding="utf-8")
        host_setup = (
            ROOT / "scripts/ci-cloud/configure-conformance-host.sh"
        ).read_text(encoding="utf-8")
        activation = host_setup.split("activate_operator_ssh() {", 1)[1].split(
            "\n}", 1
        )[0]
        handoff = host_setup.split("perform_operator_ssh_handoff() {", 1)[
            1
        ].split("\n}", 1)[0]
        restore = host_setup.split("restore_diagnostic_ssh() {", 1)[1].split(
            "\n}", 1
        )[0]

        self.assertIn(
            "ConditionPathExists=/var/lib/secpal-ci-diagnostic/selected",
            installer,
        )
        self.assertIn(
            'operator_ssh_gate="$operator_ssh_gate_dir/secpal-ci-ready.conf"',
            installer,
        )
        self.assertIn("operator_ssh_boot_gate_is_valid() {", host_setup)
        marker = "publish_completion_marker"
        stop_diagnostic = 'systemctl stop "$diagnostic_ssh_service"'
        restart_operator = "systemctl restart ssh.service"
        self.assertIn(stop_diagnostic, handoff)
        self.assertNotIn('systemctl disable "$diagnostic_ssh_service"', handoff)
        self.assertLess(
            handoff.index(stop_diagnostic),
            handoff.index(marker),
        )
        self.assertLess(
            handoff.index(restart_operator),
            handoff.index(marker),
        )
        self.assertNotIn('systemctl enable "$diagnostic_ssh_service"', restore)
        self.assertLess(
            restore.index('rm -f -- "$completion_marker"'),
            restore.index('systemctl start "$diagnostic_ssh_recovery_service"'),
        )

    def test_initial_boot_listener_selection_is_atomic(self) -> None:
        installer = (
            ROOT / "scripts/ci-cloud/install-diagnostic-ssh.sh"
        ).read_text(encoding="utf-8")
        start = installer.split("start_diagnostic_fallback_locked() {", 1)[
            1
        ].split("\n}", 1)[0]

        selector = "/var/lib/secpal-ci-diagnostic/selected"
        self.assertIn('diagnostic_selector="$diagnostic_root/selected"', installer)
        self.assertIn(f"ConditionPathExists={selector}", installer)
        self.assertIn("ConditionPathExists=!%s\\n'", installer)
        self.assertLess(
            installer.index("prepare_operator_ssh_boot_gate"),
            installer.index('systemctl enable "$diagnostic_service"'),
        )
        self.assertLess(
            start.index('systemctl enable "$diagnostic_service"'),
            start.index("select_diagnostic_ssh"),
        )
        self.assertLess(
            start.index("select_diagnostic_ssh"),
            start.index("systemctl mask --now ssh.service ssh.socket"),
        )

    def test_handoff_recovery_owns_the_selector_transition(self) -> None:
        installer = (
            ROOT / "scripts/ci-cloud/install-diagnostic-ssh.sh"
        ).read_text(encoding="utf-8")
        host_setup = (
            ROOT / "scripts/ci-cloud/configure-conformance-host.sh"
        ).read_text(encoding="utf-8")
        activation = host_setup.split("activate_operator_ssh() {", 1)[1].split(
            "\n}", 1
        )[0]
        handoff = host_setup.split("perform_operator_ssh_handoff() {", 1)[
            1
        ].split("\n}", 1)[0]
        restore = host_setup.split("restore_diagnostic_ssh() {", 1)[1].split(
            "\n}", 1
        )[0]

        self.assertIn("Unit=secpal-ci-diagnostic-ssh-recover.service", installer)
        self.assertIn(
            "ConditionPathExists=!/var/lib/secpal-ci/host-setup-complete",
            installer,
        )
        self.assertIn("select_diagnostic_ssh() {", installer)
        self.assertIn(
            "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            installer.split("<<'RECOVERY'", 1)[1].split("\nRECOVERY", 1)[0],
        )
        self.assertIn('rm -f -- "$diagnostic_ssh_selector"', handoff)
        self.assertLess(
            activation.index("arm_diagnostic_ssh_recovery"),
            activation.index("acquire_ssh_handoff_lock"),
        )
        self.assertLess(
            handoff.index("systemctl enable ssh.service"),
            handoff.index('rm -f -- "$diagnostic_ssh_selector"'),
        )
        self.assertLess(
            handoff.index('rm -f -- "$diagnostic_ssh_selector"'),
            handoff.index("systemctl restart ssh.service"),
        )
        self.assertLess(
            handoff.index("systemctl is-active --quiet ssh.service"),
            handoff.index("publish_completion_marker"),
        )
        self.assertIn(
            'systemctl start "$diagnostic_ssh_recovery_service"', restore
        )

    def test_ssh_handoff_and_recovery_share_one_kernel_lock(self) -> None:
        installer = (
            ROOT / "scripts/ci-cloud/install-diagnostic-ssh.sh"
        ).read_text(encoding="utf-8")
        host_setup = (
            ROOT / "scripts/ci-cloud/configure-conformance-host.sh"
        ).read_text(encoding="utf-8")
        recovery = installer.split("<<'RECOVERY'\n", 1)[1].split(
            "\nRECOVERY", 1
        )[0]
        activation = host_setup.split("activate_operator_ssh() {", 1)[1].split(
            "\n}", 1
        )[0]
        handoff = host_setup.split("perform_operator_ssh_handoff() {", 1)[
            1
        ].split("\n}", 1)[0]
        diagnostic_start = installer.split("start_diagnostic_fallback() {", 1)[
            1
        ].split("\n}", 1)[0]
        locked_start = installer.split(
            "start_diagnostic_fallback_locked() {", 1
        )[1].split("\n}", 1)[0]
        stop_diagnostic = host_setup.split("stop_diagnostic_ssh() {", 1)[
            1
        ].split("\n}", 1)[0]

        lock = "ssh_handoff_lock=/run/secpal-ci-ssh-handoff.lock"
        self.assertIn(lock, installer)
        self.assertIn(lock, recovery)
        self.assertIn(lock, host_setup)
        self.assertLess(
            recovery.index('flock -x "$ssh_handoff_lock_fd"'),
            recovery.index('[[ ! -e "$completion_marker"'),
        )
        self.assertLess(
            activation.index("acquire_ssh_handoff_lock"),
            activation.index("perform_operator_ssh_handoff"),
        )
        self.assertLess(
            activation.index("perform_operator_ssh_handoff"),
            activation.index("release_ssh_handoff_lock"),
        )
        self.assertIn("publish_completion_marker", handoff)
        self.assertLess(
            diagnostic_start.index("acquire_ssh_handoff_lock"),
            diagnostic_start.index("start_diagnostic_fallback_locked"),
        )
        self.assertLess(
            locked_start.index("completed_setup_is_valid"),
            locked_start.index(
                'rm -f -- "$completion_marker" "$active_operator_key"'
            ),
        )
        self.assertLess(
            locked_start.index(
                'rm -f -- "$completion_marker" "$active_operator_key"'
            ),
            locked_start.index("prepare_diagnostic_fallback"),
        )
        self.assertIn(
            'systemctl stop "$diagnostic_ssh_recovery_service"',
            stop_diagnostic,
        )

    def test_systemd_reboot_contract_has_no_sshd_binary_dependency(self) -> None:
        test = (ROOT / "tests/ci-cloud-systemd-reboot.py").read_text(
            encoding="utf-8"
        )

        self.assertNotIn('shutil.which("sshd")', test)
        self.assertNotIn('/usr/sbin/sshd").is_file()', test)
        self.assertIn('replace("/usr/sbin/sshd", "/bin/true")', test)

    def test_static_contract_rejects_ephemeral_reboot_diagnostics(self) -> None:
        cases = (
            (
                "scripts/ci-cloud/install-diagnostic-ssh.sh",
                "diagnostic_root=/var/lib/secpal-ci-diagnostic",
                "diagnostic_root=/run/secpal-ci-diagnostic",
            ),
            (
                "scripts/ci-cloud/install-diagnostic-ssh.sh",
                'diagnostic_service_unit="/etc/systemd/system/'
                '$diagnostic_service"',
                'diagnostic_service_unit="/run/systemd/system/'
                '$diagnostic_service"',
            ),
            (
                "scripts/ci-cloud/install-diagnostic-ssh.sh",
                '  systemctl enable "$diagnostic_service" '
                ">/dev/null 2>&1 || return 1\n",
                "",
            ),
            (
                "scripts/ci-cloud/install-diagnostic-ssh.sh",
                "RuntimeDirectory=sshd secpal-ci-evidence\n",
                "",
            ),
            (
                "scripts/ci-cloud/install-diagnostic-ssh.sh",
                "RuntimeDirectoryPreserve=yes\n",
                "RuntimeDirectoryPreserve=restart\n",
            ),
            (
                "scripts/ci-cloud/install-diagnostic-ssh.sh",
                "Before=secpal-ci-bootstrap-continue.service\n",
                "",
            ),
            (
                "scripts/ci-cloud/install-diagnostic-ssh.sh",
                "ConditionPathExists=/var/lib/secpal-ci-diagnostic/selected\n",
                "",
            ),
            (
                "scripts/ci-cloud/install-diagnostic-ssh.sh",
                "ConditionPathExists=!%s\\n'",
                "",
            ),
            (
                "scripts/ci-cloud/install-diagnostic-ssh.sh",
                "Unit=secpal-ci-diagnostic-ssh-recover.service\n",
                "Unit=secpal-ci-diagnostic-sshd.service\n",
            ),
            (
                "scripts/ci-cloud/install-diagnostic-ssh.sh",
                "ConditionPathExists=!/var/lib/secpal-ci/host-setup-complete\n",
                "",
            ),
            (
                "scripts/ci-cloud/install-diagnostic-ssh.sh",
                '  mv -T -- "$selector_tmp" "$diagnostic_selector"\n',
                "",
            ),
            (
                "scripts/ci-cloud/install-diagnostic-ssh.sh",
                "  prepare_operator_ssh_boot_gate || return 1\n",
                "",
            ),
            (
                "scripts/ci-cloud/install-diagnostic-ssh.sh",
                'exec 9<>"$ssh_handoff_lock"\n'
                'flock -x "$ssh_handoff_lock_fd"\n',
                'exec 9<>"$ssh_handoff_lock"\n',
            ),
            (
                "scripts/ci-cloud/install-diagnostic-ssh.sh",
                "  acquire_ssh_handoff_lock || return 1\n",
                "",
            ),
            (
                "scripts/ci-cloud/install-diagnostic-ssh.sh",
                "  if completed_setup_is_valid; then\n"
                "    return 0\n"
                "  fi\n",
                "",
            ),
            (
                "scripts/ci-cloud/configure-conformance-host.sh",
                '    ! rm -f -- "$diagnostic_ssh_selector" ||\n',
                "",
            ),
            (
                "scripts/ci-cloud/configure-conformance-host.sh",
                '  systemctl start "$diagnostic_ssh_recovery_service" || return 1\n',
                "",
            ),
            (
                "scripts/ci-cloud/configure-conformance-host.sh",
                "  if ! acquire_ssh_handoff_lock; then\n",
                "  if false; then\n",
            ),
            (
                "scripts/ci-cloud/configure-conformance-host.sh",
                "  release_ssh_handoff_lock\n  ssh_key_activated=true\n",
                "  ssh_key_activated=true\n",
            ),
            (
                "scripts/ci-cloud/bootstrap-conformance-host.tftpl",
                "After=network-online.target "
                "secpal-ci-diagnostic-sshd.service\n",
                "After=network-online.target\n",
            ),
            (
                "scripts/ci-cloud/continue-conformance-bootstrap.sh",
                "failure_marker_ready=true\n",
                "",
            ),
            (
                "scripts/ci-cloud/configure-conformance-host.sh",
                '  systemctl disable "$diagnostic_ssh_service" '
                ">/dev/null 2>&1 || \\\n"
                "    cleanup_failed=true\n",
                "",
            ),
            (
                "scripts/ci-cloud/configure-conformance-host.sh",
                '    ! rmdir -- "$diagnostic_root"; then\n',
                "    false; then\n",
            ),
        )
        for relative, old, new in cases:
            with self.subTest(relative=relative, mutation=old):
                self.assert_mutation_rejected(relative, old, new)

    def test_static_contract_rejects_unsafe_kernel_reboot_continuation(self) -> None:
        cases = (
            (
                "scripts/ci-cloud/bootstrap-conformance-host.tftpl",
                "systemctl enable secpal-ci-bootstrap-continue.service",
                "true",
            ),
            (
                "scripts/ci-cloud/bootstrap-conformance-host.tftpl",
                "systemctl reboot",
                "systemctl reboot\nsystemctl reboot",
            ),
            (
                "scripts/ci-cloud/bootstrap-conformance-host.tftpl",
                'apt-cache policy "$kernel_image_package"',
                'printf \'Candidate: %s\\n\' "$installed_kernel_version"',
            ),
            (
                "scripts/ci-cloud/continue-conformance-bootstrap.sh",
                '[[ "$current_boot_id" != "$initial_boot_id" ]]',
                "true",
            ),
            (
                "scripts/ci-cloud/continue-conformance-bootstrap.sh",
                '[[ "$(uname -r)" == "$expected_kernel" ]]',
                "true",
            ),
            (
                "scripts/ci-cloud/continue-conformance-bootstrap.sh",
                "/usr/local/sbin/secpal-ci-install-diagnostic-ssh",
                "/bin/true",
            ),
            (
                "scripts/ci-cloud/continue-conformance-bootstrap.sh",
                'validate_state_file "$context_file" 1024',
                "true",
            ),
            (
                "scripts/ci-cloud/continue-conformance-bootstrap.sh",
                'systemctl disable "$continuation_service"',
                "true",
            ),
            (
                "scripts/ci-cloud/continue-conformance-bootstrap.sh",
                "/usr/local/sbin/secpal-ci-configure-conformance-host "
                '"$runner_ipv4"',
                'rm -f -- "$pending_file" "$context_file" '
                '"$continuation_unit"\n'
                "/usr/local/sbin/secpal-ci-configure-conformance-host "
                '"$runner_ipv4"',
            ),
            (
                "scripts/ci-cloud/continue-conformance-bootstrap.sh",
                '! "$failure_writer" read >/dev/null 2>&1',
                "true",
            ),
        )
        for relative, old, new in cases:
            with self.subTest(relative=relative, old=old):
                self.assert_mutation_rejected(relative, old, new)

    def test_static_contract_rejects_missing_kernel_verify_evidence_stage(
        self,
    ) -> None:
        self.assert_mutation_rejected(
            "schemas/ci-cloud-bootstrap-failure.schema.json",
            '                    "kernel-verify",\n',
            "",
        )

    def test_static_contract_rejects_stale_bootstrap_failure_schema_version(
        self,
    ) -> None:
        for stale_version in (4, 50):
            with self.subTest(stale_version=stale_version):
                self.assert_mutation_rejected(
                    "scripts/ci-cloud/write-bootstrap-failure.py",
                    '"schema_version": 5',
                    f'"schema_version": {stale_version}',
                )

    def test_native_bootstrap_publishes_ssh_policy_with_exact_mode(self) -> None:
        bootstrap = (
            ROOT / "scripts/ci-cloud/bootstrap-conformance-host.tftpl"
        ).read_text(encoding="utf-8")

        self.assertIn(
            "install -o root -g root -m 0644 /dev/null \\\n"
            "  /etc/ssh/sshd_config.d/00-secpal-ci.conf",
            bootstrap,
        )

    def test_native_bootstrap_replaces_provider_apt_sources_with_d1_sources(self) -> None:
        bootstrap = (
            ROOT / "scripts/ci-cloud/bootstrap-conformance-host.tftpl"
        ).read_text(encoding="utf-8")

        self.assertIn("Suites: trixie trixie-updates", bootstrap)
        self.assertIn("Suites: trixie-security", bootstrap)
        self.assertNotIn("trixie-backports", bootstrap)
        self.assertIn("/usr/share/keyrings/debian-archive-keyring.gpg", bootstrap)
        self.assertIn(
            'find "$apt_lists_dir" -mindepth 1 -maxdepth 1 \\\n'
            "  ! -name lock \\( -type f -o -type l \\) -delete",
            bootstrap,
        )
        self.assertIn("APT::Update::Pre-Invoke::=$apt_lists_cleanup", bootstrap)
        self.assertNotIn(
            'find "$apt_lists_dir" -mindepth 1 -maxdepth 1 \\\n'
            "  \\( -type f -o -type l \\) -delete",
            bootstrap,
        )
        self.assertLess(
            bootstrap.index("Suites: trixie trixie-updates"),
            bootstrap.index("apt-get -o DPkg::Lock::Timeout=300"),
        )

    def test_native_bootstrap_validator_reports_missing_block_markers(self) -> None:
        cases = (
            (
                "SSH policy start",
                "<<'SECPAL_SSH_CONFIG'\n",
                "<<'SECPAL_SSH_CONFIG_MISSING'\n",
                "native bootstrap SSH policy start marker is missing",
            ),
            (
                "SSH policy end",
                "\nSECPAL_SSH_CONFIG\n",
                "\nSECPAL_SSH_CONFIG_MISSING\n",
                "native bootstrap SSH policy end marker is missing",
            ),
            (
                "package start",
                "apt-get -o DPkg::Lock::Timeout=300 install -y "
                "--no-install-recommends \\\n",
                "apt-get -o DPkg::Lock::Timeout=300 install -y ",
                "native bootstrap package block start marker is missing",
            ),
            (
                "package end",
                '  unattended-upgrades\n\nsetup_stage="operator-identity"',
                '  unattended-upgrades\nsetup_stage="operator-identity"',
                "native bootstrap package block end marker is missing",
            ),
        )
        for label, old, new, expected in cases:
            with self.subTest(label=label):
                fixture = self.mutated_root(
                    "scripts/ci-cloud/bootstrap-conformance-host.tftpl",
                    old,
                    new,
                )
                result = self.run_validator(fixture)
                self.assertNotEqual(0, result.returncode, result.stdout)
                self.assertNotIn("Traceback", result.stdout)
                self.assertIn(expected, result.stdout)

    def test_validator_reports_missing_runtime_block_markers(self) -> None:
        cases = (
            (
                "scripts/ci-cloud/install-diagnostic-ssh.sh",
                "cleanup() {",
                "cleanup_missing() {",
                "diagnostic cleanup block start marker is missing",
            ),
            (
                "scripts/ci-cloud/configure-conformance-host.sh",
                "activate_operator_ssh() {",
                "activate_operator_ssh_missing() {",
                "operator SSH activation block start marker is missing",
            ),
            (
                "scripts/ci-cloud/run-remote-conformance.sh",
                'bootstrap_stage="root-ssh"',
                'bootstrap_stage="root-ssh-missing"',
                "root SSH admission block start marker is missing",
            ),
            (
                "scripts/ci-cloud/run-remote-conformance.sh",
                "classify_host_key_scan() {",
                "classify_host_key_scan_missing() {",
                "host-key classifier block start marker is missing",
            ),
        )
        for relative, old, new, expected in cases:
            with self.subTest(relative=relative, marker=old):
                fixture = self.mutated_root(relative, old, new)
                result = self.run_validator(fixture)
                self.assertNotEqual(0, result.returncode, result.stdout)
                self.assertNotIn("Traceback", result.stdout)
                self.assertIn(expected, result.stdout)

    def test_diagnostic_identity_has_existing_root_controlled_home(self) -> None:
        installer = (
            ROOT / "scripts/ci-cloud/install-diagnostic-ssh.sh"
        ).read_text(encoding="utf-8")

        self.assertIn(
            'diagnostic_home="$diagnostic_root/home"', installer
        )
        self.assertIn(
            'install -d -o root -g root -m 0755 "$diagnostic_home"', installer
        )
        self.assertIn('--home-dir "$diagnostic_home"', installer)
        self.assertNotIn("--home-dir /nonexistent", installer)
        host_setup = (
            ROOT / "scripts/ci-cloud/configure-conformance-host.sh"
        ).read_text(encoding="utf-8")
        self.assertIn(
            'diagnostic_ssh_home="$diagnostic_root/home"', host_setup
        )
        self.assertIn(
            '[[ -e "$diagnostic_ssh_home" || -L "$diagnostic_ssh_home" ]]',
            host_setup,
        )
        self.assertIn('rmdir -- "$diagnostic_ssh_home"', host_setup)

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
            ".github/workflows/cloud-conformance.yml",
            ".github/workflows/cloud-janitor.yml",
            ".github/workflows/rocky-cloud-qualification.yml",
            "config/ci-cloud/gcp-rocky-10-2-arm64.json",
            "infra/ci-cloud/digitalocean",
            "infra/ci-cloud/gcp",
            "infra/ci-cloud/gcp-rocky",
            "schemas",
            "scripts/ci-cloud",
            "scripts/fetch-oci-attestation.py",
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

    def test_rejects_weakened_current_boot_runtime_user_readiness(self) -> None:
        publisher = "scripts/ci-cloud/publish-rocky-qualification-readiness.py"
        mutations = (
            (
                publisher,
                '["systemctl", "is-active", "--quiet", f"user@{runtime_uid}.service"]',
                '["true"]',
            ),
            (
                publisher,
                "def observe_runtime_user(\n",
                "# loginctl enable-linger is not readiness\n"
                "def observe_runtime_user(\n",
            ),
            (
                publisher,
                "def observe_runtime_user(\n",
                "# runtime.systemd_user from preparation\n"
                "def observe_runtime_user(\n",
            ),
            (
                publisher,
                'stat.S_ISSOCK(os.stat(f"/run/user/{runtime_uid}/bus").st_mode)',
                "True",
            ),
            (publisher, '"show-environment"', '"daemon-reload"'),
            (publisher, "WAIT_SECONDS = 60", "WAIT_SECONDS = 0"),
            (
                publisher,
                "timeout=min(COMMAND_TIMEOUT_SECONDS, remaining)",
                "timeout=COMMAND_TIMEOUT_SECONDS",
            ),
            (
                publisher,
                "sleep(min(interval, remaining))",
                "time.sleep(WAIT_SECONDS)",
            ),
            (
                publisher,
                '"runtime_user_bus_available": result.observation.bus_available,',
                '"runtime_user_bus_available": result.observation.manager_active,',
            ),
            (
                publisher,
                "if current_boot_id() != arguments.boot_id:\n",
                "if False:\n",
            ),
            (
                "scripts/ci-cloud/bootstrap-rocky-host.tftpl",
                '  --boot-id "$boot_id" \\\n',
                "",
            ),
            (
                "scripts/ci-cloud/run-rocky-target-qualification.sh",
                "set -euo pipefail\n",
                "set -euo pipefail\n"
                "/usr/local/sbin/secpal-publish-rocky-qualification-readiness\n",
            ),
        )
        for relative, old, new in mutations:
            with self.subTest(relative=relative, old=old):
                self.assert_mutation_rejected(relative, old, new)

    def test_rejects_collapsed_quadlet_target_diagnostics(self) -> None:
        classifier = "scripts/ci-cloud/classify-rocky-target-qualification-failure.py"
        for old, new in (
            (
                '(242, 242, "qualify-quadlet-daemon-reload"),',
                '(242, 242, "qualify-quadlet-runtime"),',
            ),
            (
                '(243, 243, "qualify-quadlet-start"),',
                '(243, 243, "qualify-quadlet-daemon-reload"),',
            ),
            (
                '(244, 244, "qualify-quadlet-active-state"),',
                '(244, 244, "qualify-quadlet-start"),',
            ),
        ):
            with self.subTest(new=new):
                self.assert_mutation_rejected(classifier, old, new)

    def test_rejects_weakened_target_trace_binding_bounds_and_ambiguity(self) -> None:
        classifier = "scripts/ci-cloud/classify-rocky-target-qualification-failure.py"
        for old, new in (
            (
                'EXPECTED_TARGET_SHA = "d89214795bc1bdf0e65d9bbf7c8b9647b7e1ebd6"',
                'EXPECTED_TARGET_SHA = ""',
            ),
            (
                'EXPECTED_HARNESS_SHA256 = "ad6d2518aa3f72054e6fa373b05345e7c37c21ac65feb6075eb69f3c434fea53"',
                'EXPECTED_HARNESS_SHA256 = ""',
            ),
            ("MAX_TRACE_FRAMES = 8", "MAX_TRACE_FRAMES = 9"),
            ("MAX_TRACE_LINE = 9_999", "MAX_TRACE_LINE = 10_000"),
            (
                'if len(traced_operations) == 1:\n        return traced_operations.pop(), "command-failed"\n    return "qualification-harness", "unclassified-target-failure"',
                'if traced_operations:\n        return sorted(traced_operations)[0], "command-failed"\n    return "qualification-harness", "unclassified-target-failure"',
            ),
        ):
            with self.subTest(new=new):
                self.assert_mutation_rejected(classifier, old, new)

    def test_rejects_weakened_daemon_reload_failure_adjacency(self) -> None:
        trace = "scripts/ci-cloud/rocky-target-qualification-trace.sh"
        runner = "scripts/ci-cloud/run-rocky-target-qualification.sh"
        observer = "scripts/ci-cloud/observe-rocky-quadlet-reload-adjacency.py"
        classifier = "scripts/ci-cloud/classify-rocky-target-qualification-failure.py"
        mutations = (
            (
                trace,
                "SECPAL_QUADLET_RELOAD_FAILURE_V2:%s:%s:%s",
                "SECPAL_UNBOUNDED_RELOAD_FAILURE:%s:%s",
            ),
            (trace, '"$status" "$$" "$frames"', '"$status" "1" "$frames"'),
            (trace, "10#$frame == 242", "10#$frame == 243"),
            (trace, "read -r -t 25 -u 5", "read -r -u 5"),
            (trace, "trap - ERR", ":"),
            (
                runner,
                "ad6d2518aa3f72054e6fa373b05345e7c37c21ac65feb6075eb69f3c434fea53",
                "",
            ),
            (runner, "mkfifo -m 0600", "install -m 0600 /dev/null"),
            (runner, '--reload-adjacency "$reload_adjacency"', ""),
            (observer, "MAX_INPUT_BYTES = 4_096", "MAX_INPUT_BYTES = 65_536"),
            (observer, "CAPTURE_DEADLINE_SECONDS = 22", "CAPTURE_DEADLINE_SECONDS = 26"),
            (observer, "time.monotonic() > deadline", "False"),
            (
                observer,
                'raise ObservationError("adjacency command could not execute")',
                "return 125",
            ),
            (
                observer,
                "os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW",
                "os.O_RDONLY | os.O_CLOEXEC",
            ),
            (observer, "stat.S_ISFIFO", "stat.S_ISREG"),
            (observer, "stat.S_ISLNK(link_metadata.st_mode)", "False"),
            (
                observer,
                "directory.resolve(strict=True) == directory",
                "directory.resolve(strict=True) != directory",
            ),
            (observer, 'f"QUADLET_UNIT_DIRS={input_path.parent}"', '"QUADLET_UNIT_DIRS=/"'),
            (observer, '"--dryrun"', '"daemon-reload"'),
            (observer, '"show-environment"', '"daemon-reload"'),
            (
                observer,
                'f"CODE_FUNC={GENERATOR_CODE_FUNC}"',
                'f"IGNORED_CODE_FUNC={GENERATOR_CODE_FUNC}"',
            ),
            (
                observer,
                'f"CODE_FILE={GENERATOR_CODE_FILE}"',
                'f"IGNORED_CODE_FILE={GENERATOR_CODE_FILE}"',
            ),
            (
                observer,
                'f"--boot={boot_id.replace(\'-\', \'\')}"',
                'f"--boot={boot_id}"',
            ),
            (
                observer,
                'f"--output-fields={GENERATOR_OUTPUT_FIELDS}"',
                '"--output=json-pretty"',
            ),
            (
                observer,
                "max_bytes=MAX_GENERATOR_JOURNAL_BYTES",
                "max_bytes=MAX_COMMAND_BYTES",
            ),
            (
                observer,
                'ROCKY_SYSTEMD_SOURCE_RPM = "systemd-257-23.el10_2.2.rocky.0.1.src.rpm"',
                'ROCKY_SYSTEMD_SOURCE_RPM = "upstream-main"',
            ),
            (
                observer,
                'f"--output-fields={RELOAD_OUTPUT_FIELDS}"',
                '"--output=json-pretty"',
            ),
            (observer, 'f"_PID={manager_pid}"', '"_UID=0"'),
            (observer, 'os.statvfs("/run/systemd")', 'os.statvfs("/run")'),
            (observer, '"tclass=system"', '"tclass=file"'),
            (
                observer,
                'r"avc:\\s+denied\\s+\\{\\s*reload\\s*\\}"',
                'r"avc:.*denied"',
            ),
            (observer, 'comm="podman-system-g"', 'comm="systemd"'),
            (
                classifier,
                '_closed_boolean(observation, "captured_before_cleanup")',
                "True",
            ),
            (
                classifier,
                '_closed_boolean(\n            observation, "generator_failure_ambiguous"\n        )',
                "False",
            ),
            (
                classifier,
                'generator_ambiguous != (generator_reason != "none")',
                "False",
            ),
            (
                classifier,
                're.fullmatch(r"[0-9a-f]{64}", str(observation["failure_event_sha256"]))',
                "None",
            ),
            (
                classifier,
                'return "reload-authorization-denied", "none"',
                'return "reload-reply-transport-failed", "none"',
            ),
            (
                classifier,
                'return "reload-rate-limited", "none"',
                'return "manager-reload-transaction-failed", "none"',
            ),
            (
                classifier,
                'return "reload-reply-transport-failed", "none"\n',
                'return "manager-reload-transaction-failed", "none"\n',
            ),
        )
        for relative, old, new in mutations:
            with self.subTest(relative=relative, old=old):
                self.assert_mutation_rejected(relative, old, new)

    def test_preflight_prunes_generated_opentofu_cache(self) -> None:
        preflight = (ROOT / "scripts" / "preflight.sh").read_text(encoding="utf-8")
        self.assertEqual(
            3,
            preflight.count("-name .terraform"),
            "Markdown, YAML, and Prettier discovery must prune OpenTofu caches",
        )
        self.assertIn("python3 tests/ci-cloud-gcp-janitor.py", preflight)
        self.assertIn("bash tests/ci-cloud-gcp-identity.sh", preflight)
        self.assertIn("python3 tests/ci-cloud-bootstrap-failure.py", preflight)
        self.assertIn("python3 tests/ci-cloud-config.py", preflight)
        self.assertIn("python3 tests/ci-cloud-host-setup-failure.py", preflight)
        self.assertNotIn("required_tools=(actionlint cloud-init", preflight)

    def test_repository_contract_requires_every_cloud_provider_root_and_janitor(self) -> None:
        repository_contract = (ROOT / "tests" / "repository-contract.sh").read_text(
            encoding="utf-8"
        )
        for relative in (
            "infra/ci-cloud/gcp/.terraform.lock.hcl",
            "scripts/ci-cloud/bootstrap-conformance-host.tftpl",
            "infra/ci-cloud/gcp/iam-role.yaml",
            "infra/ci-cloud/gcp/main.tf",
            "infra/ci-cloud/gcp/outputs.tf",
            "infra/ci-cloud/gcp/variables.tf",
            "infra/ci-cloud/gcp/versions.tf",
            "infra/ci-cloud/gcp-rocky/.terraform.lock.hcl",
            "infra/ci-cloud/gcp-rocky/main.tf",
            "infra/ci-cloud/gcp-rocky/outputs.tf",
            "infra/ci-cloud/gcp-rocky/variables.tf",
            "infra/ci-cloud/gcp-rocky/versions.tf",
            "scripts/ci-cloud/gcp-rocky-janitor.py",
            "scripts/ci-cloud/rocky-control.py",
            "tests/ci-cloud-gcp-rocky-janitor.py",
            "tests/ci-cloud-rocky-control.py",
            "tests/ci-cloud-rocky-target-diagnostics.py",
            "schemas/ci-cloud-bootstrap-failure.schema.json",
            "scripts/ci-cloud/gcp-janitor.py",
            "scripts/ci-cloud/detach-gcp-vm-identity.sh",
            "scripts/ci-cloud/defer-bootstrap-for-gcp-identity.sh",
            "tests/ci-cloud-gcp-janitor.py",
            "tests/ci-cloud-gcp-identity.sh",
        ):
            with self.subTest(relative=relative):
                self.assertIn(relative, repository_contract)

    def test_static_contract_rejects_opaque_target_harness_failure_regression(
        self,
    ) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/run-rocky-target-qualification.sh",
            "exit 91",
            "printf 'qualification harness failed with exit status %s\\n' \"$status\" >&2\n  exit 1",
        )
        self.assert_mutation_rejected(
            ".github/workflows/rocky-cloud-qualification.yml",
            "Retrieve and validate bounded target-qualification failure",
            "Discard target-qualification failure",
        )

    def test_static_contract_rejects_target_call_stack_coverage_regressions(
        self,
    ) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/rocky-target-qualification-trace.sh",
            '"${BASH_LINENO[@]}"',
            '"${BASH_LINENO[0]}"',
        )
        self.assert_mutation_rejected(
            "scripts/ci-cloud/rocky-target-qualification-trace.sh",
            "if ((frame_count >= 8)); then",
            "if false; then",
        )
        self.assert_mutation_rejected(
            "scripts/ci-cloud/rocky-target-qualification-trace.sh",
            'local frames=""',
            'local frames="${FUNCNAME[*]}"',
        )
        self.assert_mutation_rejected(
            "scripts/ci-cloud/classify-rocky-target-qualification-failure.py",
            'LINE_RULES = (\n    (117, 123, "qualify-host-identity"),',
            'LINE_RULES = (\n    (48, 50, "qualify-rootless-runtime"),\n'
            '    (117, 123, "qualify-host-identity"),',
        )
        self.assert_mutation_rejected(
            "scripts/ci-cloud/classify-rocky-target-qualification-failure.py",
            "if len(explicit) == 1 and len(traced_operations) > 1:",
            "if False:",
        )
        self.assert_mutation_rejected(
            "scripts/ci-cloud/classify-rocky-target-qualification-failure.py",
            'EXPECTED_TARGET_SHA = "d89214795bc1bdf0e65d9bbf7c8b9647b7e1ebd6"',
            'EXPECTED_TARGET_SHA = ""',
        )
        self.assert_mutation_rejected(
            "scripts/ci-cloud/classify-rocky-target-qualification-failure.py",
            "MAX_TRACE_FRAMES = 8",
            "MAX_TRACE_FRAMES = 8\nMAX_TRACE_FRAMES = 7",
        )

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
            ".github/workflows/rocky-cloud-qualification.yml",
        ):
            with self.subTest(relative=relative):
                self.assertIn(
                    strict_shell,
                    (ROOT / relative).read_text(encoding="utf-8"),
                )

    def test_cloud_runs_are_serialized_without_discarding_pending_dispatches(
        self,
    ) -> None:
        workflow = yaml.load(
            (ROOT / ".github/workflows/cloud-conformance.yml").read_text(
                encoding="utf-8"
            ),
            Loader=yaml.BaseLoader,
        )
        self.assertEqual(
            {
                "group": "debian13-cloud-conformance",
                "cancel-in-progress": "false",
                "queue": "max",
            },
            workflow["concurrency"],
        )
        for job_name, job in workflow["jobs"].items():
            with self.subTest(job=job_name):
                self.assertNotIn("concurrency", job)
        actionlint = yaml.safe_load(
            (ROOT / ".github/actionlint.yaml").read_text(encoding="utf-8")
        )
        self.assertEqual(
            [
                '^unexpected key "queue" for "concurrency" section\\. '
                'expected one of "cancel-in-progress", "group"$'
            ],
            actionlint["paths"][
                ".github/workflows/cloud-conformance.yml"
            ]["ignore"],
        )

    def test_native_bootstrap_uses_shellchecked_trusted_setup(self) -> None:
        bootstrap = (
            ROOT / "scripts/ci-cloud/bootstrap-conformance-host.tftpl"
        ).read_text(encoding="utf-8")
        host_setup = (
            ROOT / "scripts/ci-cloud/configure-conformance-host.sh"
        ).read_text(encoding="utf-8")
        diagnostic_installer = (
            ROOT / "scripts/ci-cloud/install-diagnostic-ssh.sh"
        ).read_text(encoding="utf-8")
        self.assertIn("set -euo pipefail", host_setup)
        self.assertIn("set -euo pipefail", diagnostic_installer)
        self.assertTrue(bootstrap.startswith("#!/usr/bin/env bash\n"))
        self.assertIn("${diagnostic_ssh_installer}", bootstrap)
        self.assertIn("/run/secpal-ci-evidence/apparmor-status", host_setup)
        self.assertIn(
            "systemctl disable --now podman.socket podman.service", host_setup
        )
        self.assertIn("${host_setup_failure_script}", bootstrap)
        self.assertIn(
            '[[ "$(id -G secpal-ci)" != "$(id -g secpal-ci)" ]]',
            host_setup,
        )

    def test_host_setup_failure_diagnostic_is_closed_and_uncredentialed(self) -> None:
        bootstrap = (
            ROOT / "scripts/ci-cloud/bootstrap-conformance-host.tftpl"
        ).read_text(encoding="utf-8")
        continuation = (
            ROOT / "scripts/ci-cloud/continue-conformance-bootstrap.sh"
        ).read_text(encoding="utf-8")
        host_setup = (
            ROOT / "scripts/ci-cloud/configure-conformance-host.sh"
        ).read_text(encoding="utf-8")
        remote = (
            ROOT / "scripts/ci-cloud/run-remote-conformance.sh"
        ).read_text(encoding="utf-8")
        self.assertIn("secpal-ci-host-setup-failure", host_setup)
        for stage in (
            "diagnostic-ssh",
            "apt-sources",
            "apt-update",
            "kernel-install",
            "package-install",
            "operator-identity",
            "host-policy",
            "kernel-admission",
            "reboot-state",
        ):
            self.assertIn(f'setup_stage="{stage}"', bootstrap)
        for stage in (
            "continuation-state",
            "kernel-verify",
            "host-setup",
        ):
            self.assertIn(f'setup_stage="{stage}"', continuation)
        for stage in (
            "host-initialize",
            "subordinate-ids",
            "service-policy",
            "apparmor",
            "ssh",
        ):
            self.assertIn(f'setup_stage="{stage}"', host_setup)
        self.assertNotIn('setup_stage="initialize"', bootstrap)
        self.assertNotIn('setup_stage="initialize"', continuation)
        self.assertNotIn('setup_stage="initialize"', host_setup)
        self.assertIn("host-setup-failure.py", remote)
        self.assertIn("Trusted host setup failure", remote)
        self.assertNotIn("cloud-init-output.log", remote)

    def test_native_bootstrap_repairs_automatic_subordinate_ids(self) -> None:
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
        template = (
            ROOT / "scripts/ci-cloud/bootstrap-conformance-host.tftpl"
        ).read_text(encoding="utf-8")
        continuation = (
            ROOT / "scripts/ci-cloud/continue-conformance-bootstrap.sh"
        ).read_text(encoding="utf-8")
        self.assertNotIn("ssh_authorized_keys", template)
        self.assertNotIn("/run/secpal-ci-authorized-key", template)
        self.assertIn("/run/secpal-ci-authorized-key", continuation)
        self.assertIn(
            'install -o root -g root -m 0600 /dev/null "$staged_operator_key"',
            continuation,
        )
        self.assertIn("${ssh_public_key}", template)
        self.assertIn(
            "AuthorizedKeysFile /var/lib/secpal-ci/authorized-keys/%u",
            template,
        )
        self.assertIn("/etc/ssh/sshd_config.d/00-secpal-ci.conf", template)
        self.assertNotIn("sshd_config.d/90-secpal-ci.conf", template)
        self.assertIn("AuthenticationMethods publickey", template)
        self.assertIn("AuthorizedKeysCommand none", template)
        self.assertIn("AuthorizedPrincipalsCommand none", template)
        self.assertIn("AuthorizedPrincipalsFile none", template)
        self.assertIn("PermitRootLogin no", template)
        self.assertIn("TrustedUserCAKeys none", template)
        self.assertIn("UseDNS no", template)
        self.assertIn("AllowUsers secpal-ci", template)
        self.assertIn("${diagnostic_ssh_installer}", template)
        self.assertIn(
            '/usr/local/sbin/secpal-ci-configure-conformance-host "$runner_ipv4"',
            continuation,
        )
        self.assertLess(
            continuation.index('printf \'%s\\n\' "$ssh_public_key"'),
            continuation.index(
                "/usr/local/sbin/secpal-ci-configure-conformance-host"
            ),
        )
        for provider in ("digitalocean", "gcp"):
            variables = (
                ROOT / f"infra/ci-cloud/{provider}/variables.tf"
            ).read_text(encoding="utf-8")
            self.assertIn(
                " secpal-ci-${var.run_id}-${var.run_attempt}$",
                variables,
            )
            self.assertNotIn("( [A-Za-z0-9._@+-]+)?", variables)

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
        activation = host_setup.split("activate_operator_ssh() {", 1)[1].split(
            "\n}", 1
        )[0]
        handoff = host_setup.split("perform_operator_ssh_handoff() {", 1)[
            1
        ].split("\n}", 1)[0]
        self.assertIn(private_install, host_setup)
        self.assertIn(expose_file, host_setup)
        self.assertIn(expose_directory, host_setup)
        self.assertLess(
            activation.index(private_install), activation.index(publish)
        )
        self.assertLess(activation.index(publish), activation.index(expose_file))
        self.assertLess(
            activation.index(expose_file), activation.index(expose_directory)
        )
        self.assertLess(
            activation.index(expose_directory),
            activation.index("perform_operator_ssh_handoff"),
        )
        self.assertLess(
            handoff.index("systemctl unmask ssh.service ssh.socket"),
            handoff.index("systemctl restart ssh.service"),
        )
        self.assertNotIn('chmod 0755 "$authorized_keys_tmp_dir"', host_setup)
        remote = (
            ROOT / "scripts/ci-cloud/run-remote-conformance.sh"
        ).read_text(encoding="utf-8")
        self.assertIn("operator_ssh_ready=false", remote)
        self.assertNotIn("for _ in {1..30}; do", remote)
        self.assertIn("bootstrap_deadline=$((SECONDS + 15 * 60))", remote)
        self.assertEqual(
            2,
            remote.count("while ((SECONDS < bootstrap_deadline)); do"),
        )
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
        self.assertNotIn("host_key_deadline", remote)

    def test_setup_commits_only_after_operator_ssh_starts(self) -> None:
        host_setup = (
            ROOT / "scripts/ci-cloud/configure-conformance-host.sh"
        ).read_text(encoding="utf-8")
        activation = host_setup.split("activate_operator_ssh() {", 1)[1].split(
            "\n}\n", 1
        )[0]
        handoff = host_setup.split("perform_operator_ssh_handoff() {", 1)[
            1
        ].split("\n}\n", 1)[0]

        marker = "publish_completion_marker"
        restart = "systemctl restart ssh.service"
        activated = "ssh_key_activated=true"
        retirement = "retire_diagnostic_ssh"
        self.assertIn(marker, handoff)
        self.assertIn(restart, handoff)
        self.assertIn(activated, activation)
        self.assertIn(retirement, activation)
        self.assertLess(handoff.index(restart), handoff.index(marker))
        self.assertLess(
            activation.index("perform_operator_ssh_handoff"),
            activation.index(activated),
        )
        self.assertLess(activation.index(activated), activation.index(retirement))
        arm_timer = "arm_diagnostic_ssh_recovery"
        stop_listener = 'systemctl stop "$diagnostic_ssh_service"'
        verify_primary = 'systemctl is-active --quiet ssh.service'
        self.assertIn(arm_timer, activation)
        recovery = host_setup.split("arm_diagnostic_ssh_recovery() {", 1)[
            1
        ].split("\n}\n", 1)[0]
        self.assertIn('systemctl start "$diagnostic_ssh_timer"', recovery)
        self.assertIn(
            'systemctl is-active --quiet "$diagnostic_ssh_timer"',
            recovery,
        )
        self.assertIn(stop_listener, handoff)
        self.assertIn(verify_primary, handoff)
        self.assertLess(
            activation.index(arm_timer),
            activation.index("perform_operator_ssh_handoff"),
        )
        self.assertLess(handoff.index(stop_listener), handoff.index(restart))
        self.assertLess(handoff.index(restart), handoff.index(verify_primary))
        self.assertLess(activation.index(activated), activation.index(retirement))

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

        template = (
            ROOT / "scripts/ci-cloud/bootstrap-conformance-host.tftpl"
        ).read_text(encoding="utf-8")
        self.assertIn("${diagnostic_ssh_installer}", template)
        self.assertIn("'${ssh_public_key}'", template)
        self.assertIn("'${runner_ipv4}'", template)
        self.assertIn("'${run_id}'", template)
        self.assertIn("'${run_attempt}'", template)
        for provider in ("digitalocean", "gcp"):
            main = (ROOT / f"infra/ci-cloud/{provider}/main.tf").read_text(
                encoding="utf-8"
            )
            self.assertIn(
                'file("${path.module}/../../../scripts/ci-cloud/'
                'install-diagnostic-ssh.sh")',
                main,
            )

        for required in (
            "systemctl mask --now ssh.service ssh.socket",
            "secpal-ci-diagnostic-sshd",
            "OnActiveSec=10m",
            "ForceCommand /usr/local/sbin/secpal-ci-bootstrap-diagnostic",
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
            restore_handler.index(
                'systemctl start "$diagnostic_ssh_recovery_service"'
            ),
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

    def test_ssh_identities_are_pubkey_only_without_locked_accounts(self) -> None:
        bootstrap = (
            ROOT / "scripts/ci-cloud/bootstrap-conformance-host.tftpl"
        ).read_text(encoding="utf-8")
        installer = (
            ROOT / "scripts/ci-cloud/install-diagnostic-ssh.sh"
        ).read_text(encoding="utf-8")

        for document in (bootstrap, installer):
            self.assertNotIn("usermod --lock", document)
            self.assertIn("usermod --password '*NP*'", document)
            self.assertIn("getent shadow", document)
            self.assertIn("== '*NP*'", document)

        self.assertLess(
            installer.index("usermod --password '*NP*'"),
            installer.index("prepare_diagnostic_fallback()"),
        )
        self.assertLess(
            bootstrap.index("usermod --password '*NP*'"),
            bootstrap.index("systemctl reboot"),
        )

    def test_static_contract_rejects_locked_ssh_accounts(self) -> None:
        for relative in (
            "scripts/ci-cloud/bootstrap-conformance-host.tftpl",
            "scripts/ci-cloud/install-diagnostic-ssh.sh",
        ):
            with self.subTest(relative=relative):
                self.assert_mutation_rejected(
                    relative,
                    "usermod --password '*NP*'",
                    "usermod --lock",
                )

    def test_static_contract_rejects_unverified_pubkey_only_account_marker(
        self,
    ) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/bootstrap-conformance-host.tftpl",
            '[[ "$operator_password_marker" == \'*NP*\' ]]\n',
            "",
        )
        self.assert_mutation_rejected(
            "scripts/ci-cloud/install-diagnostic-ssh.sh",
            '  [[ "$password_marker" == \'*NP*\' ]] || return 1\n',
            "",
        )

    def test_completed_setup_revalidates_operator_ssh_identity(self) -> None:
        installer = (
            ROOT / "scripts/ci-cloud/install-diagnostic-ssh.sh"
        ).read_text(encoding="utf-8")
        validator = installer.split("validate_operator_identity() {", 1)[1].split(
            "\n}\n", 1
        )[0]
        completed = installer.split("completed_setup_is_valid() {", 1)[1].split(
            "\n}\n", 1
        )[0]

        for expected in (
            'getent passwd secpal-ci',
            'getent group secpal-ci',
            'getent shadow secpal-ci',
            '"$user_uid" == 20000',
            '"$user_gid" == 20000',
            '"$user_home" == /home/secpal-ci',
            '"$user_shell" == /bin/bash',
            '"$password_marker" == \'*NP*\'',
            '"$(id -G secpal-ci)" == 20000',
        ):
            self.assertIn(expected, validator)
        self.assertIn("validate_operator_identity || return 1", completed)

    def test_static_contract_rejects_incomplete_reboot_identity_validation(
        self,
    ) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/install-diagnostic-ssh.sh",
            "  validate_operator_identity || return 1\n",
            "",
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

    def test_diagnostic_fallback_selects_before_masking_primary_ssh(self) -> None:
        installer = (
            ROOT / "scripts/ci-cloud/install-diagnostic-ssh.sh"
        ).read_text(encoding="utf-8")
        preparation_function = installer.split(
            "prepare_diagnostic_fallback() {", 1
        )[1].split("\nstart_diagnostic_fallback_locked() {", 1)[0]
        start_function = installer.split(
            "start_diagnostic_fallback_locked() {", 1
        )[
            1
        ].split("\n}\n", 1)[0]
        for preparation in (
            "ensure_diagnostic_identity",
            "ssh-keygen -A",
            'sshd -t -f "$config_tmp"',
            'chmod 0755 "$diagnostic_command"',
        ):
            with self.subTest(preparation=preparation):
                self.assertIn(preparation, preparation_function)
        self.assertLess(
            start_function.index("prepare_diagnostic_fallback"),
            start_function.index('systemctl enable "$diagnostic_service"'),
        )
        self.assertLess(
            start_function.index('systemctl enable "$diagnostic_service"'),
            start_function.index("select_diagnostic_ssh"),
        )
        self.assertLess(
            start_function.index("select_diagnostic_ssh"),
            start_function.index("systemctl mask --now ssh.service ssh.socket"),
        )
        self.assertLess(
            start_function.index("systemctl mask --now ssh.service ssh.socket"),
            start_function.index('systemctl restart "$diagnostic_service"'),
        )
        self.assertLess(
            start_function.index('systemctl restart "$diagnostic_service"'),
            start_function.index(
                'systemctl is-active --quiet "$diagnostic_service"'
            ),
        )
        self.assertLess(
            start_function.index(
                'systemctl is-active --quiet "$diagnostic_service"'
            ),
            start_function.index('systemctl stop "$diagnostic_timer"'),
        )
        self.assertIn(
            '! systemctl is-active --quiet "$diagnostic_timer"',
            start_function,
        )
        initial_transition = installer.rsplit(
            "if completed_setup_is_valid; then", 1
        )[1]
        self.assertIn("if ! start_diagnostic_fallback; then", initial_transition)
        self.assertIn(
            "unable to establish restricted diagnostic SSH during bootstrap",
            initial_transition,
        )
        self.assertNotIn("\nprepare_diagnostic_fallback\n", initial_transition)
        cleanup = installer.split("cleanup() {", 1)[1].split("\n}\n", 1)[0]
        self.assertIn("if ! start_diagnostic_fallback; then", cleanup)
        self.assertIn(
            "unable to establish restricted diagnostic SSH after installer failure",
            cleanup,
        )
        self.assertNotIn(
            'rm -f -- "$diagnostic_key" "$diagnostic_command" '
            '"$diagnostic_config"',
            cleanup,
        )
        self.assertIn("prepare_diagnostic_fallback", installer)
        self.assertIn(
            '[[ "$(id -G "$diagnostic_user")" == "$group_gid" ]]',
            installer,
        )
        self.assertIn(
            'diagnostic_service_unit="/etc/systemd/system/$diagnostic_service"',
            installer,
        )
        self.assertIn(
            'diagnostic_timer_unit="/etc/systemd/system/$diagnostic_timer"',
            installer,
        )
        self.assertIn(
            'systemd-analyze verify "$diagnostic_service_unit" \\\n'
            '    "$diagnostic_timer_unit" "$diagnostic_recovery_service_unit"',
            installer,
        )

    def test_diagnostic_listener_readiness_precedes_timer_disarm(self) -> None:
        installer = (
            ROOT / "scripts/ci-cloud/install-diagnostic-ssh.sh"
        ).read_text(encoding="utf-8")
        host_setup = (
            ROOT / "scripts/ci-cloud/configure-conformance-host.sh"
        ).read_text(encoding="utf-8")
        preparation = installer.split(
            "prepare_diagnostic_fallback() {", 1
        )[1].split("\nstart_diagnostic_fallback_locked() {", 1)[0]
        initial_start = installer.split(
            "start_diagnostic_fallback_locked() {", 1
        )[
            1
        ].split("\n}\n", 1)[0]
        restore = host_setup.split("restore_diagnostic_ssh() {", 1)[1].split(
            "\n}\n", 1
        )[0]

        self.assertIn("Type=notify", preparation)
        self.assertNotIn("Type=exec", preparation)
        self.assertLess(
            initial_start.index('systemctl restart "$diagnostic_service"'),
            initial_start.index(
                'systemctl is-active --quiet "$diagnostic_service"'
            ),
        )
        self.assertLess(
            initial_start.index(
                'systemctl is-active --quiet "$diagnostic_service"'
            ),
            initial_start.index('systemctl stop "$diagnostic_timer"'),
        )
        self.assertLess(
            restore.index('systemctl start "$diagnostic_ssh_recovery_service"'),
            restore.index(
                'systemctl is-active --quiet "$diagnostic_ssh_service"'
            ),
        )
        self.assertLess(
            restore.index(
                'systemctl is-active --quiet "$diagnostic_ssh_service"'
            ),
            restore.index('systemctl stop "$diagnostic_ssh_timer"'),
        )

    def test_failed_host_key_scan_uses_closed_tcp_probe(self) -> None:
        remote = (
            ROOT / "scripts/ci-cloud/run-remote-conformance.sh"
        ).read_text(encoding="utf-8")
        classifier = remote.split("classify_host_key_scan() {", 1)[1].split(
            "\n}\n", 1
        )[0]
        observer = remote.split("observe_failed_host_key_scan() {", 1)[1].split(
            "\n}\n", 1
        )[0]
        self.assertIn(
            "connection_refused | connection_timeout | other",
            classifier,
        )
        self.assertIn("reachable", classifier)
        self.assertIn("scripts/ci-cloud/probe-ssh-port.py", observer)
        self.assertNotIn("grep", classifier)
        self.assertNotIn("_scan_error", remote)

    def test_root_ssh_denial_uses_transport_recheck_not_stderr(self) -> None:
        remote = (
            ROOT / "scripts/ci-cloud/run-remote-conformance.sh"
        ).read_text(encoding="utf-8")
        root_admission = remote.split('bootstrap_stage="root-ssh"', 1)[1].split(
            'started_at="$(date -u', 1
        )[0]
        self.assertIn('"$root_probe_status" -eq 255', root_admission)
        self.assertIn("operator_recheck_status", root_admission)
        self.assertIn('"secpal-ci@$address" true', root_admission)
        self.assertNotIn("permission denied", root_admission)
        self.assertNotIn("root_probe=", root_admission)

    def test_diagnostic_fallback_staging_and_reporter_are_strict(self) -> None:
        installer = (
            ROOT / "scripts/ci-cloud/install-diagnostic-ssh.sh"
        ).read_text(encoding="utf-8")
        preparation = installer.split("prepare_diagnostic_fallback() {", 1)[
            1
        ].split("\nstart_diagnostic_fallback_locked() {", 1)[0]
        reporter = preparation.split("<<'DIAGNOSTIC'\n", 1)[1].split(
            "\nDIAGNOSTIC", 1
        )[0]
        self.assertTrue(
            reporter.startswith("#!/usr/bin/env bash\nset -euo pipefail\n")
        )
        self.assertIn(
            'chmod 0600 "$key_tmp" "$config_tmp" "$service_tmp" "$timer_tmp"',
            preparation,
        )
        self.assertNotIn(
            'chmod 0644 "$service_tmp" "$timer_tmp"',
            preparation,
        )
        self.assertIn('chmod 0644 "$diagnostic_key"', preparation)
        self.assertIn('chmod 0600 "$diagnostic_config"', preparation)
        self.assertNotIn(
            'chmod 0600 "$diagnostic_key" "$diagnostic_config"',
            preparation,
        )
        for artifact, metadata in (
            ("diagnostic_key", "0:0:644"),
            ("diagnostic_config", "0:0:600"),
            ("diagnostic_command", "0:0:755"),
            ("diagnostic_recovery_command", "0:0:755"),
            ("diagnostic_service_unit", "0:0:644"),
            ("diagnostic_timer_unit", "0:0:644"),
            ("diagnostic_recovery_service_unit", "0:0:644"),
        ):
            with self.subTest(artifact=artifact):
                self.assertIn(
                    f'stat -c \'%u:%g:%a\' -- "${artifact}"',
                    preparation,
                )
                self.assertIn(
                    f'"${artifact}_metadata" != {metadata}',
                    preparation,
                )

    def test_diagnostic_failure_reader_is_executable_by_forced_command(self) -> None:
        bootstrap = (
            ROOT / "scripts/ci-cloud/bootstrap-conformance-host.tftpl"
        ).read_text(encoding="utf-8")
        self.assertIn(
            'install -o root -g root -m 0755 /dev/null "$failure_writer"',
            bootstrap,
        )

    def test_completed_setup_survives_native_bootstrap_on_reboot(self) -> None:
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
            installer.rindex("if ! start_diagnostic_fallback; then"),
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
        self.assertIn(
            "validate_effective_sshd_config || return 1",
            completed_validator,
        )
        reboot_policy = installer.split("validate_effective_sshd_config() {", 1)[
            1
        ].split("\n}\n", 1)[0]
        self.assertIn("denyusers|denygroups|allowgroups", reboot_policy)
        self.assertIn("pubkeyacceptedalgorithms", reboot_policy)
        self.assertIn("ssh-ed25519", reboot_policy)
        self.assertIn('primary_ssh_config=', installer)
        self.assertIn(
            '"$ssh_socket_state" == disabled',
            completed_validator,
        )
        self.assertNotIn("systemctl is-active", completed_validator)

        self.assertIn(
            'completion_marker="$active_ssh_root/host-setup-complete"',
            host_setup,
        )
        self.assertIn("publish_completion_marker", host_setup)
        handoff = host_setup.split("perform_operator_ssh_handoff() {", 1)[
            1
        ].split("\n}", 1)[0]
        self.assertLess(
            handoff.index('systemctl restart ssh.service'),
            handoff.index("publish_completion_marker"),
        )
        self.assertLess(
            handoff.index("systemctl enable ssh.service"),
            handoff.index("systemctl restart ssh.service"),
        )
        self.assertIn('rm -f -- "$completion_marker"', host_setup)
        self.assertNotIn("/run/secpal-ci-authorized-keys", host_setup)

    def test_static_contract_rejects_missing_completed_setup_reboot_guard(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/install-diagnostic-ssh.sh",
            "if completed_setup_is_valid; then\n  exit 0\nfi\n",
            "",
        )

    def test_static_contract_rejects_incomplete_reboot_ssh_validation(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/install-diagnostic-ssh.sh",
            "  validate_effective_sshd_config || return 1\n",
            "",
        )
        self.assert_mutation_rejected(
            "scripts/ci-cloud/install-diagnostic-ssh.sh",
            "denyusers|denygroups|allowgroups",
            "denyusers|denygroups",
        )

    def test_static_contract_rejects_masking_before_fallback_arm(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/install-diagnostic-ssh.sh",
            "if ! start_diagnostic_fallback; then\n"
            "  printf 'ERROR: unable to establish restricted diagnostic SSH "
            "during bootstrap.\\n' >&2\n"
            "  exit 1\n"
            "fi\n",
            "prepare_diagnostic_fallback\n",
        )

    def test_static_contract_rejects_disarming_before_diagnostic_readiness(
        self,
    ) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/install-diagnostic-ssh.sh",
            '  systemctl restart "$diagnostic_service" >/dev/null 2>&1 || return 1\n',
            '  systemctl stop "$diagnostic_timer" || return 1\n'
            '  systemctl restart "$diagnostic_service" >/dev/null 2>&1 || return 1\n',
        )

    def test_static_contract_rejects_unarmed_operator_ssh_handoff(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/configure-conformance-host.sh",
            "  if ! arm_diagnostic_ssh_recovery; then\n",
            "  if ! true; then\n",
        )

    def test_static_contract_rejects_nonrecovering_diagnostic_daemon(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/install-diagnostic-ssh.sh",
            "StartLimitIntervalSec=2m\n"
            "StartLimitBurst=5\n"
            "\n"
            "[Service]\n"
            "Type=notify\n"
            "ExecStart=/usr/sbin/sshd -D -e -f $diagnostic_config\n"
            "Restart=on-failure\n"
            "RestartSec=5s\n",
            "",
        )

    def test_static_contract_rejects_process_only_diagnostic_readiness(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/install-diagnostic-ssh.sh",
            "Type=notify\n",
            "Type=exec\n",
        )

    def test_static_contract_rejects_unobserved_host_key_reachability(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/run-remote-conformance.sh",
            '    python3 scripts/ci-cloud/probe-ssh-port.py "$address"\n',
            "    printf 'other\\n'\n",
        )

    def test_static_contract_rejects_scanner_stderr_inference(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/run-remote-conformance.sh",
            '  local reachability="$3"\n',
            '  local reachability="$3"\n'
            "  grep -Eqi 'connection refused' /tmp/scanner-error || true\n",
        )

    def test_static_contract_rejects_root_denial_without_transport_recheck(
        self,
    ) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/run-remote-conformance.sh",
            'operator_recheck_status=1\n'
            'if [[ "$root_probe_status" -eq 255 ]]; then\n'
            '  timeout --signal=TERM --kill-after=5s 20s \\\n'
            '    ssh "${ssh_options[@]}" "secpal-ci@$address" true '
            '>/dev/null 2>&1\n'
            '  operator_recheck_status=$?\n'
            'fi\n',
            'operator_recheck_status=0\n',
        )

    def test_static_contract_rejects_discarding_pending_cloud_dispatches(self) -> None:
        self.assert_mutation_rejected(
            ".github/workflows/cloud-conformance.yml",
            "  queue: max\n",
            "",
        )

    def test_static_contract_rejects_job_level_concurrency_hidden_by_linter_ignore(
        self,
    ) -> None:
        self.assert_mutation_rejected(
            ".github/workflows/cloud-conformance.yml",
            "  validate:\n    name: Validate immutable dispatch selection\n",
            "  validate:\n"
            "    concurrency:\n"
            "      group: hidden-invalid-queue\n"
            "      queue: max\n"
            "    name: Validate immutable dispatch selection\n",
        )

    def test_static_contract_rejects_discarded_preparation_failure_diagnostics(
        self,
    ) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/install-diagnostic-ssh.sh",
            "    if ! start_diagnostic_fallback; then\n"
            "      printf 'ERROR: unable to establish restricted diagnostic SSH "
            "after installer failure.\\n' >&2\n"
            "    fi\n",
            '    rm -f -- "$diagnostic_key" "$diagnostic_command" '
            '"$diagnostic_config"\n',
        )

    def test_static_contract_rejects_operator_start_before_setup_commit(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/configure-conformance-host.sh",
            "  publish_completion_marker\n",
            "",
        )

    def test_static_contract_rejects_fixed_operator_readiness_attempts(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/run-remote-conformance.sh",
            'diagnostic_setup_failure=""\n'
            "while ((SECONDS < bootstrap_deadline)); do\n",
            'diagnostic_setup_failure=""\n'
            "for _ in {1..30}; do\n",
        )

    def test_static_contract_rejects_short_masked_ssh_wait(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/run-remote-conformance.sh",
            "bootstrap_deadline=$((SECONDS + 15 * 60))",
            "bootstrap_deadline=$((SECONDS + 2 * 60))",
        )

    def test_static_contract_rejects_early_operator_ssh_key_release(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/continue-conformance-bootstrap.sh",
            "/run/secpal-ci-authorized-key",
            "/home/secpal-ci/.ssh/authorized_keys",
        )

    def test_static_contract_rejects_unmasked_bootstrap_ssh(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/install-diagnostic-ssh.sh",
            "  systemctl mask --now ssh.service ssh.socket >/dev/null 2>&1 || return 1\n",
            "  true\n",
        )

    def test_static_contract_rejects_missing_diagnostic_ssh_timer(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/install-diagnostic-ssh.sh",
            "OnActiveSec=10m\n",
            "",
        )

    def test_static_contract_rejects_unrestricted_diagnostic_ssh(self) -> None:
        for old, new in (
            (
                "ForceCommand /usr/local/sbin/secpal-ci-bootstrap-diagnostic",
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

    def test_static_contract_rejects_nonexecutable_diagnostic_reader(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/bootstrap-conformance-host.tftpl",
            'install -o root -g root -m 0755 /dev/null "$failure_writer"',
            'install -o root -g root -m 0700 /dev/null "$failure_writer"',
        )

    def test_static_contract_rejects_ignored_diagnostic_ssh_marker(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/run-remote-conformance.sh",
            "SECPAL_CI_DIAGNOSTIC_SSH",
            "UNRECOGNIZED_DIAGNOSTIC_SSH",
        )

    def test_static_contract_rejects_global_operator_key_path(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/bootstrap-conformance-host.tftpl",
            "AuthorizedKeysFile /var/lib/secpal-ci/authorized-keys/%u",
            "AuthorizedKeysFile /var/lib/secpal-ci/authorized-keys/key",
        )

    def test_static_contract_rejects_late_ssh_dropin(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/bootstrap-conformance-host.tftpl",
            "sshd_config.d/00-secpal-ci.conf",
            "sshd_config.d/90-secpal-ci.conf",
        )

    def test_static_contract_rejects_broadened_ssh_users(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/bootstrap-conformance-host.tftpl",
            "AllowUsers secpal-ci",
            "AllowUsers root secpal-ci",
        )

    def test_static_contract_rejects_root_key_login(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/bootstrap-conformance-host.tftpl",
            "PermitRootLogin no",
            "PermitRootLogin prohibit-password",
        )

    def test_static_contract_rejects_alternate_authentication_methods(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/bootstrap-conformance-host.tftpl",
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
                    "scripts/ci-cloud/bootstrap-conformance-host.tftpl",
                    directive,
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

    def test_effective_sshd_validation_rejects_additional_access_gates(self) -> None:
        host_setup = (
            ROOT / "scripts/ci-cloud/configure-conformance-host.sh"
        ).read_text(encoding="utf-8")
        validator = host_setup.split("validate_effective_sshd_config() {", 1)[
            1
        ].split("\n}\n", 1)[0]
        for keyword in ("denyusers", "denygroups", "allowgroups", "setenv"):
            with self.subTest(keyword=keyword):
                self.assertIn(keyword, validator)
        self.assertIn("pubkeyacceptedalgorithms", validator)
        self.assertIn("ssh-ed25519", validator)
        for expected in (
            "maxsessions 1",
            "pamservicename sshd",
            "refuseconnection no",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, validator)

    def test_static_contract_rejects_missing_additional_ssh_access_gate(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/configure-conformance-host.sh",
            "denyusers|denygroups|allowgroups",
            "denyusers|denygroups",
        )

    def test_primary_ssh_uses_only_service_activation(self) -> None:
        host_setup = (
            ROOT / "scripts/ci-cloud/configure-conformance-host.sh"
        ).read_text(encoding="utf-8")
        activation = host_setup.split(
            "perform_operator_ssh_handoff() {", 1
        )[1].split("\n}\n", 1)[0]
        self.assertIn("systemctl disable --now ssh.socket", activation)
        self.assertLess(
            activation.index("systemctl disable --now ssh.socket"),
            activation.index("systemctl enable ssh.service"),
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
        self.assertIn(
            'mktemp "$evidence_dir/.target-phase-diagnostic.XXXXXX"',
            remote,
        )
        self.assertIn('target_diagnostic_paths+=("$target_diagnostic")', remote)
        self.assertIn('rm -f -- "${target_diagnostic_paths[@]}"', remote)
        self.assertIn("bounded-target-diagnostic.py", remote)
        self.assertNotIn("<<'REMOTE' >/dev/null 2>&1", remote)

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
                "scripts/ci-cloud/run-remote-conformance.sh",
                '< scripts/ci-cloud/collect-workload-evidence.py >"$diagnostic_path"',
                '< scripts/ci-cloud/collect-workload-evidence.py >/dev/null',
            ),
            (
                "scripts/ci-cloud/run-remote-conformance.sh",
                '"$live_normalization_json" "$cleanup_normalization_json" \\\n',
                "",
            ),
            (
                "scripts/ci-cloud/assemble-evidence.py",
                'test["normalization_diagnostics"] = normalization_diagnostics',
                'test["normalization_diagnostics"] = {}',
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

    def test_early_remote_failure_writes_bounded_structured_evidence(self) -> None:
        remote = (
            ROOT / "scripts/ci-cloud/run-remote-conformance.sh"
        ).read_text(encoding="utf-8")
        self.assertIn('bootstrap_stage="host-key"', remote)
        self.assertIn('bootstrap_stage="bootstrap"', remote)
        self.assertIn("orchestration_started_at", remote)
        self.assertIn("write-bootstrap-failure.py", remote)
        self.assertIn(
            "native bootstrap did not reach trusted host setup", remote
        )
        self.assertNotIn("cloud-init", remote)
        self.assertIn("host_key_observations_json", remote)
        for observation in (
            "connection_refused",
            "connection_timeout",
            "no_key",
            "multiple_keys",
            "changed_key",
            "other",
        ):
            self.assertIn(observation, remote)
        self.assertNotIn('cat "$first_scan_error"', remote)
        self.assertNotIn('cat "$second_scan_error"', remote)

    def test_remote_bash_programs_use_strict_mode(self) -> None:
        remote = (
            ROOT / "scripts/ci-cloud/run-remote-conformance.sh"
        ).read_text(encoding="utf-8")
        fixture = (
            ROOT / "tests/ci-cloud-remote-bootstrap.sh"
        ).read_text(encoding="utf-8")
        remote_programs = remote.split("<<'REMOTE'")[1:]
        self.assertEqual(3, len(remote_programs))
        for program in remote_programs:
            remote_body = program.split("\nREMOTE", 1)[0]
            self.assertIn(
                "\nset -euo pipefail\n",
                remote_body,
            )
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
            'mktemp "$evidence_dir/.target-phase-diagnostic.XXXXXX"',
            'mktemp "/tmp/secpal-target-phase-diagnostic.XXXXXX"',
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

    def test_native_bootstrap_embeds_valid_host_setup(self) -> None:
        import base64
        import gzip

        template = (
            ROOT / "scripts/ci-cloud/bootstrap-conformance-host.tftpl"
        ).read_text(encoding="utf-8")
        host_setup = (
            ROOT / "scripts/ci-cloud/configure-conformance-host.sh"
        ).read_text(encoding="utf-8").strip()
        encoded = base64.b64encode(
            gzip.compress(host_setup.encode("utf-8"), mtime=0)
        ).decode("ascii")
        self.assertIn("${host_setup_script_base64gzip}", template)
        self.assertEqual(host_setup, gzip.decompress(base64.b64decode(encoded)).decode())

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

    def test_gcp_vm_uses_only_inert_bootstrap_identity(self) -> None:
        main = (ROOT / "infra/ci-cloud/gcp/main.tf").read_text(
            encoding="utf-8"
        )
        variables = (ROOT / "infra/ci-cloud/gcp/variables.tf").read_text(
            encoding="utf-8"
        )
        self.assertIn('variable "bootstrap_service_account"', variables)
        self.assertIn("@secpal-dev\\\\.iam\\\\.gserviceaccount\\\\.com", variables)
        self.assertIn("service_account {", main)
        self.assertIn("email  = var.bootstrap_service_account", main)
        self.assertIn("scopes = []", main)

    def test_rejects_gcp_default_vm_service_account(self) -> None:
        self.assert_mutation_rejected(
            "infra/ci-cloud/gcp/main.tf",
            "email  = var.bootstrap_service_account",
            'email  = "default"',
        )

    def test_rejects_gcp_vm_cloud_api_scope(self) -> None:
        self.assert_mutation_rejected(
            "infra/ci-cloud/gcp/main.tf",
            "scopes = []",
            'scopes = ["cloud-platform"]',
        )

    def test_gcp_identity_is_detached_before_target_execution(self) -> None:
        document = yaml.load(
            (ROOT / ".github/workflows/cloud-conformance.yml").read_text(
                encoding="utf-8"
            ),
            Loader=yaml.BaseLoader,
        )
        steps = document["jobs"]["gcp"]["steps"]
        names = [step["name"] for step in steps]
        auth_index = names.index(
            "Authenticate trusted GCP identity transition through OIDC"
        )
        detach_index = names.index("Remove and verify GCP VM cloud identity")
        target_index = names.index(
            "Run uncredentialed GCP remote conformance"
        )
        self.assertLess(auth_index, detach_index)
        self.assertLess(detach_index, target_index)
        identity_auth = steps[auth_index]
        self.assertEqual("gcp_identity_auth", identity_auth["id"])
        self.assertEqual(
            "${{ steps.gcp_apply.outcome == 'success' }}",
            identity_auth["if"],
        )
        self.assertEqual("true", identity_auth["continue-on-error"])
        detach = steps[detach_index]
        self.assertEqual("gcp_identity", detach["id"])
        self.assertEqual(
            "${{ steps.gcp_apply.outcome == 'success' && "
            "steps.gcp_identity_auth.outcome == 'success' }}",
            detach["if"],
        )
        self.assertEqual("true", detach["continue-on-error"])
        self.assertEqual(
            {
                "GOOGLE_OAUTH_ACCESS_TOKEN": (
                    "${{ steps.gcp_identity_auth.outputs.access_token }}"
                ),
                "GCP_BOOTSTRAP_SERVICE_ACCOUNT": (
                    "${{ vars.GCP_BOOTSTRAP_SERVICE_ACCOUNT }}"
                ),
                "RESOURCE_ATTEMPT": (
                    "${{ needs.validate.outputs.resource_attempt }}"
                ),
            },
            detach["env"],
        )
        self.assertEqual(
            "${{ vars.GCP_BOOTSTRAP_SERVICE_ACCOUNT }}",
            detach["env"]["GCP_BOOTSTRAP_SERVICE_ACCOUNT"],
        )
        self.assertEqual(
            "${{ steps.gcp_apply.outcome == 'success' && "
            "steps.gcp_identity.outcome == 'success' }}",
            steps[target_index]["if"],
        )
        self.assertNotIn("target_sha", detach["run"])
        self.assertNotIn("run-remote-conformance", detach["run"])
        self.assertIn(
            '"$RUNNER_TEMP/ci-cloud/ipv4_address"', detach["run"]
        )
        apply = steps[names.index("Apply GCP infrastructure")]
        self.assertNotIn("tofu output -raw ipv4_address", apply["run"])
        self.assertIn(
            '"$(cat "$RUNNER_TEMP/ci-cloud/ipv4_address")"',
            steps[target_index]["run"],
        )

    def test_rejects_stale_gcp_ip_after_identity_transition(self) -> None:
        self.assert_mutation_rejected(
            ".github/workflows/cloud-conformance.yml",
            "          unset GOOGLE_OAUTH_ACCESS_TOKEN\n"
            "          tofu output -raw image_id >",
            "          unset GOOGLE_OAUTH_ACCESS_TOKEN\n"
            "          tofu output -raw ipv4_address > "
            '"$RUNNER_TEMP/ci-cloud/ipv4_address"\n'
            "          tofu output -raw image_id >",
        )

    def test_rejects_missing_live_gcp_ip_handoff(self) -> None:
        self.assert_mutation_rejected(
            ".github/workflows/cloud-conformance.yml",
            '            "$GCP_BOOTSTRAP_SERVICE_ACCOUNT" \\\n'
            '            "$RUNNER_TEMP/ci-cloud/ipv4_address"\n',
            '            "$GCP_BOOTSTRAP_SERVICE_ACCOUNT"\n',
        )

    def test_gcp_root_does_not_export_a_pre_transition_address(self) -> None:
        outputs = (ROOT / "infra/ci-cloud/gcp/outputs.tf").read_text(
            encoding="utf-8"
        )
        self.assertNotIn('output "ipv4_address"', outputs)
        self.assertNotIn('output "initial_ipv4_address"', outputs)

    def test_rejects_gcp_pre_transition_address_output(self) -> None:
        self.assert_mutation_rejected(
            "infra/ci-cloud/gcp/outputs.tf",
            'output "image_id" {',
            'output "ipv4_address" {\n'
            "  value = google_compute_instance.conformance."
            "network_interface[0].access_config[0].nat_ip\n"
            "}\n\n"
            'output "image_id" {',
        )

    def test_rejects_live_ip_publication_before_final_gcp_postconditions(
        self,
    ) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/detach-gcp-vm-identity.sh",
            'live_ipv4="$(wait_for_admitted_identity_free_public_ipv4)"\n'
            'publish_current_ipv4 "$live_ipv4"\n',
            'publish_current_ipv4 "34.120.30.31"\n'
            'live_ipv4="$(wait_for_admitted_identity_free_public_ipv4)"\n',
        )

    def test_rejects_non_atomic_live_gcp_ip_publication(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/detach-gcp-vm-identity.sh",
            '  mv -T -- "$published_ipv4_tmp" "$ipv4_output"\n',
            '  cp -- "$published_ipv4_tmp" "$ipv4_output"\n',
        )

    def test_rejects_gcp_live_ip_pending_state_without_bounded_retry(
        self,
    ) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/detach-gcp-vm-identity.sh",
            "          75) ;;\n",
            "          75) return 1 ;;\n",
        )

    def test_gcp_native_bootstrap_waits_for_identity_detachment(self) -> None:
        bootstrap = (
            ROOT / "scripts/ci-cloud/bootstrap-conformance-host.tftpl"
        ).read_text(encoding="utf-8")
        gate = "${cloud_identity_gate}"
        diagnostic_install = (
            "install -o root -g root -m 0700 /dev/null \\\n"
            "  /usr/local/sbin/secpal-ci-install-diagnostic-ssh"
        )
        self.assertIn(gate, bootstrap)
        self.assertLess(bootstrap.index(gate), bootstrap.index(diagnostic_install))
        digitalocean_main = (
            ROOT / "infra/ci-cloud/digitalocean/main.tf"
        ).read_text(encoding="utf-8")
        gcp_main = (ROOT / "infra/ci-cloud/gcp/main.tf").read_text(
            encoding="utf-8"
        )
        self.assertRegex(
            digitalocean_main,
            r'(?m)^\s*cloud_identity_gate\s+= ":"$',
        )
        self.assertRegex(
            gcp_main,
            r'(?m)^\s*cloud_identity_gate\s+= trimspace\(file\('
            r'"\$\{path\.module\}/\.\./\.\./\.\./scripts/ci-cloud/'
            r'defer-bootstrap-for-gcp-identity\.sh"\)\)$',
        )
        identity_gate = (
            ROOT / "scripts/ci-cloud/defer-bootstrap-for-gcp-identity.sh"
        ).read_text(encoding="utf-8")
        self.assertIn(
            'identity_path="instance/service-accounts/"', identity_gate
        )
        self.assertIn(
            "instance/attributes/secpal-ci-cloud-identity-admitted",
            identity_gate,
        )

    def test_gcp_identity_transition_has_only_bounded_permissions(self) -> None:
        role = (ROOT / "infra/ci-cloud/gcp/iam-role.yaml").read_text(
            encoding="utf-8"
        )
        for permission in (
            "compute.instances.setServiceAccount",
            "compute.instances.start",
            "compute.instances.stop",
        ):
            self.assertEqual(1, role.count(f"  - {permission}\n"))
        self.assertNotIn("iam.serviceAccounts.actAs", role)
        docs = (ROOT / "docs/ci-cloud-conformance.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("roles/iam.serviceAccountUser", docs)
        self.assertIn("GCP_BOOTSTRAP_SERVICE_ACCOUNT", docs)

    def test_gcp_job_budget_covers_bounded_internal_phases(self) -> None:
        document = yaml.load(
            (ROOT / ".github/workflows/cloud-conformance.yml").read_text(
                encoding="utf-8"
            ),
            Loader=yaml.BaseLoader,
        )
        self.assertEqual("100", document["jobs"]["gcp"]["timeout-minutes"])
        workflow = (
            ROOT / ".github/workflows/cloud-conformance.yml"
        ).read_text(encoding="utf-8")
        self.assertEqual(1, workflow.count("created_at + 10800"))
        self.assertEqual(1, workflow.count("created_at + 7200"))

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
            "      - name: Run uncredentialed GCP remote conformance\n"
            "        id: gcp_conformance\n"
            "        if: >-\n"
            "          ${{ steps.gcp_apply.outcome == 'success' &&\n"
            "          steps.gcp_identity.outcome == 'success' }}\n"
            "        continue-on-error: true\n"
            "        env:\n"
            "          RESOURCE_ATTEMPT: ${{ needs.validate.outputs.resource_attempt }}\n",
            "      - name: Run uncredentialed GCP remote conformance\n"
            "        id: gcp_conformance\n"
            "        if: >-\n"
            "          ${{ steps.gcp_apply.outcome == 'success' &&\n"
            "          steps.gcp_identity.outcome == 'success' }}\n"
            "        continue-on-error: true\n"
            "        env:\n"
            "          RESOURCE_ATTEMPT: ${{ needs.validate.outputs.resource_attempt }}\n"
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

    def test_rejects_gcp_target_before_identity_detachment(self) -> None:
        self.assert_mutation_rejected(
            ".github/workflows/cloud-conformance.yml",
            "        if: >-\n"
            "          ${{ steps.gcp_apply.outcome == 'success' &&\n"
            "          steps.gcp_identity.outcome == 'success' }}\n",
            "        if: ${{ steps.gcp_apply.outcome == 'success' }}\n",
        )

    def test_rejects_gcp_bootstrap_without_identity_gate(self) -> None:
        self.assert_mutation_rejected(
            "infra/ci-cloud/gcp/main.tf",
            "defer-bootstrap-for-gcp-identity.sh",
            "disabled-gcp-identity-gate.sh",
        )

    def test_rejects_curl_dependency_in_early_gcp_identity_gate(self) -> None:
        identity_gate = (
            ROOT / "scripts/ci-cloud/defer-bootstrap-for-gcp-identity.sh"
        ).read_text(encoding="utf-8")
        self.assertNotIn("curl ", identity_gate)
        self.assertIn("/dev/tcp/169.254.169.254/80", identity_gate)

    def test_rejects_gcp_identity_start_before_stopped_detachment_check(
        self,
    ) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/detach-gcp-vm-identity.sh",
            "detached_instance=\"$(wait_for_instance_status TERMINATED)\"\n"
            'if ! verify_identity_free "$detached_instance"; then\n',
            "detached_instance='{}'\n"
            'if ! verify_identity_free "$detached_instance"; then\n',
        )

    def test_rejects_gcp_identity_admission_before_detachment(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/detach-gcp-vm-identity.sh",
            'set_admission_metadata "$detached_instance" TERMINATED',
            'set_admission_metadata "$stopped_instance" TERMINATED',
        )

    def test_rejects_gcp_bootstrap_gate_without_trusted_admission(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/defer-bootstrap-for-gcp-identity.sh",
            'admission_path="instance/attributes/'
            'secpal-ci-cloud-identity-admitted"',
            'admission_path="instance/attributes/untrusted"',
        )

    def test_rejects_gcp_gate_exiting_the_embedded_bootstrap(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/defer-bootstrap-for-gcp-identity.sh",
            "    identity_admitted=true\n    break\n",
            "    exit 0\n",
        )

    def test_rejects_gcp_admission_marker_in_initial_metadata(self) -> None:
        self.assert_mutation_rejected(
            "infra/ci-cloud/gcp/main.tf",
            '    enable-oslogin           = "FALSE"\n',
            '    enable-oslogin           = "FALSE"\n'
            '    "secpal-ci-cloud-identity-admitted" = "true"\n',
        )

    def test_rejects_missing_gcp_post_start_identity_check(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/detach-gcp-vm-identity.sh",
            '        if ! verify_identity_free "$response"; then\n',
            '        if false; then\n',
        )

    def test_rejects_gcp_collector_identity_status_without_body_semantics(
        self,
    ) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/collect-host-evidence.py",
            '"identity_present": probe_succeeded and identity_body != b"",\n',
            '"identity_present": probe_succeeded and identity_status == b"200",\n',
        )

    def test_rejects_gcp_collector_without_metadata_probe_exit_status(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/collect-host-evidence.py",
            "        probe.returncode == 0\n        and probe.stdout.strip() == \"200\"\n",
            '        probe.stdout.strip() == "200"\n',
        )

    def test_rejects_gcp_collector_without_identity_probe_exit_status(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/collect-host-evidence.py",
            "        and identity.returncode == 0\n",
            "",
        )

    def test_rejects_unbounded_gcp_collector_identity_body(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/collect-host-evidence.py",
            '                "--max-filesize",\n'
            '                "4096",\n',
            "",
        )

    def test_rejects_discarded_gcp_collector_identity_body(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/collect-host-evidence.py",
            '                "--output",\n'
            '                "-",\n',
            '                "--output",\n'
            '                "/dev/null",\n',
        )

    def test_rejects_unbounded_quadlet_fixture_unit(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/quadlet-fixture-installer.py",
            "MAX_UNIT_BYTES = 64 * 1024",
            "MAX_UNIT_BYTES = 1024 * 1024",
        )

    def test_rejects_quadlet_fixture_symlink_following(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/quadlet-fixture-installer.py",
            '        flags |= os.O_NOFOLLOW\n',
            "",
        )

    def test_rejects_writable_untrusted_quadlet_request_path(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/quadlet-fixture-installer.py",
            "ReadWritePaths={layout.quadlet_root} {layout.systemd_root} {layout.state_root}",
            "ReadWritePaths={layout.quadlet_root} {layout.systemd_root} "
            "{layout.state_root} -{layout.request_path(operation)}",
        )

    def test_rejects_quadlet_fixture_without_shared_operation_lock(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/quadlet-fixture-installer.py",
            "            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)\n",
            "            pass\n",
        )

    def test_rejects_non_resumable_quadlet_cleanup_state(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/quadlet-fixture-installer.py",
            '        state["state"] = "removing"\n',
            "        pass\n",
        )

    def test_rejects_ambiguous_quadlet_manifest_json(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/quadlet-fixture-installer.py",
            "json.loads(content, object_pairs_hook=reject_duplicate_keys)",
            "json.loads(content)",
        )

    def test_rejects_boolean_quadlet_manifest_schema_version(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/quadlet-fixture-installer.py",
            '        type(manifest["schema_version"]) is not int\n',
            "        False\n",
        )

    def test_rejects_blocking_trusted_fixture_file_open(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/quadlet-fixture-installer.py",
            "def bounded_trusted_file(\n"
            "    path: Path,\n"
            "    layout: Layout,\n"
            "    *,\n"
            "    mode: int,\n"
            "    maximum: int,\n"
            "    rejection_code: str,\n"
            ") -> bytes:\n"
            "    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK",
            "def bounded_trusted_file(\n"
            "    path: Path,\n"
            "    layout: Layout,\n"
            "    *,\n"
            "    mode: int,\n"
            "    maximum: int,\n"
            "    rejection_code: str,\n"
            ") -> bytes:\n"
            "    flags = os.O_RDONLY | os.O_CLOEXEC",
        )

    def test_rejects_blocking_untrusted_fixture_file_open(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/quadlet-fixture-installer.py",
            "def bounded_regular_file(path: Path, layout: Layout, maximum: int) -> bytes:\n"
            "    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK",
            "def bounded_regular_file(path: Path, layout: Layout, maximum: int) -> bytes:\n"
            "    flags = os.O_RDONLY | os.O_CLOEXEC",
        )

    def test_rejects_blocking_fixture_client_source_open(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/quadlet-fixture-client.py",
            "flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK",
            "flags = os.O_RDONLY | os.O_CLOEXEC",
        )

    def test_rejects_quadlet_result_without_closed_reason(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/quadlet-fixture-installer.py",
            '        "reason": reason,\n',
            "",
        )

    def test_rejects_arbitrary_quadlet_fixture_filenames(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/quadlet-fixture-installer.py",
            "        if observed_names != set(names):\n",
            "        if False:\n",
        )

    def test_rejects_quadlet_cleanup_without_recorded_digest(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/quadlet-fixture-installer.py",
            '        if not trusted_file_matches(destination, state["files"][name], layout):\n',
            "        if False:\n",
        )

    def test_rejects_quadlet_install_trigger_left_active(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/quadlet-fixture-installer.py",
            '        if operation == "install":\n'
            "            stop_path_trigger(trigger, stop_trigger)\n",
            '        if operation == "install":\n'
            "            pass\n",
        )

    def test_rejects_unbounded_quadlet_removal_retries(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/quadlet-fixture-installer.py",
            "TriggerLimitIntervalSec=60s\nTriggerLimitBurst=3",
            "TriggerLimitIntervalSec=0\nTriggerLimitBurst=0",
        )

    def test_rejects_quadlet_removal_without_automatic_resume(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/quadlet-fixture-installer.py",
            '                retrying = read_active_state(layout)["state"] == "removing"\n',
            "                retrying = False\n",
        )

    def test_rejects_persistent_quadlet_root_bridge(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/quadlet-fixture-installer.py",
            '["systemctl", "start", INSTALL_PATH_UNIT, REMOVE_PATH_UNIT],\n',
            '["systemctl", "enable", "--now", INSTALL_PATH_UNIT, REMOVE_PATH_UNIT],\n',
        )

    def test_rejects_source_path_in_quadlet_fixture_request(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/quadlet-fixture-client.py",
            '            "schema_version": SCHEMA_VERSION,\n',
            '            "schema_version": SCHEMA_VERSION,\n'
            '            "source": str(source),\n',
        )

    def test_rejects_plaintext_quadlet_installer_provider_embedding(self) -> None:
        self.assert_mutation_rejected(
            "infra/ci-cloud/digitalocean/main.tf",
            'base64gzip(file("${path.module}/../../../scripts/ci-cloud/'
            'quadlet-fixture-installer.py"))',
            'file("${path.module}/../../../scripts/ci-cloud/'
            'quadlet-fixture-installer.py")',
        )

    def test_rejects_plaintext_quadlet_client_provider_embedding(self) -> None:
        self.assert_mutation_rejected(
            "infra/ci-cloud/gcp/main.tf",
            'base64gzip(file("${path.module}/../../../scripts/ci-cloud/'
            'quadlet-fixture-client.py"))',
            'file("${path.module}/../../../scripts/ci-cloud/'
            'quadlet-fixture-client.py")',
        )

    def test_rejects_empty_email_in_gcp_identity_removal_request(self) -> None:
        identity_script = (
            ROOT / "scripts/ci-cloud/detach-gcp-vm-identity.sh"
        ).read_text(encoding="utf-8")
        self.assertIn("'{\"scopes\":[]}'", identity_script)
        self.assertNotIn("'{\"email\":\"\",\"scopes\":[]}'", identity_script)

    def test_rejects_gcp_identity_request_without_bearer_token_value(
        self,
    ) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/detach-gcp-vm-identity.sh",
            "  printf 'header = \"Authorization: Bearer %s\"\\n' "
            '"$access_token" |\n',
            "  printf 'header = \"Authorization: Bearer\"\\n' |\n",
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
            "scripts/ci-cloud/bootstrap-conformance-host.tftpl",
            "  unattended-upgrades\n",
            "",
        )

    def test_rejects_appended_unattended_upgrade_origins(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/bootstrap-conformance-host.tftpl",
            "#clear Unattended-Upgrade::Origins-Pattern;\n",
            "",
        )

    def test_rejects_backports_in_native_bootstrap_sources(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/bootstrap-conformance-host.tftpl",
            "Suites: trixie trixie-updates\n",
            "Suites: trixie trixie-updates trixie-backports\n",
        )

    def test_rejects_apt_list_cleanup_that_deletes_the_lock(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/bootstrap-conformance-host.tftpl",
            "  ! -name lock \\( -type f -o -type l \\) -delete\n",
            "  \\( -type f -o -type l \\) -delete\n",
        )

    def test_rejects_apt_list_cleanup_outside_the_update_lock(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/bootstrap-conformance-host.tftpl",
            '  -o "APT::Update::Pre-Invoke::=$apt_lists_cleanup" update\n',
            "  update\n",
        )

    def test_rejects_cloud_credential_in_remote_test_step(self) -> None:
        self.assert_mutation_rejected(
            ".github/workflows/cloud-conformance.yml",
            "      - name: Run uncredentialed DigitalOcean remote conformance\n"
            "        id: conformance\n"
            "        if: ${{ steps.apply.outcome == 'success' }}\n"
            "        continue-on-error: true\n"
            "        env:\n"
            "          RESOURCE_ATTEMPT: ${{ needs.validate.outputs.resource_attempt }}\n",
            "      - name: Run uncredentialed DigitalOcean remote conformance\n"
            "        id: conformance\n"
            "        if: ${{ steps.apply.outcome == 'success' }}\n"
            "        continue-on-error: true\n"
            "        env:\n"
            "          RESOURCE_ATTEMPT: ${{ needs.validate.outputs.resource_attempt }}\n"
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

    def test_cleanup_reuses_validated_resource_attempt_across_reruns(
        self,
    ) -> None:
        workflow = (
            ROOT / ".github/workflows/cloud-conformance.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "resource_attempt: ${{ steps.inputs.outputs.resource_attempt }}",
            workflow,
        )
        self.assertIn(
            "RAW_RESOURCE_ATTEMPT: ${{ github.run_attempt }}", workflow
        )
        self.assertEqual(
            11,
            workflow.count(
                "${{ needs.validate.outputs.resource_attempt }}"
            ),
        )

    def test_provider_jobs_reject_targeted_reruns_with_stale_identity(
        self,
    ) -> None:
        document = yaml.load(
            (ROOT / ".github/workflows/cloud-conformance.yml").read_text(
                encoding="utf-8"
            ),
            Loader=yaml.BaseLoader,
        )
        jobs = document["jobs"]
        for provider in ("digitalocean", "gcp"):
            with self.subTest(provider=provider):
                self.assertEqual(
                    "${{ needs.validate.outputs.provider == "
                    f"'{provider}' && github.run_attempt == "
                    "fromJSON(needs.validate.outputs.resource_attempt) }}",
                    jobs[provider]["if"],
                )

    def test_cleanup_init_uses_bounded_retry_helper(self) -> None:
        workflow = (
            ROOT / ".github/workflows/cloud-conformance.yml"
        ).read_text(encoding="utf-8")
        helper = (
            ROOT / "scripts/ci-cloud/init-cleanup-root.sh"
        ).read_text(encoding="utf-8")
        self.assertEqual(
            2,
            workflow.count(
                '"$GITHUB_WORKSPACE/scripts/ci-cloud/init-cleanup-root.sh"'
            ),
        )
        self.assertIn(
            "timeout --signal=TERM --kill-after=15s 90s", helper
        )

    def test_rejects_cleanup_bound_to_current_rerun_attempt(self) -> None:
        self.assert_mutation_rejected(
            ".github/workflows/cloud-conformance.yml",
            "cloud-state-digitalocean-${{ github.run_id }}-"
            "${{ needs.validate.outputs.resource_attempt }}",
            "cloud-state-digitalocean-${{ github.run_id }}-"
            "${{ github.run_attempt }}",
        )

    def test_rejects_cleanup_without_bounded_init_retry(self) -> None:
        self.assert_mutation_rejected(
            ".github/workflows/cloud-conformance.yml",
            '"$GITHUB_WORKSPACE/scripts/ci-cloud/init-cleanup-root.sh"',
            "tofu init -input=false -lockfile=readonly",
        )

    def test_rejects_provider_job_rerun_without_fresh_identity(self) -> None:
        for provider in ("digitalocean", "gcp"):
            with self.subTest(provider=provider):
                guarded = (
                    "    if: >-\n"
                    "      ${{ needs.validate.outputs.provider == "
                    f"'{provider}' &&\n"
                    "      github.run_attempt == "
                    "fromJSON(needs.validate.outputs.resource_attempt) }}\n"
                )
                self.assert_mutation_rejected(
                    ".github/workflows/cloud-conformance.yml",
                    guarded,
                    "    if: ${{ needs.validate.outputs.provider == "
                    f"'{provider}' }}\n",
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
