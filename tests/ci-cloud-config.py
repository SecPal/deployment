#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Validate the fully rendered provider-native bootstrap shell payload."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = ROOT / "scripts" / "ci-cloud" / "bootstrap-conformance-host.tftpl"
HOST_SETUP = ROOT / "scripts" / "ci-cloud" / "configure-conformance-host.sh"
HOST_SETUP_FAILURE = ROOT / "scripts" / "ci-cloud" / "host-setup-failure.py"
BOOTSTRAP_CONTINUATION = (
    ROOT / "scripts" / "ci-cloud" / "continue-conformance-bootstrap.sh"
)
DIAGNOSTIC_SSH_INSTALLER = (
    ROOT / "scripts" / "ci-cloud" / "install-diagnostic-ssh.sh"
)


def render() -> str:
    rendered = BOOTSTRAP.read_text(encoding="utf-8")
    replacements = {
        "${ssh_public_key}": (
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAISynthetic fixture@example"
        ),
        "${runner_ipv4}": "192.0.2.10",
        "${run_id}": "12345",
        "${run_attempt}": "1",
        "${diagnostic_ssh_installer}": DIAGNOSTIC_SSH_INSTALLER.read_text(
            encoding="utf-8"
        ).strip(),
        "${host_setup_script}": HOST_SETUP.read_text(encoding="utf-8").strip(),
        "${host_setup_failure_script}": HOST_SETUP_FAILURE.read_text(
            encoding="utf-8"
        ).strip(),
        "${bootstrap_continuation_script}": BOOTSTRAP_CONTINUATION.read_text(
            encoding="utf-8"
        ).strip(),
    }
    for old, new in replacements.items():
        rendered = rendered.replace(old, new)
    return rendered.replace("$${", "${")


class ProviderBootstrapTests(unittest.TestCase):
    def test_rendered_native_bootstrap_is_valid_bash(self) -> None:
        rendered = render()
        self.assertLessEqual(len(rendered.encode("utf-8")), 64 * 1024)
        for placeholder in (
            "${diagnostic_ssh_installer}",
            "${host_setup_script}",
            "${host_setup_failure_script}",
            "${bootstrap_continuation_script}",
            "${runner_ipv4}",
            "${run_id}",
            "${run_attempt}",
            "${ssh_public_key}",
        ):
            self.assertNotIn(placeholder, rendered)
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", suffix=".sh"
        ) as rendered_file:
            rendered_file.write(rendered)
            rendered_file.flush()
            completed = subprocess.run(
                ["bash", "-n", rendered_file.name],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(
            0,
            completed.returncode,
            f"{completed.stdout}\n{completed.stderr}",
        )


if __name__ == "__main__":
    unittest.main()
