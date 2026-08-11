#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Validate fully rendered provider cloud-init against cloud-init's schema."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HOST_SETUP = ROOT / "scripts" / "ci-cloud" / "configure-conformance-host.sh"
HOST_SETUP_FAILURE = ROOT / "scripts" / "ci-cloud" / "host-setup-failure.py"
DIAGNOSTIC_SSH_INSTALLER = (
    ROOT / "scripts" / "ci-cloud" / "install-diagnostic-ssh.sh"
)
TEMPLATES = (
    ROOT / "infra" / "ci-cloud" / "digitalocean" / "cloud-init.tftpl",
    ROOT / "infra" / "ci-cloud" / "gcp" / "cloud-init.tftpl",
)


def indent_embedded_script(path: Path, spaces: int = 6) -> str:
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    indentation = " " * spaces
    return lines[0] + "\n" + "\n".join(
        f"{indentation}{line}" for line in lines[1:]
    )


def render(template_path: Path) -> str:
    rendered = template_path.read_text(encoding="utf-8")
    replacements = {
        "${ssh_public_key}": (
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAISynthetic fixture@example"
        ),
        "${runner_ipv4}": "192.0.2.10",
        "${run_id}": "12345",
        "${run_attempt}": "1",
        "${diagnostic_ssh_installer}": indent_embedded_script(
            DIAGNOSTIC_SSH_INSTALLER, 8
        ),
        "${host_setup_script}": indent_embedded_script(HOST_SETUP),
        "${host_setup_failure_script}": indent_embedded_script(
            HOST_SETUP_FAILURE
        ),
        "$${distro_codename}": "${distro_codename}",
    }
    for old, new in replacements.items():
        rendered = rendered.replace(old, new)
    return rendered


class CloudConfigTests(unittest.TestCase):
    def test_provider_templates_pass_cloud_init_schema(self) -> None:
        for template in TEMPLATES:
            with self.subTest(template=template):
                with tempfile.NamedTemporaryFile(
                    mode="w", encoding="utf-8", suffix=".yaml"
                ) as rendered_file, tempfile.NamedTemporaryFile(
                    mode="w", encoding="utf-8", suffix=".json"
                ) as instance_data_file:
                    rendered = render(template)
                    self.assertNotIn("${host_setup", rendered)
                    self.assertNotIn("${diagnostic_ssh_installer}", rendered)
                    self.assertNotIn("${runner_ipv4}", rendered)
                    rendered_file.write(rendered)
                    rendered_file.flush()
                    instance_data_file.write("{}\n")
                    instance_data_file.flush()
                    completed = subprocess.run(
                        [
                            "cloud-init",
                            "schema",
                            "--schema-type",
                            "cloud-config",
                            "--config-file",
                            rendered_file.name,
                            "--instance-data",
                            instance_data_file.name,
                        ],
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
