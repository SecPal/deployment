#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Validate the fully rendered provider-native bootstrap shell payload."""

from __future__ import annotations

import base64
import gzip
import re
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
QUADLET_FIXTURE_INSTALLER = (
    ROOT / "scripts" / "ci-cloud" / "quadlet-fixture-installer.py"
)
QUADLET_FIXTURE_CLIENT = (
    ROOT / "scripts" / "ci-cloud" / "quadlet-fixture-client.py"
)


def base64gzip(path: Path) -> str:
    return base64.b64encode(gzip.compress(path.read_bytes(), mtime=0)).decode("ascii")


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
        "${host_setup_script_base64gzip}": base64gzip(HOST_SETUP),
        "${host_setup_failure_script}": HOST_SETUP_FAILURE.read_text(
            encoding="utf-8"
        ).strip(),
        "${bootstrap_continuation_script}": BOOTSTRAP_CONTINUATION.read_text(
            encoding="utf-8"
        ).strip(),
        "${quadlet_fixture_installer_base64gzip}": base64gzip(
            QUADLET_FIXTURE_INSTALLER
        ),
        "${quadlet_fixture_client_base64gzip}": base64gzip(
            QUADLET_FIXTURE_CLIENT
        ),
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
            "${host_setup_script_base64gzip}",
            "${host_setup_failure_script}",
            "${bootstrap_continuation_script}",
            "${quadlet_fixture_installer_base64gzip}",
            "${quadlet_fixture_client_base64gzip}",
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

    def test_compressed_trusted_scripts_round_trip_from_rendered_payload(self) -> None:
        rendered = render()
        for destination, source in (
            (
                "/usr/local/sbin/secpal-ci-configure-conformance-host",
                HOST_SETUP,
            ),
            (
                "/usr/local/sbin/secpal-ci-quadlet-fixture-installer",
                QUADLET_FIXTURE_INSTALLER,
            ),
            (
                "/usr/local/bin/secpal-ci-quadlet-fixture",
                QUADLET_FIXTURE_CLIENT,
            ),
        ):
            match = re.search(
                r"decode_embedded_script '([A-Za-z0-9+/=]+)' \\\n"
                + re.escape(f"  {destination}"),
                rendered,
            )
            self.assertIsNotNone(match, destination)
            decoded = gzip.decompress(base64.b64decode(match.group(1)))
            self.assertEqual(source.read_bytes(), decoded)


if __name__ == "__main__":
    unittest.main()
