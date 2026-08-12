#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Validate the rendered systemd boundary across the one-shot kernel reboot."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DIAGNOSTIC_SERVICE = "secpal-ci-diagnostic-sshd.service"
CONTINUATION_SERVICE = "secpal-ci-bootstrap-continue.service"


def fail(message: str) -> None:
    raise RuntimeError(message)


def heredoc(source: str, opener: str, closer: str) -> str:
    try:
        return source.split(opener, 1)[1].split(f"\n{closer}", 1)[0]
    except IndexError:
        fail(f"missing rendered unit heredoc: {opener}")


def require_line(document: str, line: str) -> None:
    if document.splitlines().count(line) != 1:
        fail(f"rendered unit must contain exactly one {line!r}")


def main() -> int:
    installer = (
        ROOT / "scripts/ci-cloud/install-diagnostic-ssh.sh"
    ).read_text(encoding="utf-8")
    bootstrap = (
        ROOT / "scripts/ci-cloud/bootstrap-conformance-host.tftpl"
    ).read_text(encoding="utf-8")

    diagnostic = heredoc(installer, 'cat >"$service_tmp" <<EOF\n', "EOF")
    continuation = heredoc(
        bootstrap,
        "cat >\"$continuation_unit\" <<'SECPAL_CONTINUATION_UNIT'\n",
        "SECPAL_CONTINUATION_UNIT",
    )

    for line in (
        "ConditionPathExists=!/var/lib/secpal-ci/host-setup-complete",
        "Before=secpal-ci-bootstrap-continue.service",
        "RuntimeDirectory=sshd secpal-ci-evidence",
        "RuntimeDirectoryMode=0755",
        "RuntimeDirectoryPreserve=yes",
        "WantedBy=multi-user.target",
    ):
        require_line(diagnostic, line)
    for line in (
        "Wants=network-online.target secpal-ci-diagnostic-sshd.service",
        "After=network-online.target secpal-ci-diagnostic-sshd.service",
        "ConditionPathExists=/var/lib/secpal-ci-bootstrap/pending",
    ):
        require_line(continuation, line)

    systemd_analyze = "/usr/bin/systemd-analyze"
    if not Path(systemd_analyze).is_file():
        fail("systemd-analyze is required")

    rendered_diagnostic = diagnostic.replace("/usr/sbin/sshd", "/bin/true").replace(
        "$diagnostic_config", "/etc/ssh/sshd_config"
    )
    rendered_continuation = continuation.replace(
        "/usr/local/sbin/secpal-ci-continue-bootstrap", "/bin/true"
    )
    with tempfile.TemporaryDirectory(prefix="secpal-ci-systemd-") as directory:
        root = Path(directory)
        diagnostic_path = root / DIAGNOSTIC_SERVICE
        continuation_path = root / CONTINUATION_SERVICE
        diagnostic_path.write_text(rendered_diagnostic, encoding="utf-8")
        continuation_path.write_text(rendered_continuation, encoding="utf-8")
        result = subprocess.run(
            [
                systemd_analyze,
                "verify",
                str(diagnostic_path),
                str(continuation_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    if result.returncode != 0:
        fail(f"rendered systemd units failed verification:\n{result.stdout}")

    print("Cloud systemd reboot lifecycle contract passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
