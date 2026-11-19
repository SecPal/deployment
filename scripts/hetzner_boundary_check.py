#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT
"""Run as the normal caller after administrator installation. Never read values."""
import json
import os
from pathlib import Path
import sys


def main():
    passed = os.geteuid() != 0
    results = {}
    for name, path in {
        "credential_read_denied": "/etc/secpal-hetzner/token",
        "policy_read_denied": "/etc/secpal-hetzner/policy.json",
    }.items():
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except PermissionError:
            results[name] = True
        except OSError:
            results[name] = False
        else:
            os.close(fd)
            results[name] = False
        passed = passed and results[name]
    for path in [
        "/opt/secpal-hetzner",
        "/opt/secpal-hetzner/hetzner_broker.py",
        "/etc/secpal-hetzner",
        "/etc/systemd/system/secpal-hetzner.service",
        "/etc/systemd/system/secpal-hetzner.socket",
    ]:
        key = "immutable:" + path
        results[key] = Path(path).exists() and not os.access(path, os.W_OK)
        passed = passed and results[key]
    print(
        json.dumps(
            {
                "code": (
                    "boundary.access-checks-complete" if passed else "boundary.pending"
                ),
                "checks": results,
                # EACCES under a sealed parent does not prove that its child exists.
                "protected_file_existence": "administrator-verification-required",
                "credential_transition": "not-evaluated",
            },
            sort_keys=True,
        )
    )
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
