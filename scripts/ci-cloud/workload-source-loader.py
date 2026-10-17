#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Install only the exact protected-control workload closure over trusted SSH."""

from __future__ import annotations
import hashlib
import json
import os
import re
from pathlib import Path
import sys

CONTROL = Path("/opt/secpal-control")
MAX_BYTES = 256 * 1024
TARGET = "402c22b0a1d69a5a3dba74ffb68cf016caba606b"
HARNESS = "436756f79c7f120d5c4b9fc15b12b2fd91da0fdea5e93ed2907172a73c2861ac"

class Failure(ValueError):
    pass

SOURCES = {
    "run-rocky-workload-qualification.py": (CONTROL / "scripts/ci-cloud/run-rocky-workload-qualification.py", 0o700),
    "collect-workload-evidence.py": (CONTROL / "scripts/ci-cloud/collect-workload-evidence.py", 0o555),
    "quadlet-fixture-installer.py": (Path("/usr/local/sbin/secpal-ci-quadlet-fixture-installer"), 0o700),
    "quadlet-fixture-client.py": (Path("/usr/local/bin/secpal-ci-quadlet-fixture"), 0o555),
    "bounded-target-diagnostic.py": (CONTROL / "scripts/ci-cloud/bounded-target-diagnostic.py", 0o700),
    "workload-purity.py": (CONTROL / "scripts/ci-cloud/workload-purity.py", 0o700),
    "workload-admission.py": (CONTROL / "scripts/ci-cloud/workload-admission.py", 0o700),
}


def exact_object(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("duplicate transport key")
    return result


def admit_sources(payload, manifest):
    if not 0 < len(payload) <= 1024 * 1024:
        raise Failure("admit-control-source-size")
    try:
        sources = json.loads(payload, object_pairs_hook=exact_object)
    except (ValueError, UnicodeError):
        raise Failure("admit-control-source-format") from None
    if (not isinstance(sources, dict) or set(sources) != set(SOURCES)
            or not isinstance(manifest, dict) or set(manifest) != set(SOURCES)
            or any(not isinstance(value, str) or len(value.encode()) > MAX_BYTES
                   or hashlib.sha256(value.encode()).hexdigest() != manifest[name]
                   for name, value in sources.items())):
        raise Failure("admit-control-source-digests")
    return {name: value.encode() for name, value in sources.items()}


def install_sources():
    try:
        manifest = json.loads((CONTROL / "workload-manifest.json").read_bytes(),
                              object_pairs_hook=exact_object)
    except (OSError, ValueError):
        raise Failure("read-control-source-manifest") from None
    # Verify the entire closed source set before the first installation.
    sources = admit_sources(sys.stdin.buffer.read(1024 * 1024 + 1), manifest)
    for name, content in sources.items():
        destination, mode = SOURCES[name]
        if destination.exists() or destination.is_symlink():
            raise Failure("admit-fresh-control-destination")
    for name, content in sources.items():
        destination, mode = SOURCES[name]
        try:
            with destination.open("xb") as output:
                output.write(content)
            destination.chmod(mode)
        except OSError:
            raise Failure("install-control-source-" + name) from None


def main():
    if sys.argv[1:] == ["source-bundle"]:
        directory = Path(__file__).resolve().parent
        print(json.dumps({name: (directory / name).read_text() for name in SOURCES},
                         separators=(",", ":")))
        return 0
    if (len(sys.argv) != 6 or os.geteuid() != 0 or sys.argv[1] != TARGET
            or sys.argv[5] != HARNESS
            or re.fullmatch(r"[0-9a-f]{40}", sys.argv[2]) is None
            or re.fullmatch(r"[1-9][0-9]{0,19}", sys.argv[3]) is None
            or re.fullmatch(r"[1-9][0-9]{0,2}", sys.argv[4]) is None):
        return 1
    operation = "admit-current-boot-binding"
    try:
        readiness_path = Path("/var/lib/secpal-rocky/qualification-readiness.json")
        readiness = json.loads(readiness_path.read_bytes())
        expected = {"target_sha": TARGET, "trusted_control_sha": sys.argv[2],
                    "access_run_id": sys.argv[3], "access_run_attempt": sys.argv[4],
                    "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                    "cloud_identity_absent": True}
        if any(readiness.get(key) != value for key, value in expected.items()):
            raise Failure("admit-current-boot-binding")
        install_sources()
        executable = str(CONTROL / "scripts/ci-cloud/run-rocky-workload-qualification.py")
        operation = "start-workload-collection"
        os.execv("/usr/bin/python3", ["python3", "-I", executable, *sys.argv[1:]])
    except (OSError, ValueError) as error:
        operation = str(error) if isinstance(error, Failure) else operation
        print(f"ROCKY_WORKLOAD_FAILURE operation={operation}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
