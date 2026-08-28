#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Wait for one authenticated, current-boot Rocky qualification boundary."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import selectors
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable, NamedTuple


SHA = re.compile(r"^[0-9a-f]{40}$")
NUMBER = re.compile(r"^[1-9][0-9]{0,19}$")
ATTEMPT = re.compile(r"^[1-9][0-9]{0,2}$")
BOOT_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
KEY = re.compile(
    r"^ssh-ed25519 [A-Za-z0-9+/]+={0,2} "
    r"secpal-rocky-[1-9][0-9]{0,19}-[1-9][0-9]{0,2}$"
)
MARKER_KEYS = {
    "schema_version",
    "target_sha",
    "trusted_control_sha",
    "access_run_id",
    "access_run_attempt",
    "boot_id",
    "ssh_public_key_sha256",
    "cloud_identity_absent",
    "guest_startup_complete",
}
REMOTE_READ = (
    "boot=$(cat /proc/sys/kernel/random/boot_id) || exit 1; "
    "printf '%s\\n' \"$boot\"; "
    "marker=/var/lib/secpal-rocky/qualification-readiness.json; "
    "if test -r \"$marker\"; then head -c 4097 \"$marker\"; "
    "else printf 'absent\\n'; fi"
)
SSH_OUTPUT_MAX_BYTES = 4200


class Expectation(NamedTuple):
    target_sha: str
    trusted_control_sha: str
    access_run_id: str
    access_run_attempt: str
    ssh_public_key_sha256: str


class ProbeResult(NamedTuple):
    state: str
    current_boot_id: str | None = None
    document: dict[str, object] | None = None

    @classmethod
    def transport(cls) -> "ProbeResult":
        return cls("transport")

    @classmethod
    def authentication(cls) -> "ProbeResult":
        return cls("authentication")

    @classmethod
    def missing(cls, boot_id: str) -> "ProbeResult":
        return cls("missing", boot_id)

    @classmethod
    def ready(cls, boot_id: str, document: dict[str, object]) -> "ProbeResult":
        return cls("ready", boot_id, document)


class ReadinessFailure(RuntimeError):
    def __init__(self, operation: str, reason: str) -> None:
        super().__init__(f"qualification-readiness/{operation}/{reason}")
        self.operation = operation
        self.reason = reason


class StepClock:
    """Deterministic monotonic clock used by bounded behavioral tests."""

    def __init__(self) -> None:
        self.value = -1

    def __call__(self) -> int:
        self.value += 1
        return self.value


def admit_marker(
    document: dict[str, object], current_boot_id: str, expected: Expectation
) -> dict[str, object]:
    if set(document) != MARKER_KEYS or document.get("schema_version") != 1:
        raise ReadinessFailure("guest-state", "binding-mismatch")
    bindings = {
        "target_sha": expected.target_sha,
        "trusted_control_sha": expected.trusted_control_sha,
        "access_run_id": expected.access_run_id,
        "access_run_attempt": expected.access_run_attempt,
        "boot_id": current_boot_id,
        "ssh_public_key_sha256": expected.ssh_public_key_sha256,
        "cloud_identity_absent": True,
        "guest_startup_complete": True,
    }
    if any(document.get(key) != value for key, value in bindings.items()):
        raise ReadinessFailure("guest-state", "binding-mismatch")
    return document


def wait_for_readiness(
    probe: Callable[[], ProbeResult],
    expected: Expectation,
    *,
    deadline: float,
    interval: float,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, object]:
    last = ProbeResult.transport()
    while True:
        last = probe()
        if last.state == "ready":
            if (
                last.current_boot_id is None
                or BOOT_ID.fullmatch(last.current_boot_id) is None
                or last.document is None
            ):
                raise ReadinessFailure("guest-state", "binding-mismatch")
            return admit_marker(last.document, last.current_boot_id, expected)
        if last.state not in {"transport", "authentication", "missing"}:
            raise ReadinessFailure("guest-state", "binding-mismatch")
        if monotonic() >= deadline:
            break
        sleep(interval)
    if last.state == "transport":
        raise ReadinessFailure("ssh-transport", "not-ready-timeout")
    if last.state == "authentication":
        raise ReadinessFailure("ssh-authentication", "not-ready-timeout")
    raise ReadinessFailure("guest-state", "missing-or-stale")


def build_probe(address: str, identity: Path, known_hosts: Path) -> Callable[[], ProbeResult]:
    def probe() -> ProbeResult:
        try:
            with socket.create_connection((address, 22), timeout=5):
                pass
        except (OSError, TimeoutError):
            return ProbeResult.transport()
        try:
            process = subprocess.Popen(
                [
                    "ssh",
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "StrictHostKeyChecking=accept-new",
                    "-o",
                    f"UserKnownHostsFile={known_hosts}",
                    "-o",
                    "ConnectTimeout=5",
                    "-o",
                    "ConnectionAttempts=1",
                    "-i",
                    str(identity),
                    f"secpal-cloud@{address}",
                    REMOTE_READ,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
        except OSError:
            return ProbeResult.authentication()
        assert process.stdout is not None
        output = bytearray()
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        expires = time.monotonic() + 15
        try:
            while True:
                remaining = expires - time.monotonic()
                if remaining <= 0:
                    process.kill()
                    process.wait()
                    return ProbeResult.authentication()
                events = selector.select(remaining)
                if not events:
                    process.kill()
                    process.wait()
                    return ProbeResult.authentication()
                chunk = os.read(process.stdout.fileno(), 4096)
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > SSH_OUTPUT_MAX_BYTES:
                    process.kill()
                    process.wait()
                    raise ReadinessFailure("guest-state", "binding-mismatch")
        finally:
            selector.close()
            process.stdout.close()
        return_code = process.wait()
        if return_code != 0:
            return ProbeResult.authentication()
        try:
            boot_raw, marker_raw = bytes(output).split(b"\n", 1)
            boot_id = boot_raw.decode("ascii")
        except (ValueError, UnicodeDecodeError):
            raise ReadinessFailure("guest-state", "binding-mismatch") from None
        if BOOT_ID.fullmatch(boot_id) is None:
            raise ReadinessFailure("guest-state", "binding-mismatch")
        if marker_raw.strip() == b"absent":
            return ProbeResult.missing(boot_id)
        try:
            document = json.loads(marker_raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ReadinessFailure("guest-state", "binding-mismatch") from None
        if not isinstance(document, dict):
            raise ReadinessFailure("guest-state", "binding-mismatch")
        return ProbeResult.ready(boot_id, document)

    return probe


def write_failure(
    path: Path,
    failure: ReadinessFailure,
    expected: Expectation,
    *,
    probe_count: int,
    elapsed_seconds: int,
) -> None:
    document = {
        "schema_version": 1,
        "phase": "qualification-readiness",
        "operation": failure.operation,
        "reason": failure.reason,
        "target_sha": expected.target_sha,
        "trusted_control_sha": expected.trusted_control_sha,
        "run_id": expected.access_run_id,
        "run_attempt": expected.access_run_attempt,
        "probe_count": probe_count,
        "elapsed_seconds": elapsed_seconds,
    }
    encoded = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(encoded) > 2048:
        raise ReadinessFailure("guest-state", "binding-mismatch")
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(encoded)
    temporary.chmod(0o600)
    os.replace(temporary, path)


def parse_options() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ipv4", required=True)
    parser.add_argument("--identity", required=True, type=Path)
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--known-hosts", required=True, type=Path)
    parser.add_argument("--target-sha", required=True)
    parser.add_argument("--control-sha", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--diagnostic-output", required=True, type=Path)
    parser.add_argument("--timeout-seconds", type=int, default=450)
    parser.add_argument("--interval-seconds", type=int, default=5)
    return parser.parse_args()


def main() -> int:
    options = parse_options()
    started = time.monotonic()
    probe_count = 0
    try:
        address = ipaddress.ip_address(options.ipv4)
        if address.version != 4 or not address.is_global:
            raise ValueError("public IPv4 required")
        if SHA.fullmatch(options.target_sha) is None or SHA.fullmatch(options.control_sha) is None:
            raise ValueError("full lowercase SHAs required")
        if NUMBER.fullmatch(options.run_id) is None or ATTEMPT.fullmatch(options.run_attempt) is None:
            raise ValueError("bounded run identity required")
        if not 30 <= options.timeout_seconds <= 900 or not 5 <= options.interval_seconds <= 10:
            raise ValueError("readiness budget is outside the reviewed bound")
        public_key = options.public_key.read_text(encoding="ascii").strip()
        if len(public_key) > 128 or KEY.fullmatch(public_key) is None:
            raise ValueError("public key is outside the reviewed format")
        if not options.identity.is_file():
            raise ValueError("private identity is absent")
        key_digest = hashlib.sha256(f"{public_key}\n".encode("ascii")).hexdigest()
        expected = Expectation(
            options.target_sha,
            options.control_sha,
            options.run_id,
            options.run_attempt,
            key_digest,
        )
        actual_probe = build_probe(str(address), options.identity, options.known_hosts)

        def counted_probe() -> ProbeResult:
            nonlocal probe_count
            probe_count += 1
            return actual_probe()

        wait_for_readiness(
            counted_probe,
            expected,
            deadline=started + options.timeout_seconds,
            interval=options.interval_seconds,
        )
    except ReadinessFailure as failure:
        write_failure(
            options.diagnostic_output,
            failure,
            expected,
            probe_count=probe_count,
            elapsed_seconds=min(900, max(0, int(time.monotonic() - started))),
        )
        print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    except (OSError, UnicodeError, ValueError) as error:
        print(f"ERROR: invalid readiness input: {error}", file=sys.stderr)
        return 64
    print(f"Rocky qualification readiness accepted after {probe_count} bounded probes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
