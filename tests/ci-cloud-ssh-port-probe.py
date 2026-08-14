#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Tests for the closed SSH TCP reachability observation."""

from __future__ import annotations

import errno
import importlib.util
import socket
import subprocess
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "scripts" / "ci-cloud" / "probe-ssh-port.py"


def load_probe():
    spec = importlib.util.spec_from_file_location("ci_cloud_ssh_port_probe", PROBE)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load SSH port probe")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeSocket:
    def __init__(self, result: int | BaseException) -> None:
        self.result = result
        self.timeout: float | None = None
        self.address: tuple[str, int] | None = None

    def __enter__(self):
        return self

    def __exit__(self, *_arguments) -> None:
        return None

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def connect_ex(self, address: tuple[str, int]) -> int:
        self.address = address
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result


class SSHPortProbeTests(unittest.TestCase):
    def test_maps_connect_results_to_closed_observations(self) -> None:
        probe = load_probe()
        for result, expected in (
            (0, "reachable"),
            (errno.ECONNREFUSED, "connection_refused"),
            (errno.EAGAIN, "connection_timeout"),
            (errno.ETIMEDOUT, "connection_timeout"),
            (errno.ENETUNREACH, "other"),
        ):
            with self.subTest(result=result):
                self.assertEqual(expected, probe.classify_connect_result(result))

    def test_probe_uses_bounded_ipv4_tcp_connection(self) -> None:
        probe = load_probe()
        fake_socket = FakeSocket(0)
        with mock.patch.object(probe.socket, "socket", return_value=fake_socket):
            self.assertEqual("reachable", probe.probe("192.0.2.1"))
        self.assertEqual(probe.PROBE_TIMEOUT_SECONDS, fake_socket.timeout)
        self.assertEqual(("192.0.2.1", 22), fake_socket.address)

    def test_socket_timeout_is_closed_observation(self) -> None:
        probe = load_probe()
        fake_socket = FakeSocket(socket.timeout())
        with mock.patch.object(probe.socket, "socket", return_value=fake_socket):
            self.assertEqual("connection_timeout", probe.probe("192.0.2.1"))

    def test_cli_rejects_non_public_address_without_echoing_it(self) -> None:
        completed = subprocess.run(
            ["python3", str(PROBE), "127.0.0.1"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(0, completed.returncode)
        self.assertEqual("", completed.stdout)
        self.assertNotIn("127.0.0.1", completed.stderr)


if __name__ == "__main__":
    unittest.main()
