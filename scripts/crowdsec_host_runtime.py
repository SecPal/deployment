#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Bounded #105 native observations; no socket listener or firewall rule owner."""
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import re
import socket
import stat
import struct
import time

import crowdsec_host_contract as contract

ROOT = Path("/usr/share/secpal/crowdsec")
LAPI = Path("/run/secpal-crowdsec/lapi.sock")
MAX_RESPONSE = 2 * 1024 * 1024


class SecurityError(ValueError):
    """Closed non-secret failure identity."""


def _digest(path):
    if not stat.S_ISREG(path.lstat().st_mode):
        raise SecurityError("observe-crowdsec-regular-payload")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_inputs(configuration_root=ROOT, package_root=Path("/"), *, payload=True):
    """Hash exact required signed-package bytes, not sandbox-masked RPM paths.

    Signature/NEVRA admission belongs to authenticated installation; these hashes
    are the reviewed exact-payload pins from that qualification. This does not
    claim a current host RPM transaction or extend the Rocky base signer.
    """
    policy = json.loads((configuration_root / "supply.json").read_text())
    arch = platform.machine()
    if arch not in policy["packages"]:
        raise SecurityError("admit-crowdsec-architecture")
    package_patterns = package_root / "etc/crowdsec/patterns"
    if (configuration_root / "patterns").resolve(strict=True) != package_patterns.resolve(strict=True):
        raise SecurityError("admit-pinned-grok-patterns")
    expected_patterns = {path for path in policy["packages"][arch]["files"]
                         if path.startswith("etc/crowdsec/patterns/")}
    observed_patterns = {"etc/crowdsec/patterns/" + path.name
                         for path in package_patterns.iterdir()}
    if expected_patterns != observed_patterns:
        raise SecurityError("admit-crowdsec-pattern-files")
    files = policy["packages"][arch]["files"] if payload else {}
    for relative, expected in files.items():
        if not (relative in ("usr/bin/crowdsec", "usr/bin/cscli") or
                re.fullmatch(r"etc/crowdsec/patterns/[A-Za-z0-9_-]+", relative)):
            raise SecurityError("admit-crowdsec-payload-path")
        if _digest(package_root / relative) != expected:
            raise SecurityError("admit-crowdsec-payload")
    expected = policy["configuration_files"]
    actual = {str(path.relative_to(configuration_root))
              for path in configuration_root.rglob("*")
              if path.suffix in (".yaml", ".json") and path.name != "supply.json"}
    if actual != set(expected):
        raise SecurityError("admit-crowdsec-configuration-files")
    for relative, digest in expected.items():
        if _digest(configuration_root / relative) != digest:
            raise SecurityError("admit-crowdsec-configuration")
    return {"architecture": arch, "version": policy["version"]}


class _UnixConnection(http.client.HTTPConnection):
    def __init__(self, path, uid):
        super().__init__("localhost", timeout=3)
        self.path, self.uid = path, uid

    def connect(self):
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(self.timeout)
        try:
            client.connect(str(self.path))
            _, uid, _ = struct.unpack("3i", client.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
            if uid != self.uid:
                raise SecurityError("admit-lapi-peer-identity")
            self.sock = client
        except BaseException:
            client.close()
            raise


class Lapi:
    def __init__(self, path, uid, key):
        if type(key) is not str or re.fullmatch(r"[A-Za-z0-9+/=_-]{32,128}", key) is None:
            raise SecurityError("admit-lapi-credential")
        self.path, self.uid, self.key = Path(path), uid, key

    def decisions(self):
        # Peer credentials are checked before sending the secret. No HTTP proxy,
        # redirect, caller URL, forwarding header or unauthenticated TCP fallback.
        started = time.monotonic()
        connection = _UnixConnection(self.path, self.uid)
        try:
            connection.request("GET", "/v1/decisions?origins=crowdsec",
                               headers={"X-Api-Key": self.key, "Accept": "application/json"})
            response = connection.getresponse()
            if response.status != 200:
                raise SecurityError("authenticate-lapi-read-only-client")
            raw = response.read(MAX_RESPONSE + 1)
            if len(raw) > MAX_RESPONSE:
                raise SecurityError("admit-lapi-response-bound")
            document = contract.firewall.prefixes._decode_json(raw)
            return document, time.monotonic() - started
        except SecurityError:
            raise
        except (OSError, http.client.HTTPException, ValueError, contract.firewall.prefixes.ContractError):
            raise SecurityError("observe-local-crowdsec-decisions") from None
        finally:
            connection.close()


def admit_projection(desired, authority, *, started_at):
    """Read-only comparison shared by health and post-mutation admission."""
    observed = {entry["elem"]["val"] for name in ("remediation4", "remediation6")
                for entry in authority.native.decisions(name)}
    expected = {address for address, ttl in desired.items()
                if started_at + ttl > time.monotonic()}
    if not expected <= observed or observed - desired.keys():
        raise SecurityError("admit-current-crowdsec-projection")


def synchronize(client, authority, accepted, *, direct_single, allowlist):
    """The injected authority is the actual #104 Controller, not an adapter."""
    authority.check()
    started = time.monotonic()
    document, _ = client.decisions()
    config = accepted["configuration"]
    source = accepted["prefixes"] if config["edge_mode"] == "PROTECTED" else None
    desired = contract.select_decisions(document, config, source,
        direct_single=direct_single, allowlist=allowlist)
    current = {}
    for name in ("remediation4", "remediation6"):
        entries = authority.native.decisions(name)
        observed = time.monotonic()
        # nft's whole-second expiry may truncate a fraction. Completion time
        # plus one second is a conservative upper bound, never a stale grant.
        current.update({entry["elem"]["val"]: observed + entry["elem"]["expires"] + 1
                        for entry in entries})
    contract.reconcile(desired, current,
        lambda address, ttl: authority.remediate(address, ttl=ttl),
        lambda address: authority.remediate(address, remove=True), started_at=started)
    authority.check()
    admit_projection(desired, authority, started_at=started)
    return {"security": "DECISIONS_SYNCHRONIZED", "desired_count": len(desired)}
