#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Pure #105 selection; #104 exclusively defines effective firewall authority."""
from decimal import Decimal, ROUND_FLOOR
import ipaddress
import math
import re
import time

import host_firewall_contract as firewall

SCENARIOS = {"crowdsecurity/ssh-bf", "secpal/haproxy-auth-v1"}
FIELDS = {"duration", "id", "origin", "scenario", "scope", "type", "value"}
OPTIONAL = {"uuid", "until", "simulated"}


def validate_allowlist(values):
    if type(values) is not list or len(values) > 64:
        raise ValueError("admit-security-allowlist")
    normalized = []
    for value in values:
        try:
            network = ipaddress.ip_network(value, strict=True)
        except (ValueError, TypeError):
            raise ValueError("admit-security-allowlist") from None
        if not network.prefixlen or str(network) != value:
            raise ValueError("admit-security-allowlist")
        normalized.append(network)
    if values != sorted(set(str(value) for value in normalized)):
        raise ValueError("admit-security-allowlist")
    return normalized


def _seconds(value):
    # The pinned LAPI v1 returns Go durations. Our profiles never issue >1h;
    # subsecond remnants expire without another kernel mutation.
    if type(value) is not str or not 1 <= len(value) <= 32:
        raise ValueError("admit-decision-duration")
    small = re.fullmatch(r"(\d+(?:\.\d{1,9})?)(ms|us|µs|ns)", value)
    if small:
        divisor = {"ms": 1000, "us": 1000000, "µs": 1000000, "ns": 1000000000}[small[2]]
        result = Decimal(small[1]) / divisor
        if result > firewall.MAX_TTL:
            raise ValueError("admit-decision-duration")
        return result
    match = re.fullmatch(r"(?:(\d+)h)?(?:(\d+)m)?(?:(\d+(?:\.\d{1,9})?)s)?", value)
    if match is None or not any(match.groups()):
        raise ValueError("admit-decision-duration")
    hours, minutes, seconds = (Decimal(part or "0") for part in match.groups())
    result = hours * 3600 + minutes * 60 + seconds
    if not 0 <= result <= firewall.MAX_TTL:
        raise ValueError("admit-decision-duration")
    return result


def select_decisions(document, config, source, *, direct_single, allowlist, elapsed=0):
    firewall.policy(config, source)  # Consume the existing invariant owner.
    networks = validate_allowlist(allowlist)
    if type(direct_single) is not bool or not math.isfinite(elapsed) or elapsed < 0:
        raise ValueError("admit-decision-observation")
    if document is None:
        document = []  # The native empty query response is nullable.
    if type(document) is not list or len(document) > firewall.MAX_DECISIONS:
        raise ValueError("admit-decision-capacity")
    identifiers, result = set(), {}
    for row in document:
        if (type(row) is not dict or not FIELDS <= row.keys()
                or row.keys() - FIELDS - OPTIONAL
                or type(row["id"]) is not int or not 0 < row["id"] < 2**63
                or row["id"] in identifiers or row["origin"] != "crowdsec"
                or type(row["scenario"]) is not str or row["scenario"] not in SCENARIOS
                or row["scope"] not in ("Ip", "ip") or row["type"] != "ban"
                or row.get("simulated", False) is not False):
            raise ValueError("admit-local-decision")
        identifiers.add(row["id"])
        remaining = _seconds(row["duration"]) - Decimal(str(elapsed))
        ttl = int(remaining.to_integral_value(rounding=ROUND_FLOOR))
        # Validate even expired/HTTP-only values; malformed input cannot hide
        # behind a non-operative decision.
        address = row["value"]
        if type(address) is not str or "%" in address:
            raise ValueError("admit-decision-address")
        try:
            firewall.remediation(config, source, address, ttl=max(1, ttl))
        except ValueError as error:
            if error.args != ("admit-remediation-protected-peer",):
                raise
            continue
        peer = ipaddress.ip_address(address)
        if ttl < 1 or any(peer in network for network in networks):
            continue
        if row["scenario"] == "secpal/haproxy-auth-v1" and (
                config["edge_mode"] != "DIRECT" or not direct_single):
            # A canonical Viewer behind an LB/CDN is not the kernel peer.
            # Retain the native LAPI decision for #106's L7 consumer, never ban
            # the proxy or pretend an L3 client ban would enforce L7.
            continue
        result[address] = max(result.get(address, 0), ttl)
    return result


def reconcile(desired, current, add, remove, *, clock=time.monotonic, started_at=None):
    """Stateless projection into #104's #105-only remediation sets.

    No shadow decision database. A partial failure is reported; the next call
    starts with fresh authoritative LAPI/kernel observations.
    """
    started = clock() if started_at is None else started_at
    for address in sorted(current.keys() - desired.keys()):
        remove(address)
    for address in sorted(desired, key=lambda address: (address in current, address)):
        ttl = math.floor(desired[address] - max(0, clock() - started))
        deadline = started + desired[address]
        # Existing entries are upper-bounded native expiry observations.
        # Keep an already shorter ban; never continually reset its TTL.
        if ttl > 0 and (address not in current or current[address] > deadline):
            add(address, ttl)
