#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Pure #104 ingress owner; existing specialized tables retain their authority."""
from copy import deepcopy
import importlib.util
import ipaddress
import json
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "_secpal_firewall_prefix_owner", Path(__file__).with_name("cloudfront-origin-prefix-lkg.py"))
prefixes = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(prefixes)

TABLE = "secpal_host"
MAX_DECISIONS = 4096
MAX_TTL = 3600


def configuration(value):
    if (type(value) is not dict or value.keys() !=
            {"edge_mode", "management_ipv4", "management_ipv6"}
            or value["edge_mode"] not in ("DIRECT", "PROTECTED")):
        raise ValueError("admit-host-firewall-configuration")
    for key, family in (("management_ipv4", 4), ("management_ipv6", 6)):
        entries = value[key]
        if type(entries) is not list or len(entries) > 64:
            raise ValueError("admit-management-prefixes")
        try:
            normalized = [prefixes._parse_network(entry, family) for entry in entries]
        except prefixes.ContractError:
            raise ValueError("admit-management-prefixes") from None
        if entries != sorted(set(normalized)):
            raise ValueError("admit-management-prefixes")
    if not value["management_ipv4"] and not value["management_ipv6"]:
        raise ValueError("admit-management-required")
    return deepcopy(value)


def _scope(config, source):
    config = configuration(config)
    if config["edge_mode"] == "PROTECTED":
        try:
            prefixes.validate_candidate(source)
        except prefixes.ContractError:
            raise ValueError("admit-origin-prefix-authority") from None
    elif source is not None:
        raise ValueError("admit-direct-without-cloudfront-authority")
    return config


def _match(left, right, op="=="):
    return {"match": {"op": op, "left": left, "right": right}}


def _address(family, field):
    return {"payload": {"protocol": family, "field": field}}


def _network(value):
    network = ipaddress.ip_network(value)
    if network.prefixlen == network.max_prefixlen:
        return str(network.network_address)
    return {"prefix": {"addr": str(network.network_address), "len": network.prefixlen}}


def policy(config, source=None):
    """Native nft JSON is the single rule definition and read-back projection."""
    config = _scope(config, source)
    table = {"family": "inet", "table": TABLE}
    objects = [{"table": {"family": "inet", "name": TABLE}}]
    for name, hook in (("ingress", "input"), ("transit", "forward")):
        objects.append({"chain": dict(**table, name=name, type="filter", hook=hook,
                                      prio=0, policy="drop")})
    for name, kind in (("remediation4", "ipv4_addr"), ("remediation6", "ipv6_addr")):
        objects.append({"set": dict(**table, name=name, type=kind, flags=["timeout"],
                                    timeout=MAX_TTL, size=MAX_DECISIONS)})

    def rule(*expressions):
        objects.append({"rule": dict(**table, chain="ingress", expr=list(expressions))})
    def allow(*expressions):
        rule(*expressions, {"accept": None})
    port = lambda value: _match(_address("tcp", "dport"), value)
    rule(_match({"ct": {"key": "state"}}, "invalid"), {"drop": None})
    allow(_match({"meta": {"key": "iifname"}}, "lo"))
    for family, loopback in (("ip", "127.0.0.0/8"), ("ip6", "::1/128")):
        rule(_match(_address(family, "saddr"), _network(loopback)), {"drop": None})
    # Explicit management is checked before remediation, preserving its exact
    # authorization even for established inbound SSH. No arbitrary management port.
    for family, key in (("ip", "management_ipv4"), ("ip6", "management_ipv6")):
        for network in config[key]:
            allow(_match(_address(family, "saddr"), _network(network)), port(22))
    for family, name in (("ip", "remediation4"), ("ip6", "remediation6")):
        rule(_match(_address(family, "saddr"), "@" + name), {"drop": None})
    # Only replies to host-initiated traffic bypass ingress listener admission.
    # An old DIRECT inbound connection never survives PROTECTED via ct established.
    allow(_match({"ct": {"key": "direction"}}, "reply"),
          _match({"ct": {"key": "state"}}, {"set": ["established", "related"]}))
    # Essential error/PMTU and IPv6 neighbor discovery, not arbitrary TCP/UDP.
    allow(_match(_address("icmp", "type"),
                 {"set": ["destination-unreachable", "time-exceeded", "parameter-problem"]}))
    allow(_match(_address("icmpv6", "type"),
                 {"set": ["destination-unreachable", "packet-too-big", "time-exceeded", "parameter-problem"]}))
    allow(_match(_address("ip6", "hoplimit"), 255),
          _match(_address("icmpv6", "type"), {"set": ["nd-neighbor-solicit", "nd-neighbor-advert"]}))
    # RA only from link-local peers with the required on-link hop limit.
    allow(_match(_address("ip6", "saddr"), _network("fe80::/10")),
          _match(_address("ip6", "hoplimit"), 255),
          _match(_address("icmpv6", "type"), "nd-router-advert"))
    if config["edge_mode"] == "DIRECT":
        # #220 owns these public HAProxy ports; #103 owns HTTP routing to its
        # loopback-only ACME responder. No external 18084 exception is added.
        allow(port({"set": [80, 443]}))
    else:
        for family, key in (("ip", "ipv4_prefixes"), ("ip6", "ipv6_prefixes")):
            for network in source[key]:
                allow(_match(_address(family, "saddr"), _network(network)), port(443))
    return objects


def batch(config, source=None, *, initial=False):
    objects = policy(config, source)
    commands = []
    if initial:
        commands.extend({"create": item} for item in objects if "rule" not in item)
    else:
        for name in ("ingress", "transit"):
            commands.append({"flush": {"chain": {"family": "inet", "table": TABLE, "name": name}}})
    commands.extend({"add": item} for item in objects if "rule" in item)
    return {"nftables": commands}


def normalize_table(document):
    if (type(document) is not dict or document.keys() != {"nftables"}
            or type(document["nftables"]) is not list):
        raise ValueError("admit-firewall-observation")
    objects = []
    for item in document["nftables"]:
        if type(item) is not dict or len(item) != 1:
            raise ValueError("admit-firewall-observation")
        kind, value = next(iter(item.items()))
        if kind == "metainfo":
            if type(value) is not dict or value.get("json_schema_version") != 1:
                raise ValueError("admit-nft-json-schema")
            continue
        if kind not in {"table", "set", "chain", "rule"} or type(value) is not dict:
            raise ValueError("admit-firewall-authority")
        # --terse intentionally omits set elements. Nothing semantic is stripped.
        objects.append({kind: {key: entry for key, entry in value.items() if key != "handle"}})
    return objects


def admit_table(document, config, source=None):
    if normalize_table(document) != policy(config, source):
        raise ValueError("admit-effective-host-firewall")


def remediation(config, source, address, *, ttl):
    config = _scope(config, source)
    try:
        peer = ipaddress.ip_address(address)
    except ValueError:
        raise ValueError("admit-remediation-address") from None
    if str(peer) != address or peer.is_loopback or peer.is_multicast or peer.is_unspecified:
        raise ValueError("admit-remediation-address")
    if type(ttl) is not int or not 1 <= ttl <= MAX_TTL:
        raise ValueError("admit-remediation-lifetime")
    protected = config["management_ipv" + str(peer.version)]
    if source is not None:
        protected = protected + source["ipv" + str(peer.version) + "_prefixes"]
    if any(peer in ipaddress.ip_network(network) for network in protected):
        raise ValueError("admit-remediation-protected-peer")
    return "remediation" + str(peer.version), str(peer)
