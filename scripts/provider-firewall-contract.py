#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Pure, provider-neutral admission and planning for PROTECTED Origin firewalls.

This seam does not select a provider, load credentials, observe a provider, or
mutate one.  A concrete adapter owns those effects and passes its bounded
observations through the functions below.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import re
import sys
from typing import Any


def _load_capability():
    path = Path(__file__).with_name("provider-capability-contract.py")
    specification = importlib.util.spec_from_file_location("provider_firewall_capability", path)
    if specification is None or specification.loader is None:
        raise RuntimeError("provider capability contract is unavailable")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


capability = _load_capability()
SHA256 = re.compile(r"^[0-9a-f]{64}$")
DIAGNOSTIC = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
SERVICE = "CLOUDFRONT_ORIGIN_FACING"
SOURCE_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"


class ContractError(ValueError):
    """The firewall request, observation, or result is unsafe to use."""


class EdgeMode(str, Enum):
    DIRECT = "direct"
    PROTECTED = "protected"


class PlanAction(str, Enum):
    NO_MUTATION = "no-mutation"
    REPLACE_OWNED = "replace-owned"


class ApplyOutcome(str, Enum):
    APPLY_ACCEPTED = "apply-accepted"
    FAILED = "failed"


class RollbackAction(str, Enum):
    RESTORE_PRIOR = "restore-prior"


def _identity(label: str, value: object) -> None:
    if type(value) is not str or not value or value != value.strip() or not value.isprintable():
        raise ContractError(f"{label} is invalid")


def _canonical(document: dict[str, Any]) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()


def prefix_digest(document: dict[str, Any]) -> str:
    """Return the #214 candidate identity for one already-admitted document."""
    material = dict(document)
    material.pop("candidate_sha256", None)
    return hashlib.sha256(_canonical(material)).hexdigest()


def _prefixes(values: object, version: int) -> tuple[str, ...]:
    if type(values) is not list or not values:
        raise ContractError("accepted LKG has an empty prefix family")
    normalized: list[str] = []
    for value in values:
        if type(value) is not str or not value or value.strip() != value:
            raise ContractError("accepted LKG CIDR is invalid")
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as error:
            raise ContractError("accepted LKG CIDR is malformed") from error
        if network.version != version or str(network) != value or network.prefixlen == 0:
            raise ContractError("accepted LKG CIDR is wrong-family, non-canonical, or default")
        normalized.append(value)
    if len(set(normalized)) != len(normalized):
        raise ContractError("accepted LKG CIDRs are ambiguous")
    return tuple(sorted(normalized, key=lambda value: (ipaddress.ip_network(value).network_address.packed, ipaddress.ip_network(value).prefixlen)))


def _accepted_prefixes(document: object, identity: object) -> tuple[tuple[str, ...], tuple[str, ...]]:
    expected = {
        "schema_version", "source_url", "source_sync_token", "source_create_date",
        "retrieved_at", "service", "ipv4_prefixes", "ipv6_prefixes", "candidate_sha256",
    }
    if type(document) is not dict or set(document) != expected:
        raise ContractError("accepted LKG has an invalid #214 representation")
    if document["schema_version"] != 1 or document["source_url"] != SOURCE_URL or document["service"] != SERVICE:
        raise ContractError("accepted LKG is not CloudFront Origin-facing evidence")
    if type(identity) is not str or SHA256.fullmatch(identity) is None:
        raise ContractError("accepted LKG identity is invalid")
    if document["candidate_sha256"] != prefix_digest(document) or identity != document["candidate_sha256"]:
        raise ContractError("accepted LKG identity is stale or substituted")
    return _prefixes(document["ipv4_prefixes"], 4), _prefixes(document["ipv6_prefixes"], 6)


@dataclass(frozen=True, slots=True)
class FirewallRule:
    """One provider-normalized rule; ownership is an exact adapter identity."""

    rule_id: str
    ownership_id: str
    protocol: str
    port: int
    ipv4_sources: tuple[str, ...]
    ipv6_sources: tuple[str, ...]

    def __post_init__(self) -> None:
        _identity("rule identity", self.rule_id)
        _identity("rule ownership identity", self.ownership_id)
        if self.protocol != "tcp" or type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ContractError("provider rule protocol or port is invalid")
        for sources, family in ((self.ipv4_sources, 4), (self.ipv6_sources, 6)):
            if type(sources) is not tuple:
                raise ContractError("provider rule sources are invalid")
            normalized = _prefixes(list(sources), family) if sources else ()
            if sources != normalized:
                raise ContractError("provider rule sources are not deterministic")
        if not self.ipv4_sources and not self.ipv6_sources:
            raise ContractError("provider rule has no sources")


@dataclass(frozen=True, slots=True)
class FirewallObservation:
    """One fresh, normalized provider read-back, bounded to an exact target."""

    target: capability.ResourceTarget
    revision: str | None
    rules: tuple[FirewallRule, ...]

    def __post_init__(self) -> None:
        if type(self.target) is not capability.ResourceTarget or self.target.provider_resource_id is None:
            raise ContractError("observation lacks an exact provider firewall target")
        if self.revision is not None:
            _identity("provider observation revision", self.revision)
        if type(self.rules) is not tuple or any(type(rule) is not FirewallRule for rule in self.rules):
            raise ContractError("provider observation rules are invalid")
        if len({rule.rule_id for rule in self.rules}) != len(self.rules):
            raise ContractError("provider observation has duplicate rule identities")


@dataclass(frozen=True, slots=True)
class FirewallInput:
    """Explicit runtime inputs for one PROTECTED firewall reconciliation."""

    authority: capability.ExecutionAuthority
    target: capability.ResourceTarget
    edge_mode: EdgeMode
    accepted_lkg: dict[str, Any]
    accepted_lkg_identity: str
    origin_protocol: str
    origin_port: int
    ownership_id: str
    operator_access: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.authority) is not capability.ExecutionAuthority or type(self.target) is not capability.ResourceTarget:
            raise ContractError("#169 authority and exact target are required")
        if self.authority.target != self.target or self.target.provider_resource_id is None:
            raise ContractError("firewall target does not match #169 authority")
        if type(self.edge_mode) is not EdgeMode or self.edge_mode is not EdgeMode.PROTECTED:
            raise ContractError("DIRECT is not a CloudFront Origin firewall operation")
        if self.origin_protocol != "tcp" or type(self.origin_port) is not int or self.origin_port != 443:
            raise ContractError("PROTECTED Origin firewall policy is TCP 443 only")
        _identity("owned policy identity", self.ownership_id)
        if type(self.operator_access) is not tuple:
            raise ContractError("operator access facts are invalid")
        for rule_id in self.operator_access:
            _identity("operator access rule identity", rule_id)
        if len(set(self.operator_access)) != len(self.operator_access):
            raise ContractError("operator access facts are ambiguous")


@dataclass(frozen=True, slots=True)
class AdmittedFirewallInput:
    request: FirewallInput
    desired: FirewallRule


@dataclass(frozen=True, slots=True)
class FirewallPlan:
    action: PlanAction
    target: capability.ResourceTarget
    expected_revision: str | None
    desired: FirewallRule
    prior: FirewallObservation
    unrelated_rules: tuple[FirewallRule, ...]
    operator_access: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ApplyResult:
    plan: FirewallPlan
    outcome: ApplyOutcome
    diagnostic_code: str | None = None

    def __post_init__(self) -> None:
        if type(self.plan) is not FirewallPlan or type(self.outcome) is not ApplyOutcome:
            raise ContractError("apply result is outside the closed contract")
        failure = self.outcome is ApplyOutcome.FAILED
        if failure != (self.diagnostic_code is not None):
            raise ContractError("apply result diagnostic contradicts outcome")
        if self.diagnostic_code is not None and (type(self.diagnostic_code) is not str or DIAGNOSTIC.fullmatch(self.diagnostic_code) is None):
            raise ContractError("apply diagnostic is invalid")


@dataclass(frozen=True, slots=True)
class RollbackPlan:
    action: RollbackAction
    target: capability.ResourceTarget
    expected_revision: str | None
    prior: FirewallObservation


def admit_input(request: FirewallInput) -> AdmittedFirewallInput:
    """Admit only an accepted #214 dual-stack input for an exact #169 target."""
    if type(request) is not FirewallInput:
        raise ContractError("firewall input is required")
    ipv4, ipv6 = _accepted_prefixes(request.accepted_lkg, request.accepted_lkg_identity)
    return AdmittedFirewallInput(
        request=request,
        desired=FirewallRule(
            rule_id="owned-origin-ingress",
            ownership_id=request.ownership_id,
            protocol=request.origin_protocol,
            port=request.origin_port,
            ipv4_sources=ipv4,
            ipv6_sources=ipv6,
        ),
    )


def plan(admitted: AdmittedFirewallInput, current: FirewallObservation) -> FirewallPlan:
    """Compare current state without granting deletion authority over unrelated rules."""
    if type(admitted) is not AdmittedFirewallInput or type(current) is not FirewallObservation:
        raise ContractError("admitted input and current observation are required")
    request = admitted.request
    if current.target != request.target:
        raise ContractError("provider observation target mismatch")
    if (
        request.target.expected_version is not None
        and current.revision != request.target.expected_version
    ):
        raise ContractError("provider observation target or concurrency authority is stale")
    owned = tuple(rule for rule in current.rules if rule.ownership_id == request.ownership_id)
    if len(owned) > 1:
        raise ContractError("owned provider policy is ambiguous")
    unrelated = tuple(rule for rule in current.rules if rule.ownership_id != request.ownership_id)
    present = {rule.rule_id for rule in current.rules}
    if not set(request.operator_access) <= present:
        raise ContractError("required operator access is absent from the current policy")
    action = PlanAction.NO_MUTATION if owned == (admitted.desired,) else PlanAction.REPLACE_OWNED
    return FirewallPlan(
        action,
        request.target,
        current.revision,
        admitted.desired,
        current,
        unrelated,
        request.operator_access,
    )


def admit_apply_result(result: ApplyResult) -> RollbackPlan | None:
    """Keep apply acceptance distinct from verification; failure requires exact recovery."""
    if type(result) is not ApplyResult:
        raise ContractError("apply result is required")
    if result.outcome is ApplyOutcome.FAILED:
        return rollback_plan(result.plan)
    return None


def verify(plan_to_verify: FirewallPlan, fresh: FirewallObservation) -> None:
    """Require a fresh semantic read-back before the desired policy is verified."""
    if type(plan_to_verify) is not FirewallPlan or type(fresh) is not FirewallObservation:
        raise ContractError("plan and fresh provider observation are required")
    if fresh.target != plan_to_verify.target:
        raise ContractError("verification target mismatch")
    owned = tuple(rule for rule in fresh.rules if rule.ownership_id == plan_to_verify.desired.ownership_id)
    if owned != (plan_to_verify.desired,):
        raise ContractError("verification did not observe the exact owned Origin policy")
    unrelated = tuple(rule for rule in fresh.rules if rule.ownership_id != plan_to_verify.desired.ownership_id)
    if unrelated != plan_to_verify.unrelated_rules:
        raise ContractError("verification detected unrelated provider policy drift")
    present = {rule.rule_id for rule in fresh.rules}
    if not set(plan_to_verify.operator_access) <= present:
        raise ContractError("verification lost required operator access")


def rollback_plan(plan_to_rollback: FirewallPlan) -> RollbackPlan:
    if type(plan_to_rollback) is not FirewallPlan:
        raise ContractError("rollback requires one admitted plan")
    return RollbackPlan(RollbackAction.RESTORE_PRIOR, plan_to_rollback.target, plan_to_rollback.expected_revision, plan_to_rollback.prior)


def verify_rollback(rollback: RollbackPlan, fresh: FirewallObservation) -> None:
    if type(rollback) is not RollbackPlan or type(fresh) is not FirewallObservation:
        raise ContractError("rollback and fresh provider observation are required")
    if fresh.target != rollback.target or fresh != rollback.prior:
        raise ContractError("rollback did not restore the exact prior known-safe observation")
