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




def _load_contract_module(filename: str, module_name: str):
    path = Path(__file__).with_name(filename)
    specification = importlib.util.spec_from_file_location(module_name, path)
    if specification is None or specification.loader is None:
        raise RuntimeError(f"{module_name} is unavailable")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


capability = _load_contract_module(
    "provider-capability-contract.py", "provider_firewall_capability"
)
lkg = _load_contract_module(
    "cloudfront-origin-prefix-lkg.py", "provider_firewall_accepted_lkg"
)
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ContractError(ValueError):
    """The firewall intent, provider evidence, or recovery state is unsafe."""


class EdgeMode(str, Enum):
    DIRECT = "direct"
    PROTECTED = "protected"


class PlanAction(str, Enum):
    NO_MUTATION = "no-mutation"
    REPLACE_OWNED = "replace-owned"


class ObservationPhase(str, Enum):
    CURRENT = "current"
    POST_MUTATION = "post-mutation"
    POST_ROLLBACK = "post-rollback"


class OwnershipScope(str, Enum):
    PROTECTED_ORIGIN = "secpal-protected-origin-v1"


class ProjectionCompleteness(str, Enum):
    COMPLETE = "complete-ownership-scoped-provider-read"


class MutationDisposition(str, Enum):
    REINSPECTION_REQUIRED = "reinspection-required"


class RecoveryDecision(str, Enum):
    DESIRED_VERIFIED = "desired-verified"
    PRIOR_VERIFIED = "prior-verified"


def _identity(label: str, value: object) -> None:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or not value.isprintable()
        or len(value.encode("utf-8")) > capability.MAX_IDENTITY_BYTES
    ):
        raise ContractError(f"{label} is invalid")


def _sha256(label: str, value: object) -> None:
    if type(value) is not str or SHA256.fullmatch(value) is None:
        raise ContractError(f"{label} is invalid")


def _supported_operations(value: object) -> None:
    if type(value) is not frozenset or not value or any(
        type(operation) is not capability.Operation for operation in value
    ):
        raise ContractError("adapter supported operations are invalid")


def _canonical_digest(document: dict[str, Any]) -> str:
    encoded = (
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _target_document(target: capability.ResourceTarget) -> dict[str, Any]:
    if type(target) is not capability.ResourceTarget:
        raise ContractError("one exact #169 target is required")
    return {
        "provider": target.provider,
        "scope": target.scope,
        "requested_key": target.requested_key,
        "provider_resource_id": target.provider_resource_id,
        "expected_version": target.expected_version,
    }


def _request_document(
    request: capability.CapabilityRequest,
) -> dict[str, Any]:
    if type(request) is not capability.CapabilityRequest:
        raise ContractError("one exact #169 predecessor request is required")
    return {
        "request_id": request.request_id,
        "adapter_id": request.adapter_id,
        "source_revision": request.source_revision,
        "operation": request.operation.value,
        "target": _target_document(request.target),
        "parameters_sha256": request.parameters_sha256,
    }


def _same_resource(
    left: capability.ResourceTarget, right: capability.ResourceTarget
) -> bool:
    return (
        left.provider,
        left.scope,
        left.requested_key,
        left.provider_resource_id,
    ) == (
        right.provider,
        right.scope,
        right.requested_key,
        right.provider_resource_id,
    )


def _prefixes(values: object, version: int, *, required: bool) -> tuple[str, ...]:
    if type(values) is not tuple or (required and not values):
        raise ContractError("firewall prefix family is invalid")
    normalized: list[str] = []
    for value in values:
        if type(value) is not str or value.strip() != value:
            raise ContractError("firewall CIDR is invalid")
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as error:
            raise ContractError("firewall CIDR is malformed") from error
        if (
            network.version != version
            or str(network) != value
            or network.prefixlen == 0
        ):
            raise ContractError(
                "firewall CIDR is wrong-family, non-canonical, or default"
            )
        normalized.append(value)
    ordered = tuple(
        sorted(
            set(normalized),
            key=lambda value: (
                ipaddress.ip_network(value).network_address.packed,
                ipaddress.ip_network(value).prefixlen,
            ),
        )
    )
    if ordered != values:
        raise ContractError("firewall CIDRs are duplicate or non-deterministic")
    return ordered


@dataclass(frozen=True, slots=True)
class FirewallIntent:
    """Caller intent contains policy semantics, never provider ownership."""

    edge_mode: EdgeMode
    origin_protocol: str
    origin_port: int

    def __post_init__(self) -> None:
        if type(self.edge_mode) is not EdgeMode or self.edge_mode is not EdgeMode.PROTECTED:
            raise ContractError("DIRECT is not a CloudFront Origin firewall operation")
        if (
            type(self.origin_protocol) is not str
            or self.origin_protocol != "tcp"
            or type(self.origin_port) is not int
            or self.origin_port != 443
        ):
            raise ContractError("PROTECTED Origin policy is TCP 443 only")


@dataclass(frozen=True, slots=True)
class FirewallPolicy:
    """Semantic #215-owned ingress, independent of provider rule identity."""

    protocol: str
    port: int
    ipv4_sources: tuple[str, ...]
    ipv6_sources: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            type(self.protocol) is not str
            or self.protocol != "tcp"
            or type(self.port) is not int
            or not 1 <= self.port <= 65535
        ):
            raise ContractError("owned firewall policy protocol or port is invalid")
        _prefixes(self.ipv4_sources, 4, required=False)
        _prefixes(self.ipv6_sources, 6, required=False)
        if not self.ipv4_sources and not self.ipv6_sources:
            raise ContractError("owned firewall policy has no sources")


@dataclass(frozen=True, slots=True)
class OwnedFirewallPolicy:
    """Adapter-authenticated provider identity plus normalized owned semantics."""

    provider_rule_id: str
    policy: FirewallPolicy

    def __post_init__(self) -> None:
        _identity("provider-native rule identity", self.provider_rule_id)
        if type(self.policy) is not FirewallPolicy:
            raise ContractError("owned firewall policy is invalid")


@dataclass(frozen=True, slots=True)
class FirewallObservation:
    """One complete ownership-scoped provider read tied to #169 INSPECT."""

    phase: ObservationPhase
    request: capability.CapabilityRequest
    result: capability.CapabilityResult
    supported_operations: frozenset[capability.Operation]
    ownership_scope: OwnershipScope
    owned: tuple[OwnedFirewallPolicy, ...]
    operator_access: tuple[str, ...]
    preserved_state_sha256: str
    completeness: ProjectionCompleteness

    def __post_init__(self) -> None:
        if (
            type(self.phase) is not ObservationPhase
            or type(self.request) is not capability.CapabilityRequest
            or type(self.result) is not capability.CapabilityResult
            or type(self.ownership_scope) is not OwnershipScope
            or self.ownership_scope is not OwnershipScope.PROTECTED_ORIGIN
        ):
            raise ContractError("provider observation identity is invalid")
        _supported_operations(self.supported_operations)
        if (
            type(self.owned) is not tuple
            or len(self.owned) > 1
            or any(type(item) is not OwnedFirewallPolicy for item in self.owned)
        ):
            raise ContractError("adapter ownership classification is ambiguous")
        if type(self.operator_access) is not tuple:
            raise ContractError("operator-access observation is invalid")
        for rule_id in self.operator_access:
            _identity("operator-access rule identity", rule_id)
        if len(set(self.operator_access)) != len(self.operator_access):
            raise ContractError("operator-access observation is ambiguous")
        owned_ids = {item.provider_rule_id for item in self.owned}
        if owned_ids & set(self.operator_access):
            raise ContractError(
                "one provider rule cannot be both #215-owned and operator access"
            )
        _sha256("complete preserved provider-state identity", self.preserved_state_sha256)
        if (
            type(self.completeness) is not ProjectionCompleteness
            or self.completeness is not ProjectionCompleteness.COMPLETE
        ):
            raise ContractError("provider observation is not complete")

    @property
    def revision(self) -> str | None:
        return self.result.provider_resource_version


@dataclass(frozen=True, slots=True)
class FirewallPlan:
    """Data-only plan; mutation authority is independently admitted through #169."""

    action: PlanAction
    target: capability.ResourceTarget
    adapter_id: str
    source_revision: str
    supported_operations: frozenset[capability.Operation]
    accepted_lkg_identity: str
    desired: FirewallPolicy
    prior_owned: OwnedFirewallPolicy | None
    preserved_state_sha256: str
    operator_access: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.action) is not PlanAction:
            raise ContractError("firewall plan action is invalid")
        if (
            type(self.target) is not capability.ResourceTarget
            or self.target.provider_resource_id is None
        ):
            raise ContractError("firewall plan target is invalid")
        _identity("plan adapter identity", self.adapter_id)
        if (
            type(self.source_revision) is not str
            or capability.SHA1.fullmatch(self.source_revision) is None
        ):
            raise ContractError("plan source revision is invalid")
        _supported_operations(self.supported_operations)
        _sha256("accepted #214 LKG identity", self.accepted_lkg_identity)
        if type(self.desired) is not FirewallPolicy:
            raise ContractError("desired firewall policy is invalid")
        if self.prior_owned is not None and type(self.prior_owned) is not OwnedFirewallPolicy:
            raise ContractError("prior owned policy is invalid")
        _sha256("preserved provider-state identity", self.preserved_state_sha256)
        if type(self.operator_access) is not tuple:
            raise ContractError("plan operator-access state is invalid")


@dataclass(frozen=True, slots=True)
class RollbackPlan:
    """Semantic prior-state restoration bound to a fresh post-failure revision."""

    target: capability.ResourceTarget
    adapter_id: str
    source_revision: str
    supported_operations: frozenset[capability.Operation]
    restore_policy: FirewallPolicy | None
    preserved_state_sha256: str
    operator_access: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            type(self.target) is not capability.ResourceTarget
            or self.target.provider_resource_id is None
            or self.target.expected_version is None
        ):
            raise ContractError("rollback lacks fresh concurrency authority")
        _identity("rollback adapter identity", self.adapter_id)
        if (
            type(self.source_revision) is not str
            or capability.SHA1.fullmatch(self.source_revision) is None
        ):
            raise ContractError("rollback source revision is invalid")
        _supported_operations(self.supported_operations)
        if self.restore_policy is not None and type(self.restore_policy) is not FirewallPolicy:
            raise ContractError("rollback policy is invalid")
        _sha256("rollback preserved-state identity", self.preserved_state_sha256)
        if type(self.operator_access) is not tuple:
            raise ContractError("rollback operator-access state is invalid")


def inspection_parameters_sha256(
    target: capability.ResourceTarget,
    phase: ObservationPhase,
    supported_operations: frozenset[capability.Operation],
    predecessor_request: capability.CapabilityRequest | None = None,
) -> str:
    if type(phase) is not ObservationPhase:
        raise ContractError("inspection phase is invalid")
    _supported_operations(supported_operations)
    if phase is ObservationPhase.CURRENT:
        if predecessor_request is not None:
            raise ContractError("current inspection has no predecessor transaction")
        predecessor = None
    else:
        predecessor = _request_document(predecessor_request)
    return _canonical_digest(
        {
            "contract": "secpal-provider-firewall-inspection-v1",
            "target": _target_document(target),
            "phase": phase.value,
            "ownership_scope": OwnershipScope.PROTECTED_ORIGIN.value,
            "projection": ProjectionCompleteness.COMPLETE.value,
            "supported_operations": sorted(
                operation.value for operation in supported_operations
            ),
            "predecessor_request": predecessor,
        }
    )


def _admit_observation(
    observation: FirewallObservation,
    authority: capability.ExecutionAuthority,
    phase: ObservationPhase,
    expected_target: capability.ResourceTarget | None = None,
    predecessor_request: capability.CapabilityRequest | None = None,
) -> None:
    if (
        type(observation) is not FirewallObservation
        or type(authority) is not capability.ExecutionAuthority
    ):
        raise ContractError("provider observation and #169 authority are required")
    if observation.phase is not phase:
        raise ContractError("provider observation is from the wrong lifecycle phase")
    expected_parameters = inspection_parameters_sha256(
        observation.request.target,
        phase,
        observation.supported_operations,
        predecessor_request,
    )
    if observation.request.parameters_sha256 != expected_parameters:
        raise ContractError("inspection parameters do not bind the firewall read")
    capability.admit_request(
        observation.request,
        authority,
        observation.supported_operations,
    )
    capability.admit_result(observation.request, observation.result)
    if observation.request.operation is not capability.Operation.INSPECT:
        raise ContractError("provider observation is not an INSPECT operation")
    if observation.result.outcome is not capability.Outcome.OBSERVED:
        raise ContractError("provider observation requires an OBSERVED result")
    if expected_target is not None and not _same_resource(
        observation.request.target, expected_target
    ):
        raise ContractError("provider observation target mismatch")


def _desired_policy(
    intent: FirewallIntent, accepted: dict[str, Any]
) -> FirewallPolicy:
    if type(intent) is not FirewallIntent:
        raise ContractError("one admitted PROTECTED firewall intent is required")
    return FirewallPolicy(
        protocol=intent.origin_protocol,
        port=intent.origin_port,
        ipv4_sources=tuple(accepted["ipv4_prefixes"]),
        ipv6_sources=tuple(accepted["ipv6_prefixes"]),
    )


def plan(
    intent: FirewallIntent,
    accepted_lkg_state_directory: Path,
    current: FirewallObservation,
    inspect_authority: capability.ExecutionAuthority,
) -> FirewallPlan:
    """Read #214 accepted state and plan only the authenticated owned slice."""
    if not isinstance(accepted_lkg_state_directory, Path):
        raise ContractError("#214 accepted-LKG state directory is required")
    accepted = lkg.read_lkg(accepted_lkg_state_directory)
    if accepted is None:
        raise ContractError("no #214 accepted CloudFront Origin LKG exists")
    _admit_observation(
        current, inspect_authority, ObservationPhase.CURRENT
    )
    desired = _desired_policy(intent, accepted)
    prior_owned = current.owned[0] if current.owned else None
    action = (
        PlanAction.NO_MUTATION
        if prior_owned is not None and prior_owned.policy == desired
        else PlanAction.REPLACE_OWNED
    )
    observed_target = current.request.target
    target = capability.ResourceTarget(
        provider=observed_target.provider,
        scope=observed_target.scope,
        requested_key=observed_target.requested_key,
        provider_resource_id=observed_target.provider_resource_id,
        expected_version=current.revision,
    )
    return FirewallPlan(
        action=action,
        target=target,
        adapter_id=current.request.adapter_id,
        source_revision=current.request.source_revision,
        supported_operations=current.supported_operations,
        accepted_lkg_identity=accepted["candidate_sha256"],
        desired=desired,
        prior_owned=prior_owned,
        preserved_state_sha256=current.preserved_state_sha256,
        operator_access=current.operator_access,
    )


def _policy_document(policy: FirewallPolicy) -> dict[str, Any]:
    return {
        "protocol": policy.protocol,
        "port": policy.port,
        "ipv4_sources": list(policy.ipv4_sources),
        "ipv6_sources": list(policy.ipv6_sources),
    }


def _owned_document(owned: OwnedFirewallPolicy | None) -> dict[str, Any] | None:
    if owned is None:
        return None
    return {
        "provider_rule_id": owned.provider_rule_id,
        "policy": _policy_document(owned.policy),
    }


def mutation_parameters_sha256(plan_to_authorize: FirewallPlan) -> str:
    if type(plan_to_authorize) is not FirewallPlan:
        raise ContractError("one firewall plan is required")
    return _canonical_digest(
        {
            "contract": "secpal-provider-firewall-mutation-v1",
            "edge_mode": EdgeMode.PROTECTED.value,
            "action": plan_to_authorize.action.value,
            "target": _target_document(plan_to_authorize.target),
            "adapter_id": plan_to_authorize.adapter_id,
            "source_revision": plan_to_authorize.source_revision,
            "supported_operations": sorted(operation.value for operation in plan_to_authorize.supported_operations),
            "accepted_lkg_identity": plan_to_authorize.accepted_lkg_identity,
            "ownership_scope": OwnershipScope.PROTECTED_ORIGIN.value,
            "desired": _policy_document(plan_to_authorize.desired),
            "prior_owned": _owned_document(plan_to_authorize.prior_owned),
            "preserved_state_sha256": plan_to_authorize.preserved_state_sha256,
            "operator_access": list(plan_to_authorize.operator_access),
        }
    )


def build_mutation_request(
    plan_to_authorize: FirewallPlan,
    authority: capability.ExecutionAuthority,
    request_id: str,
) -> capability.CapabilityRequest:
    if type(plan_to_authorize) is not FirewallPlan:
        raise ContractError("one firewall plan is required")
    if plan_to_authorize.action is not PlanAction.REPLACE_OWNED:
        raise ContractError("no provider mutation is authorized for this plan")
    if plan_to_authorize.target.expected_version is None:
        raise ContractError("provider mutation requires fresh concurrency authority")
    _identity("mutation request identity", request_id)
    expected_parameters = mutation_parameters_sha256(plan_to_authorize)
    if (
        type(authority) is not capability.ExecutionAuthority
        or authority.adapter_id != plan_to_authorize.adapter_id
        or authority.source_revision != plan_to_authorize.source_revision
        or authority.target != plan_to_authorize.target
        or authority.parameters_sha256 != expected_parameters
    ):
        raise ContractError("mutation authority does not bind the exact firewall plan")
    request = capability.CapabilityRequest(
        request_id=request_id,
        adapter_id=plan_to_authorize.adapter_id,
        source_revision=plan_to_authorize.source_revision,
        operation=capability.Operation.REBUILD,
        target=plan_to_authorize.target,
        parameters_sha256=expected_parameters,
    )
    capability.admit_request(
        request, authority, plan_to_authorize.supported_operations
    )
    return request


def _admit_mutation_context(
    plan_to_check: FirewallPlan,
    authority: capability.ExecutionAuthority,
    request: capability.CapabilityRequest,
    result: capability.CapabilityResult,
) -> None:
    if (
        type(request) is not capability.CapabilityRequest
        or type(result) is not capability.CapabilityResult
    ):
        raise ContractError("correlated #169 mutation request and result are required")
    expected_request = build_mutation_request(
        plan_to_check, authority, request.request_id
    )
    if request != expected_request:
        raise ContractError("mutation request does not match the exact firewall plan")
    capability.admit_result(request, result)


def admit_mutation_result(
    plan_to_check: FirewallPlan,
    authority: capability.ExecutionAuthority,
    request: capability.CapabilityRequest,
    result: capability.CapabilityResult,
) -> MutationDisposition:
    """Every mutation result, including success, requires fresh inspection."""
    _admit_mutation_context(plan_to_check, authority, request, result)
    return MutationDisposition.REINSPECTION_REQUIRED


def _admit_fresh_observation(
    plan_to_check: FirewallPlan,
    fresh: FirewallObservation,
    inspect_authority: capability.ExecutionAuthority,
    phase: ObservationPhase,
    predecessor_request: capability.CapabilityRequest,
) -> None:
    _admit_observation(
        fresh,
        inspect_authority,
        phase,
        expected_target=plan_to_check.target,
        predecessor_request=predecessor_request,
    )
    if (
        fresh.request.adapter_id != plan_to_check.adapter_id
        or fresh.request.source_revision != plan_to_check.source_revision
        or fresh.supported_operations != plan_to_check.supported_operations
    ):
        raise ContractError("fresh observation uses a different adapter authority")
    if (
        fresh.preserved_state_sha256 != plan_to_check.preserved_state_sha256
        or fresh.operator_access != plan_to_check.operator_access
    ):
        raise ContractError(
            "fresh observation did not preserve unrelated/operator provider state"
        )


def verify(
    plan_to_verify: FirewallPlan,
    mutation_authority: capability.ExecutionAuthority,
    mutation_request: capability.CapabilityRequest,
    mutation_result: capability.CapabilityResult,
    fresh: FirewallObservation,
    fresh_inspect_authority: capability.ExecutionAuthority,
) -> None:
    """Admit the mutation result, then independently verify fresh semantics."""
    _admit_mutation_context(
        plan_to_verify, mutation_authority, mutation_request, mutation_result
    )
    _admit_fresh_observation(
        plan_to_verify,
        fresh,
        fresh_inspect_authority,
        ObservationPhase.POST_MUTATION,
        mutation_request,
    )
    if len(fresh.owned) != 1 or fresh.owned[0].policy != plan_to_verify.desired:
        raise ContractError("fresh provider read did not verify exact desired policy")


def recovery_plan(
    plan_to_recover: FirewallPlan,
    mutation_authority: capability.ExecutionAuthority,
    mutation_request: capability.CapabilityRequest,
    mutation_result: capability.CapabilityResult,
    fresh: FirewallObservation,
    fresh_inspect_authority: capability.ExecutionAuthority,
) -> RecoveryDecision | RollbackPlan:
    """Classify only a fresh post-mutation read; never roll back stale state."""
    _admit_mutation_context(
        plan_to_recover,
        mutation_authority,
        mutation_request,
        mutation_result,
    )
    _admit_fresh_observation(
        plan_to_recover,
        fresh,
        fresh_inspect_authority,
        ObservationPhase.POST_MUTATION,
        mutation_request,
    )
    fresh_owned = fresh.owned[0] if fresh.owned else None
    prior_policy = (
        plan_to_recover.prior_owned.policy
        if plan_to_recover.prior_owned is not None
        else None
    )
    fresh_policy = fresh_owned.policy if fresh_owned is not None else None
    no_retained_effect = (
        mutation_result.outcome
        in {
            capability.Outcome.UNSUPPORTED,
            capability.Outcome.ALREADY_SATISFIED,
        }
        or (
            mutation_result.outcome is capability.Outcome.FAILED
            and mutation_result.cleanup is capability.CleanupOutcome.COMPLETE
        )
    )
    if no_retained_effect:
        if fresh_policy == prior_policy:
            return RecoveryDecision.PRIOR_VERIFIED
        raise ContractError(
            "no-effect mutation result cannot authorize recovery of provider drift"
        )
    if fresh_owned is not None and fresh_owned.policy == plan_to_recover.desired:
        return RecoveryDecision.DESIRED_VERIFIED
    if fresh_policy == prior_policy:
        return RecoveryDecision.PRIOR_VERIFIED
    if fresh.revision is None:
        raise ContractError("rollback planning requires fresh concurrency authority")
    observed_target = fresh.request.target
    target = capability.ResourceTarget(
        provider=observed_target.provider,
        scope=observed_target.scope,
        requested_key=observed_target.requested_key,
        provider_resource_id=observed_target.provider_resource_id,
        expected_version=fresh.revision,
    )
    return RollbackPlan(
        target=target,
        adapter_id=plan_to_recover.adapter_id,
        source_revision=plan_to_recover.source_revision,
        supported_operations=plan_to_recover.supported_operations,
        restore_policy=prior_policy,
        preserved_state_sha256=plan_to_recover.preserved_state_sha256,
        operator_access=plan_to_recover.operator_access,
    )


def rollback_parameters_sha256(rollback: RollbackPlan) -> str:
    if type(rollback) is not RollbackPlan:
        raise ContractError("one rollback plan is required")
    return _canonical_digest(
        {
            "contract": "secpal-provider-firewall-rollback-v1",
            "action": "restore-prior-owned-semantics",
            "target": _target_document(rollback.target),
            "adapter_id": rollback.adapter_id,
            "source_revision": rollback.source_revision,
            "supported_operations": sorted(operation.value for operation in rollback.supported_operations),
            "ownership_scope": OwnershipScope.PROTECTED_ORIGIN.value,
            "restore_policy": _policy_document(rollback.restore_policy) if rollback.restore_policy is not None else None,
            "preserved_state_sha256": rollback.preserved_state_sha256,
            "operator_access": list(rollback.operator_access),
        }
    )


def build_rollback_request(
    rollback: RollbackPlan,
    authority: capability.ExecutionAuthority,
    request_id: str,
) -> capability.CapabilityRequest:
    _identity("rollback request identity", request_id)
    expected_parameters = rollback_parameters_sha256(rollback)
    if (
        type(authority) is not capability.ExecutionAuthority
        or authority.adapter_id != rollback.adapter_id
        or authority.source_revision != rollback.source_revision
        or authority.target != rollback.target
        or authority.parameters_sha256 != expected_parameters
    ):
        raise ContractError("rollback authority does not bind fresh provider state")
    request = capability.CapabilityRequest(
        request_id=request_id,
        adapter_id=rollback.adapter_id,
        source_revision=rollback.source_revision,
        operation=capability.Operation.REBUILD,
        target=rollback.target,
        parameters_sha256=expected_parameters,
    )
    capability.admit_request(
        request, authority, rollback.supported_operations
    )
    return request


def _admit_rollback_context(
    rollback: RollbackPlan,
    authority: capability.ExecutionAuthority,
    request: capability.CapabilityRequest,
    result: capability.CapabilityResult,
) -> None:
    if (
        type(request) is not capability.CapabilityRequest
        or type(result) is not capability.CapabilityResult
    ):
        raise ContractError("correlated #169 rollback request and result are required")
    expected_request = build_rollback_request(
        rollback, authority, request.request_id
    )
    if request != expected_request:
        raise ContractError("rollback request does not match fresh recovery state")
    capability.admit_result(request, result)


def admit_rollback_result(
    rollback: RollbackPlan,
    authority: capability.ExecutionAuthority,
    request: capability.CapabilityRequest,
    result: capability.CapabilityResult,
) -> MutationDisposition:
    _admit_rollback_context(rollback, authority, request, result)
    return MutationDisposition.REINSPECTION_REQUIRED


def verify_rollback(
    rollback: RollbackPlan,
    rollback_authority: capability.ExecutionAuthority,
    rollback_request: capability.CapabilityRequest,
    rollback_result: capability.CapabilityResult,
    fresh: FirewallObservation,
    fresh_inspect_authority: capability.ExecutionAuthority,
) -> None:
    """Verify prior semantics at a fresh revision, never obsolete revision equality."""
    _admit_rollback_context(
        rollback, rollback_authority, rollback_request, rollback_result
    )
    _admit_observation(
        fresh,
        fresh_inspect_authority,
        ObservationPhase.POST_ROLLBACK,
        expected_target=rollback.target,
        predecessor_request=rollback_request,
    )
    if (
        fresh.request.adapter_id != rollback.adapter_id
        or fresh.request.source_revision != rollback.source_revision
        or fresh.supported_operations != rollback.supported_operations
        or fresh.preserved_state_sha256 != rollback.preserved_state_sha256
        or fresh.operator_access != rollback.operator_access
    ):
        raise ContractError("rollback did not preserve exact non-owned provider state")
    fresh_policy = fresh.owned[0].policy if fresh.owned else None
    if fresh_policy != rollback.restore_policy:
        raise ContractError("rollback did not restore prior owned semantics")
