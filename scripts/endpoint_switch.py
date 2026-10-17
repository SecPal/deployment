#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""#170 endpoint adapter v1; #131 owns admission, dispatch intent and writers."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import importlib.util
from pathlib import Path
import sys
from typing import Protocol

_name = "_secpal_endpoint_provider_capability"
if _name not in sys.modules:
    _spec = importlib.util.spec_from_file_location(
        _name, Path(__file__).with_name("provider-capability-contract.py"))
    _module = importlib.util.module_from_spec(_spec)
    sys.modules[_name] = _module
    _spec.loader.exec_module(_module)
_provider = sys.modules[_name]
ResourceTarget = _provider.ResourceTarget
ContractError = _provider.ContractError
CONTRACT_VERSION = 1


def _identity(value):
    _provider._identity("endpoint identity", value)


class Intent(str, Enum):
    SWITCH = "switch"
    PRE_WRITE_REVERSAL = "pre-write-reversal"


class Mutation(str, Enum):
    """REJECTED guarantees no mutation; pending/lost/malformed ACK is UNKNOWN."""
    APPLIED = "applied"
    REJECTED = "rejected"
    UNKNOWN = "unknown"


class Outcome(str, Enum):
    APPLIED = "applied"
    ALREADY_SATISFIED = "already-satisfied"
    REJECTED = "rejected"
    UNCERTAIN = "uncertain"
    RECOVERY_REQUIRED = "recovery-required"


@dataclass(frozen=True, slots=True)
class Endpoint:
    deployment_id: str
    resource: ResourceTarget

    def __post_init__(self):
        _identity(self.deployment_id)
        # Public #169 targets also arrive through #241's own module instance.
        # Re-admit their fields through the canonical owner, as #241 does.
        try:
            resource = ResourceTarget(**asdict(self.resource))
        except (TypeError, ContractError):
            raise ContractError("endpoint-resource-format") from None
        if resource.provider_resource_id is None or resource.expected_version is not None:
            raise ContractError("endpoint-requires-exact-resource-and-observed-generation")
        object.__setattr__(self, "resource", resource)


@dataclass(frozen=True, slots=True)
class RoutingState:
    endpoint: Endpoint
    generation: str
    target: str
    exposure_sha256: str
    operation_id: str | None = None

    def __post_init__(self):
        if type(self.endpoint) is not Endpoint:
            raise ContractError("endpoint-scope-required")
        _identity(self.generation)
        _identity(self.target)
        if not _provider._matches(_provider.SHA256, self.exposure_sha256):
            raise ContractError("endpoint-exposure-binding-required")
        if self.operation_id is not None:
            _identity(self.operation_id)


@dataclass(frozen=True, slots=True)
class SwitchPlan:
    version: int
    operation_id: str
    before: RoutingState
    target: str
    intent: Intent

    def __post_init__(self):
        if type(self.version) is not int or self.version != CONTRACT_VERSION:
            raise ContractError("unsupported-endpoint-contract")
        if type(self.before) is not RoutingState or type(self.intent) is not Intent:
            raise ContractError("endpoint-plan-required")
        _identity(self.operation_id)
        _identity(self.target)
        if self.target == self.before.target:
            raise ContractError("endpoint-candidate-already-current")


@dataclass(frozen=True, slots=True)
class Result:
    outcome: Outcome
    diagnostic: str
    observed: RoutingState | None = None


class Observer(Protocol):
    def observe(self, endpoint: Endpoint) -> RoutingState:
        """Fresh authenticated native read, not an apply-response projection."""


class Adapter(Protocol):
    def validate(self, request: SwitchPlan) -> None:
        """Pure exact-resource/target/exposure projection admission; raise to deny."""

    def compare_and_switch(self, request: SwitchPlan) -> Mutation:
        """Atomic full before-state CAS; native generations never suffer ABA."""


class CutoverAuthority(Protocol):
    def authorize(self, request: SwitchPlan) -> None:
        """Fresh #131 admission of exact scope/intent/target; raise to deny.

        This is trusted construction, never a requester-supplied readiness flag.
        Routing health grants no writer authority or safe post-write reversal.
        """

    def claim_dispatch(self, request: SwitchPlan) -> bool:
        """Atomically reauthorize and persist exact intent in the owner's state.

        True: first dispatch; False: already claimed, so observation only.
        Bind the operation ID to the whole plan across processes/restarts.
        This port adds no #170 registry, journal, signer or credential authority.
        """


class ObservationUnavailable(OSError):
    pass


def plan(operation_id, current, target, *, intent=Intent.SWITCH):
    """Pure dry-run plan. It grants no admission or provider authority."""
    return SwitchPlan(CONTRACT_VERSION, operation_id, current, target, intent)


def inspect(endpoint, observer):
    if type(endpoint) is not Endpoint:
        raise ContractError("endpoint-scope-required")
    try:
        observed = observer.observe(endpoint)
    except Exception:
        raise ObservationUnavailable("observe-endpoint-unavailable") from None
    if type(observed) is not RoutingState or observed.endpoint != endpoint:
        raise ContractError("observe-endpoint-scope-mismatch")
    return observed


def _committed(request, observed):
    return (observed.endpoint == request.before.endpoint
            and observed.target == request.target
            and observed.exposure_sha256 == request.before.exposure_sha256
            and observed.generation != request.before.generation
            and observed.operation_id == request.operation_id)


def assess(request, mutation, observed):
    """Pure result admission. Apply ACK, reachability and DNS caches cannot pass."""
    if type(request) is not SwitchPlan:
        return Result(Outcome.REJECTED, "endpoint-plan-required")
    if (type(observed) is not RoutingState
            or observed.endpoint != request.before.endpoint
            or observed.exposure_sha256 != request.before.exposure_sha256):
        return Result(Outcome.RECOVERY_REQUIRED, "endpoint-readback-boundary")
    if type(mutation) is not Mutation:
        mutation = Mutation.UNKNOWN
    if mutation is Mutation.REJECTED and observed.operation_id == request.operation_id:
        return Result(Outcome.RECOVERY_REQUIRED, "endpoint-contradictory-rejection", observed)
    if _committed(request, observed):
        return Result(Outcome.APPLIED, "endpoint-switch-verified", observed)
    if observed == request.before:
        if mutation is Mutation.REJECTED:
            return Result(Outcome.REJECTED, "endpoint-provider-precondition", observed)
        if mutation is Mutation.UNKNOWN:
            return Result(Outcome.UNCERTAIN, "endpoint-provider-outcome-unknown", observed)
    elif mutation is Mutation.REJECTED:
        # A concurrent winner is not authority for this request or a rollback.
        return Result(Outcome.REJECTED, "endpoint-provider-precondition", observed)
    return Result(Outcome.RECOVERY_REQUIRED, "endpoint-readback-mismatch", observed)


def reconcile(request, observer, authority):
    """Read-only recovery boundary: never dispatch or infer safe rollback/retry."""
    if type(request) is not SwitchPlan:
        return Result(Outcome.REJECTED, "endpoint-plan-required")
    try:
        authority.authorize(request)
    except Exception:
        return Result(Outcome.REJECTED, "endpoint-cutover-admission")
    try:
        observed = inspect(request.before.endpoint, observer)
    except ObservationUnavailable:
        return Result(Outcome.UNCERTAIN, "endpoint-reconcile-unavailable")
    except ContractError:
        return Result(Outcome.RECOVERY_REQUIRED, "endpoint-reconcile-scope")
    result = assess(request, Mutation.UNKNOWN, observed)
    if result.outcome is Outcome.APPLIED:
        return Result(Outcome.ALREADY_SATISFIED, "endpoint-existing-switch-verified", observed)
    return result


def execute(request, adapter, observer, authority):
    """One admitted dispatch; unresolved attempts can only reconcile."""
    if type(request) is not SwitchPlan:
        return Result(Outcome.REJECTED, "endpoint-plan-required")
    try:
        authority.authorize(request)
    except Exception:
        return Result(Outcome.REJECTED, "endpoint-cutover-admission")
    try:
        adapter.validate(request)
    except Exception:
        return Result(Outcome.REJECTED, "endpoint-candidate-admission")
    try:
        current = inspect(request.before.endpoint, observer)
    except ObservationUnavailable:
        return Result(Outcome.UNCERTAIN, "endpoint-inspect-unavailable")
    except ContractError:
        return Result(Outcome.REJECTED, "endpoint-inspect-scope")
    if _committed(request, current):
        return Result(Outcome.ALREADY_SATISFIED, "endpoint-existing-switch-verified", current)
    if current != request.before:
        return Result(Outcome.REJECTED, "endpoint-stale-precondition", current)
    try:
        claimed = authority.claim_dispatch(request)
        if type(claimed) is not bool:
            raise ContractError("endpoint-dispatch-claim-required")
    except Exception:
        return Result(Outcome.UNCERTAIN, "endpoint-dispatch-claim-unknown")
    if not claimed:
        return reconcile(request, observer, authority)
    try:
        mutation = adapter.compare_and_switch(request)
    except Exception:
        mutation = Mutation.UNKNOWN
    try:
        observed = inspect(request.before.endpoint, observer)
    except ObservationUnavailable:
        return Result(Outcome.UNCERTAIN, "endpoint-verify-unavailable")
    except ContractError:
        return Result(Outcome.RECOVERY_REQUIRED, "endpoint-verify-scope")
    return assess(request, mutation, observed)
