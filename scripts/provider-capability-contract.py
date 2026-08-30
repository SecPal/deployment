#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Pure admission contract for bounded provider adapter operations.

This module cannot select or invoke an adapter, load credentials or policy, or
perform network, filesystem, persistence, or provider operations.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from typing import FrozenSet


SHA1 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
DIAGNOSTIC = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
MAX_IDENTITY_BYTES = 512


class ContractError(ValueError):
    """The request, authority, or result fails the portable contract."""


class UnsupportedCapability(ContractError):
    """The explicitly selected adapter does not implement the operation."""


class Operation(str, Enum):
    CREATE = "create"
    INSPECT = "inspect"
    REBUILD = "rebuild"
    DELETE = "delete"


class Outcome(str, Enum):
    APPLIED = "applied"
    OBSERVED = "observed"
    ALREADY_SATISFIED = "already-satisfied"
    UNSUPPORTED = "unsupported"
    FAILED = "failed"


class CleanupOutcome(str, Enum):
    NOT_APPLICABLE = "not-applicable"
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"


def _identity(label: str, value: object) -> None:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ContractError(f"{label} must be one explicit non-empty identity")
    encoded = value.encode("utf-8")
    if len(encoded) > MAX_IDENTITY_BYTES or any(
        character == "\x7f" or ord(character) < 0x20 for character in value
    ):
        raise ContractError(f"{label} is outside the bounded identity format")


@dataclass(frozen=True, slots=True)
class ResourceTarget:
    """One provider context and desired target, with native identity if known."""

    provider: str
    scope: str
    requested_key: str
    provider_resource_id: str | None = None
    expected_version: str | None = None

    def __post_init__(self) -> None:
        for label, value in (
            ("provider", self.provider),
            ("provider scope", self.scope),
            ("requested target key", self.requested_key),
        ):
            _identity(label, value)
        if self.provider_resource_id is not None:
            _identity("provider resource identity", self.provider_resource_id)
        if self.expected_version is not None:
            _identity("expected provider resource version", self.expected_version)


@dataclass(frozen=True, slots=True)
class ExecutionAuthority:
    """Runtime authority supplied separately from the capability definition."""

    authorization_id: str
    adapter_id: str
    source_revision: str
    target: ResourceTarget
    operations: FrozenSet[Operation]
    credential_mechanism: str

    def __post_init__(self) -> None:
        for label, value in (
            ("authorization identity", self.authorization_id),
            ("adapter identity", self.adapter_id),
            ("credential mechanism", self.credential_mechanism),
        ):
            _identity(label, value)
        if SHA1.fullmatch(self.source_revision) is None:
            raise ContractError("authority requires one lowercase full source SHA")
        if not isinstance(self.target, ResourceTarget):
            raise ContractError("authority requires one exact target")
        if not isinstance(self.operations, frozenset) or not self.operations or any(
            not isinstance(operation, Operation) for operation in self.operations
        ):
            raise ContractError("authority requires a closed allowed operation set")


@dataclass(frozen=True, slots=True)
class CapabilityRequest:
    """Provider-neutral operation request passed to one selected adapter."""

    request_id: str
    adapter_id: str
    source_revision: str
    operation: Operation
    target: ResourceTarget
    parameters_sha256: str

    def __post_init__(self) -> None:
        _identity("request identity", self.request_id)
        _identity("adapter identity", self.adapter_id)
        if SHA1.fullmatch(self.source_revision) is None:
            raise ContractError("request requires one lowercase full source SHA")
        if not isinstance(self.operation, Operation) or not isinstance(
            self.target, ResourceTarget
        ):
            raise ContractError("request operation or target is invalid")
        if SHA256.fullmatch(self.parameters_sha256) is None:
            raise ContractError("adapter parameters require one SHA-256 binding")


@dataclass(frozen=True, slots=True)
class CapabilityResult:
    """Correlated bounded result; provider evidence remains provider-specific."""

    request_id: str
    adapter_id: str
    operation: Operation
    target: ResourceTarget
    outcome: Outcome
    cleanup: CleanupOutcome
    provider_resource_id: str | None = None
    provider_resource_version: str | None = None
    provider_image_id: str | None = None
    diagnostic_code: str | None = None

    def __post_init__(self) -> None:
        _identity("result request identity", self.request_id)
        _identity("result adapter identity", self.adapter_id)
        if not all(
            (
                isinstance(self.operation, Operation),
                isinstance(self.target, ResourceTarget),
                isinstance(self.outcome, Outcome),
                isinstance(self.cleanup, CleanupOutcome),
            )
        ):
            raise ContractError("result is outside the closed contract")
        for label, value in (
            ("observed provider resource identity", self.provider_resource_id),
            ("observed provider resource version", self.provider_resource_version),
            ("observed provider image identity", self.provider_image_id),
        ):
            if value is not None:
                _identity(label, value)
        if self.diagnostic_code is not None and (
            len(self.diagnostic_code) > 128
            or DIAGNOSTIC.fullmatch(self.diagnostic_code) is None
        ):
            raise ContractError("diagnostic code is outside the bounded format")


def admit_request(
    request: CapabilityRequest,
    authority: ExecutionAuthority,
    supported_operations: FrozenSet[Operation] | set[Operation],
) -> None:
    """Admit one request without selecting or invoking an adapter."""

    if not isinstance(request, CapabilityRequest) or not isinstance(
        authority, ExecutionAuthority
    ):
        raise ContractError("request and authority are required")
    if (
        request.adapter_id != authority.adapter_id
        or request.source_revision != authority.source_revision
        or request.target != authority.target
    ):
        raise ContractError("request does not match the exact authorized target")
    if request.operation not in authority.operations:
        raise ContractError("operation is not authorized for this exact target")
    if request.operation not in supported_operations:
        raise UnsupportedCapability("selected adapter does not support this operation")
    if (
        request.operation in {Operation.INSPECT, Operation.REBUILD, Operation.DELETE}
        and request.target.provider_resource_id is None
    ):
        raise ContractError("operation requires an exact provider-native identity")


def admit_result(request: CapabilityRequest, result: CapabilityResult) -> None:
    """Admit one correlated result and its bounded failure semantics."""

    if not isinstance(request, CapabilityRequest) or not isinstance(
        result, CapabilityResult
    ):
        raise ContractError("request and result are required")
    if (
        result.request_id != request.request_id
        or result.adapter_id != request.adapter_id
        or result.operation is not request.operation
        or result.target != request.target
    ):
        raise ContractError("result is not bound to the exact request")

    allowed = {
        Operation.CREATE: {Outcome.APPLIED, Outcome.ALREADY_SATISFIED},
        Operation.INSPECT: {Outcome.OBSERVED},
        Operation.REBUILD: {Outcome.APPLIED, Outcome.ALREADY_SATISFIED},
        Operation.DELETE: {Outcome.APPLIED, Outcome.ALREADY_SATISFIED},
    }[request.operation] | {Outcome.UNSUPPORTED, Outcome.FAILED}
    if result.outcome not in allowed:
        raise ContractError("outcome contradicts the requested operation")

    if (
        result.provider_resource_id is not None
        and request.target.provider_resource_id is not None
        and result.provider_resource_id != request.target.provider_resource_id
    ):
        raise ContractError("observed resource identity mismatches the target")
    failure = result.outcome in {Outcome.FAILED, Outcome.UNSUPPORTED}
    if failure != (result.diagnostic_code is not None):
        raise ContractError("diagnostic presence contradicts the result outcome")

    if result.outcome is Outcome.UNSUPPORTED:
        if (
            result.cleanup is not CleanupOutcome.NOT_APPLICABLE
            or result.provider_resource_id is not None
            or result.provider_resource_version is not None
            or result.provider_image_id is not None
        ):
            raise ContractError("unsupported result must not imply provider mutation")
        return
    if result.outcome is Outcome.FAILED:
        allowed_cleanup = (
            {CleanupOutcome.NOT_APPLICABLE}
            if request.operation is Operation.INSPECT
            else {CleanupOutcome.COMPLETE, CleanupOutcome.INCOMPLETE}
        )
        if result.cleanup not in allowed_cleanup:
            raise ContractError("failed mutation must report its cleanup outcome")
        return
    if request.operation is Operation.DELETE:
        if result.cleanup is not CleanupOutcome.COMPLETE or any(
            value is not None
            for value in (
                result.provider_resource_id,
                result.provider_resource_version,
                result.provider_image_id,
            )
        ):
            raise ContractError("successful delete requires exact complete cleanup")
        return
    if (
        result.cleanup is not CleanupOutcome.NOT_APPLICABLE
        or result.provider_resource_id is None
    ):
        raise ContractError("successful operation requires bounded provider read-back")
    if (
        request.operation is Operation.INSPECT
        and request.target.expected_version is not None
        and result.provider_resource_version != request.target.expected_version
    ):
        raise ContractError("observed resource version is stale or mismatched")
