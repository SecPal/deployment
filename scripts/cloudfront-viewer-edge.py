#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Pure PROTECTED CloudFront Viewer Edge lifecycle contract.

The module builds and admits bounded CloudFront control-plane operations.  It
does not load credentials, select an AWS account, call AWS, change DNS, or store
live state.  A separately authorized adapter supplies observation and mutation.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from enum import Enum
import re
from typing import FrozenSet, Mapping


CACHING_DISABLED_ID = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
ALL_VIEWER_EXCEPT_HOST_ID = "b689b0a8-53d0-40ab-baf2-68738e2966ac"
ORIGIN_PARAMETER = "OriginDomain"
ORIGIN_TEMPLATE = "{{OriginDomain}}"
ORIGIN_ID = "secpal-origin"
SHA1 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
DIAGNOSTIC = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
AWS_ACCOUNT_ID = re.compile(r"^[0-9]{12}$")
AWS_PARTITION = re.compile(r"^aws(?:-us-gov|-cn)?$")
ETAG = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
MAX_IDENTITY_BYTES = 4096


class ContractError(ValueError):
    """An input, observation, transition, or result fails closed."""


class Operation(str, Enum):
    CREATE_DISTRIBUTION = "create-distribution"
    INSPECT_DISTRIBUTION = "inspect-distribution"
    UPDATE_DISTRIBUTION = "update-distribution"
    CREATE_CONNECTION_GROUP = "create-connection-group"
    INSPECT_CONNECTION_GROUP = "inspect-connection-group"
    DISABLE_CONNECTION_GROUP = "disable-connection-group"
    DELETE_CONNECTION_GROUP = "delete-connection-group"
    CREATE_TENANT = "create-tenant"
    INSPECT_TENANT = "inspect-tenant"
    INSPECT_CERTIFICATE = "inspect-certificate"
    ATTACH_CERTIFICATE = "attach-certificate"
    UPDATE_TENANT = "update-tenant"
    DISABLE_TENANT = "disable-tenant"
    DELETE_TENANT = "delete-tenant"
    DISABLE_DISTRIBUTION = "disable-distribution"
    DELETE_DISTRIBUTION = "delete-distribution"


class CertificateState(str, Enum):
    REQUESTED = "requested"
    VALIDATION_REQUIRED = "validation-required"
    ISSUED = "issued"
    ATTACHED = "attached"
    ACTIVE = "active"
    INACTIVE = "inactive"
    FAILED = "failed"


class Outcome(str, Enum):
    APPLIED = "applied"
    OBSERVED = "observed"
    DELETED = "deleted"
    FAILED = "failed"


def _identity(label: str, value: object) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise ContractError(f"{label} must be one explicit non-empty identity")
    if not value.isprintable() or len(value.encode("utf-8")) > MAX_IDENTITY_BYTES:
        raise ContractError(f"{label} is outside the bounded identity format")


def _domain(label: str, value: object) -> None:
    _identity(label, value)
    assert isinstance(value, str)
    try:
        ascii_value = value.encode("idna").decode("ascii")
    except UnicodeError as error:
        raise ContractError(f"{label} is not a valid DNS identity") from error
    if (
        len(ascii_value) > 253
        or ascii_value.endswith(".")
        or "." not in ascii_value
        or any(
            not label_part
            or len(label_part) > 63
            or label_part.startswith("-")
            or label_part.endswith("-")
            or re.fullmatch(r"[A-Za-z0-9-]+", label_part) is None
            for label_part in ascii_value.split(".")
        )
    ):
        raise ContractError(f"{label} is not a bounded DNS hostname")


def _etag(value: object) -> None:
    if type(value) is not str or ETAG.fullmatch(value) is None:
        raise ContractError("a current CloudFront control-plane ETag is required")


def deep_copy(value: object):
    """Return a deterministic defensive copy for request fixture mutation."""

    return deepcopy(value)


@dataclass(frozen=True, slots=True)
class AwsProviderContext:
    partition: str
    account_id: str
    cloudfront_scope: str
    certificate_region: str

    def __post_init__(self) -> None:
        if type(self.partition) is not str or AWS_PARTITION.fullmatch(self.partition) is None:
            raise ContractError("AWS partition is outside the closed supported set")
        if type(self.account_id) is not str or AWS_ACCOUNT_ID.fullmatch(self.account_id) is None:
            raise ContractError("AWS provider context requires one exact account ID")
        if self.cloudfront_scope != "global":
            raise ContractError("CloudFront provider context requires the global scope")
        if self.certificate_region != "us-east-1":
            raise ContractError(
                "CloudFront managed Viewer certificates require ACM us-east-1"
            )


@dataclass(frozen=True, slots=True)
class CloudFrontTarget:
    requested_key: str
    distribution_id: str | None = None
    connection_group_id: str | None = None
    tenant_id: str | None = None

    def __post_init__(self) -> None:
        _identity("deployment-scoped technical key", self.requested_key)
        for label, value in (
            ("CloudFront distribution ID", self.distribution_id),
            ("CloudFront connection group ID", self.connection_group_id),
            ("CloudFront distribution tenant ID", self.tenant_id),
        ):
            if value is not None:
                _identity(label, value)


@dataclass(frozen=True, slots=True)
class ExecutionAuthority:
    authorization_id: str
    adapter_id: str
    source_revision: str
    provider_context: AwsProviderContext
    target: CloudFrontTarget
    operations: FrozenSet[Operation]
    parameters_sha256: str
    credential_mechanism: str

    def __post_init__(self) -> None:
        for label, value in (
            ("authorization identity", self.authorization_id),
            ("adapter identity", self.adapter_id),
            ("credential mechanism", self.credential_mechanism),
        ):
            _identity(label, value)
        if type(self.source_revision) is not str or SHA1.fullmatch(self.source_revision) is None:
            raise ContractError("authority requires one lowercase full source SHA")
        if type(self.parameters_sha256) is not str or SHA256.fullmatch(self.parameters_sha256) is None:
            raise ContractError("authority requires one SHA-256 parameter binding")
        if type(self.provider_context) is not AwsProviderContext:
            raise ContractError("authority requires one exact AWS provider context")
        if type(self.target) is not CloudFrontTarget:
            raise ContractError("authority requires one exact CloudFront target")
        if type(self.operations) is not frozenset or not self.operations or any(
            type(operation) is not Operation for operation in self.operations
        ):
            raise ContractError("authority requires a closed allowed operation set")


@dataclass(frozen=True, slots=True)
class LifecycleRequest:
    request_id: str
    adapter_id: str
    source_revision: str
    provider_context: AwsProviderContext
    target: CloudFrontTarget
    operation: Operation
    parameters_sha256: str

    def __post_init__(self) -> None:
        _identity("request identity", self.request_id)
        _identity("adapter identity", self.adapter_id)
        if type(self.source_revision) is not str or SHA1.fullmatch(self.source_revision) is None:
            raise ContractError("request requires one lowercase full source SHA")
        if type(self.parameters_sha256) is not str or SHA256.fullmatch(self.parameters_sha256) is None:
            raise ContractError("request requires one SHA-256 parameter binding")
        if not all(
            (
                type(self.provider_context) is AwsProviderContext,
                type(self.target) is CloudFrontTarget,
                type(self.operation) is Operation,
            )
        ):
            raise ContractError("request is outside the CloudFront lifecycle contract")


@dataclass(frozen=True, slots=True)
class LifecycleResult:
    request_id: str
    adapter_id: str
    source_revision: str
    provider_context: AwsProviderContext
    target: CloudFrontTarget
    operation: Operation
    parameters_sha256: str
    outcome: Outcome
    resource_id: str | None = None
    resource_etag: str | None = None
    diagnostic_code: str | None = None

    @classmethod
    def from_request(
        cls,
        request: LifecycleRequest,
        *,
        outcome: Outcome,
        resource_id: str | None = None,
        resource_etag: str | None = None,
        diagnostic_code: str | None = None,
    ) -> "LifecycleResult":
        return cls(
            request_id=request.request_id,
            adapter_id=request.adapter_id,
            source_revision=request.source_revision,
            provider_context=request.provider_context,
            target=request.target,
            operation=request.operation,
            parameters_sha256=request.parameters_sha256,
            outcome=outcome,
            resource_id=resource_id,
            resource_etag=resource_etag,
            diagnostic_code=diagnostic_code,
        )

    def __post_init__(self) -> None:
        _identity("result request identity", self.request_id)
        _identity("result adapter identity", self.adapter_id)
        if type(self.source_revision) is not str or SHA1.fullmatch(self.source_revision) is None:
            raise ContractError("result requires one lowercase full source SHA")
        if type(self.parameters_sha256) is not str or SHA256.fullmatch(self.parameters_sha256) is None:
            raise ContractError("result requires one SHA-256 parameter binding")
        if not all(
            (
                type(self.provider_context) is AwsProviderContext,
                type(self.target) is CloudFrontTarget,
                type(self.operation) is Operation,
                type(self.outcome) is Outcome,
            )
        ):
            raise ContractError("result is outside the CloudFront lifecycle contract")
        if self.resource_id is not None:
            _identity("observed CloudFront resource ID", self.resource_id)
        if self.resource_etag is not None:
            _etag(self.resource_etag)
        if self.diagnostic_code is not None and (
            type(self.diagnostic_code) is not str
            or len(self.diagnostic_code) > 128
            or DIAGNOSTIC.fullmatch(self.diagnostic_code) is None
        ):
            raise ContractError("diagnostic code is outside the bounded format")
        if (self.outcome is Outcome.FAILED) != (self.diagnostic_code is not None):
            raise ContractError("diagnostic presence contradicts result outcome")


@dataclass(frozen=True, slots=True)
class TenantInputs:
    deployment_key: str
    distribution_id: str
    connection_group_id: str
    viewer_domain: str
    origin_domain: str

    def __post_init__(self) -> None:
        _identity("deployment-scoped technical key", self.deployment_key)
        _identity("multi-tenant distribution ID", self.distribution_id)
        _identity("CloudFront connection group ID", self.connection_group_id)
        _domain("Viewer domain", self.viewer_domain)
        _domain("OriginDomain", self.origin_domain)
        if self.viewer_domain.casefold() == self.origin_domain.casefold():
            raise ContractError("Viewer Host and OriginDomain must remain distinct")


@dataclass(frozen=True, slots=True)
class ValidationToken:
    domain: str
    redirect_from: str
    redirect_to: str

    def __post_init__(self) -> None:
        _domain("certificate validation domain", self.domain)
        for label, value in (
            ("certificate validation redirect source", self.redirect_from),
            ("certificate validation redirect target", self.redirect_to),
        ):
            _identity(label, value)
            if len(value.encode("utf-8")) > 2048:
                raise ContractError(f"{label} exceeds the bounded provider format")


@dataclass(frozen=True, slots=True)
class ManagedCertificateObservation:
    status: str
    certificate_arn: str | None
    validation_token_host: str | None
    validation_tokens: tuple[ValidationToken, ...] = ()

    def __post_init__(self) -> None:
        statuses = {
            "pending-validation",
            "issued",
            "inactive",
            "expired",
            "validation-timed-out",
            "revoked",
            "failed",
        }
        if self.status not in statuses:
            raise ContractError("unknown managed certificate status")
        if self.certificate_arn is not None:
            _identity("managed certificate ARN", self.certificate_arn)
        if self.validation_token_host not in {None, "cloudfront", "self-hosted"}:
            raise ContractError("unknown managed certificate validation token host")
        if type(self.validation_tokens) is not tuple or len(self.validation_tokens) > 5 or any(
            type(token) is not ValidationToken for token in self.validation_tokens
        ):
            raise ContractError("validation tokens are outside the bounded typed set")
        if self.status == "issued" and self.certificate_arn is None:
            raise ContractError("issued managed certificate requires its ARN")


@dataclass(frozen=True, slots=True)
class TenantObservation:
    tenant_id: str
    distribution_id: str
    connection_group_id: str
    etag: str
    enabled: bool
    deployment_status: str
    viewer_domain: str
    domain_status: str
    origin_domain: str
    certificate_arn: str | None = None

    def __post_init__(self) -> None:
        _identity("distribution tenant ID", self.tenant_id)
        _identity("multi-tenant distribution ID", self.distribution_id)
        _identity("CloudFront connection group ID", self.connection_group_id)
        _etag(self.etag)
        if type(self.enabled) is not bool:
            raise ContractError("tenant enabled state must be boolean")
        if self.deployment_status not in {"InProgress", "Deployed"}:
            raise ContractError("unknown distribution tenant deployment status")
        _domain("observed Viewer domain", self.viewer_domain)
        _domain("observed OriginDomain", self.origin_domain)
        if self.domain_status not in {"active", "inactive"}:
            raise ContractError("unknown distribution tenant domain status")
        if self.certificate_arn is not None:
            _identity("attached certificate ARN", self.certificate_arn)


@dataclass(frozen=True, slots=True)
class DistributionObservation:
    distribution_id: str
    etag: str
    enabled: bool
    deployment_status: str

    def __post_init__(self) -> None:
        _identity("multi-tenant distribution ID", self.distribution_id)
        _etag(self.etag)
        if type(self.enabled) is not bool:
            raise ContractError("distribution enabled state must be boolean")
        if self.deployment_status not in {"InProgress", "Deployed"}:
            raise ContractError("unknown distribution deployment status")


@dataclass(frozen=True, slots=True)
class ConnectionGroupObservation:
    connection_group_id: str
    etag: str
    routing_endpoint: str
    enabled: bool
    deployment_status: str
    is_default: bool
    tenant_association_present: bool

    def __post_init__(self) -> None:
        _identity("CloudFront connection group ID", self.connection_group_id)
        _etag(self.etag)
        _domain("CloudFront RoutingEndpoint", self.routing_endpoint)
        if not self.routing_endpoint.casefold().endswith(".cloudfront.net"):
            raise ContractError("connection group RoutingEndpoint is not CloudFront-owned")
        if type(self.enabled) is not bool or type(self.is_default) is not bool:
            raise ContractError("connection group flags must be boolean")
        if type(self.tenant_association_present) is not bool:
            raise ContractError("connection group association state must be explicit")
        if self.deployment_status not in {"InProgress", "Deployed"}:
            raise ContractError("unknown connection group deployment status")


@dataclass(frozen=True, slots=True)
class AwsOperationPlan:
    operation: Operation
    api_operation: str
    resource_id: str | None
    if_match: str | None
    parameters: Mapping[str, object]


def build_distribution_config(caller_reference: str) -> dict[str, object]:
    """Build the reviewed one-behavior multi-tenant parent configuration."""

    _identity("CloudFront caller reference", caller_reference)
    methods = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    return {
        "CallerReference": caller_reference,
        "Comment": "SecPal portable PROTECTED Viewer Edge baseline",
        "ConnectionMode": "tenant-only",
        "Enabled": True,
        "TenantConfig": {
            "ParameterDefinitions": [
                {
                    "Name": ORIGIN_PARAMETER,
                    "Definition": {"StringSchema": {"Required": True}},
                }
            ]
        },
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": ORIGIN_ID,
                    "DomainName": ORIGIN_TEMPLATE,
                    "CustomOriginConfig": {
                        "HTTPPort": 80,
                        "HTTPSPort": 443,
                        "OriginProtocolPolicy": "https-only",
                        "OriginSslProtocols": {
                            "Quantity": 1,
                            "Items": ["TLSv1.2"],
                        },
                    },
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": ORIGIN_ID,
            "ViewerProtocolPolicy": "https-only",
            "AllowedMethods": {
                "Quantity": len(methods),
                "Items": methods,
                "CachedMethods": {
                    "Quantity": 3,
                    "Items": ["GET", "HEAD", "OPTIONS"],
                },
            },
            "CachePolicyId": CACHING_DISABLED_ID,
            "OriginRequestPolicyId": ALL_VIEWER_EXCEPT_HOST_ID,
            "Compress": False,
        },
        "CacheBehaviors": {"Quantity": 0},
    }


def plan_create_distribution(caller_reference: str) -> AwsOperationPlan:
    """Plan creation of one exact ephemeral or caller-owned parent baseline."""

    config = build_distribution_config(caller_reference)
    validate_distribution_config(config)
    return AwsOperationPlan(
        operation=Operation.CREATE_DISTRIBUTION,
        api_operation="CreateDistribution",
        resource_id=None,
        if_match=None,
        parameters={"DistributionConfig": config},
    )


def plan_create_connection_group(name: str) -> AwsOperationPlan:
    """Plan one enabled custom routing prerequisite without optional products."""

    _identity("CloudFront connection group name", name)
    return AwsOperationPlan(
        operation=Operation.CREATE_CONNECTION_GROUP,
        api_operation="CreateConnectionGroup",
        resource_id=None,
        if_match=None,
        parameters={"Name": name, "Enabled": True},
    )


def validate_distribution_config(config: object) -> None:
    """Admit only the ADR-019 dynamic/authenticated parent baseline."""

    if type(config) is not dict:
        raise ContractError("distribution configuration must be one mapping")
    try:
        behavior = config["DefaultCacheBehavior"]
        origins = config["Origins"]
        origin = origins["Items"][0]
        definitions = config["TenantConfig"]["ParameterDefinitions"]
    except (KeyError, IndexError, TypeError) as error:
        raise ContractError("distribution configuration is incomplete") from error
    if config.get("ConnectionMode") != "tenant-only":
        raise ContractError("parent must be a CloudFront multi-tenant distribution")
    if behavior.get("ViewerProtocolPolicy") != "https-only":
        raise ContractError("authenticated Viewer traffic requires https-only")
    if behavior.get("CachePolicyId") != CACHING_DISABLED_ID:
        raise ContractError("authenticated Viewer traffic requires CachingDisabled")
    if behavior.get("OriginRequestPolicyId") != ALL_VIEWER_EXCEPT_HOST_ID:
        raise ContractError("the reviewed Origin Request Policy is mandatory")
    if behavior.get("TargetOriginId") != ORIGIN_ID:
        raise ContractError("default behavior targets an unknown origin")
    if config.get("CacheBehaviors") != {"Quantity": 0}:
        raise ContractError("unqualified route-specific cache behaviors are forbidden")
    if origins.get("Quantity") != 1 or len(origins.get("Items", [])) != 1:
        raise ContractError("the bounded baseline requires exactly one parameterized origin")
    if origin.get("Id") != ORIGIN_ID or origin.get("DomainName") != ORIGIN_TEMPLATE:
        raise ContractError("OriginDomain must be a required tenant parameter")
    if origin.get("CustomOriginConfig", {}).get("OriginProtocolPolicy") != "https-only":
        raise ContractError("the PROTECTED Origin seam requires https-only")
    expected_definition = [
        {
            "Name": ORIGIN_PARAMETER,
            "Definition": {"StringSchema": {"Required": True}},
        }
    ]
    if definitions != expected_definition:
        raise ContractError("OriginDomain must be the sole required tenant parameter")


def build_create_tenant_request(inputs: TenantInputs) -> dict[str, object]:
    """Create one enabled tenant and request, but never imply, domain activation."""

    if type(inputs) is not TenantInputs:
        raise ContractError("typed tenant inputs are required")
    return {
        "DistributionId": inputs.distribution_id,
        "Name": inputs.deployment_key,
        "Domains": [{"Domain": inputs.viewer_domain}],
        "Parameters": [{"Name": ORIGIN_PARAMETER, "Value": inputs.origin_domain}],
        "ConnectionGroupId": inputs.connection_group_id,
        "ManagedCertificateRequest": {
            "ValidationTokenHost": "cloudfront",
            "PrimaryDomainName": inputs.viewer_domain,
            "CertificateTransparencyLoggingPreference": "enabled",
        },
        "Enabled": True,
    }


def plan_create_tenant(inputs: TenantInputs) -> AwsOperationPlan:
    request = build_create_tenant_request(inputs)
    return AwsOperationPlan(
        operation=Operation.CREATE_TENANT,
        api_operation="CreateDistributionTenant",
        resource_id=None,
        if_match=None,
        parameters=request,
    )


def plan_inspection(operation: Operation, target: CloudFrontTarget) -> AwsOperationPlan:
    """Plan an exact-ID read; names and account-wide discovery are excluded."""

    if operation is Operation.INSPECT_DISTRIBUTION:
        resource_id = target.distribution_id
        api_operation = "GetDistributionConfig"
    elif operation is Operation.INSPECT_CONNECTION_GROUP:
        resource_id = target.connection_group_id
        api_operation = "GetConnectionGroup"
    elif operation is Operation.INSPECT_TENANT:
        resource_id = target.tenant_id
        api_operation = "GetDistributionTenant"
    elif operation is Operation.INSPECT_CERTIFICATE:
        resource_id = target.tenant_id
        api_operation = "GetManagedCertificateDetails"
    else:
        raise ContractError("operation is not a CloudFront inspection")
    if resource_id is None:
        raise ContractError("inspection requires the strongest provider-native ID")
    return AwsOperationPlan(
        operation=operation,
        api_operation=api_operation,
        resource_id=resource_id,
        if_match=None,
        parameters={},
    )


def normalize_connection_group_response(
    response: object, *, tenant_association_present: bool
) -> ConnectionGroupObservation:
    """Normalize GetConnectionGroup plus the caller's exact known association fact."""

    if type(response) is not dict or type(response.get("ConnectionGroup")) is not dict:
        raise ContractError("CloudFront connection group response is outside the reviewed shape")
    group = response["ConnectionGroup"]
    try:
        return ConnectionGroupObservation(
            connection_group_id=group["Id"],
            etag=response["ETag"],
            routing_endpoint=group["RoutingEndpoint"],
            enabled=group["Enabled"],
            deployment_status=group["Status"],
            is_default=group["IsDefault"],
            tenant_association_present=tenant_association_present,
        )
    except (KeyError, TypeError) as error:
        raise ContractError("CloudFront connection group response is incomplete") from error


def validate_connection_group_observation(
    observation: ConnectionGroupObservation,
    target: CloudFrontTarget,
    *,
    qualification_owned: bool,
) -> None:
    if type(observation) is not ConnectionGroupObservation or type(target) is not CloudFrontTarget:
        raise ContractError("typed connection group admission inputs are required")
    if (
        target.connection_group_id is None
        or observation.connection_group_id != target.connection_group_id
    ):
        raise ContractError("connection group observation mismatches the exact target")
    if qualification_owned and observation.is_default:
        raise ContractError("qualification-owned connection group must be custom")


def normalize_tenant_response(response: object) -> TenantObservation:
    """Normalize the reviewed GetDistributionTenant SDK representation."""

    if type(response) is not dict or type(response.get("DistributionTenant")) is not dict:
        raise ContractError("CloudFront tenant response is outside the reviewed shape")
    tenant = response["DistributionTenant"]
    domains = tenant.get("Domains")
    parameters = tenant.get("Parameters")
    if type(domains) is not list or len(domains) != 1 or type(domains[0]) is not dict:
        raise ContractError("tenant response requires exactly one Viewer domain")
    if type(parameters) is not list:
        raise ContractError("tenant response has no parameter read-back")
    origin_values = [
        parameter.get("Value")
        for parameter in parameters
        if type(parameter) is dict and parameter.get("Name") == ORIGIN_PARAMETER
    ]
    if len(origin_values) != 1:
        raise ContractError("tenant response has missing or ambiguous OriginDomain")
    customizations = tenant.get("Customizations", {})
    certificate = (
        customizations.get("Certificate", {}).get("Arn")
        if type(customizations) is dict
        else None
    )
    try:
        return TenantObservation(
            tenant_id=tenant["Id"],
            distribution_id=tenant["DistributionId"],
            connection_group_id=tenant["ConnectionGroupId"],
            etag=response["ETag"],
            enabled=tenant["Enabled"],
            deployment_status=tenant["Status"],
            viewer_domain=domains[0]["Domain"],
            domain_status=domains[0]["Status"],
            origin_domain=origin_values[0],
            certificate_arn=certificate,
        )
    except (KeyError, TypeError) as error:
        raise ContractError("CloudFront tenant response is incomplete") from error


def normalize_certificate_response(response: object) -> ManagedCertificateObservation:
    """Normalize GetManagedCertificateDetails without retaining arbitrary output."""

    if type(response) is not dict or type(response.get("ManagedCertificateDetails")) is not dict:
        raise ContractError("managed certificate response is outside the reviewed shape")
    details = response["ManagedCertificateDetails"]
    raw_tokens = details.get("ValidationTokenDetails", [])
    if type(raw_tokens) is not list:
        raise ContractError("managed certificate validation details are malformed")
    try:
        tokens = tuple(
            ValidationToken(
                domain=token["Domain"],
                redirect_from=token["RedirectFrom"],
                redirect_to=token["RedirectTo"],
            )
            for token in raw_tokens
        )
        return ManagedCertificateObservation(
            status=details["CertificateStatus"],
            certificate_arn=details.get("CertificateArn"),
            validation_token_host=details.get("ValidationTokenHost"),
            validation_tokens=tokens,
        )
    except (KeyError, TypeError) as error:
        raise ContractError("managed certificate response is incomplete") from error


def validate_tenant_observation(
    observation: TenantObservation, inputs: TenantInputs, target: CloudFrontTarget
) -> None:
    if not all(
        (
            type(observation) is TenantObservation,
            type(inputs) is TenantInputs,
            type(target) is CloudFrontTarget,
        )
    ):
        raise ContractError("typed tenant admission inputs are required")
    if (
        target.tenant_id is None
        or observation.tenant_id != target.tenant_id
        or observation.distribution_id != inputs.distribution_id
        or observation.distribution_id != target.distribution_id
        or observation.connection_group_id != inputs.connection_group_id
        or observation.connection_group_id != target.connection_group_id
        or observation.viewer_domain != inputs.viewer_domain
        or observation.origin_domain != inputs.origin_domain
    ):
        raise ContractError("tenant observation mismatches the exact target or parameters")


def classify_certificate_state(
    tenant: TenantObservation,
    certificate: ManagedCertificateObservation | None,
) -> CertificateState:
    """Classify only provider-observed facts; tenant existence is never active."""

    if type(tenant) is not TenantObservation:
        raise ContractError("one typed tenant observation is required")
    if certificate is None:
        return CertificateState.REQUESTED
    if type(certificate) is not ManagedCertificateObservation:
        raise ContractError("managed certificate observation is invalid")
    if certificate.validation_token_host == "self-hosted":
        raise ContractError(
            "self-hosted validation contradicts the CloudFront-hosted lifecycle"
        )
    if certificate.status == "pending-validation":
        return CertificateState.VALIDATION_REQUIRED
    if certificate.status == "inactive":
        return CertificateState.INACTIVE
    if certificate.status in {"expired", "validation-timed-out", "revoked", "failed"}:
        return CertificateState.FAILED
    assert certificate.status == "issued"
    if tenant.certificate_arn != certificate.certificate_arn:
        return CertificateState.ISSUED
    if (
        tenant.enabled
        and tenant.deployment_status == "Deployed"
        and tenant.domain_status == "active"
    ):
        return CertificateState.ACTIVE
    return CertificateState.ATTACHED


def _admit_mutation_target(
    target: CloudFrontTarget,
    tenant: TenantObservation,
    inputs: TenantInputs,
    admitted_etag: str,
) -> None:
    validate_tenant_observation(tenant, replace_inputs_origin(inputs, tenant.origin_domain), target)
    _etag(admitted_etag)
    if admitted_etag != tenant.etag:
        raise ContractError("admitted ETag is missing, stale, or mismatched")


def replace_inputs_origin(inputs: TenantInputs, origin_domain: str) -> TenantInputs:
    """Preserve the observed current origin while authorizing a desired update."""

    return TenantInputs(
        deployment_key=inputs.deployment_key,
        distribution_id=inputs.distribution_id,
        connection_group_id=inputs.connection_group_id,
        viewer_domain=inputs.viewer_domain,
        origin_domain=origin_domain,
    )


def plan_tenant_mutation(
    operation: Operation,
    target: CloudFrontTarget,
    tenant: TenantObservation,
    inputs: TenantInputs,
    *,
    admitted_etag: str,
    certificate: ManagedCertificateObservation | None = None,
) -> AwsOperationPlan:
    """Plan one exact ETag-bound tenant mutation with no retries."""

    if type(operation) is not Operation or operation not in {
        Operation.ATTACH_CERTIFICATE,
        Operation.UPDATE_TENANT,
        Operation.DISABLE_TENANT,
        Operation.DELETE_TENANT,
    }:
        raise ContractError("operation is not a tenant mutation")
    _admit_mutation_target(target, tenant, inputs, admitted_etag)
    assert target.tenant_id is not None
    parameters: dict[str, object]
    api_operation = "UpdateDistributionTenant"
    if operation is Operation.ATTACH_CERTIFICATE:
        if certificate is None or certificate.status != "issued":
            raise ContractError("only an issued managed certificate may be attached")
        assert certificate.certificate_arn is not None
        parameters = {
            "Customizations": {"Certificate": {"Arn": certificate.certificate_arn}},
        }
    elif operation is Operation.UPDATE_TENANT:
        parameters = {
            "Parameters": [{"Name": ORIGIN_PARAMETER, "Value": inputs.origin_domain}]
        }
    elif operation is Operation.DISABLE_TENANT:
        parameters = {"Enabled": False}
    else:
        if tenant.enabled or tenant.deployment_status != "Deployed":
            raise ContractError("tenant must be disabled and deployed before deletion")
        parameters = {}
        api_operation = "DeleteDistributionTenant"
    return AwsOperationPlan(
        operation=operation,
        api_operation=api_operation,
        resource_id=target.tenant_id,
        if_match=tenant.etag,
        parameters=parameters,
    )


def plan_connection_group_mutation(
    operation: Operation,
    target: CloudFrontTarget,
    observation: ConnectionGroupObservation,
    *,
    admitted_etag: str,
) -> AwsOperationPlan:
    """Plan exact custom-group disable/delete with current ETag semantics."""

    if operation not in {
        Operation.DISABLE_CONNECTION_GROUP,
        Operation.DELETE_CONNECTION_GROUP,
    }:
        raise ContractError("operation is not a connection group mutation")
    validate_connection_group_observation(
        observation, target, qualification_owned=True
    )
    _etag(admitted_etag)
    if admitted_etag != observation.etag:
        raise ContractError("admitted connection group ETag is stale or mismatched")
    if observation.is_default:
        raise ContractError("default connection groups are never mutated by this lifecycle")
    if operation is Operation.DISABLE_CONNECTION_GROUP:
        api_operation = "UpdateConnectionGroup"
        parameters: dict[str, object] = {"Enabled": False}
    else:
        if (
            observation.enabled
            or observation.deployment_status != "Deployed"
            or observation.tenant_association_present
        ):
            raise ContractError(
                "custom connection group must be unassociated, disabled, and deployed before deletion"
            )
        api_operation = "DeleteConnectionGroup"
        parameters = {}
    return AwsOperationPlan(
        operation=operation,
        api_operation=api_operation,
        resource_id=observation.connection_group_id,
        if_match=observation.etag,
        parameters=parameters,
    )


def plan_distribution_mutation(
    operation: Operation,
    target: CloudFrontTarget,
    distribution: DistributionObservation,
    *,
    admitted_etag: str,
    current_config: Mapping[str, object] | None = None,
) -> AwsOperationPlan:
    """Plan parent update/disable/delete against its exact latest ETag."""

    if target.distribution_id is None or target.distribution_id != distribution.distribution_id:
        raise ContractError("distribution observation mismatches the exact target")
    _etag(admitted_etag)
    if admitted_etag != distribution.etag:
        raise ContractError("admitted distribution ETag is stale or mismatched")
    if operation in {Operation.UPDATE_DISTRIBUTION, Operation.DISABLE_DISTRIBUTION}:
        if type(current_config) is not dict:
            raise ContractError("distribution update requires its complete current configuration")
        parameters = {"DistributionConfig": deep_copy(current_config)}
        validate_distribution_config(parameters["DistributionConfig"])
        if operation is Operation.DISABLE_DISTRIBUTION:
            parameters["DistributionConfig"]["Enabled"] = False
        api_operation = "UpdateDistribution"
    elif operation is Operation.DELETE_DISTRIBUTION:
        if distribution.enabled or distribution.deployment_status != "Deployed":
            raise ContractError("distribution must be disabled and deployed before deletion")
        parameters = {}
        api_operation = "DeleteDistribution"
    else:
        raise ContractError("operation is not a parent teardown mutation")
    return AwsOperationPlan(
        operation=operation,
        api_operation=api_operation,
        resource_id=distribution.distribution_id,
        if_match=distribution.etag,
        parameters=parameters,
    )


def next_teardown_operation(
    tenant: TenantObservation | None,
    connection_group: ConnectionGroupObservation | None,
    distribution: DistributionObservation,
) -> Operation:
    """Return the next exact-target teardown transition; never broad cleanup."""

    if tenant is not None:
        if tenant.enabled:
            return Operation.DISABLE_TENANT
        if tenant.deployment_status != "Deployed":
            return Operation.INSPECT_TENANT
        return Operation.DELETE_TENANT
    if connection_group is not None:
        if connection_group.is_default:
            raise ContractError("default connection groups remain caller-owned prerequisites")
        if connection_group.tenant_association_present:
            raise ContractError("connection group teardown requires cleared tenant associations")
        if connection_group.enabled:
            return Operation.DISABLE_CONNECTION_GROUP
        if connection_group.deployment_status != "Deployed":
            return Operation.INSPECT_CONNECTION_GROUP
        return Operation.DELETE_CONNECTION_GROUP
    if distribution.enabled:
        return Operation.DISABLE_DISTRIBUTION
    if distribution.deployment_status != "Deployed":
        return Operation.INSPECT_DISTRIBUTION
    return Operation.DELETE_DISTRIBUTION


def admit_request(request: LifecycleRequest, authority: ExecutionAuthority) -> None:
    """Apply #169's separately supplied authority and exact-binding pattern."""

    if type(request) is not LifecycleRequest or type(authority) is not ExecutionAuthority:
        raise ContractError("request and authority are required")
    if (
        request.adapter_id != authority.adapter_id
        or request.source_revision != authority.source_revision
        or request.provider_context != authority.provider_context
        or request.target != authority.target
        or request.parameters_sha256 != authority.parameters_sha256
    ):
        raise ContractError("request does not match the exact authorized target")
    if request.operation not in authority.operations:
        raise ContractError("operation is not authorized for this exact target")
    if request.operation is not Operation.CREATE_DISTRIBUTION:
        if request.target.distribution_id is None:
            raise ContractError("operation requires a provider-native distribution ID")
    if request.operation in {
        Operation.INSPECT_CONNECTION_GROUP,
        Operation.DISABLE_CONNECTION_GROUP,
        Operation.DELETE_CONNECTION_GROUP,
        Operation.CREATE_TENANT,
        Operation.INSPECT_TENANT,
        Operation.INSPECT_CERTIFICATE,
        Operation.ATTACH_CERTIFICATE,
        Operation.UPDATE_TENANT,
        Operation.DISABLE_TENANT,
        Operation.DELETE_TENANT,
    } and request.target.connection_group_id is None:
        raise ContractError("operation requires a provider-native connection group ID")
    if request.operation in {
        Operation.INSPECT_TENANT,
        Operation.INSPECT_CERTIFICATE,
        Operation.ATTACH_CERTIFICATE,
        Operation.UPDATE_TENANT,
        Operation.DISABLE_TENANT,
        Operation.DELETE_TENANT,
    } and request.target.tenant_id is None:
        raise ContractError("tenant operation requires a provider-native tenant ID")


def admit_result(request: LifecycleRequest, result: LifecycleResult) -> None:
    """Admit a closed, correlated result without arbitrary provider output."""

    if type(request) is not LifecycleRequest or type(result) is not LifecycleResult:
        raise ContractError("request and result are required")
    if (
        result.request_id != request.request_id
        or result.adapter_id != request.adapter_id
        or result.source_revision != request.source_revision
        or result.provider_context != request.provider_context
        or result.target != request.target
        or result.operation is not request.operation
        or result.parameters_sha256 != request.parameters_sha256
    ):
        raise ContractError("result is not bound to the exact request")
    if request.operation in {
        Operation.CREATE_CONNECTION_GROUP,
        Operation.CREATE_TENANT,
    }:
        expected_resource = None
    elif request.operation in {
        Operation.INSPECT_TENANT,
        Operation.INSPECT_CERTIFICATE,
        Operation.ATTACH_CERTIFICATE,
        Operation.UPDATE_TENANT,
        Operation.DISABLE_TENANT,
        Operation.DELETE_TENANT,
    }:
        expected_resource = request.target.tenant_id
    elif request.operation in {
        Operation.INSPECT_CONNECTION_GROUP,
        Operation.DISABLE_CONNECTION_GROUP,
        Operation.DELETE_CONNECTION_GROUP,
    }:
        expected_resource = request.target.connection_group_id
    else:
        expected_resource = request.target.distribution_id
    if result.resource_id is not None and expected_resource is not None:
        if result.resource_id != expected_resource:
            raise ContractError("result resource identity mismatches the target")
    if result.outcome is Outcome.DELETED and (
        result.resource_id is not None or result.resource_etag is not None
    ):
        raise ContractError("deleted result must not imply retained mutable state")


def qualification_operations() -> tuple[Operation, ...]:
    """Closed operation order for a later explicitly authorized AWS run."""

    return (
        Operation.CREATE_DISTRIBUTION,
        Operation.INSPECT_DISTRIBUTION,
        Operation.CREATE_CONNECTION_GROUP,
        Operation.INSPECT_CONNECTION_GROUP,
        Operation.CREATE_TENANT,
        Operation.INSPECT_TENANT,
        Operation.INSPECT_CERTIFICATE,
        Operation.ATTACH_CERTIFICATE,
        Operation.INSPECT_TENANT,
        Operation.INSPECT_CERTIFICATE,
        Operation.UPDATE_TENANT,
        Operation.INSPECT_TENANT,
        Operation.DISABLE_TENANT,
        Operation.INSPECT_TENANT,
        Operation.DELETE_TENANT,
        Operation.DISABLE_CONNECTION_GROUP,
        Operation.INSPECT_CONNECTION_GROUP,
        Operation.DELETE_CONNECTION_GROUP,
        Operation.DISABLE_DISTRIBUTION,
        Operation.INSPECT_DISTRIBUTION,
        Operation.DELETE_DISTRIBUTION,
    )
