#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Pure portable contract for the ADR-019 PROTECTED CloudFront WAF baseline.

This module plans and admits bounded AWS WAF and CloudFront operations. It never
loads credentials, calls AWS, creates a resource, or retains provider output.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from typing import FrozenSet, Mapping


SHA1 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
ACCOUNT_ID = re.compile(r"^[0-9]{12}$")
DDOS_REQUEST_LABEL = "awswaf:managed:aws:anti-ddos:ddos-request"
MANAGED_VENDOR = "AWS"
MANAGED_NAME = "AWSManagedRulesAntiDDoSRuleSet"
WAF_SCOPE = "CLOUDFRONT"
PROVIDER_PRIVACY_LIMITATION = (
    "AWS-WAF-TOKEN is a provider-owned cookie exception to current AWS WAF "
    "data-protection coverage; sampling remains disabled."
)
SENSITIVE_HEADERS = (
    "authorization",
    "cookie",
    "x-secpal-origin-token",
    "x-secpal-viewer-host",
    "x-secpal-viewer-ip",
)


class ContractError(ValueError):
    """A supplied fact, plan, authority, or result is outside the contract."""


class ManagedRuleMode(str, Enum):
    QUALIFICATION_COUNT = "qualification-count"
    ENFORCEMENT = "enforcement"


class Operation(str, Enum):
    DISCOVER_MANAGED_RULE = "discover-managed-rule"
    CHECK_CAPACITY = "check-capacity"
    CREATE_WEB_ACL = "create-web-acl"
    INSPECT_WEB_ACL = "inspect-web-acl"
    UPDATE_WEB_ACL = "update-web-acl"
    ASSOCIATE_DISTRIBUTION = "associate-distribution"
    INSPECT_DISTRIBUTION = "inspect-distribution"
    INSPECT_TENANT = "inspect-tenant"
    PUT_LOGGING = "put-logging"
    INSPECT_LOGGING = "inspect-logging"
    DELETE_LOGGING = "delete-logging"
    DISASSOCIATE_DISTRIBUTION = "disassociate-distribution"
    DELETE_WEB_ACL = "delete-web-acl"


class Outcome(str, Enum):
    APPLIED = "applied"
    OBSERVED = "observed"
    FAILED = "failed"


def _identity(label: str, value: object) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise ContractError(f"{label} requires one explicit non-empty identity")
    if not value.isprintable() or len(value.encode("utf-8")) > 4096:
        raise ContractError(f"{label} is outside the bounded identity format")


def _token(label: str, value: object) -> None:
    _identity(label, value)
    if len(value) > 4096:
        raise ContractError(f"{label} is too long")


def _mapping(label: str, value: object) -> dict[str, object]:
    if type(value) is not dict:
        raise ContractError(f"{label} is outside the reviewed response shape")
    return value


@dataclass(frozen=True, slots=True)
class AwsProviderContext:
    """The exact AWS account and endpoint authority for this WAF contract."""

    partition: str
    account_id: str
    waf_region: str

    def __post_init__(self) -> None:
        if self.partition != "aws" or self.waf_region != "us-east-1":
            raise ContractError("PROTECTED WAF requires aws/us-east-1")
        if ACCOUNT_ID.fullmatch(self.account_id) is None:
            raise ContractError("AWS account identity must contain exactly 12 digits")


@dataclass(frozen=True, slots=True)
class WafTarget:
    """Exact CloudFront and WAF identities; names never authorize mutation."""

    requested_key: str
    distribution_id: str
    web_acl_id: str | None = None
    web_acl_arn: str | None = None
    logging_destination_arn: str | None = None
    qualification_owned: bool = False

    def __post_init__(self) -> None:
        _identity("requested WAF key", self.requested_key)
        _identity("CloudFront distribution identity", self.distribution_id)
        if (self.web_acl_id is None) != (self.web_acl_arn is None):
            raise ContractError("Web ACL ID and ARN must be present together")
        for label, value in (
            ("Web ACL identity", self.web_acl_id),
            ("Web ACL ARN", self.web_acl_arn),
        ):
            if value is not None:
                _identity(label, value)
        if self.logging_destination_arn is not None:
            validate_logging_destination_arn(self.logging_destination_arn)


@dataclass(frozen=True, slots=True)
class ManagedRuleVersion:
    """One bounded static-version fact; lifetime is absent when AWS omits it."""

    name: str
    forecasted_lifetime: str | None

    def __post_init__(self) -> None:
        _identity("managed-rule version", self.name)
        if self.forecasted_lifetime is not None:
            _identity("managed-rule forecasted lifetime", self.forecasted_lifetime)


@dataclass(frozen=True, slots=True)
class ManagedRule:
    """A current provider rule/action observation, not a permanent rule list."""

    name: str
    action: str

    def __post_init__(self) -> None:
        _identity("managed-rule name", self.name)
        _identity("managed-rule action", self.action)


@dataclass(frozen=True, slots=True)
class ProviderDiscovery:
    """Closed discovery facts needed to admit the exact shared WAF baseline."""

    vendor: str
    name: str
    scope: str
    current_default_version: str
    available_versions: tuple[ManagedRuleVersion, ...]
    capacity: int
    check_capacity: int
    web_acl_capacity_ceiling: int
    available_rules: tuple[ManagedRule, ...]
    available_labels: FrozenSet[str]
    consumed_labels: FrozenSet[str]
    challenge_usage_values: FrozenSet[str]
    block_sensitivity_values: FrozenSet[str]

    def __post_init__(self) -> None:
        for label, value, expected in (
            ("managed-rule vendor", self.vendor, MANAGED_VENDOR),
            ("managed-rule name", self.name, MANAGED_NAME),
            ("managed-rule scope", self.scope, WAF_SCOPE),
        ):
            if value != expected:
                raise ContractError(f"{label} is not the accepted provider identity")
        _identity("current default managed-rule version", self.current_default_version)
        if not self.available_versions or any(
            type(version) is not ManagedRuleVersion for version in self.available_versions
        ):
            raise ContractError("managed-rule versions are outside the reviewed shape")
        if not self.available_rules or any(
            type(rule) is not ManagedRule for rule in self.available_rules
        ):
            raise ContractError("managed-rule inventory is outside the reviewed shape")
        for label, value in (
            ("available labels", self.available_labels),
            ("consumed labels", self.consumed_labels),
            ("challenge usage values", self.challenge_usage_values),
            ("block sensitivity values", self.block_sensitivity_values),
        ):
            if type(value) is not frozenset or any(type(item) is not str for item in value):
                raise ContractError(f"{label} are outside the reviewed shape")


def admit_provider_discovery(discovery: ProviderDiscovery) -> None:
    """Fail closed when mutable provider facts no longer support this contract."""

    if type(discovery) is not ProviderDiscovery:
        raise ContractError("typed provider discovery is required")
    if discovery.current_default_version not in {
        version.name for version in discovery.available_versions
    }:
        raise ContractError("current default managed-rule version is unresolved")
    if not all(type(value) is int and value > 0 for value in (
        discovery.capacity, discovery.check_capacity, discovery.web_acl_capacity_ceiling,
    )):
        raise ContractError("provider capacity facts must be positive")
    if discovery.check_capacity != discovery.capacity:
        raise ContractError("exact CheckCapacity does not admit the managed-rule capacity")
    if discovery.check_capacity > discovery.web_acl_capacity_ceiling:
        raise ContractError("exact WAF configuration exceeds the current Web ACL ceiling")
    if DDOS_REQUEST_LABEL not in discovery.available_labels:
        raise ContractError("reviewed anti-DDoS logging label is absent")
    if "DISABLED" not in discovery.challenge_usage_values:
        raise ContractError("provider no longer supports disabled client-side challenge")
    if "LOW" not in discovery.block_sensitivity_values:
        raise ContractError("provider no longer supports low block sensitivity")


def _visibility(metric_name: str) -> dict[str, object]:
    return {
        "CloudWatchMetricsEnabled": True,
        "MetricName": metric_name,
        "SampledRequestsEnabled": False,
    }


def build_managed_rule(mode: ManagedRuleMode) -> dict[str, object]:
    """Build the one reviewed managed-rule entry without pinning Version."""

    if type(mode) is not ManagedRuleMode:
        raise ContractError("managed-rule mode must be closed")
    override = (
        {"Count": {}}
        if mode is ManagedRuleMode.QUALIFICATION_COUNT
        else {"None": {}}
    )
    return {
        "Name": "secpal-anti-ddos",
        "Priority": 0,
        "Statement": {
            "ManagedRuleGroupStatement": {
                "VendorName": MANAGED_VENDOR,
                "Name": MANAGED_NAME,
                "ManagedRuleGroupConfigs": [{
                    "AWSManagedRulesAntiDDoSRuleSet": {
                        "ClientSideActionConfig": {
                            "Challenge": {"UsageOfAction": "DISABLED"},
                        },
                        "SensitivityToBlock": "LOW",
                    },
                }],
            },
        },
        "OverrideAction": override,
        "VisibilityConfig": _visibility("secpal-anti-ddos"),
    }


def production_enforcement_accepted(mode: ManagedRuleMode) -> bool:
    """Count is qualification evidence only and can never claim enforcement."""

    if type(mode) is not ManagedRuleMode:
        raise ContractError("managed-rule mode must be closed")
    return mode is ManagedRuleMode.ENFORCEMENT


def _data_protections() -> list[dict[str, object]]:
    return [
        {
            "Action": "SUBSTITUTION",
            "Field": {"FieldType": "BODY"},
            "ExcludeRateBasedDetails": False,
            "ExcludeRuleMatchDetails": False,
        },
        {
            "Action": "SUBSTITUTION",
            "Field": {"FieldType": "QUERY_STRING"},
            "ExcludeRateBasedDetails": False,
            "ExcludeRuleMatchDetails": False,
        },
        {
            "Action": "SUBSTITUTION",
            "Field": {"FieldType": "SINGLE_HEADER"},
            "ExcludeRateBasedDetails": False,
            "ExcludeRuleMatchDetails": False,
        },
    ]


def build_web_acl(mode: ManagedRuleMode) -> dict[str, object]:
    """Build the complete shared Web ACL replacement configuration."""

    rule = build_managed_rule(mode)
    configuration = {
        "Scope": WAF_SCOPE,
        "DefaultAction": {"Allow": {}},
        "Rules": [rule],
        "VisibilityConfig": _visibility("secpal-protected-waf"),
        "DataProtectionConfig": {"DataProtections": _data_protections()},
    }
    validate_waf_rule_trust(configuration)
    return configuration


def _walk_strings(value: object):
    if type(value) is dict:
        for item in value.values():
            yield from _walk_strings(item)
    elif type(value) is list:
        for item in value:
            yield from _walk_strings(item)
    elif type(value) is str:
        yield value


def validate_waf_rule_trust(configuration: object) -> None:
    """Reject WAF rule statements that derive authority from #211 internal headers."""

    config = _mapping("WAF configuration", configuration)
    rules = config.get("Rules")
    if type(rules) is not list or len(rules) != 1:
        raise ContractError("shared WAF requires exactly one managed rule entry")
    for value in _walk_strings(rules):
        if value.lower() in SENSITIVE_HEADERS[2:]:
            raise ContractError("WAF rule configuration trusts a Function-bound header")


def waf_contract_for_viewer_headers(headers: Mapping[str, str]) -> dict[str, object]:
    """Return the unchanged WAF contract; Viewer headers are never WAF authority."""

    if not isinstance(headers, Mapping) or any(
        type(key) is not str or type(value) is not str for key, value in headers.items()
    ):
        raise ContractError("Viewer headers must be ordinary string request data")
    return build_web_acl(ManagedRuleMode.ENFORCEMENT)


def validate_logging_destination_arn(arn: object) -> None:
    """Accept only documented WAF destination families without parsing their details."""

    _identity("logging destination ARN", arn)
    parts = arn.split(":", 5)
    if len(parts) != 6 or parts[0] != "arn" or parts[2] not in {"logs", "s3", "firehose"}:
        raise ContractError("logging destination is not a supported AWS WAF destination")


def _redacted_fields() -> list[dict[str, object]]:
    return [
        {"UriPath": {}},
        {"QueryString": {}},
        *[{"SingleHeader": {"Name": header}} for header in SENSITIVE_HEADERS],
    ]


def build_logging_configuration(target: WafTarget) -> dict[str, object]:
    """Build one default-drop, label-only logging configuration for an exact ACL."""

    if type(target) is not WafTarget or target.web_acl_arn is None:
        raise ContractError("logging requires the exact Web ACL ARN")
    if target.logging_destination_arn is None:
        raise ContractError("logging requires one exact caller-supplied destination")
    return {
        "ResourceArn": target.web_acl_arn,
        "LogDestinationConfigs": [target.logging_destination_arn],
        "RedactedFields": _redacted_fields(),
        "LoggingFilter": {
            "DefaultBehavior": "DROP",
            "Filters": [{
                "Behavior": "KEEP",
                "Requirement": "MEETS_ANY",
                "Conditions": [{"LabelNameCondition": {"LabelName": DDOS_REQUEST_LABEL}}],
            }],
        },
    }


@dataclass(frozen=True, slots=True)
class TenantWafObservation:
    tenant_id: str
    distribution_id: str


def normalize_tenant_waf_observation(response: object, target: WafTarget) -> TenantWafObservation:
    """Inspect only the tenant WAF seam; unrelated customizations remain valid."""

    if type(target) is not WafTarget:
        raise ContractError("typed WAF target is required")
    response_map = _mapping("response", response)
    tenant = _mapping(
        "Distribution Tenant response", response_map.get("DistributionTenant")
    )
    tenant_id = tenant.get("Id")
    distribution_id = tenant.get("DistributionId")
    _identity("Distribution Tenant identity", tenant_id)
    if distribution_id != target.distribution_id:
        raise ContractError("tenant does not belong to the exact shared distribution")
    customizations = tenant.get("Customizations")
    if customizations is None:
        return TenantWafObservation(tenant_id, distribution_id)
    customizations = _mapping("tenant customizations", customizations)
    web_acl = customizations.get("WebAcl")
    if web_acl is None:
        return TenantWafObservation(tenant_id, distribution_id)
    web_acl = _mapping("tenant WebAcl customization", web_acl)
    action = web_acl.get("Action")
    if action in {"override", "disable"}:
        raise ContractError("tenant WAF override or disable escapes the shared baseline")
    raise ContractError("tenant WebAcl customization has an unknown action")


@dataclass(frozen=True, slots=True)
class DistributionObservation:
    distribution_id: str
    etag: str
    web_acl_arn: str | None

    def __post_init__(self) -> None:
        _identity("distribution identity", self.distribution_id)
        _token("CloudFront ETag", self.etag)
        if self.web_acl_arn is not None:
            _identity("observed distribution Web ACL ARN", self.web_acl_arn)


@dataclass(frozen=True, slots=True)
class WebAclObservation:
    web_acl_id: str
    web_acl_arn: str
    lock_token: str
    configuration: dict[str, object]

    def __post_init__(self) -> None:
        _identity("Web ACL identity", self.web_acl_id)
        _identity("Web ACL ARN", self.web_acl_arn)
        _token("WAF LockToken", self.lock_token)
        _mapping("complete Web ACL configuration", self.configuration)


def normalize_web_acl_observation(response: object, target: WafTarget) -> WebAclObservation:
    """Normalize one exact GetWebACL response without retaining arbitrary output."""

    if type(target) is not WafTarget:
        raise ContractError("typed WAF target is required")
    response_map = _mapping("GetWebACL response", response)
    web_acl = _mapping("GetWebACL WebACL", response_map.get("WebACL"))
    observation = WebAclObservation(
        web_acl.get("Id"), web_acl.get("ARN"), response_map.get("LockToken"), web_acl
    )
    _exact_web_acl(target, observation)
    return observation


def normalize_distribution_observation(response: object, target: WafTarget) -> DistributionObservation:
    """Normalize the exact CloudFront distribution configuration and its ETag."""

    if type(target) is not WafTarget:
        raise ContractError("typed WAF target is required")
    response_map = _mapping("GetDistributionConfig response", response)
    config = _mapping(
        "distribution configuration", response_map.get("DistributionConfig")
    )
    observation = DistributionObservation(
        response_map.get("Id", target.distribution_id), response_map.get("ETag"),
        config.get("WebACLId"),
    )
    if observation.distribution_id != target.distribution_id:
        raise ContractError("distribution observation does not match the exact target")
    return observation


@dataclass(frozen=True, slots=True)
class AwsOperationPlan:
    operation: Operation
    api_operation: str
    resource_id: str
    parameters: dict[str, object]
    if_match: str | None = None
    lock_token: str | None = None


def _exact_web_acl(target: WafTarget, observation: WebAclObservation) -> None:
    if target.web_acl_id != observation.web_acl_id or target.web_acl_arn != observation.web_acl_arn:
        raise ContractError("Web ACL observation does not match the exact target")


def plan_create_web_acl(
    target: WafTarget, mode: ManagedRuleMode
) -> AwsOperationPlan:
    """Plan creation only before a provider-native Web ACL identity exists."""

    if type(target) is not WafTarget:
        raise ContractError("typed WAF target is required")
    if target.web_acl_id is not None or target.web_acl_arn is not None:
        raise ContractError("create requires a target without an existing Web ACL")
    return AwsOperationPlan(
        Operation.CREATE_WEB_ACL,
        "CreateWebACL",
        target.requested_key,
        {"Name": target.requested_key, **build_web_acl(mode)},
    )


def plan_associate_distribution(
    target: WafTarget,
    observation: DistributionObservation,
    admitted_etag: str,
) -> AwsOperationPlan:
    """Plan distribution-only association from the freshly admitted ETag."""

    if type(target) is not WafTarget or type(observation) is not DistributionObservation:
        raise ContractError("typed association inputs are required")
    if observation.distribution_id != target.distribution_id or admitted_etag != observation.etag:
        raise ContractError("distribution ETag is missing, stale, or mismatched")
    if target.web_acl_arn is None:
        raise ContractError("association requires the exact shared Web ACL ARN")
    return AwsOperationPlan(
        Operation.ASSOCIATE_DISTRIBUTION, "AssociateDistributionWebACL", target.distribution_id,
        {"WebACLArn": target.web_acl_arn}, if_match=observation.etag,
    )


def plan_update_web_acl(
    target: WafTarget,
    observation: WebAclObservation,
    admitted_lock_token: str,
    desired_configuration: dict[str, object],
) -> AwsOperationPlan:
    """Plan one replacement-style update with a current WAF LockToken."""

    if type(target) is not WafTarget or type(observation) is not WebAclObservation:
        raise ContractError("typed Web ACL update inputs are required")
    _exact_web_acl(target, observation)
    if admitted_lock_token != observation.lock_token:
        raise ContractError("WAF LockToken is missing, stale, or mismatched")
    _mapping("desired complete Web ACL configuration", desired_configuration)
    return AwsOperationPlan(
        Operation.UPDATE_WEB_ACL, "UpdateWebACL", observation.web_acl_id,
        desired_configuration, lock_token=observation.lock_token,
    )


def plan_rollback(
    target: WafTarget,
    current: WebAclObservation,
    admitted_lock_token: str,
    prior_configuration: dict[str, object],
) -> AwsOperationPlan:
    """Restore one prior complete configuration using a fresh post-failure token."""

    return plan_update_web_acl(target, current, admitted_lock_token, prior_configuration)


def plan_logging_configuration(target: WafTarget, operation: Operation) -> AwsOperationPlan:
    """Plan the exact Web ACL logging lifecycle without managing its destination."""

    if type(target) is not WafTarget or target.web_acl_arn is None:
        raise ContractError("logging lifecycle requires the exact Web ACL ARN")
    if type(operation) is not Operation:
        raise ContractError("logging operation must be closed")
    if operation is Operation.PUT_LOGGING:
        return AwsOperationPlan(
            operation,
            "PutLoggingConfiguration",
            target.web_acl_arn,
            build_logging_configuration(target),
        )
    if operation is Operation.INSPECT_LOGGING:
        return AwsOperationPlan(
            operation,
            "GetLoggingConfiguration",
            target.web_acl_arn,
            {"ResourceArn": target.web_acl_arn},
        )
    if operation is Operation.DELETE_LOGGING:
        return AwsOperationPlan(
            operation,
            "DeleteLoggingConfiguration",
            target.web_acl_arn,
            {"ResourceArn": target.web_acl_arn},
        )
    raise ContractError("operation is not a logging lifecycle operation")


def plan_cleanup(
    target: WafTarget,
    web_acl: WebAclObservation,
    distribution: DistributionObservation,
    admitted_lock_token: str,
    admitted_etag: str,
) -> tuple[AwsOperationPlan, ...]:
    """Return exact qualification cleanup; external or guessed resources are excluded."""

    if type(target) is not WafTarget or not target.qualification_owned:
        raise ContractError("only exact qualification-owned resources authorize cleanup")
    _exact_web_acl(target, web_acl)
    if distribution.distribution_id != target.distribution_id:
        raise ContractError("cleanup distribution does not match the exact target")
    if admitted_lock_token != web_acl.lock_token or admitted_etag != distribution.etag:
        raise ContractError("cleanup requires fresh WAF LockToken and CloudFront ETag")
    return (
        plan_logging_configuration(target, Operation.DELETE_LOGGING),
        AwsOperationPlan(
            Operation.DISASSOCIATE_DISTRIBUTION,
            "DisassociateDistributionWebACL",
            distribution.distribution_id,
            {},
            if_match=distribution.etag,
        ),
        AwsOperationPlan(
            Operation.DELETE_WEB_ACL,
            "DeleteWebACL",
            web_acl.web_acl_id,
            {},
            lock_token=web_acl.lock_token,
        ),
    )


@dataclass(frozen=True, slots=True)
class ExecutionAuthority:
    authorization_id: str
    adapter_id: str
    source_revision: str
    provider_context: AwsProviderContext
    target: WafTarget
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
        if SHA1.fullmatch(self.source_revision) is None or SHA256.fullmatch(self.parameters_sha256) is None:
            raise ContractError("authority requires exact source and parameter digests")
        if type(self.provider_context) is not AwsProviderContext or type(self.target) is not WafTarget:
            raise ContractError("authority requires exact provider context and target")
        if (
            type(self.operations) is not frozenset
            or not self.operations
            or any(type(item) is not Operation for item in self.operations)
        ):
            raise ContractError("authority requires closed WAF operations")


@dataclass(frozen=True, slots=True)
class LifecycleRequest:
    request_id: str
    adapter_id: str
    source_revision: str
    provider_context: AwsProviderContext
    target: WafTarget
    operation: Operation
    parameters_sha256: str

    def __post_init__(self) -> None:
        _identity("request identity", self.request_id)
        _identity("adapter identity", self.adapter_id)
        if SHA1.fullmatch(self.source_revision) is None or SHA256.fullmatch(self.parameters_sha256) is None:
            raise ContractError("request requires exact source and parameter digests")
        if type(self.provider_context) is not AwsProviderContext or type(self.target) is not WafTarget or type(self.operation) is not Operation:
            raise ContractError("request is outside the closed WAF contract")


@dataclass(frozen=True, slots=True)
class LifecycleResult:
    request_id: str
    adapter_id: str
    source_revision: str
    provider_context: AwsProviderContext
    target: WafTarget
    operation: Operation
    parameters_sha256: str
    outcome: Outcome
    diagnostic_code: str | None = None

    def __post_init__(self) -> None:
        if type(self.outcome) is not Outcome:
            raise ContractError("result outcome is outside the closed WAF contract")
        if self.diagnostic_code is not None:
            _identity("bounded diagnostic code", self.diagnostic_code)
            if re.fullmatch(r"[a-z0-9]+(?:[._-][a-z0-9]+)*", self.diagnostic_code) is None:
                raise ContractError("diagnostic code is outside the bounded format")


def admit_request(request: LifecycleRequest, authority: ExecutionAuthority) -> None:
    if type(request) is not LifecycleRequest or type(authority) is not ExecutionAuthority:
        raise ContractError("typed request and authority are required")
    request_binding = (
        request.adapter_id,
        request.source_revision,
        request.provider_context,
        request.target,
        request.parameters_sha256,
    )
    authority_binding = (
        authority.adapter_id,
        authority.source_revision,
        authority.provider_context,
        authority.target,
        authority.parameters_sha256,
    )
    if request_binding != authority_binding:
        raise ContractError("request is not bound to the exact execution authority")
    if request.operation not in authority.operations:
        raise ContractError("WAF operation is not authorized")


def admit_result(request: LifecycleRequest, result: LifecycleResult) -> None:
    if type(request) is not LifecycleRequest or type(result) is not LifecycleResult:
        raise ContractError("typed request and result are required")
    result_binding = (
        result.request_id,
        result.adapter_id,
        result.source_revision,
        result.provider_context,
        result.target,
        result.operation,
        result.parameters_sha256,
    )
    request_binding = (
        request.request_id,
        request.adapter_id,
        request.source_revision,
        request.provider_context,
        request.target,
        request.operation,
        request.parameters_sha256,
    )
    if result_binding != request_binding:
        raise ContractError("result is not bound to the exact WAF request")
    if result.outcome is Outcome.FAILED and result.diagnostic_code is None:
        raise ContractError("failed result requires a bounded diagnostic code")
    if result.outcome is not Outcome.FAILED and result.diagnostic_code is not None:
        raise ContractError("successful result cannot carry a failure diagnostic")
    observed_operations = {
        Operation.DISCOVER_MANAGED_RULE,
        Operation.CHECK_CAPACITY,
        Operation.INSPECT_WEB_ACL,
        Operation.INSPECT_DISTRIBUTION,
        Operation.INSPECT_TENANT,
        Operation.INSPECT_LOGGING,
    }
    if (
        result.outcome is Outcome.OBSERVED
        and request.operation not in observed_operations
    ):
        raise ContractError("observed outcome contradicts a mutating WAF operation")
