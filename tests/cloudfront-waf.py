#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Behavior evidence for the portable PROTECTED CloudFront WAF contract."""

from __future__ import annotations

import copy
from dataclasses import replace
import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "scripts" / "cloudfront-waf.py"


def load_contract():
    specification = importlib.util.spec_from_file_location("cloudfront_waf", CONTRACT_PATH)
    if specification is None or specification.loader is None:
        raise RuntimeError("unable to load CloudFront WAF contract")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


class CloudFrontWafTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = load_contract()
        cls.context = cls.contract.AwsProviderContext(
            partition="aws", account_id="123456789012", waf_region="us-east-1"
        )
        cls.target = cls.contract.WafTarget(
            requested_key="qualification-212",
            distribution_id="E1EXAMPLEDISTRIBUTION",
            web_acl_id="acl-example", web_acl_arn="arn:aws:wafv2:us-east-1:123456789012:global/webacl/example/acl-example",
            logging_destination_arn="arn:aws:logs:us-east-1:123456789012:log-group:aws-waf-logs-example",
            qualification_owned=True,
        )
        cls.discovery = cls.contract.ProviderDiscovery(
            vendor="AWS", name="AWSManagedRulesAntiDDoSRuleSet", scope="CLOUDFRONT",
            current_default_version="Version_1.0", available_versions=(
                cls.contract.ManagedRuleVersion("Version_1.0", None),
            ), capacity=50, check_capacity=50, web_acl_capacity_ceiling=5000,
            available_rules=(
                cls.contract.ManagedRule("challenge-a", "Challenge"),
                cls.contract.ManagedRule("block-a", "Block"),
            ), available_labels=frozenset({cls.contract.DDOS_REQUEST_LABEL}),
            consumed_labels=frozenset(), challenge_usage_values=frozenset({"DISABLED", "ENABLED"}),
            block_sensitivity_values=frozenset({"LOW", "MEDIUM", "HIGH"}),
        )

    def test_provider_default_is_admitted_without_a_permanent_pin(self) -> None:
        self.contract.admit_provider_discovery(self.discovery)
        with_additional_version = replace(
            self.discovery,
            available_versions=self.discovery.available_versions
            + (self.contract.ManagedRuleVersion("Version_new", None),),
        )
        self.contract.admit_provider_discovery(with_additional_version)
        rule = self.contract.build_managed_rule(self.contract.ManagedRuleMode.ENFORCEMENT)
        self.assertNotIn("Version", rule["Statement"]["ManagedRuleGroupStatement"])

    def test_capacity_is_dynamic_not_fixed_at_fifty(self) -> None:
        dynamic = replace(self.discovery, capacity=61, check_capacity=61)
        self.contract.admit_provider_discovery(dynamic)
        self.assertEqual(61, dynamic.capacity)

    def test_unqualified_new_provider_default_requires_requalification(self) -> None:
        drifted = replace(
            self.discovery,
            current_default_version="Version_new",
            available_versions=(
                self.contract.ManagedRuleVersion("Version_1.0", None),
                self.contract.ManagedRuleVersion("Version_new", None),
            ),
        )
        with self.assertRaisesRegex(self.contract.ContractError, "requalification"):
            self.contract.admit_provider_discovery(drifted)

    def test_provider_drift_fails_closed(self) -> None:
        cases = {
            "missing-label": replace(self.discovery, available_labels=frozenset()),
            "missing-low": replace(self.discovery, block_sensitivity_values=frozenset({"HIGH"})),
            "bad-capacity": replace(self.discovery, capacity=0),
            "check-failed": replace(self.discovery, check_capacity=51),
            "unknown-default": replace(self.discovery, current_default_version="unknown"),
        }
        for label, observation in cases.items():
            with self.subTest(label=label):
                with self.assertRaises(self.contract.ContractError):
                    self.contract.admit_provider_discovery(observation)

    def test_count_is_not_accepted_enforcement(self) -> None:
        count = self.contract.build_managed_rule(self.contract.ManagedRuleMode.QUALIFICATION_COUNT)
        enforced = self.contract.build_managed_rule(self.contract.ManagedRuleMode.ENFORCEMENT)
        self.assertEqual({"Count": {}}, count["OverrideAction"])
        self.assertEqual({"None": {}}, enforced["OverrideAction"])
        self.assertFalse(self.contract.production_enforcement_accepted(self.contract.ManagedRuleMode.QUALIFICATION_COUNT))
        self.assertTrue(self.contract.production_enforcement_accepted(self.contract.ManagedRuleMode.ENFORCEMENT))

    def test_tenant_waf_escape_is_rejected_but_certificate_is_not(self) -> None:
        response = {"DistributionTenant": {"Id": "tenant-1", "DistributionId": self.target.distribution_id, "Customizations": {"Certificate": {"Arn": "arn:certificate"}}}}
        tenant = self.contract.normalize_tenant_waf_observation(response, self.target)
        self.assertEqual("tenant-1", tenant.tenant_id)
        for action in ("override", "disable", "unexpected"):
            changed = {"DistributionTenant": {"Id": "tenant-1", "DistributionId": self.target.distribution_id, "Customizations": {"WebAcl": {"Action": action}, "Certificate": {"Arn": "arn:certificate"}}}}
            with self.subTest(action=action):
                with self.assertRaises(self.contract.ContractError):
                    self.contract.normalize_tenant_waf_observation(changed, self.target)

    def test_forged_internal_headers_never_change_waf_authority(self) -> None:
        plain = self.contract.waf_contract_for_viewer_headers({"host": "viewer.example.test"})
        forged = self.contract.waf_contract_for_viewer_headers({
            "host": "viewer.example.test", "x-secpal-origin-token": "forged",
            "x-secpal-viewer-host": "forged.example", "x-secpal-viewer-ip": "203.0.113.8",
        })
        self.assertEqual(plain, forged)
        self.contract.validate_waf_rule_trust(plain)

    def test_sampling_and_logging_filter_are_independent_and_minimized(self) -> None:
        web_acl = self.contract.build_web_acl(self.contract.ManagedRuleMode.ENFORCEMENT)
        rule = web_acl["Rules"][0]
        self.assertFalse(web_acl["VisibilityConfig"]["SampledRequestsEnabled"])
        self.assertFalse(rule["VisibilityConfig"]["SampledRequestsEnabled"])
        logging = self.contract.build_logging_configuration(self.target)
        filter_ = logging["LoggingFilter"]
        self.assertEqual("DROP", filter_["DefaultBehavior"])
        self.assertEqual(1, len(filter_["Filters"]))
        self.assertEqual(self.contract.DDOS_REQUEST_LABEL, filter_["Filters"][0]["Conditions"][0]["LabelNameCondition"]["LabelName"])

    def test_sensitive_data_protection_and_redaction_are_explicit(self) -> None:
        web_acl = self.contract.build_web_acl(self.contract.ManagedRuleMode.ENFORCEMENT)
        protections = web_acl["DataProtectionConfig"]["DataProtections"]
        self.assertTrue(all(item["Action"] == "SUBSTITUTION" for item in protections))
        fields = {item["Field"]["FieldType"]: item["Field"] for item in protections}
        self.assertEqual({"FieldType": "BODY"}, fields["BODY"])
        self.assertEqual({"FieldType": "QUERY_STRING"}, fields["QUERY_STRING"])
        self.assertEqual(
            {
                "FieldType": "SINGLE_HEADER",
                "FieldKeys": [
                    "authorization",
                    "cookie",
                    "x-secpal-origin-token",
                    "x-secpal-viewer-host",
                    "x-secpal-viewer-ip",
                ],
            },
            fields["SINGLE_HEADER"],
        )
        self.assertNotIn("x-unreviewed-sensitive-header", fields["SINGLE_HEADER"]["FieldKeys"])
        logging = self.contract.build_logging_configuration(self.target)
        headers = {item["SingleHeader"]["Name"] for item in logging["RedactedFields"] if "SingleHeader" in item}
        self.assertTrue({"authorization", "cookie", "x-secpal-origin-token", "x-secpal-viewer-host", "x-secpal-viewer-ip"}.issubset(headers))
        self.assertIn("AWS-WAF-TOKEN", self.contract.PROVIDER_PRIVACY_LIMITATION)

    def test_destination_is_exact_but_destination_family_neutral(self) -> None:
        for arn in (
            "arn:aws:logs:us-east-1:123456789012:log-group:aws-waf-logs-example",
            "arn:aws:s3:::aws-waf-logs-example",
            "arn:aws:firehose:us-east-1:123456789012:deliverystream/aws-waf-logs-example",
        ):
            with self.subTest(arn=arn):
                self.contract.validate_logging_destination_arn(arn)
        with self.assertRaises(self.contract.ContractError):
            self.contract.validate_logging_destination_arn("arn:aws:lambda:us-east-1:123:function:bad")

    def test_logging_destination_rejects_wrong_name_and_partition(self) -> None:
        invalid = (
            "arn:aws:logs:us-east-1:123456789012:log-group:not-prefixed",
            "arn:aws-cn:logs:us-east-1:123456789012:log-group:aws-waf-logs-test",
            "arn:aws-us-gov:logs:us-east-1:123456789012:log-group:aws-waf-logs-test",
            "arn:aws:logs:eu-west-1:123456789012:log-group:aws-waf-logs-test",
            "arn:aws:logs:us-east-1:123:log-group:aws-waf-logs-test",
            "arn:aws:logs:us-east-1:123456789012:stream:aws-waf-logs-test",
            "not-an-arn",
        )
        for arn in invalid:
            with self.subTest(arn=arn):
                with self.assertRaises(self.contract.ContractError):
                    self.contract.validate_logging_destination_arn(arn)
        other_account = self.contract.AwsProviderContext(
            partition="aws", account_id="210987654321", waf_region="us-east-1"
        )
        with self.assertRaisesRegex(self.contract.ContractError, "provider context"):
            self.contract.validate_logging_destination_arn(
                self.target.logging_destination_arn, other_account
            )

    def test_logging_lifecycle_binds_only_the_exact_web_acl(self) -> None:
        plans = [
            self.contract.plan_logging_configuration(self.target, operation)
            for operation in (
                self.contract.Operation.PUT_LOGGING,
                self.contract.Operation.INSPECT_LOGGING,
                self.contract.Operation.DELETE_LOGGING,
            )
        ]
        self.assertEqual([self.target.web_acl_arn] * 3, [plan.resource_id for plan in plans])
        self.assertEqual("PutLoggingConfiguration", plans[0].api_operation)

    def test_logging_readback_requires_the_complete_admitted_configuration(self) -> None:
        configuration = self.contract.build_logging_configuration(self.target)
        observation = self.contract.normalize_logging_observation(
            {"LoggingConfiguration": copy.deepcopy(configuration)},
            self.target,
            self.context,
        )
        request = self.contract.LifecycleRequest(
            "request-logging-readback",
            "aws-cloudfront-waf-v1",
            "a" * 40,
            self.context,
            self.target,
            self.contract.Operation.INSPECT_LOGGING,
            "b" * 64,
        )
        result = self.contract.LifecycleResult(
            request.request_id,
            request.adapter_id,
            request.source_revision,
            request.provider_context,
            request.target,
            request.operation,
            request.parameters_sha256,
            self.contract.Outcome.OBSERVED,
            logging_observation=observation,
        )
        self.contract.admit_result(request, result)

        invalid_configurations = {}
        for label, destination in (
            (
                "wrong-destination",
                "arn:aws:logs:us-east-1:123456789012:log-group:aws-waf-logs-other",
            ),
            (
                "wrong-prefix",
                "arn:aws:logs:us-east-1:123456789012:log-group:not-prefixed",
            ),
            (
                "wrong-partition",
                "arn:aws-cn:logs:us-east-1:123456789012:log-group:aws-waf-logs-example",
            ),
        ):
            changed = copy.deepcopy(configuration)
            changed["LogDestinationConfigs"] = [destination]
            invalid_configurations[label] = changed
        weakened_filter = copy.deepcopy(configuration)
        weakened_filter["LoggingFilter"]["DefaultBehavior"] = "KEEP"
        invalid_configurations["weakened-filter"] = weakened_filter
        weakened_redaction = copy.deepcopy(configuration)
        weakened_redaction["RedactedFields"].pop()
        invalid_configurations["weakened-redaction"] = weakened_redaction

        for label, changed in invalid_configurations.items():
            changed_observation = self.contract.LoggingObservation(
                self.target.web_acl_arn, changed
            )
            with self.subTest(label=label):
                with self.assertRaises(self.contract.ContractError):
                    self.contract.admit_result(
                        request,
                        replace(result, logging_observation=changed_observation),
                    )

        absent = self.contract.normalize_logging_observation(
            {}, self.target, self.context
        )
        with self.assertRaisesRegex(self.contract.ContractError, "absent"):
            self.contract.admit_result(
                request, replace(result, logging_observation=absent)
            )

    def test_cloudfront_etag_and_waf_locktoken_are_not_interchangeable(self) -> None:
        distribution = self.contract.DistributionObservation(
            self.target.distribution_id, "distribution-etag", None
        )
        configuration = self.contract.build_web_acl(self.contract.ManagedRuleMode.ENFORCEMENT)
        web_acl = self.contract.WebAclObservation(self.target.web_acl_id, self.target.web_acl_arn, self.target.requested_key, "waf-lock-token", configuration)
        association = self.contract.plan_associate_distribution(self.target, distribution, "distribution-etag")
        self.assertEqual("distribution-etag", association.if_match)
        update = self.contract.plan_update_web_acl(self.target, web_acl, "waf-lock-token", configuration)
        self.assertEqual("waf-lock-token", update.lock_token)
        with self.assertRaises(self.contract.ContractError):
            self.contract.plan_associate_distribution(self.target, distribution, "waf-lock-token")
        with self.assertRaises(self.contract.ContractError):
            self.contract.plan_update_web_acl(self.target, web_acl, "distribution-etag", configuration)

    def test_update_materialization_preserves_exact_web_acl_name(self) -> None:
        configuration = self.contract.build_web_acl(
            self.contract.ManagedRuleMode.ENFORCEMENT
        )
        web_acl = self.contract.WebAclObservation(
            self.target.web_acl_id, self.target.web_acl_arn, self.target.requested_key, "fresh-token", configuration
        )
        plan = self.contract.plan_update_web_acl(
            self.target, web_acl, "fresh-token", configuration
        )
        self.assertEqual(self.target.requested_key, plan.materialize_parameters()["Name"])
        with self.assertRaises(TypeError):
            plan.parameters["Name"] = "changed"
        with self.assertRaisesRegex(self.contract.ContractError, "exact target"):
            self.contract.plan_update_web_acl(
                self.target,
                replace(web_acl, web_acl_name="other-name"),
                "fresh-token",
                configuration,
            )

    def test_association_requires_unowned_current_state(self) -> None:
        absent = self.contract.DistributionObservation(
            self.target.distribution_id, "fresh-etag", None
        )
        plan = self.contract.plan_associate_distribution(
            self.target, absent, "fresh-etag"
        )
        self.assertEqual(
            {"WebACLArn": self.target.web_acl_arn}, plan.materialize_parameters()
        )
        exact = replace(absent, web_acl_arn=self.target.web_acl_arn)
        self.assertIsNone(
            self.contract.plan_associate_distribution(
                self.target, exact, "fresh-etag"
            )
        )
        unrelated = replace(
            absent,
            web_acl_arn=(
                "arn:aws:wafv2:us-east-1:123456789012:global/"
                "webacl/unrelated/acl-other"
            ),
        )
        with self.assertRaisesRegex(
            self.contract.ContractError, "association.*ownership.*acl-other"
        ):
            self.contract.plan_associate_distribution(
                self.target, unrelated, "fresh-etag"
            )
        with self.assertRaises(self.contract.ContractError):
            self.contract.plan_associate_distribution(
                self.target, absent, "stale-etag"
            )

    def test_distribution_provider_absence_normalizes_before_ownership(self) -> None:
        for provider_value in (None, ""):
            with self.subTest(provider_value=provider_value):
                observation = self.contract.normalize_distribution_observation(
                    {
                        "ETag": "fresh-etag",
                        "DistributionConfig": {"WebACLId": provider_value},
                    },
                    self.target,
                )
                self.assertIsNone(observation.web_acl_arn)
                plan = self.contract.plan_associate_distribution(
                    self.target, observation, "fresh-etag"
                )
                self.assertEqual(
                    {"WebACLArn": self.target.web_acl_arn},
                    plan.materialize_parameters(),
                )

        for provider_value in (
            self.target.web_acl_arn,
            (
                "arn:aws:wafv2:us-east-1:123456789012:global/"
                "webacl/unrelated/acl-other"
            ),
        ):
            with self.subTest(provider_value=provider_value):
                observation = self.contract.normalize_distribution_observation(
                    {
                        "ETag": "fresh-etag",
                        "DistributionConfig": {"WebACLId": provider_value},
                    },
                    self.target,
                )
                self.assertEqual(provider_value, observation.web_acl_arn)

        exact = self.contract.normalize_distribution_observation(
            {
                "ETag": "fresh-etag",
                "DistributionConfig": {"WebACLId": self.target.web_acl_arn},
            },
            self.target,
        )
        self.assertIsNone(
            self.contract.plan_associate_distribution(
                self.target, exact, "fresh-etag"
            )
        )
        unrelated = replace(
            exact,
            web_acl_arn=(
                "arn:aws:wafv2:us-east-1:123456789012:global/"
                "webacl/unrelated/acl-other"
            ),
        )
        with self.assertRaisesRegex(
            self.contract.ContractError, "association.*ownership.*acl-other"
        ):
            self.contract.plan_associate_distribution(
                self.target, unrelated, "fresh-etag"
            )
        with self.assertRaises(self.contract.ContractError):
            self.contract.plan_associate_distribution(
                self.target,
                replace(exact, web_acl_arn=None),
                "stale-etag",
            )
        for malformed in (False, 0, [], {}, " "):
            with self.subTest(malformed=malformed):
                with self.assertRaises(self.contract.ContractError):
                    self.contract.normalize_distribution_observation(
                        {
                            "ETag": "fresh-etag",
                            "DistributionConfig": {"WebACLId": malformed},
                        },
                        self.target,
                    )

    def test_rollback_and_cleanup_require_fresh_exact_authority(self) -> None:
        configuration = self.contract.build_web_acl(self.contract.ManagedRuleMode.ENFORCEMENT)
        web_acl = self.contract.WebAclObservation(self.target.web_acl_id, self.target.web_acl_arn, self.target.requested_key, "new-lock-token", configuration)
        rollback = self.contract.plan_rollback(self.target, web_acl, "new-lock-token", configuration)
        self.assertEqual("new-lock-token", rollback.lock_token)
        distribution = self.contract.DistributionObservation(self.target.distribution_id, "new-etag", self.target.web_acl_arn)
        logging = self.contract.LoggingObservation(
            self.target.web_acl_arn,
            self.contract.build_logging_configuration(self.target),
        )
        cleanup = self.contract.plan_cleanup(self.target, web_acl, distribution, logging, "new-lock-token", "new-etag")
        self.assertEqual((self.contract.Operation.DELETE_LOGGING,), tuple(plan.operation for plan in cleanup))
        with self.assertRaises(self.contract.ContractError):
            self.contract.plan_cleanup(replace(self.target, qualification_owned=False), web_acl, distribution, logging, "new-lock-token", "new-etag")

    def test_complete_web_acl_admission_is_shared_by_create_update_and_rollback(self) -> None:
        configuration = self.contract.build_web_acl(self.contract.ManagedRuleMode.ENFORCEMENT)
        create_target = replace(
            self.target,
            web_acl_id=None,
            web_acl_arn=None,
            logging_destination_arn=None,
        )
        create = self.contract.plan_create_web_acl(
            create_target, self.contract.ManagedRuleMode.ENFORCEMENT
        )
        self.assertEqual(
            configuration,
            {
                key: value
                for key, value in create.materialize_parameters().items()
                if key != "Name"
            },
        )
        observation = self.contract.WebAclObservation(
            self.target.web_acl_id,
            self.target.web_acl_arn,
            self.target.requested_key,
            "fresh-token",
            configuration,
        )
        update = self.contract.plan_update_web_acl(
            self.target, observation, "fresh-token", configuration
        )
        rollback = self.contract.plan_rollback(
            self.target, observation, "fresh-token", configuration
        )
        expected = {"Name": self.target.requested_key, **configuration}
        self.assertEqual(expected, update.materialize_parameters())
        self.assertEqual(expected, rollback.materialize_parameters())

    def test_count_requires_explicit_qualification_ownership(self) -> None:
        count = self.contract.build_web_acl(
            self.contract.ManagedRuleMode.QUALIFICATION_COUNT,
            qualification_owned=True,
        )
        permanent = replace(self.target, qualification_owned=False)
        permanent_create = replace(
            permanent,
            web_acl_id=None,
            web_acl_arn=None,
            logging_destination_arn=None,
        )
        observation = self.contract.WebAclObservation(
            permanent.web_acl_id,
            permanent.web_acl_arn,
            permanent.requested_key,
            "fresh-token",
            self.contract.build_web_acl(self.contract.ManagedRuleMode.ENFORCEMENT),
        )
        with self.assertRaises(self.contract.ContractError):
            self.contract.plan_create_web_acl(
                permanent_create, self.contract.ManagedRuleMode.QUALIFICATION_COUNT
            )
        for planner in (
            self.contract.plan_update_web_acl,
            self.contract.plan_rollback,
        ):
            with self.subTest(planner=planner.__name__):
                with self.assertRaises(self.contract.ContractError):
                    planner(permanent, observation, "fresh-token", count)

        qualification_create = replace(
            self.target,
            web_acl_id=None,
            web_acl_arn=None,
            logging_destination_arn=None,
        )
        self.contract.plan_create_web_acl(
            qualification_create, self.contract.ManagedRuleMode.QUALIFICATION_COUNT
        )
        qualification_observation = replace(
            observation,
            web_acl_id=self.target.web_acl_id,
            web_acl_arn=self.target.web_acl_arn,
        )
        self.contract.plan_update_web_acl(
            self.target, qualification_observation, "fresh-token", count
        )
        self.contract.plan_rollback(
            self.target, qualification_observation, "fresh-token", count
        )
        with self.assertRaises(self.contract.ContractError):
            replace(self.target, qualification_owned=1)

    def test_permanent_enforcement_is_admitted_for_all_replacement_paths(self) -> None:
        configuration = self.contract.build_web_acl(
            self.contract.ManagedRuleMode.ENFORCEMENT
        )
        permanent = replace(self.target, qualification_owned=False)
        create_target = replace(
            permanent,
            web_acl_id=None,
            web_acl_arn=None,
            logging_destination_arn=None,
        )
        self.contract.plan_create_web_acl(
            create_target, self.contract.ManagedRuleMode.ENFORCEMENT
        )
        observation = self.contract.WebAclObservation(
            permanent.web_acl_id,
            permanent.web_acl_arn,
            permanent.requested_key,
            "fresh-token",
            configuration,
        )
        self.contract.plan_update_web_acl(
            permanent, observation, "fresh-token", configuration
        )
        self.contract.plan_rollback(
            permanent, observation, "fresh-token", configuration
        )

    def test_plans_are_immutable_across_admission_and_materialization(self) -> None:
        configuration = self.contract.build_web_acl(
            self.contract.ManagedRuleMode.ENFORCEMENT
        )
        observation = self.contract.WebAclObservation(
            self.target.web_acl_id,
            self.target.web_acl_arn,
            self.target.requested_key,
            "fresh-token",
            configuration,
        )
        desired = copy.deepcopy(configuration)
        plan = self.contract.plan_update_web_acl(
            self.target, observation, "fresh-token", desired
        )
        desired["Rules"].clear()
        self.assertEqual({"Name": self.target.requested_key, **configuration}, plan.materialize_parameters())
        with self.assertRaises(TypeError):
            plan.parameters["DefaultAction"] = {"Block": {}}
        with self.assertRaises(AttributeError):
            plan.parameters["Rules"].append({})

        logging_plan = self.contract.plan_logging_configuration(
            self.target, self.contract.Operation.PUT_LOGGING
        )
        with self.assertRaises(AttributeError):
            logging_plan.parameters["LoggingFilter"]["Filters"].append({})
        first = logging_plan.materialize_parameters()
        second = logging_plan.materialize_parameters()
        first["LoggingFilter"]["Filters"].clear()
        self.assertEqual(1, len(second["LoggingFilter"]["Filters"]))
        self.assertEqual(
            self.contract.build_logging_configuration(self.target),
            logging_plan.materialize_parameters(),
        )

    def test_web_acl_contract_is_type_strict(self) -> None:
        configuration = self.contract.build_web_acl(
            self.contract.ManagedRuleMode.ENFORCEMENT
        )
        cases = (
            ("VisibilityConfig", "SampledRequestsEnabled", 0),
            ("VisibilityConfig", "CloudWatchMetricsEnabled", 1),
        )
        for container, field, replacement in cases:
            changed = copy.deepcopy(configuration)
            changed[container][field] = replacement
            with self.subTest(field=field, replacement=replacement):
                with self.assertRaises(self.contract.ContractError):
                    self.contract.validate_complete_web_acl(changed)
        integer_changed = copy.deepcopy(configuration)
        integer_changed["Rules"][0]["Priority"] = False
        with self.assertRaises(self.contract.ContractError):
            self.contract.validate_complete_web_acl(integer_changed)
        self.contract.validate_complete_web_acl(configuration)

    def test_get_web_acl_projects_only_mutable_contract_fields(self) -> None:
        configuration = self.contract.build_web_acl(
            self.contract.ManagedRuleMode.ENFORCEMENT
        )
        response = {
            "WebACL": {
                "Id": self.target.web_acl_id,
                "ARN": self.target.web_acl_arn,
                "Name": "qualification-212",
                "Capacity": 50,
                "LabelNamespace": "awswaf:123456789012:webacl:qualification-212:",
                **{
                    key: copy.deepcopy(value)
                    for key, value in configuration.items()
                    if key != "Scope"
                },
            },
            "LockToken": "fresh-token",
        }
        observation = self.contract.normalize_web_acl_observation(response, self.target)
        self.assertEqual(configuration, observation.configuration)
        self.contract.validate_complete_web_acl(
            observation.configuration, qualification_owned=True
        )
        projected_update = self.contract.plan_update_web_acl(
            self.target,
            observation,
            "fresh-token",
            observation.configuration,
        )
        self.assertEqual({"Name": self.target.requested_key, **configuration}, projected_update.materialize_parameters())
        response["WebACL"]["Rules"].clear()
        self.assertEqual(configuration, observation.configuration)
        incomplete = copy.deepcopy(response)
        incomplete["WebACL"]["Rules"] = copy.deepcopy(configuration["Rules"])
        del incomplete["WebACL"]["DataProtectionConfig"]
        incomplete_observation = self.contract.normalize_web_acl_observation(
            incomplete, self.target
        )
        with self.assertRaises(self.contract.ContractError):
            self.contract.validate_complete_web_acl(
                incomplete_observation.configuration, qualification_owned=True
            )

    def test_get_web_acl_classifies_every_current_provider_field(self) -> None:
        expected_provider_fields = {
            "ARN",
            "ApplicationConfig",
            "AssociationConfig",
            "Capacity",
            "CaptchaConfig",
            "ChallengeConfig",
            "CustomResponseBodies",
            "DataProtectionConfig",
            "DefaultAction",
            "Description",
            "Id",
            "LabelNamespace",
            "ManagedByFirewallManager",
            "MonetizationConfig",
            "Name",
            "OnSourceDDoSProtectionConfig",
            "PostProcessFirewallManagerRuleGroups",
            "PreProcessFirewallManagerRuleGroups",
            "RetrofittedByFirewallManager",
            "Rules",
            "TokenDomains",
            "VisibilityConfig",
        }
        self.assertEqual(
            expected_provider_fields,
            self.contract.WEB_ACL_PROVIDER_RESPONSE_FIELDS,
        )

    def test_get_web_acl_rejects_configured_unsupported_mutable_state(self) -> None:
        configured_values = {
            "ApplicationConfig": {"Attributes": {"ApplicationParam": "value"}},
            "AssociationConfig": {
                "RequestBody": {
                    "CLOUDFRONT": {"DefaultSizeInspectionLimit": "KB_16"}
                }
            },
            "CaptchaConfig": {"ImmunityTimeProperty": {"ImmunityTime": 300}},
            "ChallengeConfig": {"ImmunityTimeProperty": {"ImmunityTime": 300}},
            "CustomResponseBodies": {
                "blocked": {"ContentType": "TEXT_PLAIN", "Content": "blocked"}
            },
            "Description": "unexpected provider-managed description",
            "MonetizationConfig": {"CurrencyMode": "USD"},
            "OnSourceDDoSProtectionConfig": {
                "ALBLowReputationMode": "ACTIVE_UNDER_DDOS"
            },
            "TokenDomains": ["unrelated.example"],
        }
        self.assertEqual(
            set(configured_values),
            self.contract.WEB_ACL_UNSUPPORTED_MUTABLE_FIELDS,
        )
        baseline = self.contract.build_web_acl(
            self.contract.ManagedRuleMode.ENFORCEMENT
        )
        for field, value in configured_values.items():
            response = {
                "WebACL": {
                    "Id": self.target.web_acl_id,
                    "ARN": self.target.web_acl_arn,
                    **{
                        key: copy.deepcopy(item)
                        for key, item in baseline.items()
                        if key != "Scope"
                    },
                    field: value,
                },
                "LockToken": "fresh-token",
            }
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    self.contract.ContractError,
                    f"unsupported mutable Web ACL field {field}",
                ):
                    self.contract.normalize_web_acl_observation(
                        response, self.target
                    )

    def test_get_web_acl_allows_only_typed_semantic_absence_for_unsupported_state(self) -> None:
        absent_values = {
            "ApplicationConfig": {},
            "AssociationConfig": {},
            "CaptchaConfig": {},
            "ChallengeConfig": {},
            "CustomResponseBodies": {},
            "Description": "",
            "MonetizationConfig": {},
            "OnSourceDDoSProtectionConfig": None,
            "TokenDomains": [],
        }
        baseline = self.contract.build_web_acl(
            self.contract.ManagedRuleMode.ENFORCEMENT
        )
        response_only = {
            "Name": self.target.requested_key,
            "Capacity": 50,
            "LabelNamespace": "awswaf:example:",
            "ManagedByFirewallManager": False,
            "PostProcessFirewallManagerRuleGroups": [],
            "PreProcessFirewallManagerRuleGroups": [],
            "RetrofittedByFirewallManager": False,
        }
        response = {
            "WebACL": {
                "Id": self.target.web_acl_id,
                "ARN": self.target.web_acl_arn,
                **{
                    key: copy.deepcopy(value)
                    for key, value in baseline.items()
                    if key != "Scope"
                },
                **absent_values,
                **response_only,
            },
            "LockToken": "fresh-token",
        }
        observation = self.contract.normalize_web_acl_observation(
            response, self.target
        )
        self.assertEqual(baseline, observation.configuration)
        self.contract.validate_complete_web_acl(
            observation.configuration, qualification_owned=True
        )

        for field, value in (
            ("TokenDomains", {}),
            ("Description", []),
            ("CaptchaConfig", []),
            ("OnSourceDDoSProtectionConfig", {}),
        ):
            malformed = copy.deepcopy(response)
            malformed["WebACL"][field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaisesRegex(
                    self.contract.ContractError,
                    f"unsupported mutable Web ACL field {field}",
                ):
                    self.contract.normalize_web_acl_observation(
                        malformed, self.target
                    )

    def test_get_web_acl_rejects_unclassified_provider_fields(self) -> None:
        baseline = self.contract.build_web_acl(
            self.contract.ManagedRuleMode.ENFORCEMENT
        )
        response = {
            "WebACL": {
                "Id": self.target.web_acl_id,
                "ARN": self.target.web_acl_arn,
                **{
                    key: copy.deepcopy(value)
                    for key, value in baseline.items()
                    if key != "Scope"
                },
                "FutureMutableField": None,
            },
            "LockToken": "fresh-token",
        }
        with self.assertRaisesRegex(
            self.contract.ContractError,
            "unclassified Web ACL provider fields.*FutureMutableField",
        ):
            self.contract.normalize_web_acl_observation(response, self.target)

    def test_update_and_rollback_reject_function_bound_header_authority(self) -> None:
        configuration = self.contract.build_web_acl(self.contract.ManagedRuleMode.ENFORCEMENT)
        observation = self.contract.WebAclObservation(
            self.target.web_acl_id,
            self.target.web_acl_arn,
            self.target.requested_key,
            "fresh-token",
            configuration,
        )
        for header in self.contract.SENSITIVE_HEADERS[2:]:
            unsafe = copy.deepcopy(configuration)
            unsafe["Rules"][0]["Statement"] = {
                "ByteMatchStatement": {
                    "SearchString": "trusted",
                    "FieldToMatch": {"SingleHeader": {"Name": header}},
                    "PositionalConstraint": "EXACTLY",
                    "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                }
            }
            for planner in (
                self.contract.plan_update_web_acl,
                self.contract.plan_rollback,
            ):
                with self.subTest(header=header, planner=planner.__name__):
                    with self.assertRaises(self.contract.ContractError):
                        planner(self.target, observation, "fresh-token", unsafe)

    def test_update_and_rollback_reject_incomplete_replacement(self) -> None:
        configuration = self.contract.build_web_acl(self.contract.ManagedRuleMode.ENFORCEMENT)
        observation = self.contract.WebAclObservation(
            self.target.web_acl_id,
            self.target.web_acl_arn,
            self.target.requested_key,
            "fresh-token",
            configuration,
        )
        for incomplete in ({"Rules": []}, {"Rules": configuration["Rules"]}):
            for planner in (
                self.contract.plan_update_web_acl,
                self.contract.plan_rollback,
            ):
                with self.subTest(configuration=incomplete, planner=planner.__name__):
                    with self.assertRaises(self.contract.ContractError):
                        planner(self.target, observation, "fresh-token", incomplete)

    def test_cleanup_disassociates_only_the_owned_current_web_acl(self) -> None:
        configuration = self.contract.build_web_acl(self.contract.ManagedRuleMode.ENFORCEMENT)
        web_acl = self.contract.WebAclObservation(
            self.target.web_acl_id,
            self.target.web_acl_arn,
            self.target.requested_key,
            "fresh-token",
            configuration,
        )
        exact = self.contract.DistributionObservation(
            self.target.distribution_id, "fresh-etag", self.target.web_acl_arn
        )
        absent_logging = self.contract.LoggingObservation(
            self.target.web_acl_arn, None
        )
        exact_plan = self.contract.plan_cleanup(
            self.target, web_acl, exact, absent_logging, "fresh-token", "fresh-etag"
        )
        self.assertEqual(
            (self.contract.Operation.DISASSOCIATE_DISTRIBUTION,),
            tuple(step.operation for step in exact_plan),
        )
        absent = replace(exact, web_acl_arn=None)
        absent_plan = self.contract.plan_cleanup(
            self.target, web_acl, absent, absent_logging, "fresh-token", "fresh-etag"
        )
        self.assertEqual(
            (self.contract.Operation.DELETE_WEB_ACL,),
            tuple(step.operation for step in absent_plan),
        )
        unrelated = replace(
            exact,
            web_acl_arn="arn:aws:wafv2:us-east-1:123456789012:global/webacl/unrelated/acl-other",
        )
        with self.assertRaisesRegex(
            self.contract.ContractError, "association.*mismatch.*acl-other"
        ):
            self.contract.plan_cleanup(
                self.target, web_acl, unrelated, absent_logging, "fresh-token", "fresh-etag"
            )
        with self.assertRaises(self.contract.ContractError):
            self.contract.plan_cleanup(
                self.target, web_acl, exact, absent_logging, "fresh-token", "stale-etag"
            )

    def test_delete_request_requires_qualification_owned_target(self) -> None:
        permanent = replace(self.target, qualification_owned=False)
        authority = self.contract.ExecutionAuthority(
            "authority-delete", "aws-cloudfront-waf-v1", "a" * 40,
            self.context, permanent, frozenset({self.contract.Operation.DELETE_WEB_ACL}),
            "b" * 64, "oidc-workload-identity",
        )
        request = self.contract.LifecycleRequest(
            "request-delete", "aws-cloudfront-waf-v1", "a" * 40,
            self.context, permanent, self.contract.Operation.DELETE_WEB_ACL, "b" * 64,
        )
        with self.assertRaises(self.contract.ContractError):
            self.contract.admit_request(request, authority)
        qualified_authority = replace(authority, target=self.target)
        qualified_request = replace(request, target=self.target)
        self.contract.admit_request(qualified_request, qualified_authority)
        with self.assertRaises(self.contract.ContractError):
            self.contract.admit_request(
                qualified_request,
                replace(
                    qualified_authority,
                    operations=frozenset({self.contract.Operation.INSPECT_WEB_ACL}),
                ),
            )
        with self.assertRaises(self.contract.ContractError):
            self.contract.admit_request(
                replace(
                    qualified_request,
                    target=replace(self.target, distribution_id="E2OTHERDISTRIBUTION"),
                ),
                qualified_authority,
            )

    def test_logging_inspection_requires_semantic_observation(self) -> None:
        request = self.contract.LifecycleRequest(
            "request-logging", "aws-cloudfront-waf-v1", "a" * 40,
            self.context, self.target, self.contract.Operation.INSPECT_LOGGING, "b" * 64,
        )
        result = self.contract.LifecycleResult(
            request.request_id, request.adapter_id, request.source_revision,
            request.provider_context, request.target, request.operation,
            request.parameters_sha256, self.contract.Outcome.OBSERVED,
        )
        with self.assertRaises(self.contract.ContractError):
            self.contract.admit_result(request, result)

    def test_result_correlation_is_exact_and_operation_compatible(self) -> None:
        authority = self.contract.ExecutionAuthority("authority-1", "aws-cloudfront-waf-v1", "a" * 40, self.context, self.target, frozenset(self.contract.Operation), "b" * 64, "oidc-workload-identity")
        request = self.contract.LifecycleRequest("request-1", "aws-cloudfront-waf-v1", "a" * 40, self.context, self.target, self.contract.Operation.INSPECT_WEB_ACL, "b" * 64)
        self.contract.admit_request(request, authority)
        result = self.contract.LifecycleResult("request-1", "aws-cloudfront-waf-v1", "a" * 40, self.context, self.target, self.contract.Operation.INSPECT_WEB_ACL, "b" * 64, self.contract.Outcome.OBSERVED)
        self.contract.admit_result(request, result)
        with self.assertRaises(self.contract.ContractError):
            self.contract.admit_result(request, replace(result, operation=self.contract.Operation.DELETE_WEB_ACL))

    def test_every_operation_has_one_exact_success_outcome(self) -> None:
        observed_operations = {
            self.contract.Operation.DISCOVER_MANAGED_RULE,
            self.contract.Operation.CHECK_CAPACITY,
            self.contract.Operation.INSPECT_WEB_ACL,
            self.contract.Operation.INSPECT_DISTRIBUTION,
            self.contract.Operation.INSPECT_TENANT,
            self.contract.Operation.INSPECT_LOGGING,
        }
        for operation in self.contract.Operation:
            expected = (
                self.contract.Outcome.OBSERVED
                if operation in observed_operations
                else self.contract.Outcome.APPLIED
            )
            incompatible = (
                self.contract.Outcome.APPLIED
                if expected is self.contract.Outcome.OBSERVED
                else self.contract.Outcome.OBSERVED
            )
            request = self.contract.LifecycleRequest(
                f"request-{operation.value}",
                "aws-cloudfront-waf-v1",
                "a" * 40,
                self.context,
                self.target,
                operation,
                "b" * 64,
            )
            logging_observation = (
                self.contract.LoggingObservation(
                    self.target.web_acl_arn,
                    self.contract.build_logging_configuration(self.target),
                )
                if operation is self.contract.Operation.INSPECT_LOGGING
                else None
            )
            result = self.contract.LifecycleResult(
                request.request_id,
                request.adapter_id,
                request.source_revision,
                request.provider_context,
                request.target,
                request.operation,
                request.parameters_sha256,
                expected,
                logging_observation=logging_observation,
            )
            with self.subTest(operation=operation.value, outcome=expected.value):
                self.contract.admit_result(request, result)
            with self.subTest(operation=operation.value, outcome=incompatible.value):
                with self.assertRaises(self.contract.ContractError):
                    self.contract.admit_result(
                        request, replace(result, outcome=incompatible)
                    )
            with self.subTest(operation=operation.value, outcome="failed"):
                self.contract.admit_result(
                    request,
                    replace(
                        result,
                        outcome=self.contract.Outcome.FAILED,
                        diagnostic_code="provider.failure",
                        logging_observation=None,
                    ),
                )

    def test_inspection_rejects_applied_outcome(self) -> None:
        request = self.contract.LifecycleRequest(
            "request-inspect",
            "aws-cloudfront-waf-v1",
            "a" * 40,
            self.context,
            self.target,
            self.contract.Operation.INSPECT_WEB_ACL,
            "b" * 64,
        )
        result = self.contract.LifecycleResult(
            request.request_id,
            request.adapter_id,
            request.source_revision,
            request.provider_context,
            request.target,
            request.operation,
            request.parameters_sha256,
            self.contract.Outcome.APPLIED,
        )
        with self.assertRaises(self.contract.ContractError):
            self.contract.admit_result(request, result)


if __name__ == "__main__":
    unittest.main()
