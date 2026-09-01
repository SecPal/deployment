#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Behavior evidence for the portable PROTECTED CloudFront WAF contract."""

from __future__ import annotations

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
            current_default_version="Version_fixture", available_versions=(
                cls.contract.ManagedRuleVersion("Version_fixture", None),
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
        rule = self.contract.build_managed_rule(self.contract.ManagedRuleMode.ENFORCEMENT)
        self.assertNotIn("Version", rule["Statement"]["ManagedRuleGroupStatement"])

    def test_capacity_is_dynamic_not_fixed_at_fifty(self) -> None:
        dynamic = replace(self.discovery, capacity=61, check_capacity=61)
        self.contract.admit_provider_discovery(dynamic)
        self.assertEqual(61, dynamic.capacity)

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
        self.assertIn({"FieldType": "SINGLE_HEADER"}, [item["Field"] for item in protections])
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

    def test_cloudfront_etag_and_waf_locktoken_are_not_interchangeable(self) -> None:
        distribution = self.contract.DistributionObservation(self.target.distribution_id, "distribution-etag", self.target.web_acl_arn)
        web_acl = self.contract.WebAclObservation(self.target.web_acl_id, self.target.web_acl_arn, "waf-lock-token", {"Rules": []})
        association = self.contract.plan_associate_distribution(self.target, distribution, "distribution-etag")
        self.assertEqual("distribution-etag", association.if_match)
        update = self.contract.plan_update_web_acl(self.target, web_acl, "waf-lock-token", {"Rules": []})
        self.assertEqual("waf-lock-token", update.lock_token)
        with self.assertRaises(self.contract.ContractError):
            self.contract.plan_associate_distribution(self.target, distribution, "waf-lock-token")
        with self.assertRaises(self.contract.ContractError):
            self.contract.plan_update_web_acl(self.target, web_acl, "distribution-etag", {"Rules": []})

    def test_rollback_and_cleanup_require_fresh_exact_authority(self) -> None:
        web_acl = self.contract.WebAclObservation(self.target.web_acl_id, self.target.web_acl_arn, "new-lock-token", {"Rules": [{"old": True}]})
        rollback = self.contract.plan_rollback(self.target, web_acl, "new-lock-token", {"Rules": [{"prior": True}]})
        self.assertEqual("new-lock-token", rollback.lock_token)
        distribution = self.contract.DistributionObservation(self.target.distribution_id, "new-etag", self.target.web_acl_arn)
        cleanup = self.contract.plan_cleanup(self.target, web_acl, distribution, "new-lock-token", "new-etag")
        self.assertEqual((self.contract.Operation.DELETE_LOGGING, self.contract.Operation.DISASSOCIATE_DISTRIBUTION, self.contract.Operation.DELETE_WEB_ACL), tuple(plan.operation for plan in cleanup))
        with self.assertRaises(self.contract.ContractError):
            self.contract.plan_cleanup(replace(self.target, qualification_owned=False), web_acl, distribution, "new-lock-token", "new-etag")

    def test_result_correlation_is_exact_and_operation_compatible(self) -> None:
        authority = self.contract.ExecutionAuthority("authority-1", "aws-cloudfront-waf-v1", "a" * 40, self.context, self.target, frozenset(self.contract.Operation), "b" * 64, "oidc-workload-identity")
        request = self.contract.LifecycleRequest("request-1", "aws-cloudfront-waf-v1", "a" * 40, self.context, self.target, self.contract.Operation.INSPECT_WEB_ACL, "b" * 64)
        self.contract.admit_request(request, authority)
        result = self.contract.LifecycleResult("request-1", "aws-cloudfront-waf-v1", "a" * 40, self.context, self.target, self.contract.Operation.INSPECT_WEB_ACL, "b" * 64, self.contract.Outcome.OBSERVED)
        self.contract.admit_result(request, result)
        with self.assertRaises(self.contract.ContractError):
            self.contract.admit_result(request, replace(result, operation=self.contract.Operation.DELETE_WEB_ACL))


if __name__ == "__main__":
    unittest.main()
