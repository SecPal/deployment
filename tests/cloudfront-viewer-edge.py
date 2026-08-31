#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Behavior evidence for the PROTECTED CloudFront Viewer Edge contract."""

from __future__ import annotations

from dataclasses import fields, replace
import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "scripts" / "cloudfront-viewer-edge.py"


def load_contract():
    specification = importlib.util.spec_from_file_location(
        "cloudfront_viewer_edge", CONTRACT_PATH
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("unable to load CloudFront Viewer Edge contract")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


class CloudFrontViewerEdgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = load_contract()
        cls.inputs = cls.contract.TenantInputs(
            deployment_key="qualification-17",
            distribution_id="E1EXAMPLEPARENT",
            connection_group_id="cg_example17",
            viewer_domain="viewer.example.test",
            origin_domain="origin.example.test",
        )
        cls.target = cls.contract.CloudFrontTarget(
            requested_key="qualification-17",
            distribution_id="E1EXAMPLEPARENT",
            connection_group_id="cg_example17",
            tenant_id="dt_example17",
        )
        cls.authority = cls.contract.ExecutionAuthority(
            authorization_id="workflow-run-17",
            adapter_id="aws-cloudfront-v1",
            source_revision="a" * 40,
            provider_context=cls.contract.AwsProviderContext(
                partition="aws",
                account_id="123456789012",
                cloudfront_scope="global",
                certificate_region="us-east-1",
            ),
            target=cls.target,
            operations=frozenset(cls.contract.Operation),
            parameters_sha256="b" * 64,
            credential_mechanism="oidc-workload-identity",
        )

    def tenant(
        self,
        *,
        etag="ETAG-CURRENT",
        enabled=True,
        status="Deployed",
        domain_status="active",
        certificate_arn="arn:aws:acm:us-east-1:123456789012:certificate/example",
        origin_domain="origin.example.test",
    ):
        return self.contract.TenantObservation(
            tenant_id="dt_example17",
            distribution_id="E1EXAMPLEPARENT",
            connection_group_id="cg_example17",
            etag=etag,
            enabled=enabled,
            deployment_status=status,
            viewer_domain="viewer.example.test",
            domain_status=domain_status,
            origin_domain=origin_domain,
            certificate_arn=certificate_arn,
        )

    def certificate(
        self,
        status="issued",
        arn=None,
        tokens=(),
        validation_token_host="cloudfront",
    ):
        return self.contract.ManagedCertificateObservation(
            status=status,
            certificate_arn=(
                "arn:aws:acm:us-east-1:123456789012:certificate/example"
                if arn is None
                else arn
            ),
            validation_token_host=validation_token_host,
            validation_tokens=tuple(tokens),
        )

    def connection_group(
        self,
        *,
        etag="GROUP-ETAG",
        enabled=True,
        status="Deployed",
        is_default=False,
        tenant_association_present=False,
    ):
        return self.contract.ConnectionGroupObservation(
            connection_group_id="cg_example17",
            etag=etag,
            routing_endpoint="example17.cloudfront.net",
            enabled=enabled,
            deployment_status=status,
            is_default=is_default,
            tenant_association_present=tenant_association_present,
        )

    def request(self, operation):
        return self.contract.LifecycleRequest(
            request_id=f"request-{operation.value}",
            adapter_id="aws-cloudfront-v1",
            source_revision="a" * 40,
            provider_context=self.authority.provider_context,
            target=self.target,
            operation=operation,
            parameters_sha256="b" * 64,
        )

    def test_parent_template_is_tenant_only_and_fail_closed(self) -> None:
        config = self.contract.build_distribution_config("qualification-17")
        self.contract.validate_distribution_config(config)
        behavior = config["DefaultCacheBehavior"]
        self.assertEqual("tenant-only", config["ConnectionMode"])
        self.assertEqual("https-only", behavior["ViewerProtocolPolicy"])
        self.assertEqual(self.contract.CACHING_DISABLED_ID, behavior["CachePolicyId"])
        self.assertEqual(
            self.contract.ALL_VIEWER_EXCEPT_HOST_ID,
            behavior["OriginRequestPolicyId"],
        )
        self.assertEqual(
            "{{OriginDomain}}", config["Origins"]["Items"][0]["DomainName"]
        )
        self.assertEqual(
            "https-only",
            config["Origins"]["Items"][0]["CustomOriginConfig"][
                "OriginProtocolPolicy"
            ],
        )

        cases = (
            ("ViewerProtocolPolicy", "redirect-to-https"),
            ("ViewerProtocolPolicy", "allow-all"),
            ("CachePolicyId", "different-policy"),
            ("OriginRequestPolicyId", "different-policy"),
        )
        for key, value in cases:
            with self.subTest(key=key, value=value):
                changed = self.contract.deep_copy(config)
                changed["DefaultCacheBehavior"][key] = value
                with self.assertRaises(self.contract.ContractError):
                    self.contract.validate_distribution_config(changed)

    def test_parent_create_inspect_update_disable_delete_are_exact(self) -> None:
        create = self.contract.plan_create_distribution("qualification-17")
        self.assertEqual("CreateDistribution", create.api_operation)
        self.assertIsNone(create.resource_id)
        self.contract.validate_distribution_config(
            create.parameters["DistributionConfig"]
        )

        inspect = self.contract.plan_inspection(
            self.contract.Operation.INSPECT_DISTRIBUTION, self.target
        )
        self.assertEqual("GetDistributionConfig", inspect.api_operation)
        self.assertEqual("E1EXAMPLEPARENT", inspect.resource_id)

        parent = self.contract.DistributionObservation(
            distribution_id="E1EXAMPLEPARENT",
            etag="PARENT-ETAG",
            enabled=True,
            deployment_status="Deployed",
        )
        config = self.contract.build_distribution_config("qualification-17")
        update = self.contract.plan_distribution_mutation(
            self.contract.Operation.UPDATE_DISTRIBUTION,
            self.target,
            parent,
            admitted_etag=parent.etag,
            current_config=config,
        )
        self.assertEqual(parent.etag, update.if_match)
        disabled = self.contract.plan_distribution_mutation(
            self.contract.Operation.DISABLE_DISTRIBUTION,
            self.target,
            parent,
            admitted_etag=parent.etag,
            current_config=config,
        )
        self.assertFalse(disabled.parameters["DistributionConfig"]["Enabled"])
        deleted = self.contract.plan_distribution_mutation(
            self.contract.Operation.DELETE_DISTRIBUTION,
            self.target,
            replace(parent, enabled=False),
            admitted_etag=parent.etag,
        )
        self.assertEqual("DeleteDistribution", deleted.api_operation)

        with self.assertRaises(self.contract.ContractError):
            self.contract.plan_distribution_mutation(
                self.contract.Operation.DISABLE_DISTRIBUTION,
                self.target,
                parent,
                admitted_etag="PARENT-STALE",
                current_config=config,
            )

        for origin_value in ("fixed.example.test", "{{ViewerHost}}", ""):
            with self.subTest(origin_domain=origin_value):
                changed = self.contract.deep_copy(config)
                changed["Origins"]["Items"][0]["DomainName"] = origin_value
                with self.assertRaises(self.contract.ContractError):
                    self.contract.validate_distribution_config(changed)

    def test_tenant_create_binds_routing_and_certificate_bootstrap(self) -> None:
        request = self.contract.build_create_tenant_request(self.inputs)
        self.assertEqual([{"Domain": "viewer.example.test"}], request["Domains"])
        self.assertEqual(
            [{"Name": "OriginDomain", "Value": "origin.example.test"}],
            request["Parameters"],
        )
        self.assertTrue(request["Enabled"])
        self.assertEqual("cg_example17", request["ConnectionGroupId"])
        self.assertEqual(
            {
                "ValidationTokenHost": "cloudfront",
                "PrimaryDomainName": "viewer.example.test",
                "CertificateTransparencyLoggingPreference": "enabled",
            },
            request["ManagedCertificateRequest"],
        )

        for origin_domain in ("", self.inputs.viewer_domain):
            with self.assertRaises(self.contract.ContractError):
                self.contract.build_create_tenant_request(
                    replace(self.inputs, origin_domain=origin_domain)
                )

    def test_custom_connection_group_is_exact_routing_prerequisite(self) -> None:
        create = self.contract.plan_create_connection_group("qualification-17")
        self.assertEqual("CreateConnectionGroup", create.api_operation)
        self.assertEqual(
            {"Name": "qualification-17", "Enabled": True}, create.parameters
        )
        inspect = self.contract.plan_inspection(
            self.contract.Operation.INSPECT_CONNECTION_GROUP, self.target
        )
        self.assertEqual("GetConnectionGroup", inspect.api_operation)
        self.assertEqual("cg_example17", inspect.resource_id)

        observation = self.contract.normalize_connection_group_response(
            {
                "ETag": "GROUP-ETAG",
                "ConnectionGroup": {
                    "Id": "cg_example17",
                    "RoutingEndpoint": "example17.cloudfront.net",
                    "Enabled": True,
                    "Status": "Deployed",
                    "IsDefault": False,
                },
            },
            tenant_association_present=False,
        )
        group_target = replace(self.target, connection_group_id="cg_example17")
        self.contract.validate_connection_group_observation(
            observation, group_target, qualification_owned=True
        )
        existing_default = replace(observation, is_default=True)
        self.contract.validate_connection_group_observation(
            existing_default, group_target, qualification_owned=False
        )
        with self.assertRaises(self.contract.ContractError):
            self.contract.validate_connection_group_observation(
                existing_default, group_target, qualification_owned=True
            )
        with self.assertRaises(self.contract.ContractError):
            self.contract.validate_connection_group_observation(
                observation,
                replace(group_target, connection_group_id="cg_other"),
                qualification_owned=True,
            )
        for endpoint in ("origin.example.test", "cloudfront.net"):
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(self.contract.ContractError):
                    replace(observation, routing_endpoint=endpoint)
        disabled = self.contract.plan_connection_group_mutation(
            self.contract.Operation.DISABLE_CONNECTION_GROUP,
            group_target,
            observation,
            admitted_etag=observation.etag,
        )
        self.assertEqual({"Enabled": False}, disabled.parameters)
        deleted = self.contract.plan_connection_group_mutation(
            self.contract.Operation.DELETE_CONNECTION_GROUP,
            group_target,
            replace(observation, enabled=False),
            admitted_etag=observation.etag,
        )
        self.assertEqual("DeleteConnectionGroup", deleted.api_operation)

        with self.assertRaises(self.contract.ContractError):
            self.contract.plan_connection_group_mutation(
                self.contract.Operation.DISABLE_CONNECTION_GROUP,
                group_target,
                observation,
                admitted_etag="GROUP-STALE",
            )
        with self.assertRaises(self.contract.ContractError):
            self.contract.plan_connection_group_mutation(
                self.contract.Operation.DELETE_CONNECTION_GROUP,
                group_target,
                replace(observation, enabled=False, tenant_association_present=True),
                admitted_etag=observation.etag,
            )
        with self.assertRaises(self.contract.ContractError):
            self.contract.plan_connection_group_mutation(
                self.contract.Operation.DELETE_CONNECTION_GROUP,
                group_target,
                replace(observation, enabled=False, is_default=True),
                admitted_etag=observation.etag,
            )

    def test_qualification_orders_routing_before_tenant_without_request_update(self) -> None:
        operations = self.contract.qualification_operations()
        self.assertLess(
            operations.index(self.contract.Operation.INSPECT_CONNECTION_GROUP),
            operations.index(self.contract.Operation.CREATE_TENANT),
        )
        self.assertNotIn(
            "request-certificate", [operation.value for operation in operations]
        )
        self.assertNotIn(
            "activate-tenant", [operation.value for operation in operations]
        )

    def test_tenant_existence_is_not_certificate_activation(self) -> None:
        tenant = self.tenant(
            enabled=True,
            domain_status="inactive",
            certificate_arn=None,
        )
        self.assertEqual(
            self.contract.CertificateState.REQUESTED,
            self.contract.classify_certificate_state(tenant, None),
        )
        self.assertNotEqual(
            self.contract.CertificateState.ACTIVE,
            self.contract.classify_certificate_state(tenant, None),
        )

    def test_certificate_states_preserve_provider_distinctions(self) -> None:
        token = self.contract.ValidationToken(
            domain="viewer.example.test",
            redirect_from=(
                "viewer.example.test/.well-known/pki-validation/token-source"
            ),
            redirect_to=(
                "validation.us-east-1.acm-validations.aws/.well-known/"
                "pki-validation/token-target"
            ),
        )
        pending = self.certificate("pending-validation", tokens=(token,))
        issued = self.certificate("issued")
        unattached = self.tenant(domain_status="inactive", certificate_arn=None)
        attached = self.tenant(enabled=True, domain_status="inactive")
        active = self.tenant()

        cases = (
            (unattached, pending, self.contract.CertificateState.VALIDATION_REQUIRED),
            (unattached, issued, self.contract.CertificateState.ISSUED),
            (attached, issued, self.contract.CertificateState.ATTACHED),
            (active, issued, self.contract.CertificateState.ACTIVE),
            (
                unattached,
                self.certificate("inactive"),
                self.contract.CertificateState.INACTIVE,
            ),
            (
                unattached,
                self.certificate("validation-timed-out"),
                self.contract.CertificateState.FAILED,
            ),
        )
        for tenant, certificate, expected in cases:
            with self.subTest(expected=expected.value):
                self.assertEqual(
                    expected,
                    self.contract.classify_certificate_state(tenant, certificate),
                )

        for status in ("pending-validation", "issued"):
            with self.subTest(contradictory_validation_mode=status):
                with self.assertRaises(self.contract.ContractError):
                    self.contract.classify_certificate_state(
                        unattached,
                        self.certificate(
                            status,
                            validation_token_host="self-hosted",
                        ),
                    )

    def test_mutations_require_exact_current_etag_and_native_target(self) -> None:
        tenant = self.tenant(domain_status="inactive", certificate_arn=None)
        operations = (
            self.contract.Operation.ATTACH_CERTIFICATE,
            self.contract.Operation.UPDATE_TENANT,
            self.contract.Operation.DISABLE_TENANT,
            self.contract.Operation.DELETE_TENANT,
        )
        for operation in operations:
            with self.subTest(operation=operation.value):
                with self.assertRaises(self.contract.ContractError):
                    self.contract.plan_tenant_mutation(
                        operation,
                        self.target,
                        tenant,
                        self.inputs,
                        admitted_etag="ETAG-STALE",
                        certificate=self.certificate(),
                    )

        missing_id = replace(self.target, tenant_id=None)
        with self.assertRaises(self.contract.ContractError):
            self.contract.plan_tenant_mutation(
                self.contract.Operation.ATTACH_CERTIFICATE,
                missing_id,
                tenant,
                self.inputs,
                admitted_etag=tenant.etag,
                certificate=self.certificate(),
            )

    def test_certificate_issue_attachment_and_active_observation_are_separate(
        self,
    ) -> None:
        tenant = self.tenant(domain_status="inactive", certificate_arn=None)
        attachment = self.contract.plan_tenant_mutation(
            self.contract.Operation.ATTACH_CERTIFICATE,
            self.target,
            tenant,
            self.inputs,
            admitted_etag=tenant.etag,
            certificate=self.certificate("issued"),
        )
        self.assertEqual(
            self.certificate().certificate_arn,
            attachment.parameters["Customizations"]["Certificate"]["Arn"],
        )
        self.assertNotIn("Enabled", attachment.parameters)

        self.assertFalse(hasattr(self.contract.Operation, "ACTIVATE_TENANT"))

        with self.assertRaises(self.contract.ContractError):
            self.contract.plan_tenant_mutation(
                self.contract.Operation.ATTACH_CERTIFICATE,
                self.target,
                tenant,
                self.inputs,
                admitted_etag=tenant.etag,
                certificate=self.certificate("pending-validation"),
            )

    def test_realistic_aws_representations_normalize_before_admission(self) -> None:
        tenant_response = {
            "ETag": "ETAG-CURRENT",
            "DistributionTenant": {
                "Id": "dt_example17",
                "DistributionId": "E1EXAMPLEPARENT",
                "Name": "qualification-17",
                "Domains": [
                    {"Domain": "viewer.example.test", "Status": "inactive"}
                ],
                "Parameters": [
                    {"Name": "OriginDomain", "Value": "origin.example.test"}
                ],
                "ConnectionGroupId": "cg_example17",
                "Enabled": True,
                "Status": "Deployed",
            },
        }
        tenant = self.contract.normalize_tenant_response(tenant_response)
        self.contract.validate_tenant_observation(tenant, self.inputs, self.target)
        self.assertEqual("origin.example.test", tenant.origin_domain)

        certificate_response = {
            "ManagedCertificateDetails": {
                "CertificateArn": (
                    "arn:aws:acm:us-east-1:123456789012:certificate/example"
                ),
                "CertificateStatus": "pending-validation",
                "ValidationTokenHost": "self-hosted",
                "ValidationTokenDetails": [
                    {
                        "Domain": "viewer.example.test",
                        "RedirectFrom": (
                            "viewer.example.test/.well-known/pki-validation/source"
                        ),
                        "RedirectTo": (
                            "validation.us-east-1.acm-validations.aws/.well-known/"
                            "pki-validation/target"
                        ),
                    }
                ],
            }
        }
        certificate = self.contract.normalize_certificate_response(certificate_response)
        self.assertEqual("pending-validation", certificate.status)
        self.assertEqual(1, len(certificate.validation_tokens))

        wrong_target = replace(self.target, tenant_id="dt_other")
        with self.assertRaises(self.contract.ContractError):
            self.contract.validate_tenant_observation(
                tenant, self.inputs, wrong_target
            )

    def test_update_preserves_explicit_origin_domain(self) -> None:
        tenant = self.tenant()
        changed_inputs = replace(self.inputs, origin_domain="origin-2.example.test")
        plan = self.contract.plan_tenant_mutation(
            self.contract.Operation.UPDATE_TENANT,
            self.target,
            tenant,
            changed_inputs,
            admitted_etag=tenant.etag,
        )
        self.assertEqual(
            [{"Name": "OriginDomain", "Value": "origin-2.example.test"}],
            plan.parameters["Parameters"],
        )

    def test_teardown_is_disable_inspect_delete_then_parent(self) -> None:
        parent = self.contract.DistributionObservation(
            distribution_id="E1EXAMPLEPARENT",
            etag="PARENT-ETAG",
            enabled=True,
            deployment_status="Deployed",
        )
        self.assertEqual(
            self.contract.Operation.DISABLE_TENANT,
            self.contract.next_teardown_operation(
                self.tenant(), self.connection_group(), parent
            ),
        )
        self.assertEqual(
            self.contract.Operation.INSPECT_TENANT,
            self.contract.next_teardown_operation(
                self.tenant(enabled=False, status="InProgress"),
                self.connection_group(),
                parent,
            ),
        )
        self.assertEqual(
            self.contract.Operation.DELETE_TENANT,
            self.contract.next_teardown_operation(
                self.tenant(enabled=False), self.connection_group(), parent
            ),
        )
        self.assertFalse(hasattr(self.contract.CertificateState, "TEARDOWN_SAFE"))
        pending_without_arn = self.contract.ManagedCertificateObservation(
            status="pending-validation",
            certificate_arn=None,
            validation_token_host="cloudfront",
        )
        self.assertEqual(
            self.contract.CertificateState.VALIDATION_REQUIRED,
            self.contract.classify_certificate_state(
                self.tenant(enabled=False, certificate_arn=None),
                pending_without_arn,
            ),
        )
        self.assertEqual(
            self.contract.Operation.DISABLE_CONNECTION_GROUP,
            self.contract.next_teardown_operation(
                None, self.connection_group(), parent
            ),
        )
        self.assertEqual(
            self.contract.Operation.DELETE_CONNECTION_GROUP,
            self.contract.next_teardown_operation(
                None, self.connection_group(enabled=False), parent
            ),
        )
        self.assertEqual(
            self.contract.Operation.DISABLE_DISTRIBUTION,
            self.contract.next_teardown_operation(None, None, parent),
        )
        self.assertEqual(
            self.contract.Operation.DELETE_DISTRIBUTION,
            self.contract.next_teardown_operation(
                None, None, replace(parent, enabled=False)
            ),
        )

        unsafe = self.tenant(enabled=True)
        with self.assertRaises(self.contract.ContractError):
            self.contract.plan_tenant_mutation(
                self.contract.Operation.DELETE_TENANT,
                self.target,
                unsafe,
                self.inputs,
                admitted_etag=unsafe.etag,
            )

    def test_authority_and_results_are_exactly_correlated(self) -> None:
        request = self.request(self.contract.Operation.ATTACH_CERTIFICATE)
        self.contract.admit_request(request, self.authority)

        missing_group_target = replace(self.target, connection_group_id=None)
        with self.assertRaises(self.contract.ContractError):
            self.contract.admit_request(
                replace(request, target=missing_group_target),
                replace(self.authority, target=missing_group_target),
            )

        mismatches = (
            replace(self.authority, source_revision="c" * 40),
            replace(self.authority, parameters_sha256="d" * 64),
            replace(
                self.authority,
                target=replace(self.target, tenant_id="dt_other"),
            ),
            replace(
                self.authority,
                operations=frozenset({self.contract.Operation.INSPECT_TENANT}),
            ),
        )
        for authority in mismatches:
            with self.assertRaises(self.contract.ContractError):
                self.contract.admit_request(request, authority)

        result = self.contract.LifecycleResult.from_request(
            request,
            outcome=self.contract.Outcome.OBSERVED,
            resource_id=self.target.tenant_id,
            resource_etag="ETAG-NEW",
        )
        self.contract.admit_result(request, result)
        with self.assertRaises(self.contract.ContractError):
            self.contract.admit_result(
                request, replace(result, request_id="request-other")
            )
        with self.assertRaises(self.contract.ContractError):
            self.contract.admit_result(
                request, replace(result, resource_id="dt_other")
            )

    def test_public_types_exclude_customer_fleet_commercial_and_secrets(self) -> None:
        public_fields = {
            field.name
            for contract_type in (
                self.contract.AwsProviderContext,
                self.contract.CloudFrontTarget,
                self.contract.ExecutionAuthority,
                self.contract.LifecycleRequest,
                self.contract.LifecycleResult,
                self.contract.TenantInputs,
            )
            for field in fields(contract_type)
        }
        forbidden = {
            "customer",
            "fleet",
            "placement",
            "preferred_account",
            "commercial_tier",
            "price",
            "margin",
            "credential",
            "secret",
            "private_key",
        }
        self.assertTrue(public_fields.isdisjoint(forbidden))


if __name__ == "__main__":
    unittest.main()
