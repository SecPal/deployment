#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Behavior evidence for the PROTECTED provider-firewall adapter seam."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "scripts" / "provider-firewall-contract.py"


def load_contract():
    specification = importlib.util.spec_from_file_location(
        "provider_firewall_contract", CONTRACT_PATH
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("unable to load provider firewall contract")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module



class AuthenticatedFirewallRemediationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = load_contract()
        self.capability = self.contract.capability
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.state = Path(self.temporary.name) / "prefix-state"
        source = {
            "syncToken": "1788081425",
            "createDate": "2026-08-30-09-17-05",
            "prefixes": [
                {
                    "ip_prefix": "192.0.2.0/24",
                    "region": "GLOBAL",
                    "service": "CLOUDFRONT_ORIGIN_FACING",
                    "network_border_group": "GLOBAL",
                }
            ],
            "ipv6_prefixes": [
                {
                    "ipv6_prefix": "2001:db8:1::/48",
                    "region": "GLOBAL",
                    "service": "CLOUDFRONT_ORIGIN_FACING",
                    "network_border_group": "GLOBAL",
                }
            ],
        }
        candidate = self.contract.lkg.build_candidate(
            source, retrieved_at="2026-08-30T12:20:10Z"
        )
        self.contract.lkg.write_candidate(self.state, candidate)
        self.contract.lkg.accept_candidate(
            self.state, candidate["candidate_sha256"]
        )
        self.accepted_identity = candidate["candidate_sha256"]
        self.target = self.capability.ResourceTarget(
            provider="example-cloud",
            scope="project-42/region-a",
            requested_key="origin-firewall",
            provider_resource_id="firewall-17",
        )
        self.intent = self.contract.FirewallIntent(
            edge_mode=self.contract.EdgeMode.PROTECTED,
            origin_protocol="tcp",
            origin_port=443,
        )
        self.desired = self.contract.FirewallPolicy(
            protocol="tcp",
            port=443,
            ipv4_sources=("192.0.2.0/24",),
            ipv6_sources=("2001:db8:1::/48",),
        )

    def observation(
        self,
        *,
        phase=None,
        owned=(),
        operator_access=("operator-rule-9",),
        preserved_state_sha256="d" * 64,
        revision="revision-3",
        complete=True,
        authority_operation=None,
        request_parameters=None,
        result_request_id=None,
        result_source_revision=None,
        provider_rule_id=None,
        supported_operations=None,
    ):
        phase = phase or self.contract.ObservationPhase.CURRENT
        if supported_operations is None:
            supported_operations = frozenset(
                {
                    self.capability.Operation.INSPECT,
                    self.capability.Operation.REBUILD,
                }
            )
        digest = (
            request_parameters
            or self.contract.inspection_parameters_sha256(
                self.target, phase, supported_operations
            )
        )
        operation = authority_operation or self.capability.Operation.INSPECT
        authority = self.capability.ExecutionAuthority(
            authorization_id=f"inspect-{phase.value}",
            adapter_id="example-firewall-v2",
            source_revision="a" * 40,
            target=self.target,
            operations=frozenset({operation}),
            parameters_sha256=digest,
            credential_mechanism="oidc-workload-identity",
        )
        request = self.capability.CapabilityRequest(
            request_id=f"request-{phase.value}",
            adapter_id=authority.adapter_id,
            source_revision=authority.source_revision,
            operation=self.capability.Operation.INSPECT,
            target=self.target,
            parameters_sha256=digest,
        )
        result = self.capability.CapabilityResult(
            request_id=result_request_id or request.request_id,
            adapter_id=request.adapter_id,
            source_revision=result_source_revision or request.source_revision,
            operation=request.operation,
            target=request.target,
            parameters_sha256=request.parameters_sha256,
            outcome=self.capability.Outcome.OBSERVED,
            cleanup=self.capability.CleanupOutcome.NOT_APPLICABLE,
            provider_resource_id=self.target.provider_resource_id,
            provider_resource_version=revision,
        )
        if provider_rule_id is not None:
            owned = (
                self.contract.OwnedFirewallPolicy(provider_rule_id, self.desired),
            )
        observation = self.contract.FirewallObservation(
            phase=phase,
            request=request,
            result=result,
            supported_operations=supported_operations,
            ownership_scope=self.contract.OwnershipScope.PROTECTED_ORIGIN,
            owned=tuple(owned),
            operator_access=tuple(operator_access),
            preserved_state_sha256=preserved_state_sha256,
            completeness=(
                self.contract.ProjectionCompleteness.COMPLETE
                if complete
                else None
            ),
        )
        return observation, authority

    def mutation_authority(self, plan):
        target = plan.target
        return self.capability.ExecutionAuthority(
            authorization_id="mutate-owned-origin",
            adapter_id="example-firewall-v2",
            source_revision="a" * 40,
            target=target,
            operations=frozenset({self.capability.Operation.REBUILD}),
            parameters_sha256=self.contract.mutation_parameters_sha256(plan),
            credential_mechanism="oidc-workload-identity",
        )

    def mutation_result(self, request, *, outcome=None, cleanup=None):
        return self.capability.CapabilityResult(
            request_id=request.request_id,
            adapter_id=request.adapter_id,
            source_revision=request.source_revision,
            operation=request.operation,
            target=request.target,
            parameters_sha256=request.parameters_sha256,
            outcome=outcome or self.capability.Outcome.APPLIED,
            cleanup=cleanup or self.capability.CleanupOutcome.NOT_APPLICABLE,
            provider_resource_id=request.target.provider_resource_id,
            provider_resource_version="revision-4",
            diagnostic_code=(
                "provider-mutation-failed"
                if outcome is self.capability.Outcome.FAILED
                else None
            ),
        )

    def test_f1_only_actual_214_accepted_state_is_authority(self) -> None:
        current, inspect_authority = self.observation()
        fabricated = {
            "schema_version": 1,
            "candidate_sha256": "f" * 64,
        }
        with self.assertRaises((TypeError, self.contract.ContractError)):
            self.contract.plan(
                self.intent, fabricated, current, inspect_authority
            )
        accepted = self.contract.lkg.read_lkg(self.state)
        assert accepted is not None
        accepted["schema_version"] = True
        accepted["candidate_sha256"] = self.contract.lkg.candidate_digest(accepted)
        accepted_path = self.state / self.contract.lkg.LKG_FILE
        accepted_path.write_bytes(self.contract.lkg._canonical_bytes(accepted))
        with self.assertRaises(self.contract.lkg.ContractError):
            self.contract.plan(
                self.intent, self.state, current, inspect_authority
            )

    def test_f2_169_operation_parameter_and_result_binding(self) -> None:
        current, authority = self.observation(
            authority_operation=self.capability.Operation.CREATE
        )
        with self.assertRaises(self.capability.ContractError):
            self.contract.plan(self.intent, self.state, current, authority)
        current, authority = self.observation(request_parameters="e" * 64)
        with self.assertRaises(self.contract.ContractError):
            self.contract.plan(self.intent, self.state, current, authority)
        with self.assertRaises(self.capability.ContractError):
            current, authority = self.observation(result_request_id="other-request")
            self.contract.plan(self.intent, self.state, current, authority)
        with self.assertRaises(self.capability.ContractError):
            current, authority = self.observation(
                result_source_revision="b" * 40
            )
            self.contract.plan(self.intent, self.state, current, authority)

        current, authority = self.observation(
            supported_operations=frozenset({self.capability.Operation.INSPECT})
        )
        mutation_plan = self.contract.plan(
            self.intent, self.state, current, authority
        )
        mutation_authority = self.mutation_authority(mutation_plan)
        with self.assertRaises(self.capability.UnsupportedCapability):
            self.contract.build_mutation_request(
                mutation_plan, mutation_authority, "unsupported-rebuild"
            )

    def test_f3_no_constructor_can_bypass_admission(self) -> None:
        self.assertFalse(hasattr(self.contract, "AdmittedFirewallInput"))
        with self.assertRaises(self.contract.ContractError):
            self.contract.FirewallIntent(
                self.contract.EdgeMode.PROTECTED, "tcp", 22
            )

    def test_f4_ownership_is_adapter_bound_and_disjoint_from_operator(self) -> None:
        with self.assertRaises(self.contract.ContractError):
            self.observation(provider_rule_id="operator-rule-9")
        with self.assertRaises(TypeError):
            self.contract.FirewallIntent(
                edge_mode=self.contract.EdgeMode.PROTECTED,
                origin_protocol="tcp",
                origin_port=443,
                ownership_id="operator",
            )

    def test_f5_mutation_requires_observed_concurrency(self) -> None:
        current, authority = self.observation(revision=None)
        plan = self.contract.plan(self.intent, self.state, current, authority)
        mutation_authority = self.mutation_authority(plan)
        with self.assertRaises(self.contract.ContractError):
            self.contract.build_mutation_request(
                plan, mutation_authority, "mutation-1"
            )

    def test_f6_failure_reinspects_and_rollback_uses_fresh_revision(self) -> None:
        current, inspect_authority = self.observation()
        plan = self.contract.plan(
            self.intent, self.state, current, inspect_authority
        )
        mutation_authority = self.mutation_authority(plan)
        request = self.contract.build_mutation_request(
            plan, mutation_authority, "mutation-1"
        )
        failed = self.mutation_result(
            request,
            outcome=self.capability.Outcome.FAILED,
            cleanup=self.capability.CleanupOutcome.INCOMPLETE,
        )
        self.assertIs(
            self.contract.admit_mutation_result(
                plan, mutation_authority, request, failed
            ),
            self.contract.MutationDisposition.REINSPECTION_REQUIRED,
        )
        fresh, fresh_authority = self.observation(
            phase=self.contract.ObservationPhase.POST_MUTATION,
            revision="revision-4",
            owned=(
                self.contract.OwnedFirewallPolicy(
                    "provider-partial-8",
                    self.contract.FirewallPolicy(
                        "tcp",
                        443,
                        ("198.51.100.0/24",),
                        ("2001:db8:2::/48",),
                    ),
                ),
            ),
        )
        rollback = self.contract.recovery_plan(
            plan,
            mutation_authority,
            request,
            failed,
            fresh,
            fresh_authority,
        )
        self.assertEqual(rollback.target.expected_version, "revision-4")

    def test_f7_provider_assigned_identity_is_semantically_idempotent(self) -> None:
        current, authority = self.observation(provider_rule_id="provider-rule-99")
        plan = self.contract.plan(self.intent, self.state, current, authority)
        self.assertIs(plan.action, self.contract.PlanAction.NO_MUTATION)

    def test_f8_incomplete_or_overlapping_projection_fails_closed(self) -> None:
        with self.assertRaises(self.contract.ContractError):
            self.observation(complete=False)
        with self.assertRaises(self.contract.ContractError):
            self.observation(preserved_state_sha256="not-a-digest")

    def test_direct_and_forged_plan_cannot_reach_mutation(self) -> None:
        with self.assertRaises(self.contract.ContractError):
            self.contract.FirewallIntent(
                self.contract.EdgeMode.DIRECT, "tcp", 443
            )
        current, inspect_authority = self.observation()
        valid = self.contract.plan(
            self.intent, self.state, current, inspect_authority
        )
        valid_authority = self.mutation_authority(valid)
        forged = self.contract.FirewallPlan(
            action=self.contract.PlanAction.REPLACE_OWNED,
            target=valid.target,
            adapter_id=valid.adapter_id,
            source_revision=valid.source_revision,
            supported_operations=valid.supported_operations,
            accepted_lkg_identity=valid.accepted_lkg_identity,
            desired=self.contract.FirewallPolicy(
                "tcp",
                22,
                ("10.0.0.0/8",),
                ("2001:db8::/32",),
            ),
            prior_owned=valid.prior_owned,
            preserved_state_sha256=valid.preserved_state_sha256,
            operator_access=valid.operator_access,
        )
        with self.assertRaises(self.contract.ContractError):
            self.contract.build_mutation_request(
                forged, valid_authority, "forged-mutation"
            )

    def test_mutation_authority_and_result_are_exactly_correlated(self) -> None:
        current, inspect_authority = self.observation()
        plan = self.contract.plan(
            self.intent, self.state, current, inspect_authority
        )
        authority = self.mutation_authority(plan)
        wrong_adapter = self.capability.ExecutionAuthority(
            authorization_id="wrong-adapter",
            adapter_id="different-adapter",
            source_revision=authority.source_revision,
            target=authority.target,
            operations=authority.operations,
            parameters_sha256=authority.parameters_sha256,
            credential_mechanism=authority.credential_mechanism,
        )
        with self.assertRaises(self.contract.ContractError):
            self.contract.build_mutation_request(
                plan, wrong_adapter, "mutation-1"
            )
        request = self.contract.build_mutation_request(
            plan, authority, "mutation-1"
        )
        uncorrelated = self.mutation_result(request)
        uncorrelated = self.capability.CapabilityResult(
            request_id="different-request",
            adapter_id=uncorrelated.adapter_id,
            source_revision=uncorrelated.source_revision,
            operation=uncorrelated.operation,
            target=uncorrelated.target,
            parameters_sha256=uncorrelated.parameters_sha256,
            outcome=uncorrelated.outcome,
            cleanup=uncorrelated.cleanup,
            provider_resource_id=uncorrelated.provider_resource_id,
            provider_resource_version=uncorrelated.provider_resource_version,
        )
        with self.assertRaises(self.capability.ContractError):
            self.contract.admit_mutation_result(
                plan, authority, request, uncorrelated
            )

    def test_apply_is_not_verify_and_opaque_preserved_state_is_exact(self) -> None:
        current, inspect_authority = self.observation()
        plan = self.contract.plan(
            self.intent, self.state, current, inspect_authority
        )
        authority = self.mutation_authority(plan)
        request = self.contract.build_mutation_request(
            plan, authority, "mutation-1"
        )
        applied = self.mutation_result(request)
        self.assertIs(
            self.contract.admit_mutation_result(
                plan, authority, request, applied
            ),
            self.contract.MutationDisposition.REINSPECTION_REQUIRED,
        )
        fresh, fresh_authority = self.observation(
            phase=self.contract.ObservationPhase.POST_MUTATION,
            revision="revision-4",
            provider_rule_id="provider-assigned-99",
        )
        self.contract.verify(
            plan, authority, request, applied, fresh, fresh_authority
        )
        drifted, drifted_authority = self.observation(
            phase=self.contract.ObservationPhase.POST_MUTATION,
            revision="revision-4",
            provider_rule_id="provider-assigned-99",
            preserved_state_sha256="e" * 64,
        )
        with self.assertRaises(self.contract.ContractError):
            self.contract.verify(
                plan,
                authority,
                request,
                applied,
                drifted,
                drifted_authority,
            )

    def test_semantic_rollback_accepts_new_provider_identity_and_revision(self) -> None:
        prior_policy = self.contract.FirewallPolicy(
            "tcp",
            443,
            ("198.51.100.0/24",),
            ("2001:db8:2::/48",),
        )
        prior, inspect_authority = self.observation(
            owned=(
                self.contract.OwnedFirewallPolicy(
                    "provider-old-7", prior_policy
                ),
            )
        )
        plan = self.contract.plan(
            self.intent, self.state, prior, inspect_authority
        )
        mutation_authority = self.mutation_authority(plan)
        mutation_request = self.contract.build_mutation_request(
            plan, mutation_authority, "mutation-1"
        )
        failed = self.mutation_result(
            mutation_request,
            outcome=self.capability.Outcome.FAILED,
            cleanup=self.capability.CleanupOutcome.INCOMPLETE,
        )
        partial, partial_authority = self.observation(
            phase=self.contract.ObservationPhase.POST_MUTATION,
            revision="revision-4",
            owned=(
                self.contract.OwnedFirewallPolicy(
                    "provider-partial-8",
                    self.contract.FirewallPolicy(
                        "tcp",
                        443,
                        ("203.0.113.0/24",),
                        ("2001:db8:3::/48",),
                    ),
                ),
            ),
        )
        rollback = self.contract.recovery_plan(
            plan,
            mutation_authority,
            mutation_request,
            failed,
            partial,
            partial_authority,
        )
        self.assertIsInstance(rollback, self.contract.RollbackPlan)
        rollback_authority = self.capability.ExecutionAuthority(
            authorization_id="rollback-owned-origin",
            adapter_id=rollback.adapter_id,
            source_revision=rollback.source_revision,
            target=rollback.target,
            operations=frozenset({self.capability.Operation.REBUILD}),
            parameters_sha256=self.contract.rollback_parameters_sha256(rollback),
            credential_mechanism="oidc-workload-identity",
        )
        rollback_request = self.contract.build_rollback_request(
            rollback, rollback_authority, "rollback-1"
        )
        rollback_result = self.mutation_result(rollback_request)
        restored, restored_authority = self.observation(
            phase=self.contract.ObservationPhase.POST_ROLLBACK,
            revision="revision-5",
            owned=(
                self.contract.OwnedFirewallPolicy(
                    "provider-restored-10", prior_policy
                ),
            ),
        )
        self.contract.verify_rollback(
            rollback,
            rollback_authority,
            rollback_request,
            rollback_result,
            restored,
            restored_authority,
        )


if __name__ == "__main__":
    unittest.main()
