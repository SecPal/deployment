#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Behavior evidence for the PROTECTED provider-firewall adapter seam."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
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


class ProviderFirewallContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = load_contract()
        cls.capability = cls.contract.capability
        cls.target = cls.capability.ResourceTarget(
            provider="example-cloud",
            scope="project-42/region-a",
            requested_key="origin-firewall",
            provider_resource_id="firewall-17",
            expected_version="revision-3",
        )
        cls.authority = cls.capability.ExecutionAuthority(
            authorization_id="workflow-run-17",
            adapter_id="example-firewall-v1",
            source_revision="a" * 40,
            target=cls.target,
            operations=frozenset(cls.capability.Operation),
            parameters_sha256="b" * 64,
            credential_mechanism="oidc-workload-identity",
        )

    def accepted(self, **changes):
        document = {
            "schema_version": 1,
            "source_url": "https://ip-ranges.amazonaws.com/ip-ranges.json",
            "source_sync_token": "1788081425",
            "source_create_date": "2026-08-30-09-17-05",
            "retrieved_at": "2026-08-30T12:20:10Z",
            "service": "CLOUDFRONT_ORIGIN_FACING",
            "ipv4_prefixes": ["192.0.2.0/24"],
            "ipv6_prefixes": ["2001:db8:1::/48"],
        }
        document.update(changes)
        document["candidate_sha256"] = self.contract.prefix_digest(document)
        return document

    def input(self, **changes):
        document = self.accepted()
        values = {
            "authority": self.authority,
            "target": self.target,
            "edge_mode": self.contract.EdgeMode.PROTECTED,
            "accepted_lkg": document,
            "accepted_lkg_identity": document["candidate_sha256"],
            "origin_protocol": "tcp",
            "origin_port": 443,
            "ownership_id": "secpal-origin-lockdown-v1",
            "operator_access": ("operator-access-rule-9",),
        }
        values.update(changes)
        return self.contract.FirewallInput(**values)

    def rule(self, rule_id, ownership_id, sources, *, port=443):
        return self.contract.FirewallRule(
            rule_id=rule_id,
            ownership_id=ownership_id,
            protocol="tcp",
            port=port,
            ipv4_sources=tuple(source for source in sources if ":" not in source),
            ipv6_sources=tuple(source for source in sources if ":" in source),
        )

    def observation(self, *rules, revision="revision-3"):
        return self.contract.FirewallObservation(
            target=self.target,
            revision=revision,
            rules=tuple(rules),
        )

    def test_valid_accepted_dual_stack_protected_policy_is_admitted(self) -> None:
        admitted = self.contract.admit_input(self.input(operator_access=()))
        self.assertEqual(admitted.desired.ipv4_sources, ("192.0.2.0/24",))
        self.assertEqual(admitted.desired.ipv6_sources, ("2001:db8:1::/48",))
        self.assertEqual(admitted.desired.port, 443)

    def test_unsafe_prefix_and_evidence_inputs_fail_closed(self) -> None:
        cases = {
            "empty IPv4": self.accepted(ipv4_prefixes=[]),
            "empty IPv6": self.accepted(ipv6_prefixes=[]),
            "default IPv4": self.accepted(ipv4_prefixes=["0.0.0.0/0"]),
            "default IPv6": self.accepted(ipv6_prefixes=["::/0"]),
            "malformed IPv4": self.accepted(ipv4_prefixes=["not-a-cidr"]),
            "malformed IPv6": self.accepted(ipv6_prefixes=["not-a-cidr"]),
            "wrong service": self.accepted(service="AMAZON"),
        }
        for label, document in cases.items():
            document["candidate_sha256"] = self.contract.prefix_digest(document)
            with self.subTest(label=label), self.assertRaises(self.contract.ContractError):
                self.contract.admit_input(
                    self.input(
                        accepted_lkg=document,
                        accepted_lkg_identity=document["candidate_sha256"],
                    )
                )
        with self.assertRaises(self.contract.ContractError):
            self.contract.admit_input(self.input(accepted_lkg_identity="c" * 64))

    def test_target_provider_and_direct_mismatches_fail_closed(self) -> None:
        with self.assertRaises(self.contract.ContractError):
            self.contract.admit_input(
                self.input(target=self.capability.ResourceTarget(
                    provider="other-cloud", scope="project-42/region-a",
                    requested_key="origin-firewall", provider_resource_id="firewall-17",
                    expected_version="revision-3",
                ))
            )
        with self.assertRaises(self.contract.ContractError):
            self.contract.admit_input(self.input(edge_mode=self.contract.EdgeMode.DIRECT))

    def test_plan_is_idempotent_and_preserves_unrelated_rules(self) -> None:
        admitted = self.contract.admit_input(self.input())
        desired = admitted.desired
        unrelated = self.rule("operator-access-rule-9", "operator", ("203.0.113.0/24",), port=22)
        current = self.observation(desired, unrelated)
        plan = self.contract.plan(admitted, current)
        self.assertEqual(plan.action, self.contract.PlanAction.NO_MUTATION)
        self.assertEqual(plan.unrelated_rules, (unrelated,))

    def test_missing_or_stale_owned_rule_is_a_bounded_replacement(self) -> None:
        admitted = self.contract.admit_input(self.input())
        unrelated = self.rule("operator-access-rule-9", "operator", ("203.0.113.0/24",), port=22)
        missing = self.contract.plan(admitted, self.observation(unrelated))
        stale = self.contract.plan(
            admitted,
            self.observation(self.rule("owned-rule", "secpal-origin-lockdown-v1", ("198.51.100.0/24", "2001:db8:2::/48")), unrelated),
        )
        self.assertEqual(missing.action, self.contract.PlanAction.REPLACE_OWNED)
        self.assertEqual(stale.action, self.contract.PlanAction.REPLACE_OWNED)
        self.assertEqual(stale.unrelated_rules, (unrelated,))

    def test_ambiguous_ownership_and_stale_concurrency_fail_closed(self) -> None:
        admitted = self.contract.admit_input(self.input())
        duplicate = self.rule("owned-rule-2", "secpal-origin-lockdown-v1", ("192.0.2.0/24", "2001:db8:1::/48"))
        with self.assertRaises(self.contract.ContractError):
            self.contract.plan(admitted, self.observation(admitted.desired, duplicate))
        with self.assertRaises(self.contract.ContractError):
            self.contract.plan(admitted, self.observation(admitted.desired, revision="revision-4"))

    def test_apply_is_not_verification_and_failure_requires_exact_rollback(self) -> None:
        admitted = self.contract.admit_input(self.input(operator_access=()))
        prior = self.observation()
        plan = self.contract.plan(admitted, prior)
        failed = self.contract.ApplyResult(
            plan=plan, outcome=self.contract.ApplyOutcome.FAILED, diagnostic_code="provider-mutation-failed"
        )
        rollback = self.contract.admit_apply_result(failed)
        self.assertEqual(rollback.prior, prior)
        self.assertEqual(rollback.action, self.contract.RollbackAction.RESTORE_PRIOR)
        accepted = self.contract.ApplyResult(plan=plan, outcome=self.contract.ApplyOutcome.APPLY_ACCEPTED)
        self.assertIsNone(self.contract.admit_apply_result(accepted))
        with self.assertRaises(self.contract.ContractError):
            self.contract.verify(plan, self.observation())

    def test_verify_requires_exact_policy_operator_access_and_unrelated_rules(self) -> None:
        admitted = self.contract.admit_input(self.input())
        operator = self.rule("operator-access-rule-9", "operator", ("203.0.113.0/24",), port=22)
        prior = self.observation(operator)
        plan = self.contract.plan(admitted, prior)
        verified = self.observation(admitted.desired, operator)
        self.contract.verify(plan, verified)
        with self.assertRaises(self.contract.ContractError):
            self.contract.verify(plan, self.observation(admitted.desired))
        with self.assertRaises(self.contract.ContractError):
            self.contract.verify(plan, self.observation(admitted.desired, operator, self.rule("extra", "other", ("10.0.0.0/8",))))

    def test_rollback_is_exact_prior_observation_only(self) -> None:
        admitted = self.contract.admit_input(self.input())
        prior = self.observation(self.rule("operator-access-rule-9", "operator", ("203.0.113.0/24",), port=22))
        rollback = self.contract.rollback_plan(self.contract.plan(admitted, prior))
        self.contract.verify_rollback(rollback, prior)
        with self.assertRaises(self.contract.ContractError):
            self.contract.verify_rollback(rollback, self.observation())


if __name__ == "__main__":
    unittest.main()
