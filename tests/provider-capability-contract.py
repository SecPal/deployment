#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Behavior evidence for the portable provider capability boundary."""

from __future__ import annotations

from dataclasses import fields, replace
import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "scripts" / "provider-capability-contract.py"


def load_contract():
    specification = importlib.util.spec_from_file_location(
        "provider_capability_contract", CONTRACT_PATH
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("unable to load provider capability contract")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


class ProviderCapabilityContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = load_contract()
        cls.create_target = cls.contract.ResourceTarget(
            provider="example-cloud",
            scope="project-42/region-a",
            requested_key="qualification-run-17",
        )
        cls.existing_target = replace(
            cls.create_target,
            provider_resource_id="resource-8f2a",
            expected_version="version-3",
        )
        cls.authority = cls.contract.ExecutionAuthority(
            authorization_id="workflow-run-17",
            adapter_id="example-compute-v1",
            source_revision="a" * 40,
            target=cls.create_target,
            operations=frozenset(cls.contract.Operation),
            credential_mechanism="oidc-workload-identity",
        )

    def request(self, operation, target=None):
        return self.contract.CapabilityRequest(
            request_id=f"request-{operation.value}",
            adapter_id="example-compute-v1",
            source_revision="a" * 40,
            operation=operation,
            target=self.create_target if target is None else target,
            parameters_sha256="b" * 64,
        )

    def authority_for(self, target=None, operations=None):
        return replace(
            self.authority,
            target=self.create_target if target is None else target,
            operations=(
                frozenset(self.contract.Operation)
                if operations is None
                else frozenset(operations)
            ),
        )

    def result(self, request, outcome, *, cleanup=None, **readback):
        return self.contract.CapabilityResult(
            request_id=request.request_id,
            adapter_id=request.adapter_id,
            operation=request.operation,
            target=request.target,
            outcome=outcome,
            cleanup=(
                self.contract.CleanupOutcome.NOT_APPLICABLE
                if cleanup is None
                else cleanup
            ),
            **readback,
        )

    def observation(self):
        return {
            "provider_resource_id": "resource-8f2a",
            "provider_resource_version": "version-3",
            "provider_image_id": "image-sha256-927c",
        }

    def test_all_four_operations_have_bounded_results(self) -> None:
        cases = (
            (
                self.contract.Operation.CREATE,
                self.create_target,
                self.contract.Outcome.APPLIED,
                self.contract.CleanupOutcome.NOT_APPLICABLE,
                self.observation(),
            ),
            (
                self.contract.Operation.INSPECT,
                self.existing_target,
                self.contract.Outcome.OBSERVED,
                self.contract.CleanupOutcome.NOT_APPLICABLE,
                self.observation(),
            ),
            (
                self.contract.Operation.REBUILD,
                self.existing_target,
                self.contract.Outcome.APPLIED,
                self.contract.CleanupOutcome.NOT_APPLICABLE,
                self.observation(),
            ),
            (
                self.contract.Operation.DELETE,
                self.existing_target,
                self.contract.Outcome.APPLIED,
                self.contract.CleanupOutcome.COMPLETE,
                {},
            ),
        )
        for operation, target, outcome, cleanup, readback in cases:
            with self.subTest(operation=operation.value):
                request = self.request(operation, target)
                self.contract.admit_request(
                    request,
                    self.authority_for(target),
                    frozenset(self.contract.Operation),
                )
                self.contract.admit_result(
                    request,
                    self.result(
                        request, outcome, cleanup=cleanup, **readback
                    ),
                )

    def test_authority_and_target_mismatches_fail_closed(self) -> None:
        request = self.request(self.contract.Operation.DELETE, self.existing_target)
        cases = {
            "provider": self.authority_for(
                replace(self.existing_target, provider="different-cloud")
            ),
            "scope": self.authority_for(
                replace(self.existing_target, scope="project-99/region-b")
            ),
            "adapter": replace(
                self.authority_for(self.existing_target),
                adapter_id="different-adapter",
            ),
            "source": replace(
                self.authority_for(self.existing_target),
                source_revision="c" * 40,
            ),
            "resource": self.authority_for(
                replace(self.existing_target, provider_resource_id="resource-other")
            ),
            "operation": self.authority_for(
                self.existing_target, {self.contract.Operation.INSPECT}
            ),
        }
        for label, authority in cases.items():
            with self.subTest(label=label):
                with self.assertRaises(self.contract.ContractError):
                    self.contract.admit_request(
                        request, authority, frozenset(self.contract.Operation)
                    )

        ambiguous = self.request(
            self.contract.Operation.DELETE,
            replace(self.existing_target, provider_resource_id=None),
        )
        with self.assertRaises(self.contract.ContractError):
            self.contract.admit_request(
                ambiguous,
                self.authority_for(ambiguous.target),
                frozenset(self.contract.Operation),
            )

    def test_unsupported_and_already_satisfied_are_explicit(self) -> None:
        rebuild = self.request(self.contract.Operation.REBUILD, self.existing_target)
        with self.assertRaises(self.contract.UnsupportedCapability):
            self.contract.admit_request(
                rebuild,
                self.authority_for(self.existing_target),
                {self.contract.Operation.CREATE, self.contract.Operation.DELETE},
            )

        for operation, target, readback in (
            (self.contract.Operation.CREATE, self.create_target, self.observation()),
            (self.contract.Operation.REBUILD, self.existing_target, self.observation()),
            (self.contract.Operation.DELETE, self.existing_target, {}),
        ):
            with self.subTest(operation=operation.value):
                request = self.request(operation, target)
                cleanup = (
                    self.contract.CleanupOutcome.COMPLETE
                    if operation is self.contract.Operation.DELETE
                    else self.contract.CleanupOutcome.NOT_APPLICABLE
                )
                self.contract.admit_result(
                    request,
                    self.result(
                        request,
                        self.contract.Outcome.ALREADY_SATISFIED,
                        cleanup=cleanup,
                        **readback,
                    ),
                )

    def test_mismatch_staleness_and_incomplete_cleanup_are_closed(self) -> None:
        rebuild = self.request(self.contract.Operation.REBUILD, self.existing_target)
        with self.assertRaises(self.contract.ContractError):
            self.contract.admit_result(
                rebuild,
                self.result(
                    rebuild,
                    self.contract.Outcome.APPLIED,
                    **(self.observation() | {"provider_resource_id": "resource-other"}),
                ),
            )

        inspect = self.request(self.contract.Operation.INSPECT, self.existing_target)
        with self.assertRaises(self.contract.ContractError):
            self.contract.admit_result(
                inspect,
                self.result(
                    inspect,
                    self.contract.Outcome.OBSERVED,
                    **(
                        self.observation()
                        | {"provider_resource_version": "version-stale"}
                    ),
                ),
            )

        delete = self.request(self.contract.Operation.DELETE, self.existing_target)
        with self.assertRaises(self.contract.ContractError):
            self.contract.admit_result(
                delete,
                self.result(delete, self.contract.Outcome.APPLIED),
            )

        create = self.request(self.contract.Operation.CREATE)
        with self.assertRaises(self.contract.ContractError):
            self.contract.admit_result(
                create,
                self.result(
                    create,
                    self.contract.Outcome.FAILED,
                    diagnostic_code="provider-timeout",
                ),
            )
        self.contract.admit_result(
            create,
            self.result(
                create,
                self.contract.Outcome.FAILED,
                cleanup=self.contract.CleanupOutcome.INCOMPLETE,
                diagnostic_code="provider-timeout",
            ),
        )

    def test_contract_has_no_customer_fleet_or_commercial_policy_fields(self) -> None:
        public_fields = {
            field.name
            for contract_type in (
                self.contract.ResourceTarget,
                self.contract.ExecutionAuthority,
                self.contract.CapabilityRequest,
                self.contract.CapabilityResult,
            )
            for field in fields(contract_type)
        }
        forbidden = {
            "customer",
            "fleet",
            "placement",
            "preferred_provider",
            "sku",
            "price",
            "margin",
            "reserve",
            "credential",
            "secret",
        }
        self.assertTrue(public_fields.isdisjoint(forbidden))


if __name__ == "__main__":
    unittest.main()
