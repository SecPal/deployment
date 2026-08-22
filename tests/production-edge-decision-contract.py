#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Structural and negative-mutation evidence for the D.3 edge decision."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
ADR = ROOT / "docs" / "architecture" / "decisions" / "production-edge.md"
CONTRACT_START = "<!-- production-edge-contract:start -->"
CONTRACT_END = "<!-- production-edge-contract:end -->"

REQUIRED_KEYS = {
    "schema_version",
    "status",
    "reference_edge",
    "distribution",
    "runtime_authority",
    "orchestration",
    "public_boundary",
    "origins",
    "backend_boundary",
    "proxy_trust",
    "forwarded_metadata",
    "client_identity_evidence",
    "tls",
    "acme",
    "logging",
    "crowdsec",
    "supply_chain",
    "failure_semantics",
    "phase_b",
    "downstream",
}


class DecisionViolation(ValueError):
    """Raised when the normative ADR summary violates the selected contract."""


def load_contract(text: str) -> dict[str, object]:
    try:
        body = text.split(CONTRACT_START, 1)[1].split(CONTRACT_END, 1)[0]
        payload = body.split("```json", 1)[1].split("```", 1)[0]
        loaded = json.loads(payload)
    except (IndexError, json.JSONDecodeError) as error:
        raise DecisionViolation("missing or malformed normative decision contract") from error
    if not isinstance(loaded, dict) or set(loaded) != REQUIRED_KEYS:
        raise DecisionViolation("decision contract must use the closed D.3 key set")
    return loaded


def require(condition: bool, message: str) -> None:
    if not condition:
        raise DecisionViolation(message)


def validate(contract: dict[str, object]) -> None:
    require(contract["schema_version"] == 1, "schema version is closed")
    require(contract["status"] == "accepted", "the ADR must select one edge")

    edge = contract["reference_edge"]
    require(isinstance(edge, dict), "reference edge must be an object")
    require(edge.get("technology") == "nginx", "only the selected edge is supported")
    require(edge.get("phase_b_gateway") is False, "Phase B gateway is test-only")

    distribution = contract["distribution"]
    require(isinstance(distribution, dict), "distribution must be an object")
    require(distribution.get("package") == "nginx=1.26.3-3+deb13u7", "edge package is exact")
    require(distribution.get("architectures") == ["amd64", "arm64"], "both architectures are required")
    require(distribution.get("suites") == ["trixie", "trixie-security"], "only admitted Debian suites are allowed")

    authority = contract["runtime_authority"]
    require(isinstance(authority, dict), "runtime authority must be an object")
    require(authority.get("model") == "host-system-service", "edge is a host service")
    require(authority.get("user") == "dedicated-secpal-edge", "edge has a dedicated identity")
    require(authority.get("capabilities") == ["CAP_NET_BIND_SERVICE"], "edge capability set is closed")
    require(authority.get("read_only_system") is True, "edge system paths are read-only")
    require(authority.get("edge_state") == "/srv/secpal/edge-root-owned-edge-read-only", "edge state follows the D.2 namespace")

    orchestration = contract["orchestration"]
    require(orchestration == {
        "edge": "systemd-system",
        "backends": "systemd-user-native-quadlet",
        "podman_api_socket": "forbidden",
        "docker_socket": "forbidden",
    }, "system and rootless orchestration authorities must stay separate")

    public = contract["public_boundary"]
    require(isinstance(public, dict), "public boundary must be an object")
    require(public.get("public_roles") == ["edge"], "only the edge may be public")
    require(public.get("listeners") == ["0.0.0.0:80", "[::]:80", "0.0.0.0:443", "[::]:443"], "dual-stack listeners are exact")
    require(set(public.get("private_roles", [])) == {
        "frontend", "api", "migrate", "worker-general", "worker-hash-chain",
        "scheduler", "postgresql", "valkey",
    }, "every non-edge role must remain private")
    require(public.get("product_public_ports") is False, "product ports cannot be public")

    origins = contract["origins"]
    require(isinstance(origins, dict), "origins must be an object")
    require(origins.get("frontend") == "https://<frontend-host> -> frontend-only", "frontend origin is exact")
    require(origins.get("api") == "https://<api-host> -> api-only-all-paths", "API origin is exact")
    require(origins.get("same_origin") is False, "same-origin collapse is forbidden")
    require(origins.get("frontend_api_proxy") is False, "frontend API proxying is forbidden")

    backend = contract["backend_boundary"]
    require(isinstance(backend, dict), "backend boundary must be an object")
    require(backend.get("transport") == "owner-filtered-loopback-high-ports", "backends use owner-filtered loopback")
    require(backend.get("product_host_network") is False, "product host networking is forbidden")
    require(backend.get("data_edge_membership") is False, "data services cannot join the edge path")

    trust = contract["proxy_trust"]
    require(isinstance(trust, dict), "proxy trust must be an object")
    require(trust.get("allowlist") == "exact-d4-proven-immediate-peer-addresses", "proxy peers need an exact allowlist")
    require(trust.get("wildcards") is False, "wildcard proxy trust is forbidden")
    require(trust.get("caller_headers_are_identity") is False, "headers are not identity evidence")

    forwarding = contract["forwarded_metadata"]
    require(isinstance(forwarding, dict), "forwarded metadata must be an object")
    require(forwarding.get("discard") == ["Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Port", "X-Forwarded-Proto", "X-Real-IP"], "all caller forwarding metadata must be discarded")
    require(forwarding.get("set") == ["X-Forwarded-For", "X-Real-IP", "X-Forwarded-Proto", "X-Forwarded-Host", "X-Forwarded-Port"], "edge-authored forwarding metadata is closed")

    identity = contract["client_identity_evidence"]
    require(isinstance(identity, dict), "client identity evidence must be an object")
    require(identity.get("ipv4") == "direct-socket-peer-to-edge-then-edge-authored-header", "IPv4 needs real path evidence")
    require(identity.get("ipv6") == "direct-socket-peer-to-edge-then-edge-authored-header", "IPv6 needs independent real path evidence")
    require(identity.get("upstream_proxy") == "unsupported-without-superseding-adr", "unreviewed upstream proxies are unsupported")

    tls = contract["tls"]
    require(isinstance(tls, dict), "TLS must be an object")
    require(tls.get("termination") == "edge-only", "TLS terminates only at the edge")
    require(tls.get("product_tls") is False, "product TLS is forbidden")

    acme = contract["acme"]
    require(isinstance(acme, dict), "ACME must be an object")
    require(acme.get("client") == "certbot=4.0.0-2+deb13u1", "ACME client is exact")
    require(acme.get("authority") == "root-tls-operator", "ACME is not product-owned")
    require(acme.get("state") == "/srv/secpal/acme", "ACME state uses the D.2 boundary")
    require(acme.get("edge_access") == "runtime-read-only-last-valid-publication", "edge cannot write ACME state")

    logging = contract["logging"]
    require(isinstance(logging, dict), "logging must be an object")
    require(logging.get("format") == "json", "edge logs must be structured")
    require(logging.get("sink") == "stdout-to-operator-log-authority", "the public process cannot own persistent logs")
    require(logging.get("path_field") == "$uri-without-query", "queries cannot enter the path field")
    require(logging.get("fields") == ["client_ip", "timestamp", "method", "canonical_host", "canonical_path", "status", "response_bytes", "request_duration", "upstream_id", "upstream_status"], "log fields are closed")
    forbidden_logs = {"authorization", "cookies", "query", "request_body", "tokens", "user_agent"}
    require(set(logging.get("forbidden", [])) == forbidden_logs, "secret and unnecessary personal log fields are forbidden")

    crowdsec = contract["crowdsec"]
    require(isinstance(crowdsec, dict), "CrowdSec must be an object")
    require(crowdsec.get("remediation") == "asynchronous-host-nftables-firewall-bouncer", "remediation stays outside the product runtime")
    require(crowdsec.get("ipv4") is True and crowdsec.get("ipv6") is True, "remediation is dual-stack")
    require(crowdsec.get("application_readiness_dependency") is False, "CrowdSec may not gate application readiness")
    require(crowdsec.get("l7_plugin") is False, "no moving L7 plugin is selected")

    supply = contract["supply_chain"]
    require(isinstance(supply, dict), "supply chain must be an object")
    require(supply.get("runtime_downloads") == [], "runtime downloads are forbidden")
    require(supply.get("plugins") == [], "edge plugins are forbidden")
    require(supply.get("remote_configuration") is False, "remote configuration is forbidden")
    require(supply.get("moving_blocklists") is False, "moving blocklists are forbidden")
    require(supply.get("reviewed_updates_only") is True, "updates require review")

    failure = contract["failure_semantics"]
    require(isinstance(failure, dict), "failure semantics must be an object")
    require(failure.get("invalid_config") == "reject-before-activation", "invalid configuration fails closed")
    require(failure.get("reload_failure") == "retain-working-config", "reload failure retains service")
    require(failure.get("edge_failure") == "publicly-unavailable", "single edge failure is observable downtime")
    require(failure.get("acme_failure") == "retain-last-valid-certificate", "ACME failure cannot publish partial state")
    require(failure.get("crowdsec_failure") == "security-degraded-application-independent", "CrowdSec failure is degraded, not an app outage")

    phase_b = contract["phase_b"]
    require(phase_b == {
        "caddy_image": "test-only-not-promoted",
        "internal_ca": "disposable-not-promoted",
        "playwright_gateway": "behavioral-evidence-not-production",
    }, "Phase B artifacts remain test-only")

    downstream = contract["downstream"]
    require(downstream == {"d4_issue": 12, "d5_issue": 13, "d6_issue": 14}, "downstream ownership is exact")


class ProductionEdgeDecisionContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = load_contract(ADR.read_text(encoding="utf-8"))

    def assert_mutation_rejected(self, path: tuple[str, ...], value: object) -> None:
        candidate = copy.deepcopy(self.contract)
        current: object = candidate
        for segment in path[:-1]:
            if not isinstance(current, dict):
                raise AssertionError(f"non-object mutation path: {path}")
            current = current[segment]
        if not isinstance(current, dict):
            raise AssertionError(f"non-object mutation target: {path}")
        current[path[-1]] = value
        with self.assertRaises(DecisionViolation):
            validate(candidate)

    def test_selected_decision_is_complete(self) -> None:
        validate(self.contract)

    def test_phase_b_same_origin_and_product_edge_mutations_fail(self) -> None:
        mutations = {
            ("reference_edge", "technology"): "phase-b-caddy-gateway",
            ("reference_edge", "phase_b_gateway"): True,
            ("origins", "same_origin"): True,
            ("origins", "frontend_api_proxy"): True,
            ("tls", "product_tls"): True,
            ("public_boundary", "product_public_ports"): True,
            ("backend_boundary", "product_host_network"): True,
        }
        for path, value in mutations.items():
            with self.subTest(path=path):
                self.assert_mutation_rejected(path, value)

    def test_runtime_socket_and_proxy_trust_mutations_fail(self) -> None:
        mutations = {
            ("orchestration", "podman_api_socket"): "mounted",
            ("orchestration", "docker_socket"): "mounted",
            ("proxy_trust", "wildcards"): True,
            ("proxy_trust", "caller_headers_are_identity"): True,
            ("client_identity_evidence", "ipv4"): "assumed",
            ("client_identity_evidence", "ipv6"): "same-as-ipv4",
        }
        for path, value in mutations.items():
            with self.subTest(path=path):
                self.assert_mutation_rejected(path, value)

    def test_unpinned_or_moving_supply_chain_mutations_fail(self) -> None:
        mutations = {
            ("distribution", "package"): "nginx=latest",
            ("supply_chain", "runtime_downloads"): ["newest-version"],
            ("supply_chain", "plugins"): ["moving-marketplace-plugin"],
            ("supply_chain", "remote_configuration"): True,
            ("supply_chain", "moving_blocklists"): True,
        }
        for path, value in mutations.items():
            with self.subTest(path=path):
                self.assert_mutation_rejected(path, value)

    def test_acme_and_secret_log_mutations_fail(self) -> None:
        self.assert_mutation_rejected(("acme", "authority"), "product-container")
        for field in ("authorization", "cookies", "query", "request_body", "tokens"):
            with self.subTest(field=field):
                fields = [*self.contract["logging"]["fields"], field]
                self.assert_mutation_rejected(("logging", "fields"), fields)


if __name__ == "__main__":
    unittest.main()
