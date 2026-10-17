#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Pure implementation helper for the existing Rocky host-provenance owner.

Semantic owner: rocky_preparation_contract.admit_certbot_exception.
Kept outside the ordinary cloud bootstrap's bounded transport envelope.
"""

from typing import Any
from rocky_preparation_contract import REPOSITORIES, reject

def admit(
    provenance: dict[str, Any], architecture: str, policy: dict[str, Any]
) -> dict[str, Any] | None:
    """TLS-only exception; policy comes from the authenticated target checkout.

    This never extends REPOSITORIES, PACKAGES, admit_package, or Rocky's signer.
    Native callers must independently observe signatures, installed payloads,
    effective repository state, and runtime results before invoking admission.
    """
    operation = "admit-certbot-package-exception"
    if not isinstance(provenance, dict) or set(provenance) not in (
        {"distribution", "gpg_key", "enabled_repository_ids", "rpm_signatures_verified", "external_repositories_enabled"},
        {"distribution", "gpg_key", "enabled_repository_ids", "rpm_signatures_verified", "external_repositories_enabled", "certbot_exception"},
    ):
        reject("admission", operation, "representation-invalid")
    repositories = provenance.get("enabled_repository_ids")
    if (
        not isinstance(architecture, str)
        or architecture not in {"x86_64", "aarch64"}
        or provenance.get("distribution") != "rocky"
        or provenance.get("gpg_key") != "RPM-GPG-KEY-Rocky-10"
        or provenance.get("external_repositories_enabled") is not False
        or provenance.get("rpm_signatures_verified") is not True
        or not isinstance(repositories, list)
        or not all(isinstance(repository, str) for repository in repositories)
        or sorted(repositories) != sorted(REPOSITORIES)
    ):
        reject("admission", operation, "repository-state-invalid")
    exception = provenance.get("certbot_exception")
    if "certbot_exception" not in provenance:
        return None
    if not isinstance(exception, dict) or set(exception) != {
        "policy_id", "host_architecture", "packages", "installed_epel_names",
        "global_epel_key_present", "runtime",
    }:
        reject("admission", operation, "representation-invalid")
    expected = policy["closures"][architecture]
    expected_names = sorted(
        row["name"] for row in expected if row["repository"] == "epel-certbot-10.2"
    )
    if (
        exception["policy_id"] != policy["policy_id"]
        or exception["host_architecture"] != architecture
        or exception["global_epel_key_present"] is not False
        or exception["installed_epel_names"] != expected_names
    ):
        reject("admission", operation, "trust-scope-invalid")
    observed = exception["packages"]
    if not isinstance(observed, list) or len(observed) != len(expected):
        reject("admission", operation, "closure-invalid")
    for actual, reviewed in zip(observed, expected, strict=True):
        if (
            not isinstance(actual, dict)
            or actual.get("signature_verified") is not True
            or actual.get("installed_payload_verified") is not True
            or actual != dict(reviewed, signature_verified=True, installed_payload_verified=True)
        ):
            reject("admission", operation, "package-identity-invalid")
    runtime = exception["runtime"]
    if not isinstance(runtime, dict) or any(
        type(runtime.get(status)) is not int
        for status in ("imports_status", "standalone_plugin_status")
    ) or runtime != {
        "machine": architecture,
        "python_machine": architecture,
        "python_version": "3.12.15",
        "certbot_version": "4.2.0",
        "imports_status": 0,
        "standalone_plugin_status": 0,
    }:
        reject("admission", operation, "runtime-compatibility-invalid")
    return exception
