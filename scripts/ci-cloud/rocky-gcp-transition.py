#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Rotate access and start one exact Rocky guest without a cloud identity."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


PROJECT = "secpal-dev"
ZONE = "europe-west3-a"
PROJECT_ROOT = f"https://compute.googleapis.com/compute/v1/projects/{PROJECT}"
API_ROOT = f"{PROJECT_ROOT}/zones/{ZONE}"
INSTANCE = re.compile(r"^sprk-([1-9][0-9]{0,19})-([1-9][0-9]{0,2})-instance$")
SHA = re.compile(r"^[0-9a-f]{40}$")
NUMBER = re.compile(r"^[1-9][0-9]{0,19}$")
PUBLIC_KEY = re.compile(r"^ssh-ed25519 [A-Za-z0-9+/]+={0,2} secpal-rocky-[1-9][0-9]{0,19}-[1-9][0-9]{0,2}$")
BOOTSTRAP_ACCOUNT = "secpal-ci-bootstrap@secpal-dev.iam.gserviceaccount.com"


class TransitionError(RuntimeError):
    pass


class Client:
    def __init__(self, token: str) -> None:
        if not re.fullmatch(r"[A-Za-z0-9._~-]{20,4096}", token):
            raise TransitionError("access token is outside the bounded in-memory format")
        self.token = token

    def request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        root = PROJECT_ROOT if path.startswith("global/") else API_ROOT
        request = urllib.request.Request(
            f"{root}/{path}",
            method=method,
            data=body,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self.token}",
                **({"Content-Type": "application/json"} if body else {}),
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read(1_000_001)
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as error:
            raise TransitionError(f"GCP {method} operation failed") from error
        if len(raw) > 1_000_000:
            raise TransitionError("GCP response exceeded the size bound")
        try:
            result = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise TransitionError("GCP returned invalid JSON") from error
        if not isinstance(result, dict):
            raise TransitionError("GCP response must be an object")
        return result

    def wait_operation(self, name: str, *, global_operation: bool = False) -> None:
        if re.fullmatch(r"[a-z0-9][a-z0-9-]{0,127}", name) is None:
            raise TransitionError("GCP returned an invalid operation identity")
        for _ in range(90):
            prefix = "global/operations" if global_operation else "operations"
            operation = self.request("GET", f"{prefix}/{name}")
            status = operation.get("status")
            if status == "DONE":
                if operation.get("error") is not None:
                    raise TransitionError("GCP transition operation failed")
                return
            if status not in {"PENDING", "RUNNING"}:
                raise TransitionError("GCP operation status is outside the closed set")
            time.sleep(5)
        raise TransitionError("GCP operation exceeded the transition bound")

    def mutate(
        self,
        path: str,
        payload: dict[str, Any],
        *,
        global_operation: bool = False,
        method: str = "POST",
    ) -> None:
        operation = self.request(method, path, payload)
        name = operation.get("name")
        if not isinstance(name, str):
            raise TransitionError("GCP mutation returned no operation identity")
        self.wait_operation(name, global_operation=global_operation)


def validate_instance(instance: dict[str, Any], options: argparse.Namespace) -> None:
    match = INSTANCE.fullmatch(options.instance)
    if match is None:
        raise TransitionError("instance name is outside the closed Rocky shape")
    run_id, attempt = match.groups()
    expected_labels = {
        "secpal_ci_owner": "rocky-host-qualification",
        "repository": "secpal-deployment",
        "github_run_id": run_id,
        "github_run_attempt": attempt,
        "target_sha": options.target_sha,
        "control_sha": options.control_sha,
        "provider_profile": "gcp-rocky-10-2-arm64",
        "created_at": options.created_at,
        "expires_at": options.expires_at,
    }
    if instance.get("name") != options.instance or instance.get("labels") != expected_labels:
        raise TransitionError("instance ownership does not exactly match the continuation")
    if str(instance.get("id", "")) != options.instance_id:
        raise TransitionError("live immutable instance ID does not match the continuation")
    validate_service_accounts(instance)


def validate_service_accounts(instance: dict[str, Any]) -> None:
    """Admit only identity-free or the inert bootstrap identity.

    Compute may omit an explicitly empty scopes field or return it as null.
    Those forms have the same empty-scope meaning as the historical admission
    rule, while cardinality, exact email, and non-empty/malformed scopes remain
    fail-closed.
    """
    if "serviceAccounts" not in instance:
        return
    service_accounts = instance["serviceAccounts"]
    if not isinstance(service_accounts, list):
        raise TransitionError("instance serviceAccounts is not a list")
    if not service_accounts:
        return
    if len(service_accounts) != 1 or not isinstance(service_accounts[0], dict):
        raise TransitionError("instance has an unreviewed cloud identity")
    account = service_accounts[0]
    if account.get("email") != BOOTSTRAP_ACCOUNT:
        raise TransitionError("instance holds an unreviewed cloud identity")
    scopes = account.get("scopes")
    if scopes is None:
        return
    if not isinstance(scopes, list) or scopes:
        raise TransitionError("bootstrap identity scopes are not exactly empty")


def metadata_payload(
    instance: dict[str, Any],
    public_key: str,
    access_run_id: str,
    access_run_attempt: str,
) -> dict[str, Any]:
    metadata = instance.get("metadata")
    if not isinstance(metadata, dict) or not isinstance(metadata.get("fingerprint"), str):
        raise TransitionError("instance metadata has no exact fingerprint")
    items = metadata.get("items", [])
    if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
        raise TransitionError("instance metadata is malformed")
    replacements = {
        "secpal-rocky-ssh-public-key": public_key,
        "secpal-rocky-cloud-identity-admitted": "true",
        "secpal-rocky-access-run-id": access_run_id,
        "secpal-rocky-access-run-attempt": access_run_attempt,
    }
    retained = [item for item in items if item.get("key") not in replacements]
    retained.extend({"key": key, "value": value} for key, value in replacements.items())
    if len({item.get("key") for item in retained}) != len(retained):
        raise TransitionError("instance metadata keys are ambiguous")
    return {"fingerprint": metadata["fingerprint"], "items": retained}


def wait_status(client: Client, instance_name: str, expected: str) -> dict[str, Any]:
    for _ in range(90):
        instance = client.request("GET", f"instances/{instance_name}")
        status = instance.get("status")
        if status == expected:
            return instance
        if status not in {"PROVISIONING", "STAGING", "RUNNING", "STOPPING", "TERMINATED"}:
            raise TransitionError("instance status is outside the closed set")
        time.sleep(5)
    raise TransitionError("instance status transition timed out")


def update_runner_firewall(
    client: Client,
    instance_name: str,
    runner_ipv4: str,
    expected_labels: dict[str, str],
) -> None:
    match = INSTANCE.fullmatch(instance_name)
    if match is None:
        raise TransitionError("cannot derive exact firewall identity")
    run_id, attempt = match.groups()
    name = f"sprk-{run_id}-{attempt}-ssh"
    try:
        address = ipaddress.ip_address(runner_ipv4)
    except ValueError as error:
        raise TransitionError("runner address is not an IPv4 address") from error
    if address.version != 4:
        raise TransitionError("runner address is not an IPv4 address")
    requested_source_range = f"{address}/32"
    firewall_path = f"global/firewalls/{name}"
    firewall = client.request("GET", firewall_path)
    validate_runner_firewall(
        firewall,
        name=name,
        run_id=run_id,
        attempt=attempt,
        expected_labels=expected_labels,
    )
    client.mutate(
        firewall_path,
        {"sourceRanges": [requested_source_range]},
        global_operation=True,
        method="PATCH",
    )
    firewall = client.request("GET", firewall_path)
    validate_runner_firewall(
        firewall,
        name=name,
        run_id=run_id,
        attempt=attempt,
        expected_labels=expected_labels,
        expected_source_range=requested_source_range,
    )


def validate_runner_firewall(
    firewall: dict[str, Any],
    *,
    name: str,
    run_id: str,
    attempt: str,
    expected_labels: dict[str, str],
    expected_source_range: str | None = None,
) -> None:
    """Admit the stable security fields of one exact classic SSH firewall."""
    try:
        description = json.loads(firewall.get("description"))
    except (TypeError, json.JSONDecodeError) as error:
        raise TransitionError("firewall ownership description is invalid") from error
    expected_description = {
        "o": expected_labels["secpal_ci_owner"],
        "r": expected_labels["repository"],
        "i": expected_labels["github_run_id"],
        "a": expected_labels["github_run_attempt"],
        "t": expected_labels["target_sha"],
        "c": expected_labels["control_sha"],
        "p": expected_labels["provider_profile"],
        "n": expected_labels["created_at"],
        "x": expected_labels["expires_at"],
    }
    source_ranges = firewall.get("sourceRanges")
    source_range_valid = (
        isinstance(source_ranges, list)
        and len(source_ranges) == 1
        and isinstance(source_ranges[0], str)
    )
    if source_range_valid:
        try:
            source_network = ipaddress.ip_network(source_ranges[0], strict=True)
        except ValueError:
            source_range_valid = False
        else:
            source_range_valid = (
                source_network.version == 4 and source_network.prefixlen == 32
            )
    empty_selectors = all(
        isinstance(firewall.get(key, []), list) and not firewall.get(key, [])
        for key in ("denied", "sourceTags", "sourceServiceAccounts", "targetServiceAccounts")
    )
    if (
        firewall.get("name") != name
        or description != expected_description
        or firewall.get("network")
        != f"https://www.googleapis.com/compute/v1/projects/{PROJECT}/global/networks/sprk-{run_id}-{attempt}-network"
        or type(firewall.get("priority")) is not int
        or firewall.get("priority") != 1000
        or firewall.get("direction") != "INGRESS"
        or firewall.get("allowed") != [{"IPProtocol": "tcp", "ports": ["22"]}]
        or firewall.get("targetTags") != [f"sprk-{run_id}-{attempt}"]
        or ("disabled" in firewall and firewall["disabled"] is not False)
        or not empty_selectors
        or not source_range_valid
        or (
            expected_source_range is not None
            and source_ranges != [expected_source_range]
        )
    ):
        raise TransitionError("firewall is outside the exact run-owned SSH contract")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--instance", required=True)
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--target-sha", required=True)
    parser.add_argument("--control-sha", required=True)
    parser.add_argument("--created-at", required=True)
    parser.add_argument("--expires-at", required=True)
    parser.add_argument("--ssh-public-key", required=True)
    parser.add_argument("--runner-ipv4", required=True)
    parser.add_argument("--access-run-id", required=True)
    parser.add_argument("--access-run-attempt", required=True)
    parser.add_argument("--ipv4-output", required=True, type=Path)
    options = parser.parse_args()
    try:
        if SHA.fullmatch(options.target_sha) is None or SHA.fullmatch(options.control_sha) is None:
            raise TransitionError("full lowercase target and control SHAs are required")
        if re.fullmatch(r"[1-9][0-9]{0,29}", options.instance_id) is None:
            raise TransitionError("expected instance ID is outside the closed numeric format")
        if NUMBER.fullmatch(options.access_run_id) is None or re.fullmatch(
            r"[1-9][0-9]{0,2}", options.access_run_attempt
        ) is None:
            raise TransitionError("qualification access run identity is outside the closed format")
        if len(options.ssh_public_key) > 128 or PUBLIC_KEY.fullmatch(
            options.ssh_public_key
        ) is None:
            raise TransitionError("SSH public key is outside the per-run Ed25519 format")
        runner_address = ipaddress.ip_address(options.runner_ipv4)
        if runner_address.version != 4 or not runner_address.is_global:
            raise TransitionError("runner address is not a public IPv4 address")
        client = Client(os.environ.get("GOOGLE_OAUTH_ACCESS_TOKEN", ""))
        instance = client.request("GET", f"instances/{options.instance}")
        validate_instance(instance, options)
        expected_labels = instance["labels"]
        update_runner_firewall(client, options.instance, str(runner_address), expected_labels)
        if instance.get("status") == "RUNNING":
            client.mutate(f"instances/{options.instance}/stop", {})
            instance = wait_status(client, options.instance, "TERMINATED")
            validate_instance(instance, options)
        if instance.get("status") != "TERMINATED":
            raise TransitionError("exact instance did not stop")
        if instance.get("serviceAccounts"):
            client.mutate(f"instances/{options.instance}/setServiceAccount", {"scopes": []})
            instance = wait_status(client, options.instance, "TERMINATED")
        if instance.get("serviceAccounts", []) != []:
            raise TransitionError("cloud identity remains after detachment")
        client.mutate(
            f"instances/{options.instance}/setMetadata",
            metadata_payload(
                instance,
                options.ssh_public_key,
                options.access_run_id,
                options.access_run_attempt,
            ),
        )
        client.mutate(f"instances/{options.instance}/start", {})
        instance = wait_status(client, options.instance, "RUNNING")
        validate_instance(instance, options)
        if instance.get("serviceAccounts", []) != []:
            raise TransitionError("cloud identity reappeared after restart")
        access_configs = [
            config
            for interface in instance.get("networkInterfaces", [])
            for config in interface.get("accessConfigs", [])
        ]
        if len(access_configs) != 1 or not isinstance(access_configs[0].get("natIP"), str):
            raise TransitionError("instance public address is ambiguous")
        address = ipaddress.ip_address(access_configs[0]["natIP"])
        if address.version != 4 or not address.is_global:
            raise TransitionError("instance address is not a public IPv4 address")
        options.ipv4_output.write_text(f"{address}\n", encoding="ascii")
        options.ipv4_output.chmod(0o600)
    except (TransitionError, OSError, ValueError) as error:
        print(f"ERROR: Rocky identity transition failed closed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
