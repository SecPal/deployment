#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Delete only independently revalidated expired Rocky GCP resources."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


API_ROOT = "https://compute.googleapis.com/compute/v1"
PROJECT = "secpal-dev"
REGION = "europe-west3"
ZONE = "europe-west3-a"
RUN_ID = re.compile(r"^[1-9][0-9]{0,19}$")
RUN_ATTEMPT = re.compile(r"^[1-9][0-9]{0,2}$")
SHA = re.compile(r"^[0-9a-f]{40}$")
EPOCH = re.compile(r"^[1-9][0-9]{9}$")
LABEL_KEYS = {
    "secpal_ci_owner",
    "repository",
    "github_run_id",
    "github_run_attempt",
    "target_sha",
    "control_sha",
    "provider_profile",
    "created_at",
    "expires_at",
}
DESCRIPTION_KEYS = {"o", "r", "i", "a", "t", "c", "p", "n", "x"}
SCOPES = {
    "instance": f"zones/{ZONE}/instances",
    "disk": f"zones/{ZONE}/disks",
    "network": "global/networks",
    "subnet": f"regions/{REGION}/subnetworks",
    "ssh": "global/firewalls",
    "egress-allow": "global/firewalls",
    "egress-deny": "global/firewalls",
}
DELETE_ORDER = (
    "instance",
    "disk",
    "ssh",
    "egress-allow",
    "egress-deny",
    "subnet",
    "network",
)


class JanitorError(RuntimeError):
    pass


@dataclass(frozen=True)
class Candidate:
    component: str
    name: str
    run_id: str
    run_attempt: str
    labels: tuple[tuple[str, str], ...]


class GCPClient:
    def __init__(self, token: str) -> None:
        if not token or any(character.isspace() for character in token):
            raise JanitorError("a bounded OAuth access token is required")
        self.token = token

    def request(self, method: str, path: str) -> dict[str, Any]:
        request = urllib.request.Request(
            f"{API_ROOT}/projects/{PROJECT}/{path}",
            method=method,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self.token}",
                "User-Agent": "SecPal-Rocky-GCP-TTL-Janitor/1",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read(2_000_001)
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as error:
            raise JanitorError(f"GCP {method} request failed") from error
        if len(raw) > 2_000_000:
            raise JanitorError("GCP response exceeded the size bound")
        try:
            result = json.loads(raw) if raw else {}
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise JanitorError("GCP response was invalid JSON") from error
        if not isinstance(result, dict):
            raise JanitorError("GCP response must be an object")
        return result

    def list_component(self, component: str) -> list[dict[str, Any]]:
        path = SCOPES[component]
        result: list[dict[str, Any]] = []
        token = ""
        while True:
            suffix = "" if not token else "?pageToken=" + urllib.parse.quote(token, safe="")
            document = self.request("GET", path + suffix)
            items = document.get("items", [])
            if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
                raise JanitorError("GCP resource list is malformed")
            result.extend(items)
            next_token = document.get("nextPageToken", "")
            if not isinstance(next_token, str) or next_token == token:
                if next_token:
                    raise JanitorError("GCP pagination did not advance")
                return result
            token = next_token

    def get_component(self, component: str, name: str) -> dict[str, Any]:
        return self.request("GET", f"{SCOPES[component]}/{name}")

    def delete_component(self, component: str, name: str) -> None:
        operation = self.request("DELETE", f"{SCOPES[component]}/{name}")
        operation_name = operation.get("name")
        if not isinstance(operation_name, str) or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,127}", operation_name) is None:
            raise JanitorError("GCP deletion returned no operation identity")
        if component in {"instance", "disk"}:
            operation_path = f"zones/{ZONE}/operations/{operation_name}"
        elif component == "subnet":
            operation_path = f"regions/{REGION}/operations/{operation_name}"
        else:
            operation_path = f"global/operations/{operation_name}"
        for _ in range(60):
            status = self.request("GET", operation_path)
            if status.get("status") == "DONE":
                if status.get("error") is not None:
                    raise JanitorError("GCP deletion operation failed")
                return
            if status.get("status") not in {"PENDING", "RUNNING"}:
                raise JanitorError("GCP deletion status is outside the closed set")
            time.sleep(2)
        raise JanitorError("GCP deletion operation timed out")


def ownership(resource: dict[str, Any], component: str) -> dict[str, str] | None:
    raw: object
    if component in {"instance", "disk"}:
        raw = resource.get("labels")
    else:
        try:
            raw = json.loads(str(resource.get("description", "")))
        except json.JSONDecodeError:
            return None
    if not isinstance(raw, dict):
        return None
    if not all(isinstance(key, str) and isinstance(value, str) for key, value in raw.items()):
        return None
    if component in {"instance", "disk"}:
        return raw if set(raw) == LABEL_KEYS else None
    if set(raw) != DESCRIPTION_KEYS:
        return None
    return {
        "secpal_ci_owner": raw["o"],
        "repository": raw["r"],
        "github_run_id": raw["i"],
        "github_run_attempt": raw["a"],
        "target_sha": raw["t"],
        "control_sha": raw["c"],
        "provider_profile": raw["p"],
        "created_at": raw["n"],
        "expires_at": raw["x"],
    }


def parse_candidate(component: str, resource: dict[str, Any], now: int) -> Candidate | None:
    labels = ownership(resource, component)
    if labels is None:
        return None
    run_id = labels["github_run_id"]
    attempt = labels["github_run_attempt"]
    expected = f"sprk-{run_id}-{attempt}-{component}"
    created = labels["created_at"]
    expires = labels["expires_at"]
    if (
        labels["secpal_ci_owner"] != "rocky-host-qualification"
        or labels["repository"] != "secpal-deployment"
        or labels["provider_profile"] != "gcp-rocky-10-2-arm64"
        or RUN_ID.fullmatch(run_id) is None
        or RUN_ATTEMPT.fullmatch(attempt) is None
        or SHA.fullmatch(labels["target_sha"]) is None
        or SHA.fullmatch(labels["control_sha"]) is None
        or EPOCH.fullmatch(created) is None
        or EPOCH.fullmatch(expires) is None
        or resource.get("name") != expected
        or int(expires) <= int(created)
        or int(expires) - int(created) > 10800
        or now < int(expires)
    ):
        return None
    return Candidate(component, expected, run_id, attempt, tuple(sorted(labels.items())))


def cleanup_expired(client: Any, now: int, apply: bool) -> list[tuple[str, str]]:
    if now < 1_600_000_000:
        raise JanitorError("janitor clock is outside the supported epoch")
    candidates: dict[tuple[str, str], dict[str, Candidate]] = {}
    for component in DELETE_ORDER:
        for resource in client.list_component(component):
            candidate = parse_candidate(component, resource, now)
            if candidate is None:
                continue
            run = (candidate.run_id, candidate.run_attempt)
            if component in candidates.setdefault(run, {}):
                raise JanitorError("ambiguous duplicate Rocky ownership candidate")
            candidates[run][component] = candidate

    deleted: list[tuple[str, str]] = []
    for run in sorted(candidates):
        group = candidates[run]
        label_sets = {candidate.labels for candidate in group.values()}
        if len(label_sets) != 1:
            continue
        for component in DELETE_ORDER:
            candidate = group.get(component)
            if candidate is None:
                continue
            current = parse_candidate(
                component,
                client.get_component(component, candidate.name),
                now,
            )
            if current != candidate:
                raise JanitorError("Rocky resource ownership changed during cleanup")
            print(f"expired owned Rocky GCP {component} name={candidate.name}", flush=True)
            deleted.append((component, candidate.name))
            if apply:
                client.delete_component(component, candidate.name)
    return deleted


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", required=True, choices=[PROJECT])
    parser.add_argument("--region", required=True, choices=[REGION])
    parser.add_argument("--zone", required=True, choices=[ZONE])
    parser.add_argument("--now", required=True, type=int)
    parser.add_argument("--apply", action="store_true")
    options = parser.parse_args()
    try:
        deleted = cleanup_expired(
            GCPClient(os.environ.get("GOOGLE_OAUTH_ACCESS_TOKEN", "")),
            options.now,
            options.apply,
        )
    except (JanitorError, OSError, ValueError) as error:
        print(f"ERROR: Rocky GCP janitor failed closed: {error}", file=sys.stderr)
        return 1
    mode = "deleted" if options.apply else "found"
    print(f"Rocky GCP janitor {mode} {len(deleted)} exact expired resource(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
