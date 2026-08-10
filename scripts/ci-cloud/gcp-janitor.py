#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Delete only expired GCP fixtures with an exact SecPal ownership contract."""

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
PROJECT = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
ZONE = "europe-west3-a"
RUN_ID = re.compile(r"^[1-9][0-9]{0,19}$")
RUN_ATTEMPT = re.compile(r"^[1-9][0-9]{0,2}$")
SHA = re.compile(r"^[0-9a-f]{40}$")
EPOCH = re.compile(r"^[1-9][0-9]{9}$")
RESOURCE_ID = re.compile(r"^[1-9][0-9]{0,29}$")
RESOURCE_KINDS = ("instances", "disks")
LABEL_KEYS = {
    "secpal_ci_owner",
    "repository",
    "github_run_id",
    "github_run_attempt",
    "target_sha",
    "created_at",
    "expires_at",
}


class JanitorError(RuntimeError):
    pass


@dataclass(frozen=True)
class Candidate:
    kind: str
    resource_id: str
    name: str
    labels: tuple[tuple[str, str], ...]


class GCPClient:
    def __init__(self, access_token: str, project: str, zone: str) -> None:
        if not access_token or any(character.isspace() for character in access_token):
            raise JanitorError("a non-whitespace OAuth access token is required")
        if PROJECT.fullmatch(project) is None or zone != ZONE:
            raise JanitorError("project or zone is outside the closed janitor scope")
        self.access_token = access_token
        self.project = project
        self.zone = zone

    def request(self, method: str, path: str) -> dict[str, Any]:
        request = urllib.request.Request(
            f"{API_ROOT}{path}",
            method=method,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self.access_token}",
                "User-Agent": "SecPal-GCP-TTL-Janitor/1",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = response.read(2_000_001)
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as error:
            raise JanitorError(f"Google Compute API {method} failed") from error
        if len(payload) > 2_000_000:
            raise JanitorError("Google Compute API response exceeded the size limit")
        if not payload:
            return {}
        try:
            document = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise JanitorError("Google Compute API returned invalid JSON") from None
        if not isinstance(document, dict):
            raise JanitorError("Google Compute API response must be an object")
        return document

    def resource_path(self, kind: str, name: str = "") -> str:
        if kind not in RESOURCE_KINDS or re.fullmatch(r"[a-z0-9-]{1,63}", name or "x") is None:
            raise JanitorError("invalid resource kind or name")
        project = urllib.parse.quote(self.project, safe="")
        zone = urllib.parse.quote(self.zone, safe="")
        suffix = f"/{urllib.parse.quote(name, safe='')}" if name else ""
        return f"/projects/{project}/zones/{zone}/{kind}{suffix}"

    def list_resources(self, kind: str) -> list[dict[str, object]]:
        resources: list[dict[str, object]] = []
        page_token = ""
        while True:
            path = self.resource_path(kind)
            if page_token:
                path += "?pageToken=" + urllib.parse.quote(page_token, safe="")
            document = self.request("GET", path)
            items = document.get("items", [])
            if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
                raise JanitorError("Google Compute resource list is malformed")
            resources.extend(items)
            raw_next = document.get("nextPageToken", "")
            if not isinstance(raw_next, str):
                raise JanitorError("Google Compute pagination token is malformed")
            if not raw_next:
                return resources
            if raw_next == page_token:
                raise JanitorError("Google Compute pagination did not advance")
            page_token = raw_next

    def get_resource(self, kind: str, name: str) -> dict[str, object]:
        return self.request("GET", self.resource_path(kind, name))

    def delete_resource(self, kind: str, name: str) -> None:
        operation = self.request("DELETE", self.resource_path(kind, name))
        operation_name = operation.get("name")
        if not isinstance(operation_name, str) or re.fullmatch(r"[a-z0-9-]{1,63}", operation_name) is None:
            raise JanitorError("Google Compute deletion returned no bounded operation")
        operation_path = (
            f"/projects/{urllib.parse.quote(self.project, safe='')}/zones/"
            f"{urllib.parse.quote(self.zone, safe='')}/operations/"
            f"{urllib.parse.quote(operation_name, safe='')}"
        )
        for _ in range(60):
            status = self.request("GET", operation_path)
            if status.get("status") == "DONE":
                if "error" in status:
                    raise JanitorError("Google Compute deletion operation failed")
                return
            time.sleep(2)
        raise JanitorError("Google Compute deletion operation timed out")


def parse_candidate(kind: str, resource: dict[str, object], now: int) -> Candidate | None:
    if kind not in RESOURCE_KINDS:
        return None
    raw_labels = resource.get("labels")
    if not isinstance(raw_labels, dict) or set(raw_labels) != LABEL_KEYS:
        return None
    if not all(isinstance(key, str) and isinstance(value, str) for key, value in raw_labels.items()):
        return None
    labels: dict[str, str] = raw_labels
    run_id = labels["github_run_id"]
    attempt = labels["github_run_attempt"]
    target_sha = labels["target_sha"]
    created_at = labels["created_at"]
    expires_at = labels["expires_at"]
    singular = "instance" if kind == "instances" else "disk"
    expected_name = f"spci-{run_id}-{attempt}-{singular}"
    zone = str(resource.get("zone", "")).rsplit("/", 1)[-1]
    resource_id = str(resource.get("id", ""))
    if (
        labels["secpal_ci_owner"] != "deployment-conformance"
        or labels["repository"] != "secpal-deployment"
        or RUN_ID.fullmatch(run_id) is None
        or RUN_ATTEMPT.fullmatch(attempt) is None
        or SHA.fullmatch(target_sha) is None
        or EPOCH.fullmatch(created_at) is None
        or EPOCH.fullmatch(expires_at) is None
        or resource.get("name") != expected_name
        or zone != ZONE
        or RESOURCE_ID.fullmatch(resource_id) is None
    ):
        return None
    created = int(created_at)
    expires = int(expires_at)
    if expires <= created or expires - created > 10_800 or now < expires:
        return None
    return Candidate(kind, resource_id, expected_name, tuple(sorted(labels.items())))


def cleanup_expired(client: Any, now: int, apply: bool) -> list[tuple[str, str]]:
    if now < 1_600_000_000:
        raise JanitorError("janitor clock is outside the supported epoch")
    expired: list[Candidate] = []
    for kind in RESOURCE_KINDS:
        for resource in client.list_resources(kind):
            candidate = parse_candidate(kind, resource, now)
            if candidate is not None:
                expired.append(candidate)

    deleted: list[tuple[str, str]] = []
    for candidate in expired:
        current = parse_candidate(
            candidate.kind,
            client.get_resource(candidate.kind, candidate.name),
            now,
        )
        if current != candidate:
            raise JanitorError("resource ownership changed during cleanup")
        deleted.append((candidate.kind, candidate.name))
        print(
            f"expired owned GCP {candidate.kind[:-1]} name={candidate.name}",
            flush=True,
        )
        if apply:
            client.delete_resource(candidate.kind, candidate.name)
    return deleted


def main(arguments: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", required=True)
    parser.add_argument("--zone", required=True, choices=[ZONE])
    parser.add_argument("--now", required=True, type=int)
    parser.add_argument("--apply", action="store_true")
    options = parser.parse_args(arguments)
    token = os.environ.get("GOOGLE_OAUTH_ACCESS_TOKEN", "")
    try:
        client = GCPClient(token, options.project, options.zone)
        deleted = cleanup_expired(client, options.now, options.apply)
    except (JanitorError, OSError, ValueError) as error:
        print(f"ERROR: GCP TTL janitor failed closed: {error}", file=sys.stderr)
        return 1
    mode = "deleted" if options.apply else "found"
    print(f"GCP TTL janitor {mode} {len(deleted)} owned expired resource(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
