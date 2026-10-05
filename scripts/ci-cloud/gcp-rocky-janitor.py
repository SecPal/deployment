#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Delete only independently revalidated expired Rocky GCP resources."""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
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
PROFILES = {"gcp-rocky-10-2-arm64", "gcp-rocky-10-2-x86-64"}
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


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise JanitorError("duplicate JSON object member")
        result[key] = value
    return result


@dataclass(frozen=True)
class Candidate:
    component: str
    name: str
    run_id: str
    run_attempt: str
    labels: tuple[tuple[str, str], ...]


class GCPClient:
    def __init__(self, token: str, *, deadline: float | None = None) -> None:
        if not token or any(character.isspace() for character in token):
            raise JanitorError("a bounded OAuth access token is required")
        self.token = token
        self.deadline = deadline

    def request(self, method: str, path: str, *, deadline: float | None = None) -> dict[str, Any] | None:
        bounds = [value for value in (self.deadline, deadline) if value is not None]
        bound = min(bounds) if bounds else None
        remaining = 30.0 if bound is None else min(30.0, bound - time.monotonic())
        if remaining <= 0:
            raise JanitorError("provider action deadline exhausted")
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
            with urllib.request.urlopen(request, timeout=remaining) as response:
                raw = response.read(2_000_001)
        except urllib.error.HTTPError as error:
            # Only an exact resource GET returning HTTP 404 is absence. No
            # network exception, empty response, or arbitrary response body is.
            if method == "GET" and path in getattr(self, "exact_get_paths", ()) and error.code == 404:
                if bound is not None and time.monotonic() >= bound:
                    raise JanitorError("provider absence arrived after action deadline") from None
                return None
            raise JanitorError(f"GCP {method} request failed") from None
        except (urllib.error.URLError, TimeoutError) as error:
            raise JanitorError(f"GCP {method} request failed") from error
        if bound is not None and time.monotonic() >= bound:
            raise JanitorError("provider response arrived after action deadline")
        if len(raw) > 2_000_000:
            raise JanitorError("GCP response exceeded the size bound")
        try:
            result = json.loads(raw, object_pairs_hook=unique_object) if raw else {}
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

    def get_component(self, component: str, name: str) -> dict[str, Any] | None:
        path = component_path(component, name)
        self.exact_get_paths = (path,)
        return self.request("GET", path)

    def delete_component(self, component: str, name: str, resource_id: str) -> None:
        if re.fullmatch(r"[1-9][0-9]{0,19}", resource_id) is None:
            raise JanitorError("deletion requires admitted immutable resource ID")
        deadline = time.monotonic() + 120
        operation = self.request("DELETE", component_path(component, name), deadline=deadline)
        validate_delete_operation(operation, component, name, resource_id)
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
            if time.monotonic() >= deadline:
                raise JanitorError("GCP deletion operation timed out")
            validate_delete_operation(operation, component, name, resource_id)
            if operation.get("name") != operation_name:
                raise JanitorError("GCP deletion operation identity changed")
            if operation.get("status") == "DONE":
                if operation.get("error") is not None:
                    raise JanitorError("GCP deletion operation failed")
                return
            if operation.get("status") not in {"PENDING", "RUNNING"}:
                raise JanitorError("GCP deletion status is outside the closed set")
            time.sleep(min(2, max(0, deadline - time.monotonic())))
            operation = self.request("GET", operation_path, deadline=deadline)
        raise JanitorError("GCP deletion operation timed out")


def validate_delete_operation(operation: Any, component: str, name: str, resource_id: str) -> None:
    """Admit the provider's actual mutation target, never name-only success.

    Compute's documented delete is name-addressed, with no conditional-ID
    precondition. Its targetId provides incarnation evidence after dispatch;
    a mismatch is an integrity failure, never cleanup success or a retry.
    """
    path = component_path(component,name)
    root = f"https://www.googleapis.com/compute/v1/projects/{PROJECT}/"
    links = (root + path,root.replace("www.googleapis.com","compute.googleapis.com") + path)
    if (
        not isinstance(operation,dict)
        or operation.get("kind") != "compute#operation"
        or operation.get("operationType") != "delete"
        or operation.get("targetId") != resource_id
        or operation.get("targetLink") not in links
    ):
        raise JanitorError("GCP deletion target incarnation was not admitted")


def ownership(resource: dict[str, Any], component: str) -> dict[str, str] | None:
    raw: object
    if component in {"instance", "disk"}:
        raw = resource.get("labels")
    else:
        try:
            raw = json.loads(str(resource.get("description", "")), object_pairs_hook=unique_object)
        except (json.JSONDecodeError, JanitorError):
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


def owned_candidate(component: str, resource: dict[str, Any]) -> Candidate | None:
    if component not in SCOPES or not isinstance(resource, dict):
        return None
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
        or labels["provider_profile"] not in PROFILES
        or RUN_ID.fullmatch(run_id) is None
        or RUN_ATTEMPT.fullmatch(attempt) is None
        or SHA.fullmatch(labels["target_sha"]) is None
        or SHA.fullmatch(labels["control_sha"]) is None
        or EPOCH.fullmatch(created) is None
        or EPOCH.fullmatch(expires) is None
        or resource.get("name") != expected
        or int(expires) <= int(created)
        or int(expires) - int(created) > 10800
    ):
        return None
    return Candidate(component, expected, run_id, attempt, tuple(sorted(labels.items())))


def parse_candidate(component: str, resource: dict[str, Any], now: int) -> Candidate | None:
    candidate = owned_candidate(component, resource)
    if candidate is None or now < int(dict(candidate.labels)["expires_at"]):
        return None
    return candidate


def component_path(component: str, name: str) -> str:
    if component not in SCOPES or re.fullmatch(r"sprk-[1-9][0-9]{0,19}-[1-9][0-9]{0,2}-" + re.escape(component), name) is None:
        raise JanitorError("resource path is outside exact Rocky ownership")
    return f"{SCOPES[component]}/{name}"


@dataclass(frozen=True)
class ExactAuthority:
    labels: tuple[tuple[str, str], ...]

    def name(self, component: str) -> str:
        labels = dict(self.labels)
        return f"sprk-{labels['github_run_id']}-{labels['github_run_attempt']}-{component}"


def exact_authority(variables: dict[str, Any], env: dict[str, str], now: int) -> ExactAuthority:
    """Admit trusted artifact data against the accepted-main workflow context.

    The workflow supplies source context only after continuation admission for
    cross-run cleanup. Candidate qualification has neither this context nor a
    credential. Dates remain the original trusted provisioning artifact's dates.
    """
    if not isinstance(variables, dict):
        raise JanitorError("retained variables must be an object")
    if env.get("GITHUB_REPOSITORY") != "SecPal/deployment" or env.get("GITHUB_REF") != "refs/heads/main":
        raise JanitorError("exact cleanup requires accepted-main control")
    expected = {
        "project_id": PROJECT, "zone": ZONE,
        "run_id": env.get("SOURCE_RUN_ID") or env.get("GITHUB_RUN_ID"),
        "run_attempt": env.get("SOURCE_RUN_ATTEMPT") or env.get("GITHUB_RUN_ATTEMPT"),
        "trusted_control_sha": env.get("SOURCE_CONTROL_SHA") or env.get("GITHUB_SHA"),
        "target_sha": env.get("TARGET_SHA"), "profile": env.get("PROVIDER_PROFILE"),
    }
    if any(variables.get(k) != v or not isinstance(v,str) for k,v in expected.items()):
        raise JanitorError("retained ownership contradicts trusted run context")
    if SHA.fullmatch(env.get("GITHUB_SHA", "")) is None:
        raise JanitorError("trusted control SHA is malformed")
    labels = {
        "secpal_ci_owner": "rocky-host-qualification", "repository": "secpal-deployment",
        "github_run_id": expected["run_id"], "github_run_attempt": expected["run_attempt"],
        "target_sha": expected["target_sha"], "control_sha": expected["trusted_control_sha"],
        "provider_profile": expected["profile"], "created_at": variables.get("created_at"),
        "expires_at": variables.get("expires_at"),
    }
    candidate = owned_candidate("instance", {"name": f"sprk-{expected['run_id']}-{expected['run_attempt']}-instance", "labels": labels})
    if candidate is None or now < int(labels["created_at"]):
        raise JanitorError("trusted ownership interval or identity is malformed")
    return ExactAuthority(candidate.labels)


def admit_exact(resource: dict[str, Any], component: str, authority: ExactAuthority) -> str | None:
    """Pure provider representation admission, sharing the TTL owner predicate."""
    if not isinstance(resource,dict):
        return None
    candidate = owned_candidate(component, resource)
    if candidate is None or candidate.labels != authority.labels:
        return None
    base = f"https://www.googleapis.com/compute/v1/projects/{PROJECT}/"
    roots = (base, base.replace("www.googleapis.com", "compute.googleapis.com"))
    path = component_path(component, authority.name(component))
    if resource.get("selfLink") not in tuple(root + path for root in roots):
        return None
    kinds = {"instance":"compute#instance", "disk":"compute#disk", "network":"compute#network", "subnet":"compute#subnetwork"}
    if resource.get("kind") != kinds.get(component,"compute#firewall"):
        return None
    resource_id = resource.get("id")
    if not isinstance(resource_id,str) or re.fullmatch(r"[1-9][0-9]{0,19}",resource_id) is None:
        return None
    if component in {"instance","disk"} and resource.get("zone") not in tuple(root + f"zones/{ZONE}" for root in roots):
        return None
    if component == "instance":
        description = ownership(resource, "network")
        if description != dict(authority.labels):
            return None
    try:
        timestamp = datetime.datetime.fromisoformat(resource["creationTimestamp"].replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            return None
        created = timestamp.timestamp()
    except (KeyError,AttributeError,ValueError,TypeError,OverflowError):
        return None
    labels = dict(authority.labels)
    if not int(labels["created_at"]) <= created <= int(labels["expires_at"]):
        return None
    return resource_id


def observe_exact(client: Any, component: str, authority: ExactAuthority) -> tuple[str, str | None]:
    try:
        resource = client.get_component(component, authority.name(component))
    except (JanitorError, OSError, ValueError):
        return "UNKNOWN_PROVIDER_STATE", None
    if resource is None:
        return "ABSENT", None
    resource_id = admit_exact(resource, component, authority)
    if resource_id is None:
        return "INCOMPATIBLE_OR_AMBIGUOUS_RESOURCE", None
    return "EXACT_RUN_OWNED_INSTANCE_PRESENT" if component == "instance" else "EXACT_RUN_OWNED_RESOURCE_PRESENT", resource_id


def reconcile_instance(client: Any, authority: ExactAuthority) -> str:
    return observe_exact(client, "instance", authority)[0]


def verify_run_absence(client: Any, authority: ExactAuthority) -> bool:
    # Query every family even when an earlier read is unknown or present.
    results = [observe_exact(client,c,authority)[0] for c in DELETE_ORDER]
    return all(result == "ABSENT" for result in results)


def cleanup_run(client: Any, authority: ExactAuthority) -> dict[str, str]:
    # Admit the entire run before any mutation; refuse broad project inventory.
    observed = {c: observe_exact(client,c,authority) for c in DELETE_ORDER}
    if any(result in {"UNKNOWN_PROVIDER_STATE","INCOMPATIBLE_OR_AMBIGUOUS_RESOURCE"} for result,_ in observed.values()):
        failed = next(c for c,(result,_) in observed.items() if result in {"UNKNOWN_PROVIDER_STATE","INCOMPATIBLE_OR_AMBIGUOUS_RESOURCE"})
        raise JanitorError(f"exact {failed} inventory admission failed closed: {observed[failed][0]}")
    for component in DELETE_ORDER:
        result, resource_id = observed[component]
        if result == "ABSENT":
            continue
        current, current_id = observe_exact(client,component,authority)
        if current == "ABSENT":
            continue
        if current != result or current_id != resource_id:
            raise JanitorError(f"exact {component} identity changed before cleanup")
        try:
            client.delete_component(component,authority.name(component),resource_id)
        except (JanitorError,OSError,ValueError):
            raise JanitorError(f"exact {component} deletion unresolved") from None
    results = {component: observe_exact(client,component,authority)[0] for component in DELETE_ORDER}
    if any(outcome != "ABSENT" for outcome in results.values()):
        raise JanitorError("provider run resource absence not verified")
    return results


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
            live = client.get_component(component, candidate.name)
            current = parse_candidate(component, live, now)
            if current != candidate:
                raise JanitorError("Rocky resource ownership changed during cleanup")
            print(f"expired owned Rocky GCP {component} name={candidate.name}", flush=True)
            deleted.append((component, candidate.name))
            if apply:
                client.delete_component(component, candidate.name, str(live.get("id", "")))
    return deleted


def diagnostic(authority: ExactAuthority, action: str, component: str, outcome: str) -> dict[str, Any]:
    return {
        "schema_version": 1, "operation": action, "component": component,
        "project": PROJECT, "region": REGION, "zone": ZONE,
        "expected_name": authority.name(component),
        "ownership": dict(authority.labels), "outcome": outcome,
    }


def emit_diagnostic(authority: ExactAuthority, action: str, component: str, outcome: str) -> None:
    from jsonschema import Draft202012Validator

    document = diagnostic(authority, action, component, outcome)
    schema = json.loads((Path(__file__).resolve().parents[2] / "schemas/rocky-cloud-provider-result.schema.json").read_text())
    if not Draft202012Validator(schema).is_valid(document):
        raise JanitorError("provider diagnostic failed closed schema admission")
    print(json.dumps(document,sort_keys=True),flush=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", required=True, choices=[PROJECT])
    parser.add_argument("--region", required=True, choices=[REGION])
    parser.add_argument("--zone", required=True, choices=[ZONE])
    parser.add_argument("--now", required=True, type=int)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--exact-action", choices=["reconcile", "cleanup", "verify"])
    parser.add_argument("--variables", type=Path)
    options = parser.parse_args()
    try:
        if options.exact_action:
            if options.variables is None or options.apply:
                raise JanitorError("exact action requires retained variables and no TTL apply mode")
            if options.variables.stat().st_size > 100_000:
                raise JanitorError("retained variable artifact exceeds bound")
            variables = json.loads(options.variables.read_text(), object_pairs_hook=unique_object)
            authority = exact_authority(variables, dict(os.environ), options.now)
            # One action budget covers all reads, deletes and operation polls;
            # per-request and per-delete limits cannot multiply indefinitely.
            client = GCPClient(os.environ.get("GOOGLE_OAUTH_ACCESS_TOKEN", ""), deadline=time.monotonic() + 600)
            if options.exact_action in {"reconcile", "cleanup"}:
                result = reconcile_instance(client, authority)
                emit_diagnostic(authority, "ambiguous-create-read-back" if options.exact_action == "reconcile" else "cleanup-read-back", "instance", result)
            if options.exact_action == "reconcile":
                # Reconciliation never authorizes qualification or attempt success.
                return 1
            results = {}
            if options.exact_action == "cleanup":
                try:
                    results = cleanup_run(client, authority)
                except JanitorError:
                    for component in DELETE_ORDER:
                        outcome,_ = observe_exact(client,component,authority)
                        emit_diagnostic(authority,"cleanup-failed-read-back",component,outcome)
                    raise
            # Each observation emits a closed identity, even if another failed.
            for component in DELETE_ORDER:
                if options.exact_action == "verify":
                    results[component] = observe_exact(client,component,authority)[0]
                emit_diagnostic(authority,"final-provider-absence",component,results[component])
            absent = all(outcome == "ABSENT" for outcome in results.values())
            return 0 if absent else 1
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
