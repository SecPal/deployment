#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT
"""Independently verify exact closed replay of one Rocky failure diagnostic."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import importlib.util
import json
from importlib.machinery import SourceFileLoader
from pathlib import Path
from typing import Any


REPLAY_COMPONENT_ORDER = (
    "qualification_stdout",
    "target_qualification_trace",
    "trusted_marker",
    "reload_adjacency",
    "start_observation",
    "active_observation",
    "primary_observation",
)
COMPONENT_KEYS = {
    "present",
    "byte_count",
    "sha256",
    "replayability",
    "content_base64",
}
WITNESS_KEYS = {
    "schema_version",
    "available",
    "representation_invalid",
    "exit_status",
    "component_order",
    "separator",
    "components",
}
DOCUMENT_KEYS = {
    "schema_version",
    "phase",
    "target_sha",
    "trusted_control_sha",
    "qualification_run_id",
    "qualification_run_attempt",
    "harness_sha256",
    "operation",
    "reason",
    "exit_status",
    "diagnostic_input_sha256",
    "diagnostic_input_bytes",
    "replay_witness",
}
def canonical_json(document: object) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "ascii"
    )


def unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("replay observation contains a duplicate key")
        document[key] = value
    return document


def reject_json_constant(value: str) -> object:
    raise ValueError(f"replay observation contains invalid JSON constant {value}")


def exact_json(payload: bytes, *, require_canonical: bool = False) -> object:
    try:
        document = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=unique_json_object,
            parse_constant=reject_json_constant,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
    ) as error:
        raise ValueError("replay observation is not closed JSON") from error
    if require_canonical:
        try:
            if canonical_json(document) != payload:
                raise ValueError("replay observation is not canonical JSON")
        except (UnicodeEncodeError, TypeError, ValueError) as error:
            raise ValueError("replay observation is not closed JSON") from error
    return document


def validate_trace(payload: bytes, classifier: Any) -> None:
    if not payload:
        return
    if not payload.endswith(b"\n"):
        raise ValueError("replay trace lacks its producer terminator")
    try:
        lines = payload[:-1].decode("ascii").split("\n")
    except UnicodeDecodeError as error:
        raise ValueError("replay trace is not ASCII") from error
    for line in lines:
        match = classifier.TRACE_PATTERN.fullmatch(line)
        if match is None or not 1 <= int(match.group(1)) <= 255:
            raise ValueError("replay trace is outside the closed grammar")
        frames = match.group(2).split(",")
        if not 1 <= len(frames) <= classifier.MAX_TRACE_FRAMES:
            raise ValueError("replay trace frame count is outside its bound")
        if any(not 1 <= int(frame) <= classifier.MAX_TRACE_LINE for frame in frames):
            raise ValueError("replay trace frame is outside its bound")


def validate_marker(payload: bytes, classifier: Any) -> None:
    try:
        marker = payload.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("replay marker is not ASCII") from error
    if not marker.endswith("\n") or classifier.MARKER_PATTERN.fullmatch(marker[:-1]) is None:
        raise ValueError("replay marker is outside the closed grammar")
    operation, reason = marker[:-1].split(" ", 1)
    if operation not in classifier.OPERATIONS or reason not in classifier.REASONS:
        raise ValueError("replay marker is outside the classifier domain")


def validate_observation(
    name: str,
    payload: bytes,
    document: dict[str, object],
    classifier: Any,
    stdout: bytes,
) -> None:
    observation = exact_json(
        payload,
        require_canonical=name == "reload_adjacency",
    )
    exit_status = document["exit_status"]
    assert type(exit_status) is int
    if name == "start_observation":
        if not classifier.replay_start_observation_admitted(observation):
            raise ValueError("replay start observation is not admitted")
        return
    if name == "active_observation":
        if not classifier.replay_active_observation_admitted(observation):
            raise ValueError("replay active observation is not admitted")
        return
    if name == "primary_observation":
        if not classifier.replay_primary_observation_admitted(observation):
            raise ValueError("replay primary observation is not admitted")
        return
    if name != "reload_adjacency":
        raise ValueError("unknown replay observation component")
    admitted = classifier.admit_daemon_reload_adjacency(
        observation,
        {
            "target_sha": document["target_sha"],
            "trusted_control_sha": document["trusted_control_sha"],
            "qualification_run_id": document["qualification_run_id"],
            "qualification_run_attempt": document["qualification_run_attempt"],
            "failure_status": exit_status,
        },
        classifier.reload_client_error(stdout),
    )
    if admitted == classifier.unavailable_daemon_reload_adjacency():
        raise ValueError("replay reload adjacency is not admitted")
    classifier.validate_admitted_daemon_reload_adjacency(admitted)


def validate_component_payload(
    name: str,
    payload: bytes,
    document: dict[str, object],
    classifier: Any,
    stdout: bytes,
) -> None:
    replay_limit = classifier.REPLAY_EXACT_COMPONENT_BOUNDS[name]
    if len(payload) > replay_limit:
        raise ValueError(f"replay {name} exceeds its closed bound")
    if name == "qualification_stdout":
        if payload and payload not in classifier.REPLAYABLE_STDOUT_RECORDS:
            raise ValueError("replay stdout is outside the finite reviewed set")
    elif name == "target_qualification_trace":
        validate_trace(payload, classifier)
    elif name == "trusted_marker":
        validate_marker(payload, classifier)
    else:
        validate_observation(name, payload, document, classifier, stdout)


def validate_replay_witness(
    document: object,
    classifier: Any,
    *,
    require_available: bool = False,
) -> bytes | None:
    if not isinstance(document, dict) or set(document) != DOCUMENT_KEYS:
        raise ValueError("replay failure document is not the exact current shape")
    if (
        document["schema_version"] != 2
        or document["phase"] != "target-qualification"
        or document["target_sha"] != classifier.EXPECTED_TARGET_SHA
        or document["harness_sha256"] != classifier.EXPECTED_HARNESS_SHA256
        or document["trusted_control_sha"]
        == classifier.LEGACY_REPLAY_OPTIONAL_CONTROL_SHA
        or document["operation"] != "qualification-harness"
        or document["reason"] != "representation-invalid"
        or type(document["exit_status"]) is not int
        or not 0 <= document["exit_status"] <= 255
    ):
        raise ValueError("replay failure is outside the current negative authority")
    witness = document["replay_witness"]
    if not isinstance(witness, dict) or set(witness) != WITNESS_KEYS:
        raise ValueError("replay witness is not closed")
    if (
        witness["schema_version"] != 1
        or type(witness["available"]) is not bool
        or type(witness["representation_invalid"]) is not bool
        or type(witness["exit_status"]) is not int
        or witness["exit_status"] != document["exit_status"]
        or witness["component_order"] != list(REPLAY_COMPONENT_ORDER)
        or witness["separator"] != "NUL"
    ):
        raise ValueError("replay witness contract is invalid")
    components = witness["components"]
    if not isinstance(components, dict) or set(components) != set(REPLAY_COMPONENT_ORDER):
        raise ValueError("replay witness component inventory is incomplete")

    decoded: dict[str, bytes] = {}
    all_exact = True
    for name in REPLAY_COMPONENT_ORDER:
        component = components[name]
        if not isinstance(component, dict) or set(component) != COMPONENT_KEYS:
            raise ValueError(f"replay {name} metadata is not closed")
        present = component["present"]
        byte_count = component["byte_count"]
        digest = component["sha256"]
        replayability = component["replayability"]
        encoded = component["content_base64"]
        if (
            type(present) is not bool
            or type(byte_count) is not int
            or not 0 <= byte_count <= classifier.REPLAY_COMPONENT_BOUNDS[name]
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or replayability not in {"exact", "unavailable"}
        ):
            raise ValueError(f"replay {name} metadata is invalid")
        if replayability == "unavailable":
            if not present or encoded is not None:
                raise ValueError(f"unavailable replay {name} exports content")
            all_exact = False
            continue
        if not present:
            if encoded is not None or byte_count != 0 or digest != hashlib.sha256(b"").hexdigest():
                raise ValueError(f"absent replay {name} is inconsistent")
            decoded[name] = b""
            continue
        if not isinstance(encoded, str):
            raise ValueError(f"exact replay {name} lacks content")
        try:
            payload = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as error:
            raise ValueError(f"replay {name} content is not canonical base64") from error
        if base64.b64encode(payload).decode("ascii") != encoded:
            raise ValueError(f"replay {name} content is not canonical base64")
        if len(payload) != byte_count or hashlib.sha256(payload).hexdigest() != digest:
            raise ValueError(f"replay {name} length or digest mismatches")
        decoded[name] = payload

    if witness["available"] != all_exact:
        raise ValueError("replay availability contradicts its components")
    declared_component_bytes = sum(
        components[name]["byte_count"] for name in REPLAY_COMPONENT_ORDER
    )
    if declared_component_bytes != document["diagnostic_input_bytes"]:
        raise ValueError("declared diagnostic component byte count mismatches")
    stdout = decoded.get("qualification_stdout", b"")
    for name in REPLAY_COMPONENT_ORDER:
        if (
            components[name]["replayability"] == "exact"
            and components[name]["present"]
        ):
            if name == "reload_adjacency" and "qualification_stdout" not in decoded:
                raise ValueError("replay reload adjacency lacks its stdout input")
            validate_component_payload(
                name, decoded[name], document, classifier, stdout
            )
    if not all_exact:
        if require_available:
            raise ValueError("replay witness is unavailable")
        return None

    replayed = b"\0".join(decoded[name] for name in REPLAY_COMPONENT_ORDER)
    component_bytes = sum(len(decoded[name]) for name in REPLAY_COMPONENT_ORDER)
    if component_bytes != document["diagnostic_input_bytes"]:
        raise ValueError("replayed diagnostic component byte count mismatches")
    if hashlib.sha256(replayed).hexdigest() != document["diagnostic_input_sha256"]:
        raise ValueError("replayed diagnostic hash mismatches")
    marker = None
    if components["trusted_marker"]["present"]:
        marker = decoded["trusted_marker"].decode("ascii")
    operation, reason = classifier.classify_failure(
        stdout,
        decoded["target_qualification_trace"],
        document["exit_status"],
        target_bound=True,
        trusted_marker=marker,
        representation_invalid=witness["representation_invalid"],
        line_rules=classifier.LINE_RULES,
    )
    if (operation, reason) != (document["operation"], document["reason"]):
        raise ValueError("replayed classifier result mismatches")
    return replayed


def verify_replay_witness(document: object, classifier: Any) -> bytes:
    replayed = validate_replay_witness(document, classifier, require_available=True)
    assert replayed is not None
    return replayed


def load_classifier(path: Path) -> Any:
    loader = SourceFileLoader("rocky_target_qualification_failure", str(path))
    specification = importlib.util.spec_from_loader(
        "rocky_target_qualification_failure", loader
    )
    if specification is None or specification.loader is None:
        raise ValueError("classifier cannot be loaded")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("failure", type=Path)
    parser.add_argument("--classifier", required=True, type=Path)
    options = parser.parse_args()
    document = json.loads(options.failure.read_bytes())
    verify_replay_witness(document, load_classifier(options.classifier))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
