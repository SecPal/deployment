#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Pure normalization and admission for Rocky SELinux isolation evidence."""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any


RESPONSIBILITY = "normalization,admission"
INVARIANT_OWNER = "selinux_isolation_contract.admit_selinux_isolation"
MCS_CATEGORY_MIN = 0
MCS_CATEGORY_MAX = 1023
EXPECTED_PERMISSION = "read"
EXPECTED_TARGET_CLASS = "file"
EXPECTED_TARGET_PATH = "/foreign/marker"
EXPECTED_TARGET_NAME = "marker"

_CATEGORY = r"(?:[0-9]|[1-9][0-9]{1,2}|10(?:[01][0-9]|2[0-3]))"
SCHEMA_CONTEXT_PATTERN = (
    r"^[^:\s]+:[^:\s]+:(?:container_t|container_file_t):"
    rf"s0:c{_CATEGORY}(?:,c{_CATEGORY})?$"
)
_CONTEXT = re.compile(
    r"^(?P<user>[^:\s]+):(?P<role>[^:\s]+):(?P<type>container_t|container_file_t):"
    r"s0:(?P<categories>c[^:\s]+)$"
)
_EVENT_ID = re.compile(
    r"\bmsg=audit\("
    r"(?P<date>[0-9]{2}/[0-9]{2}/[0-9]{2}) "
    r"(?P<time>[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}):"
    r"(?P<serial>[1-9][0-9]*)\) :"
)
_RECORD = re.compile(r"^type=([A-Z][A-Z0-9_]*)\s")
_DENIAL = re.compile(r"\bavc:\s+denied\s+\{\s*([^{}]+?)\s*\}")


class IsolationError(ValueError):
    """The observed or normalized isolation representation is inadmissible."""


class NoMatchingAvc(IsolationError):
    """The bounded observation does not yet contain the tested denial."""


def canonical_bytes(document: dict[str, Any]) -> bytes:
    return (
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _parse_categories(value: str) -> tuple[int, ...]:
    raw_categories = value.split(",")
    if len(raw_categories) not in {1, 2}:
        raise IsolationError("SELinux MCS category count is invalid")
    categories: list[int] = []
    for raw in raw_categories:
        match = re.fullmatch(r"c(0|[1-9][0-9]*)", raw)
        if match is None:
            raise IsolationError("SELinux MCS category is malformed")
        category = int(match.group(1))
        if not MCS_CATEGORY_MIN <= category <= MCS_CATEGORY_MAX:
            raise IsolationError("SELinux MCS category is outside c0 through c1023")
        categories.append(category)
    if len(set(categories)) != len(categories):
        raise IsolationError("SELinux MCS categories are duplicated")
    return tuple(sorted(categories))


def normalize_context(raw: str, expected_type: str) -> dict[str, Any]:
    if expected_type not in {"container_t", "container_file_t"}:
        raise IsolationError("SELinux context type expectation is invalid")
    match = _CONTEXT.fullmatch(raw)
    if match is None or match.group("type") != expected_type:
        raise IsolationError("SELinux context is malformed or has the wrong type")
    return {
        "raw": raw,
        "selinux_type": expected_type,
        "mcs_categories": list(_parse_categories(match.group("categories"))),
    }


def normalize_context_relationship(
    process_a: str,
    process_b: str,
    storage_a: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    processes = [
        normalize_context(process_a, "container_t"),
        normalize_context(process_b, "container_t"),
    ]
    storage = normalize_context(storage_a, "container_file_t")
    if processes[0]["mcs_categories"] != storage["mcs_categories"]:
        raise IsolationError("process A and storage A MCS facts contradict")
    if processes[0]["mcs_categories"] == processes[1]["mcs_categories"]:
        raise IsolationError("process A and process B MCS facts are not distinct")
    return processes, storage


def _event_id(line: str) -> tuple[str, str]:
    match = _EVENT_ID.search(line)
    if match is None:
        raise IsolationError("audit event identity is malformed")
    event_time = f"{match.group('date')} {match.group('time')}"
    try:
        datetime.strptime(event_time, "%m/%d/%y %H:%M:%S.%f")
    except ValueError as error:
        raise IsolationError("audit event time is malformed") from error
    return event_time, match.group("serial")


def _field(line: str, name: str) -> str | None:
    matches = re.findall(
        rf"(?:^|\s){re.escape(name)}=(?:\"([^\"\r\n]*)\"|(\S+))",
        line,
    )
    if len(matches) != 1:
        return None
    quoted, bare = matches[0]
    return quoted if quoted else bare


def _proctitle_matches(line: str) -> bool:
    matches = re.findall(r'(?:^|\s)proctitle=(?:"([^"\r\n]*)"|([^\r\n]+))$', line)
    if len(matches) != 1:
        return False
    quoted, bare = matches[0]
    value = quoted if quoted else bare.strip()
    return value == f"cat {EXPECTED_TARGET_PATH}"


def _avc_matches(
    line: str,
    *,
    source_context: str,
    target_context: str,
) -> int | None:
    denial = _DENIAL.search(line)
    if denial is None or denial.group(1).split() != [EXPECTED_PERMISSION]:
        return None
    expected_fields = {
        "name": EXPECTED_TARGET_NAME,
        "scontext": source_context,
        "tcontext": target_context,
        "tclass": EXPECTED_TARGET_CLASS,
        "permissive": "0",
    }
    if not all(_field(line, name) == value for name, value in expected_fields.items()):
        return None
    raw_pid = _field(line, "pid")
    if raw_pid is None or re.fullmatch(r"[1-9][0-9]{0,9}", raw_pid) is None:
        return None
    pid = int(raw_pid)
    return pid if pid <= 2_147_483_647 else None


def _syscall_matches(line: str, pid: int) -> bool:
    return _field(line, "pid") == str(pid) and _field(line, "comm") == "cat"


def normalize_unique_enforcing_avc(
    audit_text: str,
    *,
    source_context: str,
    target_context: str,
) -> dict[str, Any]:
    events: dict[tuple[str, str], dict[str, list[str]]] = {}
    for line in audit_text.splitlines():
        if line in {"", "----"}:
            continue
        record = _RECORD.match(line)
        if record is None:
            raise IsolationError("audit record representation is malformed")
        event = events.setdefault(
            _event_id(line), {"AVC": [], "PROCTITLE": [], "SYSCALL": []}
        )
        if record.group(1) in event:
            event[record.group(1)].append(line)

    candidates: list[tuple[str, str, int]] = []
    for event_id, records in events.items():
        avcs = [
            (line, pid)
            for line in records["AVC"]
            if (pid := _avc_matches(
                line,
                source_context=source_context,
                target_context=target_context,
            )) is not None
        ]
        proctitles = [line for line in records["PROCTITLE"] if _proctitle_matches(line)]
        syscalls = (
            [line for line in records["SYSCALL"] if _syscall_matches(line, avcs[0][1])]
            if len(avcs) == 1
            else []
        )
        if len(avcs) > 1 or len(proctitles) > 1 or len(syscalls) > 1:
            raise IsolationError("audit event contains duplicated candidate records")
        if len(avcs) == 1 and len(proctitles) == 1 and len(syscalls) == 1:
            candidates.append((*event_id, avcs[0][1]))
    if not candidates:
        raise NoMatchingAvc("no uniquely correlated enforcing AVC is present")
    if len(candidates) != 1:
        raise IsolationError("multiple correlated enforcing AVC events are ambiguous")
    event_time, serial, pid = candidates[0]
    return {
        "event_time": event_time,
        "serial": serial,
        "pid": pid,
        "source_context": source_context,
        "target_context": target_context,
        "permission": EXPECTED_PERMISSION,
        "target_class": EXPECTED_TARGET_CLASS,
        "target_path": EXPECTED_TARGET_PATH,
        "target_name": EXPECTED_TARGET_NAME,
        "permissive": 0,
    }


def admit_selinux_isolation(
    *,
    process_a: str,
    process_b: str,
    storage_a: str,
    audit_text: str,
) -> dict[str, Any]:
    processes, storage = normalize_context_relationship(
        process_a, process_b, storage_a
    )
    denial = normalize_unique_enforcing_avc(
        audit_text,
        source_context=process_b,
        target_context=storage_a,
    )
    return {
        "invariant_owner": INVARIANT_OWNER,
        "process_contexts": processes,
        "storage_context": storage,
        "denial": denial,
    }


def validate_isolation_evidence(document: object) -> None:
    if not isinstance(document, dict) or set(document) != {
        "invariant_owner",
        "process_contexts",
        "storage_context",
        "denial",
    }:
        raise IsolationError("SELinux isolation evidence shape is invalid")
    if document["invariant_owner"] != INVARIANT_OWNER:
        raise IsolationError("SELinux isolation invariant owner is invalid")
    processes = document["process_contexts"]
    storage = document["storage_context"]
    denial = document["denial"]
    if not isinstance(processes, list) or len(processes) != 2:
        raise IsolationError("SELinux process context evidence is invalid")
    if not all(isinstance(item, dict) for item in processes) or not isinstance(storage, dict):
        raise IsolationError("SELinux normalized context evidence is invalid")
    normalized_processes, normalized_storage = normalize_context_relationship(
        processes[0].get("raw", ""),
        processes[1].get("raw", ""),
        storage.get("raw", ""),
    )
    if canonical_bytes({"processes": processes, "storage": storage}) != canonical_bytes(
        {"processes": normalized_processes, "storage": normalized_storage}
    ):
        raise IsolationError("raw and normalized SELinux MCS facts contradict")
    if not isinstance(denial, dict) or set(denial) != {
        "event_time",
        "serial",
        "pid",
        "source_context",
        "target_context",
        "permission",
        "target_class",
        "target_path",
        "target_name",
        "permissive",
    }:
        raise IsolationError("normalized AVC evidence shape is invalid")
    try:
        datetime.strptime(denial["event_time"], "%m/%d/%y %H:%M:%S.%f")
    except (TypeError, ValueError) as error:
        raise IsolationError("normalized AVC event time is invalid") from error
    if (
        not isinstance(denial["serial"], str)
        or re.fullmatch(r"[1-9][0-9]*", denial["serial"]) is None
        or not isinstance(denial["pid"], int)
        or isinstance(denial["pid"], bool)
        or not 1 <= denial["pid"] <= 2_147_483_647
        or denial["source_context"] != processes[1]["raw"]
        or denial["target_context"] != storage["raw"]
        or denial["permission"] != EXPECTED_PERMISSION
        or denial["target_class"] != EXPECTED_TARGET_CLASS
        or denial["target_path"] != EXPECTED_TARGET_PATH
        or denial["target_name"] != EXPECTED_TARGET_NAME
        or type(denial["permissive"]) is not int
        or denial["permissive"] != 0
    ):
        raise IsolationError("normalized AVC facts contradict the isolation contract")
