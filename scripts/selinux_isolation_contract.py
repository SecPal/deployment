#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Pure normalization and admission for Rocky SELinux isolation evidence."""

from __future__ import annotations

import hashlib
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
MAX_AUDIT_OBSERVATION_BYTES = 65_536
MAX_AVC_DIAGNOSTIC_BYTES = 12_288
MAX_AUDIT_RECORDS = 48
MAX_AUDIT_EVENTS = 8
MAX_EVENT_RECORDS = 12
MAX_EVENT_COMPONENT_RECORDS = 4

AVC_REJECTION_FACTS = (
    "no-avc-records-observed",
    "permission-mismatch",
    "target-class-mismatch",
    "target-name-mismatch",
    "source-context-mismatch",
    "target-context-mismatch",
    "permissive-mismatch",
    "avc-pid-invalid-or-missing",
    "avc-duplicate",
    "proctitle-absent",
    "proctitle-mismatch",
    "proctitle-duplicate",
    "syscall-absent",
    "syscall-mismatch",
    "syscall-duplicate",
    "event-id-parse-mismatch",
    "record-representation-malformed",
    "cross-event-separation",
    "multiple-candidate-events",
    "observation-malformed",
    "observation-oversized",
    "ausearch-no-result",
    "capture-execution-error",
)
_AVC_REJECTION_ORDER = {name: index for index, name in enumerate(AVC_REJECTION_FACTS)}
_CAPTURE_OUTCOMES = {
    "records-observed",
    "ausearch-no-result",
    "capture-execution-error",
    "observation-malformed",
    "observation-oversized",
}
_CORRELATION_OUTCOMES = {"admitted", "no-match", "invalid"}
_PID_STATUSES = {"valid", "missing", "duplicate", "malformed", "out-of-range"}

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


def _ordered_rejections(values: set[str]) -> list[str]:
    if not values <= set(AVC_REJECTION_FACTS):
        raise IsolationError("AVC diagnostic rejection fact is unknown")
    return sorted(values, key=_AVC_REJECTION_ORDER.__getitem__)


def _pid_projection(line: str) -> tuple[str, int | None]:
    matches = re.findall(r'(?:^|\s)pid=(?:"([^"\r\n]*)"|(\S+))', line)
    if not matches:
        return "missing", None
    if len(matches) != 1:
        return "duplicate", None
    quoted, bare = matches[0]
    raw = quoted if quoted else bare
    if re.fullmatch(r"[1-9][0-9]{0,9}", raw) is None:
        return "malformed", None
    pid = int(raw)
    if pid > 2_147_483_647:
        return "out-of-range", None
    return "valid", pid


def _diagnostic_contexts(
    process_a: str, process_b: str, storage_a: str
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    return normalize_context_relationship(process_a, process_b, storage_a)


def _diagnostic_base(
    *,
    process_a: str,
    process_b: str,
    storage_a: str,
    payload: bytes,
    attempt: int,
    capture_outcome: str,
    ausearch_status: int | None,
    capture_status: int | None,
) -> dict[str, Any]:
    if (
        capture_outcome not in _CAPTURE_OUTCOMES
        or type(attempt) is not int
        or not 1 <= attempt <= 12
        or any(
            status is not None
            and (type(status) is not int or not 0 <= status <= 255)
            for status in (ausearch_status, capture_status)
        )
        or len(payload) > MAX_AUDIT_OBSERVATION_BYTES + 1
    ):
        raise IsolationError("AVC diagnostic capture facts are outside their bounds")
    processes, storage = _diagnostic_contexts(process_a, process_b, storage_a)
    return {
        "schema_version": 1,
        "invariant_owner": INVARIANT_OWNER,
        "capture_outcome": capture_outcome,
        "correlation_outcome": "invalid",
        "attempt": attempt,
        "ausearch_status": ausearch_status,
        "capture_status": capture_status,
        "observation_bytes": len(payload),
        "observation_sha256": hashlib.sha256(payload).hexdigest(),
        "process_contexts": processes,
        "storage_context": storage,
        "record_count": 0,
        "event_count": 0,
        "avc_record_count": 0,
        "candidate_event_count": 0,
        "events": [],
        "rejection_facts": [],
    }


def capture_avc_correlation_diagnostic(
    *,
    process_a: str,
    process_b: str,
    storage_a: str,
    payload: bytes,
    attempt: int,
    capture_outcome: str,
    ausearch_status: int | None,
    capture_status: int | None,
) -> dict[str, Any]:
    """Build one closed non-record capture result without retaining raw output."""
    if not isinstance(payload, bytes) or capture_outcome == "records-observed":
        raise IsolationError("AVC diagnostic capture request is invalid")
    document = _diagnostic_base(
        process_a=process_a,
        process_b=process_b,
        storage_a=storage_a,
        payload=payload,
        attempt=attempt,
        capture_outcome=capture_outcome,
        ausearch_status=ausearch_status,
        capture_status=capture_status,
    )
    if capture_outcome == "ausearch-no-result":
        document["correlation_outcome"] = "no-match"
        document["rejection_facts"] = [
            "no-avc-records-observed",
            "ausearch-no-result",
        ]
    elif capture_outcome == "capture-execution-error":
        document["rejection_facts"] = ["capture-execution-error"]
    elif capture_outcome == "observation-oversized":
        document["rejection_facts"] = ["observation-oversized"]
    else:
        document["rejection_facts"] = ["observation-malformed"]
    validate_avc_correlation_diagnostic(document)
    return document


def _avc_projection(
    line: str, *, source_context: str, target_context: str
) -> dict[str, Any]:
    denial = _DENIAL.search(line)
    pid_status, pid = _pid_projection(line)
    return {
        "permission_match": bool(
            denial is not None and denial.group(1).split() == [EXPECTED_PERMISSION]
        ),
        "target_class_match": _field(line, "tclass") == EXPECTED_TARGET_CLASS,
        "target_name_match": _field(line, "name") == EXPECTED_TARGET_NAME,
        "source_context_match": _field(line, "scontext") == source_context,
        "target_context_match": _field(line, "tcontext") == target_context,
        "permissive_match": _field(line, "permissive") == "0",
        "pid_status": pid_status,
        "pid": pid,
    }


def _proctitle_projection(line: str) -> dict[str, bool]:
    return {"target_match": _proctitle_matches(line)}


def _syscall_projection(line: str) -> dict[str, Any]:
    pid_status, pid = _pid_projection(line)
    return {
        "pid_status": pid_status,
        "pid": pid,
        "comm_match": _field(line, "comm") == "cat",
    }


def _exact_avc(record: dict[str, Any]) -> bool:
    return (
        all(
            type(record[name]) is bool and record[name]
            for name in (
                "permission_match",
                "target_class_match",
                "target_name_match",
                "source_context_match",
                "target_context_match",
                "permissive_match",
            )
        )
        and record["pid_status"] == "valid"
        and type(record["pid"]) is int
    )


def _event_decision(event: dict[str, Any]) -> tuple[bool, list[str], list[int]]:
    rejections: set[str] = set()
    exact_avcs: list[dict[str, Any]] = []
    for avc in event["avc_records"]:
        for field, rejection in (
            ("permission_match", "permission-mismatch"),
            ("target_class_match", "target-class-mismatch"),
            ("target_name_match", "target-name-mismatch"),
            ("source_context_match", "source-context-mismatch"),
            ("target_context_match", "target-context-mismatch"),
            ("permissive_match", "permissive-mismatch"),
        ):
            if not avc[field]:
                rejections.add(rejection)
        if avc["pid_status"] != "valid":
            rejections.add("avc-pid-invalid-or-missing")
        if _exact_avc(avc):
            exact_avcs.append(avc)
    if len(exact_avcs) > 1:
        rejections.add("avc-duplicate")

    matching_proctitles = sum(
        record["target_match"] for record in event["proctitle_records"]
    )
    if not event["proctitle_records"]:
        rejections.add("proctitle-absent")
    elif matching_proctitles == 0:
        rejections.add("proctitle-mismatch")
    elif matching_proctitles > 1:
        rejections.add("proctitle-duplicate")

    matching_syscalls = 0
    if len(exact_avcs) == 1:
        pid = exact_avcs[0]["pid"]
        matching_syscalls = sum(
            record["pid_status"] == "valid"
            and record["pid"] == pid
            and record["comm_match"]
            for record in event["syscall_records"]
        )
    if not event["syscall_records"]:
        rejections.add("syscall-absent")
    elif matching_syscalls == 0:
        rejections.add("syscall-mismatch")
    elif matching_syscalls > 1:
        rejections.add("syscall-duplicate")

    candidate = (
        len(exact_avcs) == 1
        and matching_proctitles == 1
        and matching_syscalls == 1
    )
    return candidate, _ordered_rejections(rejections), [
        record["pid"] for record in exact_avcs
    ]


def _finalize_record_diagnostic(document: dict[str, Any]) -> None:
    global_rejections: set[str] = set()
    candidate_count = 0
    exact_avcs: list[tuple[tuple[str, str], int]] = []
    proctitle_events: set[tuple[str, str]] = set()
    syscalls: list[tuple[tuple[str, str], int]] = []
    for event in document["events"]:
        candidate, rejections, exact_pids = _event_decision(event)
        event["candidate"] = candidate
        event["rejection_facts"] = rejections
        if event["avc_records"]:
            global_rejections.update(rejections)
        candidate_count += candidate
        identity = (event["event_time"], event["serial"])
        exact_avcs.extend((identity, pid) for pid in exact_pids)
        if any(record["target_match"] for record in event["proctitle_records"]):
            proctitle_events.add(identity)
        syscalls.extend(
            (identity, record["pid"])
            for record in event["syscall_records"]
            if record["pid_status"] == "valid" and record["comm_match"]
        )
    document["candidate_event_count"] = candidate_count
    if document["avc_record_count"] == 0:
        global_rejections.add("no-avc-records-observed")
    if candidate_count > 1:
        global_rejections.add("multiple-candidate-events")
    if candidate_count == 0 and any(
        len({avc_event, proctitle_event, syscall_event}) > 1
        for avc_event, pid in exact_avcs
        for proctitle_event in proctitle_events
        for syscall_event, syscall_pid in syscalls
        if syscall_pid == pid
    ):
        global_rejections.add("cross-event-separation")
    duplicate_candidate_record = any(
        any(
            fact in event["rejection_facts"]
            for fact in ("avc-duplicate", "proctitle-duplicate", "syscall-duplicate")
        )
        for event in document["events"]
    )
    if candidate_count == 1 and not duplicate_candidate_record:
        document["correlation_outcome"] = "admitted"
        document["rejection_facts"] = []
    elif candidate_count > 1 or duplicate_candidate_record:
        document["correlation_outcome"] = "invalid"
        document["rejection_facts"] = _ordered_rejections(global_rejections)
    else:
        document["correlation_outcome"] = "no-match"
        document["rejection_facts"] = _ordered_rejections(global_rejections)


def diagnose_avc_correlation_bytes(
    *,
    process_a: str,
    process_b: str,
    storage_a: str,
    payload: bytes,
    attempt: int,
) -> dict[str, Any]:
    """Project a bounded audit observation into closed correlation facts."""
    if not isinstance(payload, bytes):
        raise IsolationError("AVC diagnostic observation is not bytes")
    if len(payload) > MAX_AUDIT_OBSERVATION_BYTES:
        return capture_avc_correlation_diagnostic(
            process_a=process_a,
            process_b=process_b,
            storage_a=storage_a,
            payload=payload[: MAX_AUDIT_OBSERVATION_BYTES + 1],
            attempt=attempt,
            capture_outcome="observation-oversized",
            ausearch_status=0,
            capture_status=0,
        )
    try:
        audit_text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return capture_avc_correlation_diagnostic(
            process_a=process_a,
            process_b=process_b,
            storage_a=storage_a,
            payload=payload,
            attempt=attempt,
            capture_outcome="observation-malformed",
            ausearch_status=0,
            capture_status=0,
        )
    document = _diagnostic_base(
        process_a=process_a,
        process_b=process_b,
        storage_a=storage_a,
        payload=payload,
        attempt=attempt,
        capture_outcome="records-observed",
        ausearch_status=0,
        capture_status=0,
    )
    events: dict[tuple[str, str], dict[str, Any]] = {}
    for line in audit_text.splitlines():
        if line in {"", "----"}:
            continue
        document["record_count"] += 1
        if document["record_count"] > MAX_AUDIT_RECORDS:
            return capture_avc_correlation_diagnostic(
                process_a=process_a,
                process_b=process_b,
                storage_a=storage_a,
                payload=payload,
                attempt=attempt,
                capture_outcome="observation-oversized",
                ausearch_status=0,
                capture_status=0,
            )
        record = _RECORD.match(line)
        if record is None:
            document["capture_outcome"] = "observation-malformed"
            document["rejection_facts"] = [
                "record-representation-malformed",
                "observation-malformed",
            ]
            validate_avc_correlation_diagnostic(document)
            return document
        try:
            identity = _event_id(line)
        except IsolationError:
            document["capture_outcome"] = "observation-malformed"
            document["rejection_facts"] = [
                "event-id-parse-mismatch",
                "observation-malformed",
            ]
            validate_avc_correlation_diagnostic(document)
            return document
        if len(identity[1]) > 64:
            document["capture_outcome"] = "observation-malformed"
            document["rejection_facts"] = [
                "event-id-parse-mismatch",
                "observation-malformed",
            ]
            validate_avc_correlation_diagnostic(document)
            return document
        if identity not in events:
            if len(events) >= MAX_AUDIT_EVENTS:
                return capture_avc_correlation_diagnostic(
                    process_a=process_a,
                    process_b=process_b,
                    storage_a=storage_a,
                    payload=payload,
                    attempt=attempt,
                    capture_outcome="observation-oversized",
                    ausearch_status=0,
                    capture_status=0,
                )
            events[identity] = {
                "event_time": identity[0],
                "serial": identity[1],
                "record_count": 0,
                "avc_records": [],
                "proctitle_records": [],
                "syscall_records": [],
                "candidate": False,
                "rejection_facts": [],
            }
        event = events[identity]
        event["record_count"] += 1
        record_type = record.group(1)
        component_name = {
            "AVC": "avc_records",
            "PROCTITLE": "proctitle_records",
            "SYSCALL": "syscall_records",
        }.get(record_type)
        if (
            event["record_count"] > MAX_EVENT_RECORDS
            or component_name is not None
            and len(event[component_name]) >= MAX_EVENT_COMPONENT_RECORDS
        ):
            return capture_avc_correlation_diagnostic(
                process_a=process_a,
                process_b=process_b,
                storage_a=storage_a,
                payload=payload,
                attempt=attempt,
                capture_outcome="observation-oversized",
                ausearch_status=0,
                capture_status=0,
            )
        if record_type == "AVC":
            event["avc_records"].append(
                _avc_projection(
                    line,
                    source_context=process_b,
                    target_context=storage_a,
                )
            )
            document["avc_record_count"] += 1
        elif record_type == "PROCTITLE":
            event["proctitle_records"].append(_proctitle_projection(line))
        elif record_type == "SYSCALL":
            event["syscall_records"].append(_syscall_projection(line))
    document["events"] = list(events.values())
    document["event_count"] = len(events)
    _finalize_record_diagnostic(document)
    if len(canonical_bytes(document)) > MAX_AVC_DIAGNOSTIC_BYTES:
        return capture_avc_correlation_diagnostic(
            process_a=process_a,
            process_b=process_b,
            storage_a=storage_a,
            payload=payload,
            attempt=attempt,
            capture_outcome="observation-oversized",
            ausearch_status=0,
            capture_status=0,
        )
    validate_avc_correlation_diagnostic(document)
    return document


def diagnose_avc_correlation(
    *,
    process_a: str,
    process_b: str,
    storage_a: str,
    audit_text: str,
    attempt: int,
) -> dict[str, Any]:
    if not isinstance(audit_text, str):
        raise IsolationError("AVC diagnostic observation is not text")
    return diagnose_avc_correlation_bytes(
        process_a=process_a,
        process_b=process_b,
        storage_a=storage_a,
        payload=audit_text.encode("utf-8"),
        attempt=attempt,
    )


def _validate_rejection_list(value: object) -> None:
    if (
        not isinstance(value, list)
        or any(not isinstance(item, str) for item in value)
        or len(value) != len(set(value))
        or value != _ordered_rejections(set(value))
    ):
        raise IsolationError("AVC diagnostic rejection facts are not canonical")


def validate_avc_correlation_diagnostic(document: object) -> None:
    """Independently validate a closed diagnostic and recompute its decision."""
    expected_keys = {
        "schema_version",
        "invariant_owner",
        "capture_outcome",
        "correlation_outcome",
        "attempt",
        "ausearch_status",
        "capture_status",
        "observation_bytes",
        "observation_sha256",
        "process_contexts",
        "storage_context",
        "record_count",
        "event_count",
        "avc_record_count",
        "candidate_event_count",
        "events",
        "rejection_facts",
    }
    if not isinstance(document, dict) or set(document) != expected_keys:
        raise IsolationError("AVC correlation diagnostic shape is invalid")
    try:
        if len(canonical_bytes(document)) > MAX_AVC_DIAGNOSTIC_BYTES:
            raise IsolationError("AVC correlation diagnostic exceeds its closed bound")
    except (TypeError, UnicodeEncodeError, ValueError) as error:
        raise IsolationError("AVC correlation diagnostic is not closed JSON") from error
    if (
        document["schema_version"] != 1
        or document["invariant_owner"] != INVARIANT_OWNER
        or document["capture_outcome"] not in _CAPTURE_OUTCOMES
        or document["correlation_outcome"] not in _CORRELATION_OUTCOMES
        or type(document["attempt"]) is not int
        or not 1 <= document["attempt"] <= 12
        or any(
            status is not None
            and (type(status) is not int or not 0 <= status <= 255)
            for status in (document["ausearch_status"], document["capture_status"])
        )
        or type(document["observation_bytes"]) is not int
        or not 0 <= document["observation_bytes"] <= MAX_AUDIT_OBSERVATION_BYTES + 1
        or not isinstance(document["observation_sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", document["observation_sha256"]) is None
        or any(
            type(document[name]) is not int or document[name] < 0
            for name in (
                "record_count",
                "event_count",
                "avc_record_count",
                "candidate_event_count",
            )
        )
        or not isinstance(document["events"], list)
        or len(document["events"]) > MAX_AUDIT_EVENTS
    ):
        raise IsolationError("AVC correlation diagnostic facts are outside their bounds")
    _validate_rejection_list(document["rejection_facts"])
    processes = document["process_contexts"]
    storage = document["storage_context"]
    if (
        not isinstance(processes, list)
        or len(processes) != 2
        or not all(isinstance(item, dict) for item in processes)
        or not isinstance(storage, dict)
    ):
        raise IsolationError("AVC diagnostic context relationship is invalid")
    normalized_processes, normalized_storage = normalize_context_relationship(
        processes[0].get("raw", ""),
        processes[1].get("raw", ""),
        storage.get("raw", ""),
    )
    if canonical_bytes({"processes": processes, "storage": storage}) != canonical_bytes(
        {"processes": normalized_processes, "storage": normalized_storage}
    ):
        raise IsolationError("AVC diagnostic contexts contradict their MCS facts")

    capture_outcome = document["capture_outcome"]
    if capture_outcome != "records-observed":
        if document["events"] or any(
            document[name] != 0
            for name in ("event_count", "avc_record_count", "candidate_event_count")
        ):
            raise IsolationError("non-record AVC diagnostic exports event facts")
        if capture_outcome != "observation-malformed" and document["record_count"] != 0:
            raise IsolationError("non-record AVC diagnostic has a record count")
        expected: tuple[str, str, list[str]]
        if capture_outcome == "ausearch-no-result":
            if (
                document["ausearch_status"] != 1
                or document["capture_status"] != 0
                or document["observation_bytes"] != 0
                or document["observation_sha256"]
                != hashlib.sha256(b"").hexdigest()
            ):
                raise IsolationError("ausearch no-result diagnostic is inconsistent")
            expected = (
                "ausearch-no-result",
                "no-match",
                ["no-avc-records-observed", "ausearch-no-result"],
            )
        elif capture_outcome == "capture-execution-error":
            if (document["ausearch_status"], document["capture_status"]) == (1, 0):
                raise IsolationError("capture error aliases ausearch no-result")
            expected = (
                "capture-execution-error",
                "invalid",
                ["capture-execution-error"],
            )
        elif capture_outcome == "observation-oversized":
            expected = (
                "observation-oversized",
                "invalid",
                ["observation-oversized"],
            )
        else:
            allowed = {
                ("observation-malformed",),
                ("event-id-parse-mismatch", "observation-malformed"),
                ("record-representation-malformed", "observation-malformed"),
            }
            if tuple(document["rejection_facts"]) not in allowed:
                raise IsolationError("malformed AVC diagnostic reason is invalid")
            expected = (
                "observation-malformed",
                "invalid",
                document["rejection_facts"],
            )
        if (
            document["capture_outcome"] != expected[0]
            or document["correlation_outcome"] != expected[1]
            or document["rejection_facts"] != expected[2]
        ):
            raise IsolationError("AVC diagnostic outcome contradicts its capture facts")
        return

    if (
        document["ausearch_status"] != 0
        or document["capture_status"] != 0
        or document["observation_bytes"] > MAX_AUDIT_OBSERVATION_BYTES
        or document["record_count"] > MAX_AUDIT_RECORDS
        or document["event_count"] != len(document["events"])
    ):
        raise IsolationError("record AVC diagnostic capture facts are inconsistent")
    event_keys = {
        "event_time",
        "serial",
        "record_count",
        "avc_records",
        "proctitle_records",
        "syscall_records",
        "candidate",
        "rejection_facts",
    }
    avc_keys = {
        "permission_match",
        "target_class_match",
        "target_name_match",
        "source_context_match",
        "target_context_match",
        "permissive_match",
        "pid_status",
        "pid",
    }
    syscall_keys = {"pid_status", "pid", "comm_match"}
    total_records = 0
    total_avcs = 0
    identities: set[tuple[str, str]] = set()
    for event in document["events"]:
        if not isinstance(event, dict) or set(event) != event_keys:
            raise IsolationError("AVC diagnostic event shape is invalid")
        identity = (event["event_time"], event["serial"])
        try:
            datetime.strptime(event["event_time"], "%m/%d/%y %H:%M:%S.%f")
        except (TypeError, ValueError) as error:
            raise IsolationError("AVC diagnostic event time is malformed") from error
        if (
            not isinstance(event["serial"], str)
            or re.fullmatch(r"[1-9][0-9]{0,63}", event["serial"]) is None
            or identity in identities
            or type(event["record_count"]) is not int
            or not 1 <= event["record_count"] <= MAX_EVENT_RECORDS
            or type(event["candidate"]) is not bool
        ):
            raise IsolationError("AVC diagnostic event identity or count is invalid")
        identities.add(identity)
        _validate_rejection_list(event["rejection_facts"])
        for name in ("avc_records", "proctitle_records", "syscall_records"):
            if (
                not isinstance(event[name], list)
                or len(event[name]) > MAX_EVENT_COMPONENT_RECORDS
            ):
                raise IsolationError("AVC diagnostic component count is outside its bound")
        retained_count = sum(
            len(event[name])
            for name in ("avc_records", "proctitle_records", "syscall_records")
        )
        if retained_count > event["record_count"]:
            raise IsolationError("AVC diagnostic event record count contradicts components")
        for avc in event["avc_records"]:
            if not isinstance(avc, dict) or set(avc) != avc_keys:
                raise IsolationError("AVC diagnostic AVC shape is invalid")
            if any(
                type(avc[name]) is not bool
                for name in (
                    "permission_match",
                    "target_class_match",
                    "target_name_match",
                    "source_context_match",
                    "target_context_match",
                    "permissive_match",
                )
            ):
                raise IsolationError("AVC diagnostic predicate is not boolean")
            if avc["pid_status"] not in _PID_STATUSES or (
                avc["pid_status"] == "valid"
            ) != (
                type(avc["pid"]) is int and 1 <= avc["pid"] <= 2_147_483_647
            ):
                raise IsolationError("AVC diagnostic PID facts are inconsistent")
        for proctitle in event["proctitle_records"]:
            if (
                not isinstance(proctitle, dict)
                or set(proctitle) != {"target_match"}
                or type(proctitle["target_match"]) is not bool
            ):
                raise IsolationError("AVC diagnostic PROCTITLE shape is invalid")
        for syscall in event["syscall_records"]:
            if (
                not isinstance(syscall, dict)
                or set(syscall) != syscall_keys
                or type(syscall["comm_match"]) is not bool
                or syscall["pid_status"] not in _PID_STATUSES
                or (syscall["pid_status"] == "valid")
                != (
                    type(syscall["pid"]) is int
                    and 1 <= syscall["pid"] <= 2_147_483_647
                )
            ):
                raise IsolationError("AVC diagnostic SYSCALL facts are inconsistent")
        total_records += event["record_count"]
        total_avcs += len(event["avc_records"])
    if (
        total_records != document["record_count"]
        or total_avcs != document["avc_record_count"]
    ):
        raise IsolationError("AVC diagnostic aggregate counts are inconsistent")
    recomputed = {
        **document,
        "events": [
            {**event, "candidate": False, "rejection_facts": []}
            for event in document["events"]
        ],
        "candidate_event_count": 0,
        "rejection_facts": [],
    }
    _finalize_record_diagnostic(recomputed)
    if (
        document["correlation_outcome"] != recomputed["correlation_outcome"]
        or document["candidate_event_count"]
        != recomputed["candidate_event_count"]
        or document["rejection_facts"] != recomputed["rejection_facts"]
        or any(
            original["candidate"] != expected["candidate"]
            or original["rejection_facts"] != expected["rejection_facts"]
            for original, expected in zip(document["events"], recomputed["events"])
        )
    ):
        raise IsolationError("AVC diagnostic classification contradicts its facts")


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
