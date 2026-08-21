#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Assemble independently collected D.1 and D.1a evidence."""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path


MAX_INPUT_BYTES = 256 * 1024
WORKLOAD_COLLECTOR = Path(__file__).with_name("collect-workload-evidence.py")
WORKLOAD_ADMISSION = Path(__file__).with_name("workload-admission.py")
TRUSTED_MODULE_RESPONSIBILITIES = {
    WORKLOAD_COLLECTOR: "workload collector",
    WORKLOAD_ADMISSION: "workload admission",
}
TRUSTED_MODULES: dict[Path, object] = {}


class DuplicateKey(ValueError):
    pass


def read_document(path: Path) -> object:
    payload = path.read_bytes()
    if not payload or len(payload) > MAX_INPUT_BYTES:
        raise ValueError(f"bounded evidence input is missing or excessive: {path.name}")

    def exact_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        document: dict[str, object] = {}
        for key, value in pairs:
            if key in document:
                raise DuplicateKey(key)
            document[key] = value
        return document

    try:
        return json.loads(payload, object_pairs_hook=exact_object)
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateKey) as error:
        raise ValueError(f"bounded evidence input is malformed: {path.name}") from error


def read_observation(
    path: Path, phase: str, collection_status: int
) -> dict[str, object]:
    module = load_workload_admission()
    if collection_status != 0:
        return module.incomplete_observation(phase)
    try:
        document = read_document(path)
    except (OSError, ValueError):
        return module.incomplete_observation(phase)
    if not isinstance(document, dict) or document.get("phase") != phase:
        return module.incomplete_observation(phase)
    return document


def status(value: str) -> int:
    if re.fullmatch(r"[0-9]{1,3}", value) is None or not 0 <= int(value) <= 255:
        raise ValueError("phase status is outside the closed range")
    return int(value)


def read_normalization_diagnostic(
    path: Path, mode: str, phase_status: int
) -> dict[str, object]:
    module = load_workload_collector()
    try:
        missing = path.stat().st_size == 0
    except OSError:
        missing = True
    if missing:
        if phase_status == 0:
            raise ValueError("successful normalization diagnostic is missing")
        return {
            "mode": mode,
            "status": 1,
            "stage": "unreported",
            "failure_reason": "unexpected-error",
            "command_status": None,
        }
    document = read_document(path)
    if not isinstance(document, dict) or set(document) != {
        "mode", "status", "stage", "failure_reason", "command_status"
    }:
        raise ValueError("normalization diagnostic is malformed")
    diagnostic_status = document["status"]
    stage = document["stage"]
    failure_reason = document["failure_reason"]
    command_status = document["command_status"]
    if (
        document["mode"] != mode
        or not isinstance(diagnostic_status, int)
        or isinstance(diagnostic_status, bool)
        or diagnostic_status not in {0, 1}
        or not isinstance(stage, str)
        or not isinstance(failure_reason, (str, type(None)))
        or not isinstance(command_status, (int, type(None)))
        or isinstance(command_status, bool)
        or (
            command_status is not None
            and not 0 < command_status <= 255
        )
    ):
        raise ValueError("normalization diagnostic is outside the closed contract")
    if diagnostic_status == 0:
        if (
            phase_status != 0
            or stage != "complete"
            or failure_reason is not None
            or command_status is not None
        ):
            raise ValueError("successful normalization diagnostic is inconsistent")
    elif (
        phase_status == 0
        or stage not in module.NORMALIZATION_EVIDENCE_STAGES
        or failure_reason not in module.NORMALIZATION_FAILURE_REASONS
        or (failure_reason == "command-exit") != (command_status is not None)
    ):
        raise ValueError("failed normalization diagnostic is inconsistent")
    return document


def load_trusted_module(path: Path, name: str):
    """Load a trusted controller-side module once per assembly run.

    Assembly reads three observations and two diagnostics, and the admission
    layer loads the collector in turn, so an uncached loader would execute the
    same trusted sources several times over. One load per path keeps every
    caller on the same reviewed definitions.
    """
    cached = TRUSTED_MODULES.get(path)
    if cached is not None:
        return cached
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        responsibility = TRUSTED_MODULE_RESPONSIBILITIES.get(path, "module")
        raise ValueError(f"trusted {responsibility} implementation is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    TRUSTED_MODULES[path] = module
    return module


def load_workload_collector():
    """Load the target-side collector, which owns the workload contract."""
    return load_trusted_module(WORKLOAD_COLLECTOR, "trusted_workload_collector")


def load_workload_admission():
    """Load the controller-side layer that owns every D.1a admission decision."""
    return load_trusted_module(WORKLOAD_ADMISSION, "trusted_workload_admission")


def assemble(
    host_document: object,
    baseline: object,
    live: object,
    post_cleanup: object,
    normalization_diagnostics: dict[str, dict[str, object]],
    phase_statuses: dict[str, int],
    collection_statuses: dict[str, int],
) -> dict[str, object]:
    if not isinstance(host_document, dict) or set(host_document) != {
        "schema_version", "workflow", "test", "platform", "apt", "host", "runtime"
    } or host_document.get("schema_version") != 1:
        raise ValueError("host evidence is outside the trusted D.1 contract")
    test = host_document.get("test")
    workflow = host_document.get("workflow")
    if not isinstance(test, dict) or not isinstance(workflow, dict):
        raise ValueError("host evidence identity is malformed")
    target_sha = workflow.get("target_sha")
    if not isinstance(target_sha, str) or re.fullmatch(r"[0-9a-f]{40}", target_sha) is None:
        raise ValueError("host evidence target SHA is malformed")

    host_failures = [
        str(value)
        for value in test.get("failed_admission_invariants", [])
        if value != "TARGET_CONFORMANCE_ENTRYPOINT"
    ]
    if phase_statuses["host"] != 0:
        host_failures.append("TARGET_HOST_CONTRACT")
    host_failures = list(dict.fromkeys(host_failures))
    workload = {
        "protocol_version": 1,
        "instance": target_sha[:12],
        "result": "failed",
        "failed_admission_invariants": [],
        "baseline": baseline,
        "live": live,
        "post_cleanup": post_cleanup,
    }
    module = load_workload_admission()
    workload_failures = module.workload_admission_failures(workload)
    status_invariants = {
        ("phase", "workload_prepare_start"): "TARGET_WORKLOAD_PREPARE_START",
        ("phase", "workload_cleanup"): "TARGET_WORKLOAD_CLEANUP",
        ("phase", "trusted_quadlet_normalize_live"):
            "TRUSTED_QUADLET_NORMALIZE_LIVE",
        ("phase", "trusted_quadlet_normalize_cleanup"):
            "TRUSTED_QUADLET_NORMALIZE_CLEANUP",
        ("collection", "baseline"): "TRUSTED_BASELINE_COLLECTION",
        ("collection", "live"): "TRUSTED_LIVE_COLLECTION",
        ("collection", "post_cleanup"): "TRUSTED_POST_CLEANUP_COLLECTION",
    }
    for (kind, name), invariant in status_invariants.items():
        values = phase_statuses if kind == "phase" else collection_statuses
        if values[name] != 0:
            workload_failures.append(invariant)
    workload_failures = list(dict.fromkeys(workload_failures))
    workload["failed_admission_invariants"] = workload_failures
    workload["result"] = "passed" if not workload_failures else "failed"

    overall_failures = list(dict.fromkeys([*host_failures, *workload_failures]))
    test.pop("target_exit_status", None)
    test["normalization_diagnostics"] = normalization_diagnostics
    test["phase_exit_statuses"] = phase_statuses
    test["collection_exit_statuses"] = collection_statuses
    test["failed_admission_invariants"] = overall_failures
    test["result"] = "passed" if not overall_failures else "failed"
    host_document["schema_version"] = 3
    host_document["host_admission"] = {
        "result": "passed" if not host_failures else "failed",
        "failed_admission_invariants": host_failures,
    }
    host_document["workload"] = workload
    return host_document


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("host", type=Path)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("live", type=Path)
    parser.add_argument("post_cleanup", type=Path)
    parser.add_argument("live_normalization", type=Path)
    parser.add_argument("cleanup_normalization", type=Path)
    parser.add_argument("host_status")
    parser.add_argument("prepare_start_status")
    parser.add_argument("cleanup_status")
    parser.add_argument("live_normalization_status")
    parser.add_argument("cleanup_normalization_status")
    parser.add_argument("baseline_collection_status")
    parser.add_argument("live_collection_status")
    parser.add_argument("cleanup_collection_status")
    arguments = parser.parse_args()
    try:
        phase_statuses = {
            "host": status(arguments.host_status),
            "workload_prepare_start": status(arguments.prepare_start_status),
            "workload_cleanup": status(arguments.cleanup_status),
            "trusted_quadlet_normalize_live": status(
                arguments.live_normalization_status
            ),
            "trusted_quadlet_normalize_cleanup": status(
                arguments.cleanup_normalization_status
            ),
        }
        collection_statuses = {
            "baseline": status(arguments.baseline_collection_status),
            "live": status(arguments.live_collection_status),
            "post_cleanup": status(arguments.cleanup_collection_status),
        }
        normalization_diagnostics = {
            "live": read_normalization_diagnostic(
                arguments.live_normalization,
                "live",
                phase_statuses["trusted_quadlet_normalize_live"],
            ),
            "cleanup": read_normalization_diagnostic(
                arguments.cleanup_normalization,
                "cleanup",
                phase_statuses["trusted_quadlet_normalize_cleanup"],
            ),
        }
        document = assemble(
            read_document(arguments.host),
            read_observation(
                arguments.baseline, "baseline", collection_statuses["baseline"]
            ),
            read_observation(arguments.live, "live", collection_statuses["live"]),
            read_observation(
                arguments.post_cleanup,
                "post-cleanup",
                collection_statuses["post_cleanup"],
            ),
            normalization_diagnostics,
            phase_statuses,
            collection_statuses,
        )
    except (OSError, ValueError) as error:
        print(f"ERROR: unable to assemble trusted cloud evidence: {error}", file=sys.stderr)
        return 1
    json.dump(document, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
