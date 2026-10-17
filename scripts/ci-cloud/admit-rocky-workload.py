#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Bind bounded guest transport to the existing independent workload pipeline."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import re
import sys

MAX_BYTES = 2 * 1024 * 1024
PHASES = ("workload_prepare_start", "workload_cleanup",
          "trusted_quadlet_normalize_live", "trusted_quadlet_normalize_cleanup")
COLLECTIONS = ("baseline", "live", "post_cleanup")
FILES = (*COLLECTIONS, "live_normalization", "cleanup_normalization")


class Failure(ValueError):
    pass


def load(name):
    spec = importlib.util.spec_from_file_location(
        name.replace("-", "_"), Path(__file__).with_name(name))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def admit(bundle, control_sha, workflow, directory):
    if (not isinstance(bundle, dict)
            or set(bundle) != {"control_sha", "workflow", "files", "statuses"}
            or re.fullmatch(r"[0-9a-f]{40}", control_sha) is None
            or bundle["control_sha"] != control_sha or bundle["workflow"] != workflow
            or not isinstance(bundle["files"], dict) or set(bundle["files"]) != set(FILES)
            or not isinstance(bundle["statuses"], dict)
            or set(bundle["statuses"]) != set((*PHASES, *COLLECTIONS))
            or any(type(value) is not int or not 0 <= value <= 255
                   for value in bundle["statuses"].values())
            or any(not isinstance(value, str) or len(value.encode()) > 256 * 1024
                   for value in bundle["files"].values())):
        raise Failure("bind-transport")
    paths = {}
    for name, content in bundle["files"].items():
        paths[name] = directory / (name + ".json")
        paths[name].write_text(content, encoding="utf-8")
    try:
        assembler = load("assemble-evidence.py")
        statuses = bundle["statuses"]
        observations = [assembler.read_observation(
            paths[name], name.replace("_", "-"), statuses[name], workflow["target_sha"])
            for name in COLLECTIONS]
        diagnostics = {mode: assembler.read_normalization_diagnostic(
            paths[mode + "_normalization"], mode,
            statuses["trusted_quadlet_normalize_" + mode])
            for mode in ("live", "cleanup")}
        document = assembler.assemble(workflow, *observations, diagnostics,
                                      {key: statuses[key] for key in PHASES},
                                      {key: statuses[key] for key in COLLECTIONS})
    except (OSError, ValueError, TypeError, KeyError):
        raise Failure("assemble-observations") from None
    # Independently recompute admission and enforce the accepted closed schema.
    validator = load("validate-evidence.py")
    try:
        validator.validate_document(document)
    except (ValueError, TypeError, KeyError):
        raise Failure("independent-validation") from None
    validator.write_summary(document, directory / "summary.md")
    (directory / "evidence.json").write_text(
        json.dumps(document, separators=(",", ":")) + "\n", encoding="utf-8")
    return document


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("transport", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--control-sha", required=True)
    parser.add_argument("--target-sha", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    args = parser.parse_args()
    try:
        payload = args.transport.read_bytes()
        if not 0 < len(payload) <= MAX_BYTES:
            raise ValueError("ROCKY_WORKLOAD_TRANSPORT_SIZE")
        # Existing duplicate-key rejection; no target-supplied grader is loaded.
        validator = load("validate-evidence.py")
        bundle = validator.exact_json_loads(payload)
        workflow = {"repository": "SecPal/deployment", "target_sha": args.target_sha,
                    "run_id": args.run_id, "run_attempt": args.run_attempt}
        args.output.mkdir(mode=0o700, exist_ok=True)
        document = admit(bundle, args.control_sha, workflow, args.output)
    except (OSError, ValueError, TypeError, KeyError) as error:
        operation = str(error) if isinstance(error, Failure) else "read-or-decode-transport"
        print(f"ROCKY_WORKLOAD_ADMISSION_FAILED operation={operation}", file=sys.stderr)
        return 1
    return int(document["test"]["result"] != "passed")


if __name__ == "__main__":
    sys.exit(main())
