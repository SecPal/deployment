#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Normalize and admit the administrator-owned Rocky Quadlet representation."""

from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any


RESPONSIBILITY = "normalization,admission"
INVARIANT_OWNER = "quadlet_authority_contract.admit_quadlet_authority"
FIXTURE_IMAGE = (
    "docker.io/library/alpine@sha256:"
    "4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1"
)
UNIT = re.compile(r"^secpal-host-qualification-[A-Za-z0-9]{6}$")
FRAGMENT = re.compile(
    r"^/run/user/(?P<uid>[1-9][0-9]*)/systemd/generator/"
    r"(?P<unit>secpal-host-qualification-[A-Za-z0-9]{6})\.service$"
)
SOURCE = re.compile(
    r"^/etc/containers/systemd/users/(?P<uid>[1-9][0-9]*)/"
    r"(?P<unit>secpal-host-qualification-[A-Za-z0-9]{6})\.container$"
)
PROPERTY_KEYS = frozenset(
    {"FragmentPath", "SourcePath", "DropInPaths", "ExecStart"}
)
EVIDENCE_KEYS = frozenset(
    {
        "schema_version",
        "invariant_owner",
        "runtime_uid",
        "unit_name",
        "fragment_path",
        "source_path",
        "drop_in_paths",
        "exec_start",
    }
)
EXECUTION_KEYS = frozenset(
    {
        "executable",
        "argv",
        "ignore_errors",
        "start_time",
        "stop_time",
        "pid",
        "code",
        "status",
    }
)


class AuthorityError(ValueError):
    """The effective Quadlet representation is outside the closed contract."""


def expected_argv(unit_name: str) -> list[str]:
    if not isinstance(unit_name, str) or UNIT.fullmatch(unit_name) is None:
        raise AuthorityError("Quadlet unit identity is malformed")
    return [
        "/usr/bin/podman",
        "run",
        "--name",
        unit_name,
        "--replace",
        "--rm",
        "--cgroups=split",
        "--pull",
        "never",
        "--network",
        "none",
        "--sdnotify=conmon",
        "-d",
        "--cap-drop",
        "all",
        "--user",
        "65532:65532",
        "--security-opt=no-new-privileges",
        FIXTURE_IMAGE,
        "sleep",
        "infinity",
    ]


def expected_exec_start(unit_name: str) -> str:
    argv = " ".join(expected_argv(unit_name))
    return (
        f"{{ path=/usr/bin/podman ; argv[]={argv} ; ignore_errors=no ; "
        "start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; "
        "status=0/0 }"
    )


def parse_properties(text: str) -> dict[str, str]:
    if not isinstance(text, str) or len(text.encode("utf-8")) > 16_384:
        raise AuthorityError("Quadlet service properties exceed their closed bound")
    properties: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            raise AuthorityError("Quadlet service property is malformed")
        name, value = line.split("=", 1)
        if name in properties:
            raise AuthorityError("Quadlet service property is duplicated")
        properties[name] = value
    if properties.keys() != PROPERTY_KEYS:
        raise AuthorityError("Quadlet service property set is incomplete")
    return properties


def _identities(fragment_path: str, source_path: str) -> tuple[int, str]:
    if not isinstance(fragment_path, str) or not isinstance(source_path, str):
        raise AuthorityError("Quadlet authority paths are malformed")
    fragment = FRAGMENT.fullmatch(fragment_path)
    source = SOURCE.fullmatch(source_path)
    if fragment is None or source is None:
        raise AuthorityError("Quadlet authority paths are malformed")
    if fragment.group("uid", "unit") != source.group("uid", "unit"):
        raise AuthorityError("Quadlet authority paths disagree")
    return int(fragment.group("uid")), fragment.group("unit")


def admit_quadlet_authority(
    properties_text: str, expected_fragment: str, expected_source: str
) -> dict[str, Any]:
    properties = parse_properties(properties_text)
    runtime_uid, unit_name = _identities(expected_fragment, expected_source)
    if (
        properties["FragmentPath"] != expected_fragment
        or properties["SourcePath"] != expected_source
        or properties["DropInPaths"]
        or properties["ExecStart"] != expected_exec_start(unit_name)
    ):
        raise AuthorityError(
            "effective Quadlet service contradicts administrator authority"
        )
    evidence: dict[str, Any] = {
        "schema_version": 1,
        "invariant_owner": INVARIANT_OWNER,
        "runtime_uid": runtime_uid,
        "unit_name": unit_name,
        "fragment_path": expected_fragment,
        "source_path": expected_source,
        "drop_in_paths": [],
        "exec_start": {
            "executable": "/usr/bin/podman",
            "argv": expected_argv(unit_name),
            "ignore_errors": False,
            "start_time": None,
            "stop_time": None,
            "pid": 0,
            "code": None,
            "status": "0/0",
        },
    }
    validate_authority_evidence(evidence)
    return evidence


def validate_authority_evidence(evidence: object) -> None:
    if not isinstance(evidence, dict) or evidence.keys() != EVIDENCE_KEYS:
        raise AuthorityError("normalized Quadlet authority evidence is malformed")
    if (
        type(evidence["schema_version"]) is not int
        or evidence["schema_version"] != 1
        or evidence["invariant_owner"] != INVARIANT_OWNER
    ):
        raise AuthorityError("Quadlet authority owner disagrees")
    runtime_uid, unit_name = _identities(
        evidence["fragment_path"], evidence["source_path"]
    )
    if (
        type(evidence["runtime_uid"]) is not int
        or evidence["runtime_uid"] != runtime_uid
        or evidence["unit_name"] != unit_name
        or evidence["drop_in_paths"] != []
    ):
        raise AuthorityError("normalized Quadlet authority identities disagree")
    execution = evidence["exec_start"]
    if not isinstance(execution, dict) or execution.keys() != EXECUTION_KEYS:
        raise AuthorityError("normalized Quadlet execution is malformed")
    if (
        type(execution["ignore_errors"]) is not bool
        or type(execution["pid"]) is not int
        or execution
        != {
            "executable": "/usr/bin/podman",
            "argv": expected_argv(unit_name),
            "ignore_errors": False,
            "start_time": None,
            "stop_time": None,
            "pid": 0,
            "code": None,
            "status": "0/0",
        }
    ):
        raise AuthorityError("normalized Quadlet execution disagrees")


def canonical_bytes(evidence: object) -> bytes:
    validate_authority_evidence(evidence)
    return (json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n").encode()


def write_evidence(path: Path, evidence: object) -> None:
    payload = canonical_bytes(evidence)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".quadlet-authority.", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "wb") as temporary:
            temporary.write(payload)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.chmod(temporary_name, 0o600)
        os.replace(temporary_name, path)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("properties", type=Path)
    parser.add_argument("--expected-fragment", required=True)
    parser.add_argument("--expected-source", required=True)
    parser.add_argument("--output", required=True, type=Path)
    options = parser.parse_args()
    try:
        properties = options.properties.read_text(encoding="utf-8")
        evidence = admit_quadlet_authority(
            properties, options.expected_fragment, options.expected_source
        )
        write_evidence(options.output, evidence)
    except (OSError, UnicodeError, AuthorityError) as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
