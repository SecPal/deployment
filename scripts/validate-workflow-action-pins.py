#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Validate external GitHub Actions references from parsed YAML mappings."""

from __future__ import annotations

import re
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import yaml
from yaml.nodes import ScalarNode


PINNED_GIT_REFERENCE = re.compile(r"[^@#\s]+@[0-9a-f]{40}\Z")
PINNED_DOCKER_REFERENCE = re.compile(
    r"docker://[^@#\s]+@sha256:[0-9a-f]{64}\Z"
)
SOURCE_COMMENT = re.compile(r"[ \t]+#[ \t]*[^#\s]+(?:[ \t]+.*)?\Z")
WORKFLOW_USE_PATHS = (
    ("jobs", "*", "uses"),
    ("jobs", "*", "steps", "*", "uses"),
)
ACTION_USE_PATHS = (("runs", "steps", "*", "uses"),)


class LocatedString(str):
    """A safely constructed YAML string with its original source location."""

    node: ScalarNode

    def __new__(cls, value: str, node: ScalarNode) -> LocatedString:
        instance = super().__new__(cls, value)
        instance.node = node
        return instance


class WorkflowLoader(yaml.SafeLoader):
    """Safe YAML loader that retains locations for string keys and values."""


def construct_located_string(
    loader: WorkflowLoader, node: ScalarNode
) -> LocatedString:
    return LocatedString(loader.construct_scalar(node), node)


WorkflowLoader.add_constructor(
    "tag:yaml.org,2002:str", construct_located_string
)


def report(path: Path, line: int, message: str) -> None:
    print(f"FAIL: {path}:{line} {message}", file=sys.stderr)


def mapping_entry(mapping: Any, name: str) -> tuple[LocatedString, Any] | None:
    if not isinstance(mapping, dict):
        return None
    for key, value in mapping.items():
        if isinstance(key, LocatedString) and key == name:
            return key, value
    return None


def entries_at(
    value: Any, path: tuple[str, ...]
) -> Iterator[tuple[LocatedString, Any]]:
    name, *remaining = path
    if name == "*":
        if isinstance(value, dict):
            children = value.values()
        elif isinstance(value, list):
            children = value
        else:
            return
        for child in children:
            yield from entries_at(child, tuple(remaining))
        return

    entry = mapping_entry(value, name)
    if entry is None:
        return
    if remaining:
        yield from entries_at(entry[1], tuple(remaining))
    else:
        yield entry


def uses_entries(
    root: Any, paths: tuple[tuple[str, ...], ...]
) -> Iterator[tuple[LocatedString, Any]]:
    for path in paths:
        yield from entries_at(root, path)


def is_action_manifest(path: Path) -> bool:
    workflow_directory = (".github", "workflows")
    path_pairs = zip(path.parts, path.parts[1:])
    return (
        path.name in {"action.yml", "action.yaml"}
        and workflow_directory not in path_pairs
    )


def has_source_comment(
    lines: list[str], key: LocatedString, value: LocatedString
) -> bool:
    key_mark = key.node.end_mark
    start_mark = value.node.start_mark
    end_mark = value.node.end_mark
    if start_mark.index < key_mark.index or start_mark.line != end_mark.line:
        return False
    if end_mark.line >= len(lines):
        return False

    remainder = lines[end_mark.line][end_mark.column :]
    return SOURCE_COMMENT.fullmatch(remainder) is not None


def validate_entry(
    path: Path, lines: list[str], key: LocatedString, value: Any
) -> int:
    line = key.node.start_mark.line + 1
    if not isinstance(value, LocatedString):
        report(path, line, "external uses reference must be a scalar string")
        return 1

    reference = str(value)
    if reference.startswith("./"):
        return 0

    pattern = (
        PINNED_DOCKER_REFERENCE
        if reference.startswith("docker://")
        else PINNED_GIT_REFERENCE
    )
    if pattern.fullmatch(reference) is None:
        report(
            path,
            line,
            "external uses reference must end with a full lowercase commit SHA "
            "or Docker sha256 digest",
        )
        return 1

    if not has_source_comment(lines, key, value):
        report(path, line, "external uses reference must include a source tag or branch comment")
        return 1

    return 0


def validate(path: Path) -> int:
    if not path.is_file():
        report(path, 0, "workflow is missing or not a regular file")
        return 1

    try:
        with path.open(encoding="utf-8-sig", newline=None) as stream:
            document = stream.read()
        roots = list(yaml.load_all(document, Loader=WorkflowLoader))
    except (OSError, UnicodeError) as error:
        report(path, 0, f"unable to read workflow: {error}")
        return 1
    except yaml.YAMLError as error:
        mark = getattr(error, "problem_mark", None)
        line = mark.line + 1 if mark is not None else 0
        report(path, line, f"invalid YAML: {getattr(error, 'problem', error)}")
        return 1

    lines = document.splitlines()
    paths = ACTION_USE_PATHS if is_action_manifest(path) else WORKFLOW_USE_PATHS
    return sum(
        validate_entry(path, lines, key, value)
        for root in roots
        for key, value in uses_entries(root, paths)
    )


def main(arguments: list[str]) -> int:
    if not arguments:
        print("ERROR: expected at least one workflow path.", file=sys.stderr)
        return 1

    failures = sum(validate(Path(argument)) for argument in arguments)
    if failures:
        print(
            f"Workflow action pin validation failed with {failures} issue(s).",
            file=sys.stderr,
        )
        return 1

    print("Workflow action pin validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
