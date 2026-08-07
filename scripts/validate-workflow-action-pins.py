#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Validate external ``uses:`` references in GitHub workflow YAML."""

from __future__ import annotations

import re
import sys
from collections.abc import Iterator
from pathlib import Path

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode


PINNED_GIT_REFERENCE = re.compile(r"[^@#\s]+@[0-9a-f]{40}\Z")
PINNED_DOCKER_REFERENCE = re.compile(
    r"docker://[^@#\s]+@sha256:[0-9a-f]{64}\Z"
)
SOURCE_COMMENT = re.compile(
    r"[ \t]+#[ \t]*[^#\s]+(?:[ \t]+[^#\r\n]*)?\Z"
)
USE_PATHS = (
    ("jobs", "*", "uses"),
    ("jobs", "*", "steps", "*", "uses"),
)


def mapping_entries(node: Node, name: str) -> Iterator[tuple[ScalarNode, Node]]:
    if not isinstance(node, MappingNode):
        return
    for key, value in node.value:
        if isinstance(key, ScalarNode) and key.value == name:
            yield key, value


def entries_at(node: Node, path: tuple[str, ...]) -> Iterator[tuple[ScalarNode, Node]]:
    name, *remaining = path
    if name == "*":
        if isinstance(node, MappingNode):
            children = (value for _, value in node.value)
        elif isinstance(node, SequenceNode):
            children = iter(node.value)
        else:
            return
        for child in children:
            yield from entries_at(child, tuple(remaining))
        return

    for key, value in mapping_entries(node, name):
        if remaining:
            yield from entries_at(value, tuple(remaining))
        else:
            yield key, value


def has_source_comment(lines: list[str], value: ScalarNode) -> bool:
    end = value.end_mark
    if value.start_mark.line != end.line:
        return False
    if end.line >= len(lines):
        return False
    return SOURCE_COMMENT.fullmatch(lines[end.line][end.column :]) is not None


def is_pinned(reference: str) -> bool:
    scheme = reference[: len("docker://")]
    if scheme.lower() == "docker://":
        normalized = "docker://" + reference[len("docker://") :]
        return PINNED_DOCKER_REFERENCE.fullmatch(normalized) is not None
    return PINNED_GIT_REFERENCE.fullmatch(reference) is not None


def validate_entry(
    path: Path, lines: list[str], key: ScalarNode, value: Node
) -> int:
    line = key.start_mark.line + 1
    if not isinstance(value, ScalarNode):
        print(f"FAIL: {path}:{line} uses reference must be a scalar", file=sys.stderr)
        return 1

    reference = value.value
    if reference.startswith("./"):
        return 0
    if not is_pinned(reference):
        print(
            f"FAIL: {path}:{line} external uses reference must use a full "
            "lowercase commit SHA or Docker sha256 digest",
            file=sys.stderr,
        )
        return 1
    if not has_source_comment(lines, value):
        print(
            f"FAIL: {path}:{line} external uses reference must include a "
            "same-line source tag or branch comment",
            file=sys.stderr,
        )
        return 1
    return 0


def validate(path: Path) -> int:
    try:
        document = path.read_text(encoding="utf-8-sig")
        roots = list(yaml.compose_all(document, Loader=yaml.BaseLoader))
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        print(f"FAIL: {path}: unable to parse workflow: {error}", file=sys.stderr)
        return 1

    lines = document.splitlines()
    return sum(
        validate_entry(path, lines, key, value)
        for root in roots
        if root is not None
        for use_path in USE_PATHS
        for key, value in entries_at(root, use_path)
    )


def main(arguments: list[str]) -> int:
    if not arguments:
        print("ERROR: expected at least one workflow path", file=sys.stderr)
        return 1
    failures = sum(validate(Path(argument)) for argument in arguments)
    if failures:
        print(f"Workflow action pin validation failed ({failures})", file=sys.stderr)
        return 1
    print("Workflow action pin validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
