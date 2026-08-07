#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Validate external GitHub Actions references from parsed YAML mappings."""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode


PINNED_REFERENCE = re.compile(r"[^@#\s]+@[0-9a-f]{40}\Z")
SOURCE_COMMENT = re.compile(r"[ \t]+#[ \t]*[^#\s]+(?:[ \t]+.*)?\Z")


def report(path: Path, line: int, message: str) -> None:
    print(f"FAIL: {path}:{line} {message}", file=sys.stderr)


def uses_entries(node: Node, visited: set[int]) -> list[tuple[ScalarNode, Node]]:
    identity = id(node)
    if identity in visited:
        return []
    visited.add(identity)

    entries: list[tuple[ScalarNode, Node]] = []
    if isinstance(node, MappingNode):
        for key, value in node.value:
            if isinstance(key, ScalarNode) and key.value == "uses":
                entries.append((key, value))
            entries.extend(uses_entries(key, visited))
            entries.extend(uses_entries(value, visited))
    elif isinstance(node, SequenceNode):
        for value in node.value:
            entries.extend(uses_entries(value, visited))
    return entries


def has_source_comment(lines: list[str], key: ScalarNode, value: ScalarNode) -> bool:
    if value.start_mark.index < key.end_mark.index:
        return False
    if value.start_mark.line != value.end_mark.line:
        return False
    if value.end_mark.line >= len(lines):
        return False

    remainder = lines[value.end_mark.line][value.end_mark.column :]
    return SOURCE_COMMENT.fullmatch(remainder) is not None


def validate_entry(path: Path, lines: list[str], key: ScalarNode, value: Node) -> int:
    line = key.start_mark.line + 1
    if not isinstance(value, ScalarNode):
        report(path, line, "external uses reference must be a scalar")
        return 1

    reference = value.value
    if reference.startswith("./"):
        return 0

    if PINNED_REFERENCE.fullmatch(reference) is None:
        report(path, line, "external uses reference must end with a full lowercase commit SHA")
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
        roots = list(yaml.compose_all(document, Loader=yaml.SafeLoader))
    except (OSError, UnicodeError) as error:
        report(path, 0, f"unable to read workflow: {error}")
        return 1
    except yaml.YAMLError as error:
        mark = getattr(error, "problem_mark", None)
        line = mark.line + 1 if mark is not None else 0
        report(path, line, f"invalid YAML: {getattr(error, 'problem', error)}")
        return 1

    lines = document.splitlines()
    failures = 0
    for root in roots:
        if root is None:
            continue
        for key, value in uses_entries(root, set()):
            failures += validate_entry(path, lines, key, value)
    return failures


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
