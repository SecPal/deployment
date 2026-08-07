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
from yaml.composer import ComposerError
from yaml.events import AliasEvent
from yaml.nodes import MappingNode, ScalarNode


DOCKER_SCHEME = "docker://"
PINNED_GIT_REFERENCE = re.compile(r"[^@#\s]+@[0-9a-f]{40}\Z")
PINNED_DOCKER_REFERENCE = re.compile(
    r"docker://[^@#\s]+@sha256:[0-9a-f]{64}\Z"
)
PINNED_IMAGE_REFERENCE = re.compile(r"[^@#\s]+@sha256:[0-9a-f]{64}\Z")
DOCKER_STAGE_NAME = re.compile(r"[A-Za-z0-9_.-]+\Z")
SOURCE_COMMENT = re.compile(
    r"[ \t,}\]]*[ \t]+#[ \t]*[^#\s]+(?:[ \t]+.*)?\Z"
)
BLOCK_SOURCE_COMMENT = re.compile(
    r"(?:(?:![^ \t]+|&[^ \t]+)[ \t]+)*"
    r"[>|][0-9+-]*[ \t]+#[ \t]*[^#\s]+(?:[ \t]+.*)?\Z"
)
USE_PATHS = (
    ("jobs", "*", "uses"),
    ("jobs", "*", "steps", "*", "uses"),
    ("runs", "steps", "*", "uses"),
)
WORKFLOW_CONTAINER_PATHS = (("jobs", "*", "container"),)
WORKFLOW_IMAGE_PATHS = (
    ("jobs", "*", "container", "image"),
    ("jobs", "*", "services", "*", "image"),
)
ACTION_IMAGE_PATHS = (("runs", "image"),)


def alias_scalar(
    node: ScalarNode, start_mark: Any, end_mark: Any, *, keep_original: bool = False
) -> ScalarNode:
    """Copy a scalar to an alias occurrence, optionally retaining its anchor."""

    relocated = ScalarNode(node.tag, node.value, start_mark, end_mark, None)
    if keep_original:
        relocated.original_node = node
    return relocated


def alias_mapping(
    node: MappingNode, start_mark: Any, end_mark: Any
) -> MappingNode:
    """Relocate only direct scalar entries of an aliased mapping."""

    entries = []
    for key_node, value_node in node.value:
        key = (
            alias_scalar(key_node, start_mark, start_mark, keep_original=True)
            if isinstance(key_node, ScalarNode)
            else key_node
        )
        value = (
            alias_scalar(value_node, start_mark, end_mark, keep_original=True)
            if isinstance(value_node, ScalarNode)
            else value_node
        )
        entries.append((key, value))
    return MappingNode(node.tag, entries, start_mark, end_mark, node.flow_style)


class LocatedString(str):
    """A safely constructed YAML string with its original source location."""

    node: ScalarNode
    original_node: ScalarNode | None

    def __new__(cls, value: str, node: ScalarNode) -> LocatedString:
        instance = super().__new__(cls, value)
        instance.node = node
        instance.original_node = getattr(node, "original_node", None)
        return instance


class WorkflowLoader(yaml.SafeLoader):
    """Safe YAML loader that retains locations for string keys and values."""

    def compose_node(self, parent: Any, index: Any) -> Any:
        # Preserve the alias occurrence so its own same-line comment is checked.
        if self.check_event(AliasEvent):
            event = self.get_event()
            if event.anchor not in self.anchors:
                raise ComposerError(
                    None,
                    None,
                    f"found undefined alias {event.anchor!r}",
                    event.start_mark,
                )
            node = self.anchors[event.anchor]
            if isinstance(node, ScalarNode):
                return alias_scalar(node, event.start_mark, event.end_mark)
            if isinstance(node, MappingNode):
                # Direct values may be annotated either where the mapping is
                # anchored or where it is used. Nested values keep their own
                # locations so one alias comment cannot cover multiple steps.
                return alias_mapping(node, event.start_mark, event.end_mark)
            return node
        return super().compose_node(parent, index)


def construct_located_string(
    loader: WorkflowLoader, node: ScalarNode
) -> LocatedString:
    return LocatedString(loader.construct_scalar(node), node)


WorkflowLoader.add_constructor(
    "tag:yaml.org,2002:str", construct_located_string
)


def report(path: Path, line: int, message: str) -> None:
    print(f"FAIL: {path}:{line} {message}", file=sys.stderr)


def normalize_docker_scheme(reference: str) -> str | None:
    """Return a runner-equivalent lowercase Docker scheme when present."""

    scheme = reference[: len(DOCKER_SCHEME)]
    if scheme.lower() != DOCKER_SCHEME:
        return None
    return DOCKER_SCHEME + reference[len(DOCKER_SCHEME) :]


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


def entries_at_paths(
    root: Any, paths: tuple[tuple[str, ...], ...]
) -> Iterator[tuple[LocatedString, Any]]:
    for path in paths:
        yield from entries_at(root, path)


def nodes_have_source_comment(
    lines: list[str], key_node: ScalarNode, value_node: ScalarNode
) -> bool:
    key_mark = key_node.end_mark
    start_mark = value_node.start_mark
    end_mark = value_node.end_mark
    if start_mark.index < key_mark.index:
        return False
    if start_mark.line >= len(lines):
        return False
    if value_node.style in {">", "|"}:
        header = lines[start_mark.line][start_mark.column :]
        return BLOCK_SOURCE_COMMENT.fullmatch(header) is not None
    if end_mark.line >= len(lines):
        return False

    remainder = lines[end_mark.line][end_mark.column :]
    return SOURCE_COMMENT.fullmatch(remainder) is not None


def has_source_comment(
    lines: list[str], key: LocatedString, value: LocatedString
) -> bool:
    if nodes_have_source_comment(lines, key.node, value.node):
        return True
    if key.original_node is None or value.original_node is None:
        return False
    return nodes_have_source_comment(lines, key.original_node, value.original_node)


def validate_entry(
    path: Path, lines: list[str], key: LocatedString, value: Any
) -> int:
    line = key.node.start_mark.line + 1
    if not isinstance(value, LocatedString):
        report(path, line, "external uses reference must be a scalar string")
        return 1

    reference = str(value)
    if reference.startswith("./"):
        return validate_local_action(path, key, reference)

    docker_reference = normalize_docker_scheme(reference)
    if docker_reference is None:
        pinned = PINNED_GIT_REFERENCE.fullmatch(reference) is not None
    else:
        pinned = PINNED_DOCKER_REFERENCE.fullmatch(docker_reference) is not None
    if not pinned:
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


def validate_workflow_image(path: Path, key: LocatedString, value: Any) -> int:
    line = key.node.start_mark.line + 1
    if not isinstance(value, LocatedString):
        report(path, line, "workflow container image must be a scalar string")
        return 1

    reference = str(value)
    if PINNED_IMAGE_REFERENCE.fullmatch(reference) is None:
        report(path, line, "workflow container image must use a full sha256 digest")
        return 1
    return 0


def validate_job_container(path: Path, key: LocatedString, value: Any) -> int:
    if isinstance(value, dict):
        return 0
    return validate_workflow_image(path, key, value)


def repository_boundary(path: Path) -> Path:
    """Return the containing Git worktree, or the manifest directory."""

    resolved = path.resolve()
    for parent in resolved.parents:
        if (parent / ".git").exists():
            return parent
    return resolved.parent


def is_dockerfile_reference(reference: str) -> bool:
    """Match the Dockerfile names recognized by the GitHub Actions runner."""

    name = reference.rsplit("/", maxsplit=1)[-1].lower()
    return name.startswith("dockerfile.") or name.endswith("dockerfile")


def dockerfile_path(action_path: Path, reference: str) -> Path | None:
    """Resolve a repository-local Dockerfile referenced by action metadata."""

    relative = Path(reference)
    if relative.is_absolute() or not is_dockerfile_reference(reference):
        return None
    try:
        candidate = (action_path.parent / relative).resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    if not candidate.is_file() or not candidate.is_relative_to(
        repository_boundary(action_path)
    ):
        return None
    return candidate


def validate_action_dockerfile(
    action_path: Path, key: LocatedString, reference: str
) -> int:
    """Resolve and validate a Dockerfile referenced by action metadata."""

    dockerfile = dockerfile_path(action_path, reference)
    line = key.node.start_mark.line + 1
    if dockerfile is None:
        report(
            action_path,
            line,
            "Docker action image must reference a repository-local Dockerfile",
        )
        return 1
    return validate_dockerfile(dockerfile)


def validate_dockerfile(dockerfile: Path) -> int:
    """Require every external Dockerfile base to use an exact digest."""

    try:
        with dockerfile.open(encoding="utf-8-sig", newline=None) as stream:
            lines = stream.read().splitlines()
    except (OSError, UnicodeError) as error:
        report(dockerfile, 0, f"unable to read Docker action Dockerfile: {error}")
        return 1

    failures = 0
    stages: set[str] = set()
    from_count = 0
    for line_number, source_line in enumerate(lines, start=1):
        fields = source_line.split()
        if not fields or fields[0].lower() != "from":
            continue
        from_count += 1
        index = 1
        while index < len(fields) and fields[index].startswith("--"):
            if not fields[index].lower().startswith("--platform="):
                report(dockerfile, line_number, "unsupported Dockerfile FROM option")
                failures += 1
            index += 1
        if index >= len(fields):
            report(dockerfile, line_number, "Dockerfile FROM image is missing")
            failures += 1
            continue

        image = fields[index]
        trailing = fields[index + 1 :]
        stage_name = None
        if trailing:
            if (
                len(trailing) != 2
                or trailing[0].lower() != "as"
                or DOCKER_STAGE_NAME.fullmatch(trailing[1]) is None
            ):
                report(
                    dockerfile,
                    line_number,
                    "Dockerfile FROM syntax is not statically verifiable",
                )
                failures += 1
            else:
                stage_name = trailing[1].lower()

        if (
            image != "scratch"
            and image.lower() not in stages
            and PINNED_IMAGE_REFERENCE.fullmatch(image) is None
        ):
            report(
                dockerfile,
                line_number,
                "external Dockerfile base image must use a full sha256 digest",
            )
            failures += 1
        if stage_name is not None:
            stages.add(stage_name)

    if from_count == 0:
        report(dockerfile, 0, "Docker action Dockerfile must contain a FROM instruction")
        return failures + 1
    return failures


def validate_local_action(
    source_path: Path, key: LocatedString, reference: str
) -> int:
    """Validate a referenced local action that consists only of a Dockerfile."""

    boundary = repository_boundary(source_path)
    try:
        action_directory = (boundary / reference).resolve(strict=True)
    except (OSError, RuntimeError):
        return 0
    if not action_directory.is_relative_to(boundary):
        report(
            source_path,
            key.node.start_mark.line + 1,
            "local action reference must remain inside the repository",
        )
        return 1
    if not action_directory.is_dir() or any(
        (action_directory / name).is_file() for name in ("action.yml", "action.yaml")
    ):
        return 0
    for name in ("Dockerfile", "dockerfile"):
        dockerfile = action_directory / name
        if dockerfile.is_file():
            try:
                resolved_dockerfile = dockerfile.resolve(strict=True)
            except (OSError, RuntimeError):
                continue
            if not resolved_dockerfile.is_relative_to(boundary):
                report(
                    source_path,
                    key.node.start_mark.line + 1,
                    "local action Dockerfile must remain inside the repository",
                )
                return 1
            return validate_dockerfile(resolved_dockerfile)
    return 0


def validate_action_image(path: Path, key: LocatedString, value: Any) -> int:
    line = key.node.start_mark.line + 1
    if not isinstance(value, LocatedString):
        report(path, line, "Docker action image must be a scalar string")
        return 1

    reference = str(value)
    docker_reference = normalize_docker_scheme(reference)
    if docker_reference is None:
        return validate_action_dockerfile(path, key, reference)
    if PINNED_DOCKER_REFERENCE.fullmatch(docker_reference) is None:
        report(path, line, "external Docker action image must use a full sha256 digest")
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
    uses_failures = sum(
        validate_entry(path, lines, key, value)
        for root in roots
        for key, value in entries_at_paths(root, USE_PATHS)
    )
    image_failures = sum(
        validate_job_container(path, key, value)
        for root in roots
        for key, value in entries_at_paths(root, WORKFLOW_CONTAINER_PATHS)
    )
    image_failures += sum(
        validate_workflow_image(path, key, value)
        for root in roots
        for key, value in entries_at_paths(root, WORKFLOW_IMAGE_PATHS)
    )
    image_failures += sum(
        validate_action_image(path, key, value)
        for root in roots
        for key, value in entries_at_paths(root, ACTION_IMAGE_PATHS)
    )
    return uses_failures + image_failures


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
