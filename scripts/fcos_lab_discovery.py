#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Report candidates from the maintained FCOS lab publishers."""

import json
from pathlib import Path
import re
import subprocess
import sys

from fcos_lab_rollout_adapter import Backend, RUNTIME_SOURCE
from integration_runtime_contract import LAB_FRONTEND_SOURCE_COMMIT


def greatest_version(tags, pattern):
    versions = []
    for tag in tags:
        match = re.fullmatch(pattern, tag)
        if match:
            versions.append((tuple(map(int, match.groups())), tag))
    if not versions:
        raise ValueError("no candidate in the supported version track")
    return max(versions)[1]


def official_tag(catalog, pattern):
    tags = (
        tag.strip()
        for line in catalog.splitlines()
        if line.startswith("Tags: ")
        for tag in line.removeprefix("Tags: ").split(",")
    )
    return greatest_version(tags, pattern)


def stable_release(releases, pattern):
    return greatest_version(
        (release["tag_name"] for release in releases
         if release["draft"] is False and release["prerelease"] is False),
        pattern,
    )


REGISTRY_EVENTS = {"SecPal/api": "workflow_dispatch", "SecPal/frontend": "push"}


def registry_publications(repo):
    return (
        f"repos/{repo}/actions/workflows/publish-container.yml/runs"
        f"?branch=main&status=success&per_page=1&event={REGISTRY_EVENTS[repo]}"
    )


def product_candidate(document, repo):
    run, = document["workflow_runs"]
    commit = run["head_sha"]
    run_id, attempt = run["id"], run["run_attempt"]
    if (
        run["head_branch"] != "main"
        or run["event"] != REGISTRY_EVENTS[repo]
        or run["conclusion"] != "success"
        or run["head_repository"]["full_name"].lower() != repo.lower()
        or re.fullmatch(r"[0-9a-f]{40}", commit) is None
        or type(run_id) is not int
        or run_id <= 0
        or type(attempt) is not int
        or attempt <= 0
    ):
        raise ValueError("invalid product publish result")
    return {"source_commit": commit, "run_id": run_id, "run_attempt": attempt}


def source_relationship(document):
    status = document["status"]
    if status not in {"identical", "ahead", "behind", "diverged"}:
        raise ValueError("invalid GitHub source comparison")
    return status


def get(endpoint, *, raw=False, paginate=False, gh="gh"):
    args = [gh, "api", "--method", "GET", endpoint]
    if raw:
        args += ["--header", "Accept: application/vnd.github.raw+json"]
    if paginate:
        args += ["--paginate", "--slurp"]
    output = subprocess.run(
        args, capture_output=True, stdin=subprocess.DEVNULL,
        check=True, timeout=45, text=True,
    ).stdout
    if raw:
        return output
    data = json.loads(output)
    return [item for page in data for item in page] if paginate else data


def discover():
    result = {}
    contract = Path(__file__).with_name(Path(RUNTIME_SOURCE).name)
    products = {"api": Backend.from_source(contract.read_text(encoding="utf-8")).source,
                "frontend": LAB_FRONTEND_SOURCE_COMMIT}
    for name, commit in products.items():
        repo = f"SecPal/{name}"
        publication = product_candidate(get(registry_publications(repo)), repo)
        relationship = get(f"repos/{repo}/compare/{commit}...{publication['source_commit']}")
        result[name] = {**publication, "source_relationship": source_relationship(relationship)}

    for image, pattern in {
        "postgres": r"(18)\.([0-9]+)-bookworm",
        "haproxy": r"(3)\.(2)\.([0-9]+)-trixie",
    }.items():
        catalog = get(f"repos/docker-library/official-images/contents/library/{image}", raw=True)
        result[image] = official_tag(catalog, pattern)

    for name, (repo, pattern) in {
        "crowdsec": ("crowdsecurity/crowdsec", r"v(1)\.([0-9]+)\.([0-9]+)"),
        "spoa": ("crowdsecurity/cs-haproxy-spoa-bouncer", r"v(0)\.([0-9]+)\.([0-9]+)"),
        "crs": ("coreruleset/coreruleset", r"v(4)\.([0-9]+)\.([0-9]+)"),
    }.items():
        result[name] = stable_release(get(f"repos/{repo}/releases?per_page=100"), pattern)
    return result


def main():
    try:
        print(json.dumps(discover(), indent=2, sort_keys=True))
    except (KeyError, OSError, TypeError, ValueError, subprocess.SubprocessError):
        print("FCOS release discovery failed to admit a complete upstream report", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
