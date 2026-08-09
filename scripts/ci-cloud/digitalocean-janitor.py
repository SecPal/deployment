#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Delete only expired DigitalOcean droplets with complete SecPal CI ownership."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Protocol


API_ROOT = "https://api.digitalocean.com"
MAX_TTL_SECONDS = 10_800
RUN_SUFFIX = r"(?P<run_id>[1-9][0-9]{0,19})-(?P<run_attempt>[1-9][0-9]{0,2})"
OWNER = re.compile(rf"^spci-owner-{RUN_SUFFIX}$")
REPOSITORY = re.compile(rf"^spci-repo-secpal-deployment-{RUN_SUFFIX}$")
SHA = re.compile(rf"^spci-sha-(?P<target_sha>[0-9a-f]{{40}})-{RUN_SUFFIX}$")
CREATED = re.compile(rf"^spci-created-(?P<created>[1-9][0-9]{{9}})-{RUN_SUFFIX}$")
EXPIRES = re.compile(rf"^spci-expires-(?P<expires>[1-9][0-9]{{9}})-{RUN_SUFFIX}$")


@dataclass(frozen=True)
class Candidate:
    resource_id: int
    run_id: str
    run_attempt: str
    target_sha: str
    created: int
    expires: int


class Client(Protocol):
    def list_droplets(self) -> list[dict[str, object]]: ...

    def get_droplet(self, resource_id: int) -> dict[str, object]: ...

    def delete(self, path: str) -> None: ...


class DigitalOceanClient:
    def __init__(self, token: str) -> None:
        if not token:
            raise ValueError("DigitalOcean token is required")
        self._token = token

    def request(self, path: str, method: str = "GET") -> dict[str, object]:
        request = urllib.request.Request(
            f"{API_ROOT}{path}",
            method=method,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self._token}",
                "User-Agent": "SecPal-CI-TTL-Janitor/1",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = response.read(1_048_577)
        except urllib.error.HTTPError as error:
            raise RuntimeError(f"DigitalOcean API returned HTTP {error.code}") from None
        if method == "DELETE":
            return {}
        if len(payload) > 1_048_576:
            raise RuntimeError("DigitalOcean API response exceeded the safety bound")
        document = json.loads(payload)
        if not isinstance(document, dict):
            raise RuntimeError("DigitalOcean API response was not an object")
        return document

    def list_droplets(self) -> list[dict[str, object]]:
        droplets: list[dict[str, object]] = []
        path = "/v2/droplets?per_page=200&page=1"
        for _ in range(20):
            document = self.request(path)
            page = document.get("droplets")
            if not isinstance(page, list) or not all(isinstance(item, dict) for item in page):
                raise RuntimeError("DigitalOcean droplet list was malformed")
            droplets.extend(page)
            links = document.get("links", {})
            pages = links.get("pages", {}) if isinstance(links, dict) else {}
            next_url = pages.get("next") if isinstance(pages, dict) else None
            if next_url is None:
                return droplets
            if not isinstance(next_url, str) or not next_url.startswith(f"{API_ROOT}/v2/droplets?"):
                raise RuntimeError("DigitalOcean pagination escaped the droplet endpoint")
            path = next_url.removeprefix(API_ROOT)
        raise RuntimeError("DigitalOcean droplet pagination exceeded 20 pages")

    def get_droplet(self, resource_id: int) -> dict[str, object]:
        document = self.request(f"/v2/droplets/{resource_id}")
        droplet = document.get("droplet")
        if not isinstance(droplet, dict):
            raise RuntimeError("DigitalOcean droplet response was malformed")
        return droplet

    def delete(self, path: str) -> None:
        self.request(path, method="DELETE")


def _one_match(tags: list[str], pattern: re.Pattern[str]) -> re.Match[str] | None:
    matches = [match for tag in tags if (match := pattern.fullmatch(tag)) is not None]
    return matches[0] if len(matches) == 1 else None


def parse_candidate(droplet: dict[str, object], now: int) -> Candidate | None:
    resource_id = droplet.get("id")
    name = droplet.get("name")
    raw_tags = droplet.get("tags")
    if not isinstance(resource_id, int) or resource_id <= 0:
        return None
    if not isinstance(name, str) or not isinstance(raw_tags, list):
        return None
    if len(raw_tags) != 5 or not all(isinstance(tag, str) for tag in raw_tags):
        return None
    tags = list(raw_tags)
    matches = [_one_match(tags, pattern) for pattern in (OWNER, REPOSITORY, SHA, CREATED, EXPIRES)]
    if any(match is None for match in matches):
        return None
    owner, repository, sha, created, expires = matches
    assert owner is not None and repository is not None and sha is not None
    assert created is not None and expires is not None
    suffixes = {(match["run_id"], match["run_attempt"]) for match in matches if match is not None}
    if len(suffixes) != 1:
        return None
    run_id, run_attempt = suffixes.pop()
    created_epoch = int(created["created"])
    expires_epoch = int(expires["expires"])
    if name != f"spci-{run_id}-{run_attempt}":
        return None
    if expires_epoch <= created_epoch or expires_epoch - created_epoch > MAX_TTL_SECONDS:
        return None
    if expires_epoch > now or created_epoch > now:
        return None
    return Candidate(
        resource_id=resource_id,
        run_id=run_id,
        run_attempt=run_attempt,
        target_sha=sha["target_sha"],
        created=created_epoch,
        expires=expires_epoch,
    )


def cleanup_expired(client: Client, now: int, apply: bool) -> list[int]:
    candidates = [
        candidate
        for droplet in client.list_droplets()
        if (candidate := parse_candidate(droplet, now)) is not None
    ]
    deleted: list[int] = []
    for candidate in candidates:
        current = parse_candidate(client.get_droplet(candidate.resource_id), now)
        if current != candidate:
            continue
        print(
            f"expired owned droplet id={candidate.resource_id} "
            f"run={candidate.run_id} attempt={candidate.run_attempt}"
        )
        deleted.append(candidate.resource_id)
        if apply:
            client.delete(f"/v2/droplets/{candidate.resource_id}")
    return deleted


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--now", type=int, required=True)
    arguments = parser.parse_args()
    token = os.environ.get("DIGITALOCEAN_TOKEN", "")
    if arguments.now <= 0:
        parser.error("--now must be a positive Unix timestamp")
    try:
        deleted = cleanup_expired(
            DigitalOceanClient(token), now=arguments.now, apply=arguments.apply
        )
    except (RuntimeError, ValueError, json.JSONDecodeError) as error:
        print(f"ERROR: TTL janitor failed closed: {error}", file=sys.stderr)
        return 1
    mode = "deleted" if arguments.apply else "would delete"
    print(f"DigitalOcean TTL janitor {mode} {len(deleted)} owned expired droplet(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
