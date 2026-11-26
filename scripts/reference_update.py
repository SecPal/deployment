#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Run the existing public reference update transactions from protected evidence."""

from contextlib import ExitStack, contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
from urllib.request import ProxyHandler, Request, build_opener
from zipfile import BadZipFile

sys.path.insert(0, str(Path(__file__).resolve().parent))

import fcos_lab_rollout_adapter as publisher
from fcos_lab_rollout import RolloutError, fetch_release, git, source_release
from reference_runtime import (
    NATIVE, STATE, UNITS, Container, NoRedirect, apply, as_user, exposure, migration_login_disabled,
    observe, postgres_facts, protected, public_accept, run, run_migration,
)

ROOT = Path(__file__).resolve().parent
CONFIG = Path("/etc/secpal/reference-update.json")
LOCK = Path("/run/lock/secpal-reference-frontend.lock")
OCI_STAGING = Path("/run/secpal-reference-oci")
GH = ROOT / "gh"
COMPATIBILITY = "config/quadlet/fcos-lab-rollout/backend-compatibility.json"
SHA = r"[a-f0-9]{40}"
STAGES = ("observation", "publisher", "comparison", "activation")
ERRORS = (BadZipFile, KeyError, OSError, RolloutError, TypeError, ValueError, subprocess.SubprocessError)


@dataclass(frozen=True)
class Pin:
    source: str
    identity: str


def planned_change(installed, selected):
    if installed == selected:
        return None
    if installed.source == selected.source or installed.identity == selected.identity:
        raise ValueError("reference has inconsistent source and OCI identities")
    return selected


def pin(value):
    return Pin(value.source, value.index if isinstance(value, publisher.Frontend) else value.pair)


def forge(_gh, endpoint):
    if not re.fullmatch(r"repos/SecPal/(deployment|frontend|api)/[a-zA-Z0-9._/?&=-]+", endpoint):
        raise ValueError("unexpected reference forge route")
    request = Request("https://api.github.com/" + endpoint,
                      headers={"Accept": "application/vnd.github+json", "User-Agent": "SecPal-reference-update"})
    with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=25) as response:
        data = response.read(2 * 1024 * 1024 + 1)
    if len(data) > 2 * 1024 * 1024:
        raise ValueError("unexpected reference forge response size")
    return json.loads(data)


def protected_head(product):
    record = forge(GH, f"repos/SecPal/{product}/branches/main")
    commit = record["commit"]
    if (record["name"] != "main" or record["protected"] is not True or
            commit["commit"]["verification"]["verified"] is not True or not re.fullmatch(SHA, commit["sha"])):
        raise ValueError("invalid protected source head")
    return commit["sha"]


def publisher_zip(gh, product, artifact, output, limit):
    # Only the fixed read of the independently identified ZIP uses existing auth.
    # No developer-owned executable, metadata or credential enters the root process.
    if product not in {"api", "frontend"} or type(artifact) is not int or artifact <= 0:
        raise ValueError("invalid publisher artifact identity")
    reader = as_user("artifact", [gh, "api", "--hostname", "github.com", "--method", "GET",
                                  f"repos/SecPal/{product}/actions/artifacts/{artifact}/zip"])
    run(["/usr/bin/prlimit", f"--fsize={limit}:{limit}", "--", *reader], timeout=220, output=output)


def describe(declaration):
    for stage in ("source", *STAGES, "rollback"):
        name = "reference-update." + stage
        declaration["external_operations"].append(
            {"id": name, "reachable": True, "fallible": True, "trusted": True,
             "diagnostic_identity": {"id": name, "kind": "semantic"}})
    return declaration


def root_json(path):
    return json.loads(protected(path))


def record(path, value):
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write((json.dumps(value, sort_keys=True) + "\n").encode())
            stream.flush()
            os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


@contextmanager
def signed_runtime(target, work, *, current):
    if target == "frontend":
        with publisher.verified_frontend_archive(work, gh=GH, current=current) as result:
            _, run_id, attempt, children, _, root = result
            yield children, run_id, attempt, root
    else:
        with publisher.verified_backend_archive(work, gh=GH, current=current) as result:
            _, run_id, attempt, children, pair, _, root = result
            yield children, run_id, publisher.api_native_attempt(pair, NATIVE, attempt), root


def binds(target, active, value, children):
    expected = {role: Container(f"ghcr.io/secpal/{target}@{digest}", value.source, digest)
                for (role, platform), digest in children.items() if platform == NATIVE}
    if active != expected:
        raise ValueError("live reference predecessor differs from signed evidence")
    return expected


def compatible(repo, release, before, after, database):
    raw = git(repo, "show", f"{release.revision}:{COMPATIBILITY}")
    if not 0 < len(raw) <= 16384 or hashlib.sha256(raw).hexdigest() != after.compatibility:
        raise ValueError("invalid protected API compatibility digest")
    data = json.loads(raw)
    version = data["schema_version"]
    if type(version) is not int or version not in (1, 2):
        raise ValueError("unsupported API compatibility record")
    expected = {"previous_pair": before.pair, "candidate_pair": after.pair,
                "schema": database["schema"], "ledger": database["ledger"]}
    extras = {"migration"} if version == 2 else set()
    if (set(data) != set(expected) | {"schema_version", "forward", "rollback"} | extras or
            any(data[key] != value for key, value in expected.items())):
        raise ValueError("public database does not match the qualified API pair")
    proofs = []
    for direction in ("forward", "rollback"):
        entries = data[direction]
        if not isinstance(entries, dict) or set(entries) != set(publisher.HOSTS.values()):
            raise ValueError("native forward and reverse API qualification required")
        proofs.extend(entries.values())
    if len(set(proofs)) != 4 or any(re.fullmatch(publisher.DIGEST, evidence) is None for evidence in proofs):
        raise ValueError("invalid native API qualification identities")
    if version == 1:
        return None
    migration = data["migration"]
    if (not isinstance(migration, dict) or migration.keys() != {"schema", "ledger"}
            or not all(isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value)
                       for value in migration.values())
            or migration["ledger"] == database["ledger"]):
        raise ValueError("invalid qualified post-migration database")
    return migration


def validate_enrollment(config):
    if (set(config) != {"baseline", "exposure", "data_class"} or
            config["data_class"] != "secpal-owned-synthetic" or
            re.fullmatch(SHA, config["baseline"]) is None):
        raise ValueError("reference update requires an enrolled synthetic target")


def lane(repo, latest, target, baseline, posture, progress):
    print(f"reference-update.{target}.observation: check installed reference", flush=True)
    if (STATE / (target + ".blocked")).exists():
        raise ValueError("a prior rollback requires reconciliation")
    parser = publisher.Frontend if target == "frontend" else publisher.Backend
    saved = STATE / (target + ".json")
    previous = root_json(saved) if saved.exists() else {"revision": baseline, "runtime": None}
    accepted = source_release(repo, previous["revision"])
    git(repo, "merge-base", "--is-ancestor", accepted.revision, latest.revision)
    before = parser.from_source(publisher.admit_source_text(repo, accepted))
    desired = parser.from_source(publisher.admit_source_text(repo, latest))
    active = observe(target)
    serialized = {role: asdict(value) for role, value in active.items()}
    if previous["runtime"] is not None and previous["runtime"] != serialized:
        raise ValueError("reference differs from the last accepted transaction")
    expected_posture = {name: posture[name] for name in (*UNITS[target], "edge")}

    def exposure_matches(*, live=True):
        return exposure(target, live=live) == expected_posture

    if not exposure_matches():
        raise ValueError("root-enrolled public exposure differs")
    with ExitStack() as stack:
        old_children = None
        if previous["runtime"] is None:
            progress[0] = "publisher"
            old_children = stack.enter_context(signed_runtime(target, before, current=False))[0]
            binds(target, active, before, old_children)
            record(saved, {"revision": accepted.revision, "runtime": serialized})
        if planned_change(pin(before), pin(desired)) is None:
            print(f"reference-update.{target}: already current ({before.source[:12]})", flush=True)
            return
        progress[0] = "publisher"
        if protected_head(target) != desired.source:
            print(f"reference-update.{target}: protected selection superseded", flush=True)
            return
        relationship = forge(GH, f"repos/SecPal/{target}/compare/{before.source}...{desired.source}")
        if relationship["status"] != "ahead":
            raise ValueError("reference candidate does not advance the accepted source")
        if old_children is None:
            old_children = stack.enter_context(signed_runtime(target, before, current=False))[0]
            binds(target, active, before, old_children)
        children, publisher_run, attempt, native_root = stack.enter_context(signed_runtime(target, desired, current=True))
        # Rootless Podman enters its existing mount namespace during import.
        # Only the verified OCI tar is staged outside the service's private tmp.
        root = Path(stack.enter_context(tempfile.TemporaryDirectory(dir=OCI_STAGING, prefix=f"reference-{target}-")))
        root.chmod(0o711)
        native = native_root / "native"
        name = f"{target}-native-amd64-{publisher_run}-{attempt}"
        publisher.download_publisher_artifact(GH, target, publisher_run, desired.source, name, native, publisher.ARCHIVE_MAX)
        stages, archives = {}, {}
        for (role, platform), value in children.items():
            if platform != NATIVE:
                continue
            stages[role] = Container(f"ghcr.io/secpal/{target}@{value}", desired.source, value)
            tarfile = root / (role + ".tar")
            publisher.make_oci_archive((native if target == "frontend" else native / role) / "image", value, tarfile)
            tarfile.chmod(0o644)
            archives[role] = tarfile

        progress[0] = "comparison"
        evidence = publisher.protected_comparison(repo, latest, target, old_children, children)
        database = postgres_facts() if target == "api" else None
        migration = compatible(repo, latest, before, desired, database) if target == "api" else None
        expected = {**database, **migration} if migration is not None else database

        def migrate():
            if postgres_facts() != database:
                raise ValueError("reference database changed before migration")
            run_migration(stages)
            if postgres_facts() != expected:
                raise ValueError("reference migration did not reach its qualified schema and ledger")

        def now():
            return datetime.now(timezone.utc)

        def rollback_allowed():
            if target == "api" and now() >= datetime.fromisoformat(before.expires):
                raise ValueError("predecessor API rollback qualification expired")
            if target == "api" and postgres_facts() not in (database, expected):
                raise ValueError("reference rollback database differs from both qualified states")
            if migration is not None and not migration_login_disabled():
                raise ValueError("reference migration login is active")
            if not exposure_matches(live=False):
                raise ValueError("rollback database or exposure no longer agrees")

        def ready():
            if observe(target) != active or not exposure_matches() or (
                    target == "api" and postgres_facts() != database):
                raise ValueError("reference predecessor, isolation or database changed during staging")
            if protected_head("deployment") != latest.revision or protected_head(target) != desired.source:
                raise ValueError("protected source advanced before reference activation")
            public_accept(target=target)
            progress[0] = "comparison"
            publisher.admit_component_update(**evidence, observed_at=now().isoformat())
            rollback_allowed()
            progress[0] = "activation"

        def finish():
            if not exposure_matches() or (target == "api" and postgres_facts() != expected):
                raise ValueError("reference exposure or database changed during activation")
            public_accept(authenticated=True, target=target, source=desired.source)
            record(saved, {"revision": latest.revision, "runtime": {role: asdict(value) for role, value in stages.items()}})

        ready()
        apply(target, active, stages, archives, ready, finish, rollback_allowed,
              migrate=migrate if migration is not None else None)
        print(f"reference-update.{target}: activated {desired.source[:12]}", flush=True)


def interrupted(_signo, _frame):
    raise ValueError("reference transaction interrupted")


def main():
    if os.geteuid() != 0 or os.uname().nodename != "secpal.dev" or len(sys.argv) != 1:
        return 1
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    os.umask(0o077)
    tempfile.tempdir = "/var/tmp"
    publisher.github_json = forge
    publisher.fetch_publisher_zip = publisher_zip
    try:
        config = root_json(CONFIG)
        validate_enrollment(config)
        fd = os.open(LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "rb+") as lock:
            lock_info = os.fstat(lock.fileno())
            if lock_info.st_uid != 0 or lock_info.st_nlink != 1 or lock_info.st_mode & 0o022:
                raise ValueError("unexpected reference lock ownership")
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                print("reference-update: existing reference transaction holds the lock", flush=True)
                return 0
            repo, latest = fetch_release(STATE)
            if protected_head("deployment") != latest.revision:
                raise ValueError("protected deployment source differs from the fetched source")
            publisher.admit_dispatch(repo, latest, describe)
            result = 0
            for product in ("frontend", "api"):
                progress = ["observation"]
                try:
                    lane(repo, latest, product, config["baseline"], config["exposure"], progress)
                except ERRORS as error:
                    print(f"reference-update.{progress[0]}: {product}: {type(error).__name__}: "
                          "reference admission or operation failed", file=sys.stderr, flush=True)
                    result = 1
            return result
    except ERRORS as error:
        print(f"reference-update.source: {type(error).__name__}: reference dispatch failed", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
