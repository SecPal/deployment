#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Sequence migration-free FCOS lab updates from SecPal/deployment protected main."""

import argparse
from dataclasses import asdict, dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


HOSTS = {"cx23": "linux/amd64", "cx33": "linux/amd64", "cax21": "linux/arm64"}
UPSTREAM = "https://github.com/SecPal/deployment.git"
RELEASE_PATHS = tuple(
    line for line in Path(__file__).with_name("fcos-lab-release-paths.txt").read_text(encoding="ascii").splitlines()
    if line and not line.startswith("#")
)
RUNTIME_SOURCE = "scripts/integration_runtime_contract.py"
LAB_FRONTEND_PINS = re.compile(
    rb'^LAB_FRONTEND_(DIGEST|SOURCE_COMMIT) = "(sha256:[0-9a-f]{64}|[0-9a-f]{40})"$',
    re.MULTILINE,
)


class RolloutError(Exception):
    """A bounded failure that stops the rollout."""


class AcceptanceRejected(RolloutError):
    """A definite failed check on the observed candidate."""


@dataclass(frozen=True)
class Release:
    revision: str
    fingerprint: str

    def __post_init__(self):
        if re.fullmatch(r"[a-f0-9]{40}", self.revision) is None or re.fullmatch(
            r"[a-f0-9]{64}", self.fingerprint
        ) is None:
            raise ValueError("invalid release identity")


def write_state(path, state):
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as target:
        temporary = Path(target.name)
        try:
            target.write((json.dumps(state, sort_keys=True) + "\n").encode())
            target.flush()
            os.fsync(target.fileno())
            temporary.replace(path)
            directory = os.open(path.parent, os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)


def baseline_state(initial, adapter):
    for host in HOSTS:
        if adapter("observe", host, initial, initial) != initial.fingerprint:
            raise RolloutError(f"{host}: installed baseline does not match")
    return {"accepted": asdict(initial), "pending": None, "next": 0,
            "in_flight": False, "blocked": False}


def recover(path, initial, adapter):
    blocked = json.loads(path.read_text(encoding="utf-8"))
    if blocked["blocked"] is not True:
        raise RolloutError("recovery requires a blocked rollout")
    reconciled = baseline_state(initial, adapter)
    archive = Path(tempfile.mkdtemp(prefix="blocked-", dir=path.parent))
    write_state(archive / path.name, blocked)
    write_state(path, reconciled)


def run_rollout(desired, path, adapter, baseline, *, admit=None):
    if not path.exists():
        write_state(path, baseline_state(baseline, adapter))
        return

    state = json.loads(path.read_text(encoding="utf-8"))
    if (
        set(state) != {"accepted", "pending", "next", "in_flight", "blocked"}
        or type(state["next"]) is not int
        or not 0 <= state["next"] <= len(HOSTS)
        or type(state["in_flight"]) is not bool
        or type(state["blocked"]) is not bool
        or (state["pending"] is None and (state["next"] or state["in_flight"]))
        or (state["next"] == len(HOSTS) and state["in_flight"])
    ):
        raise RolloutError("invalid rollout state")
    if state["blocked"]:
        raise RolloutError("rollout blocked; reconcile the recorded release before resuming")

    previous = Release(**state["accepted"])
    if state["pending"] is None:
        if previous.fingerprint == desired.fingerprint:
            return
        if admit is not None:
            admit(desired, previous)
        for host in HOSTS:
            if adapter("observe", host, desired, previous) != previous.fingerprint:
                raise RolloutError(f"{host}: drift from last accepted release")
        for host in HOSTS:
            adapter("prepare", host, desired, previous)
        state["pending"] = asdict(desired)
        write_state(path, state)
    elif admit is not None:
        admit(Release(**state["pending"]), previous)

    release = Release(**state["pending"])
    for index, host in enumerate(HOSTS):
        if index < state["next"]:
            if adapter("observe", host, release, previous) != release.fingerprint:
                raise RolloutError(f"{host}: drift from release already accepted on this host")
            continue
        try:
            actual = adapter("observe", host, release, previous)
            if state["in_flight"]:
                # A timeout or process interruption can occur before or after the
                # switch. Only a complete, observed switch is safe to continue.
                if actual != release.fingerprint:
                    raise RolloutError(f"{host}: interrupted switch requires reconciliation")
            else:
                if actual != previous.fingerprint:
                    raise RolloutError(f"{host}: unexpected installed revision before switch")
                state["in_flight"] = True
                write_state(path, state)
                adapter("activate", host, release, previous)
                if adapter("observe", host, release, previous) != release.fingerprint:
                    raise RolloutError(f"{host}: activation read-back differs")
            adapter("accept", host, release, previous)
        except AcceptanceRejected:
            state["blocked"] = True
            write_state(path, state)
            # The adapter must independently admit rollback and verify its result.
            adapter("rollback", host, release, previous)
            if adapter("observe", host, release, previous) != previous.fingerprint:
                raise RolloutError(f"{host}: rollback read-back differs")
            raise
        except RolloutError:
            state["blocked"] = True
            write_state(path, state)
            raise
        state["next"] = index + 1
        state["in_flight"] = False
        write_state(path, state)

    write_state(path, {"accepted": asdict(release), "pending": None, "next": 0,
                       "in_flight": False, "blocked": False})


def git(repo, *arguments, timeout=30):
    try:
        return subprocess.run(
            ["/usr/bin/git", "-C", str(repo), *arguments],
            env={
                "PATH": "/usr/bin:/bin",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_TERMINAL_PROMPT": "0",
            },
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            check=True, timeout=timeout,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        raise RolloutError("could not resolve protected main") from None


def source_release(repo, revision):
    if re.fullmatch(r"[a-f0-9]{40}", revision) is None:
        raise ValueError("invalid source revision")
    tree = git(repo, "ls-tree", "-r", "-z", "--full-tree", revision, "--", *RELEASE_PATHS)
    records = [record.split(b"\t", 1) for record in tree.split(b"\0") if record]
    for path in RELEASE_PATHS:
        encoded = path.encode()
        if path == "config/quadlet/fcos-security":
            present = any(name.startswith(encoded + b"/") for _, name in records)
        else:
            present = any(name == encoded for _, name in records)
        if not present:
            raise RolloutError("required lab release input is absent")
    if any(mode.split()[:2] not in ([b"100644", b"blob"], [b"100755", b"blob"])
           for mode, _ in records):
        raise RolloutError("lab release inputs must be regular files")
    return Release(revision, hashlib.sha256(tree).hexdigest())


def admit_frontend_only(repo, release, previous, protected_main):
    """Allow only value changes to the two pins owned by the lab frontend proposal."""
    git(repo, "merge-base", "--is-ancestor", previous.revision, release.revision)
    git(repo, "merge-base", "--is-ancestor", release.revision, protected_main.revision)
    for identity in (previous, release):
        if source_release(repo, identity.revision) != identity:
            raise RolloutError("frontend-only: journal identity differs from protected source")
    changed = git(repo, "diff", "--no-ext-diff", "--no-renames", "--name-only", "-z",
                  previous.revision, release.revision, "--", *RELEASE_PATHS)
    if changed != RUNTIME_SOURCE.encode() + b"\0":
        raise RolloutError("frontend-only: release changes inputs outside the lab frontend pins")

    def read(identity):
        entry = git(repo, "ls-tree", identity.revision, "--", RUNTIME_SOURCE)
        if not entry.startswith(b"100644 blob "):
            raise RolloutError("frontend-only: unexpected runtime contract file mode")
        source = git(repo, "show", f"{identity.revision}:{RUNTIME_SOURCE}")
        entries = LAB_FRONTEND_PINS.findall(source)
        pins = dict(entries)
        if (len(entries) != 2 or set(pins) != {b"DIGEST", b"SOURCE_COMMIT"}
                or not pins[b"DIGEST"].startswith(b"sha256:")
                or len(pins[b"SOURCE_COMMIT"]) != 40):
            raise RolloutError("frontend-only: invalid lab frontend pins")
        return pins[b"DIGEST"].decode(), pins[b"SOURCE_COMMIT"].decode(), LAB_FRONTEND_PINS.sub(rb"\1", source)

    index, source, contract = read(release)
    old_index, old_source, old_contract = read(previous)
    if contract != old_contract or index == old_index or source == old_source:
        raise RolloutError("frontend-only: expected a new index and source with all other inputs unchanged")
    return index, source


def command_adapter(executable, state_directory=None):
    environment = {"PATH": "/usr/bin:/bin", "HOME": str(Path.home())}
    if state_directory is not None:
        environment["SECPAL_ROLLOUT_STATE"] = str(state_directory)

    def call(operation, host, release, previous):
        argv = [str(executable), operation, host, HOSTS[host],
                release.revision, release.fingerprint, previous.revision, previous.fingerprint]
        try:
            with tempfile.TemporaryFile() as output:
                result = subprocess.run(
                    argv, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.DEVNULL,
                    env=environment, timeout=900,
                    check=False,
                )
                if operation == "accept" and result.returncode == 10:
                    raise AcceptanceRejected(f"{host}: candidate rejected by acceptance checks")
                if result.returncode != 0:
                    raise RolloutError(f"{host}: {operation} failed")
                output.seek(0)
                # A fingerprint and newline occupy 65 bytes. Read one extra
                # byte so a valid prefix alone cannot satisfy the protocol.
                reply = output.read(66)
        except (OSError, subprocess.SubprocessError):
            raise RolloutError(f"{host}: {operation} unavailable or timed out") from None
        if operation == "observe" and re.fullmatch(rb"[a-f0-9]{64}\n", reply):
            return reply.decode().strip()
        if operation != "observe" and not reply:
            return None
        raise RolloutError(f"{host}: invalid {operation} response")
    return call


def fetch_release(directory):
    repository = directory / "release.git"
    if not repository.exists():
        git(directory, "init", "--bare", "release.git")
    git(repository, "fetch", "--no-tags", UPSTREAM,
        "refs/heads/main:refs/remotes/release/main", timeout=180)
    revision = git(repository, "rev-parse", "--verify", "refs/remotes/release/main")
    return repository, source_release(repository, revision.decode().strip())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-directory", type=Path, required=True)
    parser.add_argument("--baseline", help="already qualified protected-main commit")
    parser.add_argument("--adapter", type=Path, help="installed lab-only adapter")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--inspect", action="store_true", help="report the desired source without contacting guests")
    mode.add_argument("--recover", action="store_true", help="archive a blocked rollout after baseline reconciliation")
    mode.add_argument("--frontend-only", action="store_true", help="admit only publisher-accepted lab frontend updates")
    args = parser.parse_args()
    if args.inspect:
        if args.adapter is not None or args.baseline is not None:
            parser.error("inspection does not accept adapter or baseline arguments")
    elif not args.baseline or args.adapter is None or not args.adapter.is_absolute():
        parser.error("rollout requires a baseline and an absolute path to the installed lab adapter")
    os.umask(0o077)
    try:
        with (args.state_directory / "lock").open("a", encoding="utf-8") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return 0
            repository, desired = fetch_release(args.state_directory)
            if args.inspect:
                print(json.dumps(asdict(desired), sort_keys=True))
                return 0
            initial = source_release(repository, args.baseline)
            git(repository, "merge-base", "--is-ancestor", initial.revision, desired.revision)
            state = args.state_directory / "rollout.json"
            adapter = command_adapter(args.adapter, args.state_directory)
            if args.recover:
                recover(state, initial, adapter)
            else:
                def admit(release, previous):
                    index, source = admit_frontend_only(repository, release, previous, desired)
                    sys.path.insert(0, str(Path(__file__).resolve().parent))
                    try:
                        from fcos_lab_rollout_adapter import Frontend, publisher_children

                        publisher_children(Frontend(index, source), require_acceptance=True)
                    except (ImportError, KeyError, OSError, subprocess.SubprocessError, TypeError, ValueError):
                        raise RolloutError("frontend-only: exact signed publisher acceptance unavailable") from None
                    finally:
                        sys.path.pop(0)

                run_rollout(desired, state, adapter, baseline=initial,
                            admit=admit if args.frontend_only else None)
    except (KeyError, OSError, RolloutError, TypeError, ValueError) as error:
        detail = str(error) if isinstance(error, RolloutError) else "invalid rollout configuration or state"
        print(detail, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
