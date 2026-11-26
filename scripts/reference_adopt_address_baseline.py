# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT
"""Enroll the observed reference state after the attended address cutover."""

from dataclasses import asdict
import fcntl
import json
import os
from pathlib import Path
import shutil
import signal
import sys
import tempfile


def enroll(revision, reference, runtime):
    publisher = reference.publisher
    publisher.github_json = reference.forge
    publisher.fetch_publisher_zip = reference.publisher_zip
    repo, latest = reference.fetch_release(runtime.STATE)
    if latest.revision != revision or reference.protected_head("deployment") != revision:
        raise ValueError("expected the reviewed protected-main baseline")
    source = f"{revision}:scripts/reference_adopt_address_baseline.py"
    if reference.git(repo, "show", source) != Path(__file__).read_bytes():
        raise ValueError("expected the protected enrollment program")
    publisher.admit_dispatch(repo, latest, reference.describe)
    config = reference.root_json(reference.CONFIG)
    reference.validate_enrollment(config)
    if runtime.exposure() != config["exposure"]:
        raise ValueError("reference isolation differs")
    database = runtime.postgres_facts()
    if (not database["identity"].endswith("|7711085157316866085\n")
            or database["schema"] != "62126b55ff35c255997e59c4a4356f360b8990a36a3b085a597141bfdd3aa889"
            or database["ledger"] != "650271e203e03a473618dbe7f7bcb1e9e9a26e4627ce4a27cef2c7f932e87e93"
            or not runtime.migration_login_disabled()):
        raise ValueError("reference database differs from the completed cutover")

    text = publisher.admit_source_text(repo, latest)
    frontend = publisher.Frontend.from_source(text)
    backend = publisher.Backend.from_source(text)
    if (frontend.source != "0a5bcc9f218703c5a602556f7cbfad82a254f722"
            or frontend.index != "sha256:3c859855647284cbeee9ddf26dee547265d992e86f8e6630b8fd8a727205cb15"
            or backend.source != "abb3bed3db54aa20335e054342ffa5f55b09b1be"
            or backend.pair != "sha256:fec1bf683cc4cb545d0b7e1af7038b0b5f317499388b22f828c9b5735c3e4c1e"):
        raise ValueError("only the exact completed cutover can be enrolled")

    updates = {}
    observations = {}
    for product, pins in (("frontend", frontend), ("api", backend)):
        if (runtime.STATE / (product + ".blocked")).exists():
            raise ValueError("reference has an unresolved recovery")
        observations[product] = active = runtime.observe(product)
        with reference.signed_runtime(product, pins, current=False) as (children, _, _, _):
            reference.binds(product, active, pins, children)
        runtime.public_accept(authenticated=True, target=product, source=pins.source)
        updates[runtime.STATE / (product + ".json")] = {
            "revision": revision, "runtime": {role: asdict(value) for role, value in active.items()}
        }
    if (runtime.postgres_facts() != database or runtime.exposure() != config["exposure"]
            or any(runtime.observe(p) != observation for p, observation in observations.items())):
        raise ValueError("reference state changed during enrollment")
    if config["baseline"] == revision and all(reference.root_json(p) == v for p, v in updates.items()):
        return
    snapshot = Path(tempfile.mkdtemp(prefix="pre-address-enrollment.", dir=runtime.STATE))
    paths = (*updates, reference.CONFIG)
    previous = {path: runtime.protected(path) for path in paths}
    for path in paths:
        shutil.copy2(path, snapshot / path.name)
    try:
        for path, value in updates.items():
            reference.record(path, value)
        config["baseline"] = revision
        runtime.replace_protected_config(reference.CONFIG, (json.dumps(config, sort_keys=True) + "\n").encode())
        if reference.root_json(reference.CONFIG) != config or any(
                reference.root_json(path) != value for path, value in updates.items()):
            raise ValueError("reference enrollment did not persist")
    except Exception:
        for path, content in previous.items():
            runtime.replace_protected_config(path, content)
        raise
    print("Verified the exact reference baseline and retained the prior enrollment.")


def main():
    if os.geteuid() != 0 or os.uname().nodename != "secpal.dev" or len(sys.argv) != 2:
        raise ValueError("expected root on the enrolled reference host")
    sys.path.insert(0, "/usr/local/libexec/secpal/reference-update")
    import reference_runtime
    import reference_update

    signal.signal(signal.SIGTERM, reference_update.interrupted)
    signal.signal(signal.SIGINT, reference_update.interrupted)
    os.umask(0o077)
    tempfile.tempdir = "/var/tmp"
    fd = os.open(reference_update.LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "rb+") as lock:
        info = os.fstat(lock.fileno())
        if info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o022:
            raise ValueError("unexpected reference lock ownership")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for unit in ("secpal-reference-update.timer", "secpal-reference-update.service"):
            state = reference_runtime.run(["/usr/bin/systemctl", "show", "-p", "ActiveState", "--value", unit])
            if state.strip() not in (b"inactive", b"failed"):
                raise ValueError("stop the reference update timer and service before enrollment")
        enroll(sys.argv[1], reference_update, reference_runtime)


if __name__ == "__main__":
    main()
