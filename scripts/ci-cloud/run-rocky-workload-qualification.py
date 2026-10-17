#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Collect the existing workload phases on one prepared ephemeral Rocky guest.

Installed only by the trusted bootstrap. No admission or provider operations.
The fixed target remains unprivileged; the existing fixture installer owns the
bounded administrator Quadlet publication interface.
"""

from __future__ import annotations

import grp
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import signal
import subprocess
import sys
import tempfile

CONTROL = Path("/opt/secpal-control")
CHECKOUT = Path("/home/secpal-ci/deployment-target")
TARGET = "402c22b0a1d69a5a3dba74ffb68cf016caba606b"
HARNESS = "436756f79c7f120d5c4b9fc15b12b2fd91da0fdea5e93ed2907172a73c2861ac"
MAX_BYTES = 256 * 1024

PHASES = (
    "baseline", "workload_prepare_start", "trusted_quadlet_normalize_live",
    "live", "workload_cleanup", "trusted_quadlet_normalize_cleanup", "post_cleanup",
)
FILES = {
    "baseline": "baseline", "live": "live", "post_cleanup": "post_cleanup",
    "trusted_quadlet_normalize_live": "live_normalization",
    "trusted_quadlet_normalize_cleanup": "cleanup_normalization",
}


def run_phases(execute):
    files = {name: "" for name in FILES.values()}
    statuses = {name: 255 for name in PHASES}
    def run(phase):
        try:
            status, content = execute(phase)
        except (OSError, subprocess.SubprocessError, Failure):
            print(f"ROCKY_WORKLOAD_FAILURE operation={phase}", file=sys.stderr)
            status, content = 1, ""
        statuses[phase] = status
        if phase in FILES:
            files[FILES[phase]] = content
    try:
        run("baseline")
        if statuses["baseline"] == 0:
            run("workload_prepare_start")
            run("trusted_quadlet_normalize_live")
            run("live")
    finally:
        # Attempt every cleanup observation even if an earlier cleanup fails.
        try:
            run("workload_cleanup")
        finally:
            try:
                run("trusted_quadlet_normalize_cleanup")
            finally:
                run("post_cleanup")
    return files, statuses


class Failure(ValueError):
    pass


def command(operation, arguments, *, capture=False, cwd=None, timeout=60,
            allow_failure=False):
    # Closed operation names only; never expose raw target/package output.
    with tempfile.TemporaryFile() as output:
        try:
            result = subprocess.run(["timeout", "--signal=TERM", "--kill-after=15s",
                                     str(timeout), *arguments], cwd=cwd, timeout=timeout + 20,
                                    stdout=output if capture else subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, check=False)
            output.seek(0)
            data = output.read(MAX_BYTES + 1)
            if (result.returncode and not allow_failure) or len(data) > MAX_BYTES:
                raise Failure(operation)
            content = data.decode("utf-8")
            status = result.returncode if result.returncode >= 0 else 128 - result.returncode
            return (min(255, status), content) if allow_failure else content
        except (OSError, UnicodeError, subprocess.SubprocessError):
            raise Failure(operation) from None


def user_command(arguments):
    return ["runuser", "--user", "secpal-ci", "--", "env", "-i",
            "HOME=/home/secpal-ci", "USER=secpal-ci", "LOGNAME=secpal-ci",
            "PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8",
            "XDG_RUNTIME_DIR=/run/user/20000",
            "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/20000/bus",
            "CONTAINERS_CONF=/dev/null",
            f"SECPAL_TARGET_SHA={TARGET}", f"SECPAL_FIXTURE_INSTANCE={TARGET[:12]}",
            *arguments]


def load_collector():
    purity_spec = importlib.util.spec_from_file_location(
        "rocky_workload_purity", CONTROL / "scripts/ci-cloud/workload-purity.py")
    purity = importlib.util.module_from_spec(purity_spec)
    purity_spec.loader.exec_module(purity)
    try:
        purity.check_files(CONTROL / "scripts/ci-cloud")
    except ValueError:
        raise Failure("check-workload-purity") from None
    spec = importlib.util.spec_from_file_location(
        "rocky_workload_collector", CONTROL / "scripts/ci-cloud/collect-workload-evidence.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def prepare():
    # Never adopt an existing identity or checkout, including after interruption.
    # Retry requires exact provider teardown and a fresh admitted ephemeral run.
    for lookup, identity in ((pwd.getpwnam, "secpal-ci"), (pwd.getpwuid, 20000),
                             (grp.getgrnam, "secpal-ci"), (grp.getgrgid, 20000)):
        try:
            lookup(identity)
        except KeyError:
            continue
        raise Failure("admit-fresh-workload-account")
    if CHECKOUT.exists() or CHECKOUT.is_symlink() or Path("/srv/secpal-ci").exists():
        raise Failure("admit-fresh-workload-paths")
    command("create-workload-group", ["groupadd", "--gid", "20000", "secpal-ci"])
    command("create-workload-account", ["useradd", "--system", "--uid", "20000", "--gid", "20000",
            "--create-home", "--shell", "/usr/sbin/nologin", "secpal-ci"])
    start = command("allocate-workload-subids",
                    ["/usr/local/sbin/secpal-allocate-rocky-subids",
                     "/etc/subuid", "/etc/subgid"], capture=True).strip()
    if re.fullmatch(r"[1-9][0-9]{0,9}", start) is None:
        raise Failure("allocate-workload-subids")
    # The accepted allocator owns overlap/width semantics.
    command("assign-workload-subids", ["usermod", "--add-subuids", f"{start}-{int(start)+65535}",
            "--add-subgids", f"{start}-{int(start)+65535}", "secpal-ci"])
    collector = load_collector()
    generator = collector.TRUSTED_USER_ENVIRONMENT_GENERATOR_PATH
    try:
        generator.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        if generator.exists() or generator.is_symlink():
            raise Failure("admit-fresh-environment-generator")
        generator.write_bytes(collector.TRUSTED_USER_ENVIRONMENT_GENERATOR)
        generator.chmod(0o755)
    except OSError:
        raise Failure("install-reviewed-user-environment") from None
    command("enable-workload-manager", ["loginctl", "enable-linger", "secpal-ci"])
    command("start-workload-manager", ["systemctl", "start", "user@20000.service"])
    command("mask-workload-api", user_command(
        ["systemctl", "--user", "mask", "--now", "podman.socket", "podman.service"]))
    command("create-workload-staging",
            ["install", "-d", "-o", "secpal-ci", "-g", "secpal-ci", "-m", "0700",
             "/srv/secpal-ci"])
    command("setup-workload-fixture", ["/usr/local/sbin/secpal-ci-quadlet-fixture-installer",
                                      "setup"])
    command("checkout-init", user_command(["git", "init", "--quiet", str(CHECKOUT)]))
    command("checkout-origin", user_command(["git", "remote", "add", "origin",
            "https://github.com/SecPal/deployment.git"]), cwd=CHECKOUT)
    command("fetch-exact-workload-target",
            user_command(["git", "fetch", "--quiet", "--depth=1", "origin", TARGET]),
            cwd=CHECKOUT, timeout=180)
    command("checkout-exact-workload-target",
            user_command(["git", "checkout", "--quiet", "--detach", "FETCH_HEAD"]), cwd=CHECKOUT)
    actual = command("verify-exact-workload-target",
                     user_command(["git", "rev-parse", "HEAD"]), cwd=CHECKOUT, capture=True)
    if actual.strip() != TARGET:
        raise Failure("verify-exact-workload-target")
    command("create-control-network", user_command(
        ["podman", "network", "create", collector.CONTROL_NETWORK]))
    command("create-control-volume", user_command(
        ["podman", "volume", "create", collector.CONTROL_VOLUME]))


def execute(phase):
    if phase in {"workload_prepare_start", "workload_cleanup"}:
        target_phase = phase.replace("_", "-")
        # Drain raw output, retaining only the existing closed diagnostic.
        helper = str(CONTROL / "scripts/ci-cloud/bounded-target-diagnostic.py")
        with tempfile.TemporaryDirectory() as directory:
            diagnostic = str(Path(directory) / "diagnostic")
            timeout = 1800 if phase == "workload_prepare_start" else 180
            process = subprocess.Popen(
                ["timeout", "--signal=TERM", "--kill-after=15s", str(timeout),
                 *user_command(["bash", "scripts/ci-cloud/target-conformance.sh",
                                "v1", target_phase])],
                cwd=CHECKOUT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                start_new_session=True)
            capture = subprocess.Popen(
                ["/usr/bin/python3", "-I", helper, "capture", diagnostic],
                stdin=process.stdout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            process.stdout.close()
            try:
                status = process.wait()
                capture_status = capture.wait(timeout=30)
            except BaseException:
                # Stop the exact target process group before finally-cleanup.
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                    process.wait(timeout=15)
                except (ProcessLookupError, subprocess.TimeoutExpired):
                    if process.poll() is None:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=15)
                finally:
                    capture.kill()
                    capture.wait(timeout=15)
                raise
            status = max(0, min(255, status)) if status >= 0 else 128 - status
            if capture_status:
                status = 1
            if status:
                message = command("target-diagnostic", ["/usr/bin/python3", "-I", helper,
                    "emit", diagnostic, target_phase, str(status)], capture=True)
                print(message.strip(), file=sys.stderr)
            return status, ""
    mode = {"trusted_quadlet_normalize_live": "live",
            "trusted_quadlet_normalize_cleanup": "cleanup"}.get(phase)
    arguments = ["/usr/bin/python3", "-I",
                 str(CONTROL / "scripts/ci-cloud/collect-workload-evidence.py"),
                 "normalize" if mode else phase.replace("_", "-"), TARGET, TARGET[:12]]
    if mode:
        arguments.append(mode)
    try:
        status, content = command(phase, user_command(arguments), capture=True,
                                  cwd=CHECKOUT, timeout=300, allow_failure=True)
        if status:
            print(f"ROCKY_WORKLOAD_FAILURE operation={phase}", file=sys.stderr)
        return status, content
    except Failure:
        print(f"ROCKY_WORKLOAD_FAILURE operation={phase}", file=sys.stderr)
        return 1, ""


def main():
    if (len(sys.argv) != 6 or sys.argv[1] != TARGET or sys.argv[5] != HARNESS
            or re.fullmatch(r"[0-9a-f]{40}", sys.argv[2]) is None
            or re.fullmatch(r"[1-9][0-9]{0,19}", sys.argv[3]) is None
            or re.fullmatch(r"[1-9][0-9]{0,2}", sys.argv[4]) is None
            or os.geteuid() != 0):
        print("ROCKY_WORKLOAD_FAILURE operation=admit-invocation", file=sys.stderr)
        return 1
    workflow = {"repository": "SecPal/deployment", "target_sha": TARGET,
                "run_id": sys.argv[3], "run_attempt": sys.argv[4]}
    try:
        if not Path("/var/lib/secpal-rocky/prepared").is_file():
            raise Failure("admit-prepared-host")
        # Provider identity removal and host acceptance precede this command.
        command("admit-no-metadata-identity", ["bash", "-c",
            "! curl --noproxy '*' --fail --silent --max-time 2 -H 'Metadata-Flavor: Google' "
            "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"])
        for name in ("GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_OAUTH_ACCESS_TOKEN"):
            if name in os.environ:
                raise Failure("admit-no-control-credential")
        prepare()
        def interrupted(_number, _frame):
            raise KeyboardInterrupt()
        for number in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            signal.signal(number, interrupted)
        files, statuses = run_phases(execute)
        json.dump({"control_sha": sys.argv[2], "workflow": workflow,
                   "files": files, "statuses": statuses}, sys.stdout, separators=(",", ":"))
        print()
        return int(any(statuses.values()))
    except (Failure, OSError, ValueError, KeyboardInterrupt) as error:
        operation = str(error) if isinstance(error, Failure) else "interrupted-or-invalid-observation"
        print(f"ROCKY_WORKLOAD_FAILURE operation={operation}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
