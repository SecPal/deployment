#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT
"""Operator composition of #80 on an existing, authenticated public-base host.

Protected source, canonical dispatch and provider/SSH authentication precede this
explicit administrator invocation. Output is candidate evidence; the independent
operator must re-admit it against bindings obtained through that trusted channel.
This file grants neither OCI admission nor enrollment/readiness authority.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import stat
import sys
import tempfile
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
# Admit source ancestry before importing any adjacent repository implementation.
if __name__ == "__main__" and os.geteuid() == 0:
    try:
        for directory in ("scripts", "config/production", "schemas"):
            for source in (ROOT / directory).rglob("*"):
                if "__pycache__" in source.parts:
                    continue
                for entry in (source, *source.parents):
                    info = entry.lstat()
                    if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
                        raise ValueError
                if not source.is_dir() and (not source.is_file() or source.stat().st_nlink != 1):
                    raise ValueError
        _cache = tempfile.TemporaryDirectory(prefix="secpal-native-imports-")
        sys.pycache_prefix = _cache.name
    except (OSError, ValueError):
        raise SystemExit("FAIL: native:administrator-owned-source-required")

sys.path.insert(0, str(ROOT / "scripts/ci-cloud"))
sys.path.insert(0, str(ROOT / "scripts"))


def owner(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


phase = owner("_native_phase_one", "scripts/standard-installation.py")
control = owner("_native_rocky_control", "scripts/ci-cloud/rocky-control.py")
classifier = owner("_native_harness_diagnostics", "scripts/ci-cloud/classify-rocky-target-qualification-failure.py")
import rocky_preparation_contract as preparation
import selinux_isolation_contract as isolation
import quadlet_authority_contract as authority

HARNESS = ROOT / "scripts/qualify-production-host.sh"
HARNESS_SHA256 = "436756f79c7f120d5c4b9fc15b12b2fd91da0fdea5e93ed2907172a73c2861ac"
BINDING_KEYS = frozenset({"source_sha", "control_sha", "harness_sha256",
                          "host_identity", "architecture", "boot_id", "execution_id"})


@contextmanager
def diagnostic(operation):
    try:
        yield
    except phase.Error:
        raise
    except phase.rpm_observer.ObservationError as error:
        raise phase.Error("rpm-" + error.operation) from None
    except (ValueError, OSError, KeyError, RecursionError, control.ControlError,
            preparation.ContractError, isolation.IsolationError, authority.AuthorityError):
        raise phase.Error("native-" + operation) from None


def admit_fixture(raw, architecture):
    try:
        return preparation.admit_fixture_repo_digests(raw, architecture)
    except preparation.ContractError as error:
        raise ValueError(error.operation) from None


def admit_binding(observed, expected):
    """Expected values come from authenticated control, never the host envelope."""
    if (set(expected) != BINDING_KEYS or observed != expected
            or control.SHA.fullmatch(expected["source_sha"]) is None
            or control.SHA.fullmatch(expected["control_sha"]) is None
            or expected["harness_sha256"] != HARNESS_SHA256
            or expected["architecture"] not in {"x86_64", "aarch64"}
            or control.RUN_ID.fullmatch(expected["execution_id"]) is None
            or re.fullmatch(r"[a-z][a-z0-9-]*:[1-9][0-9]*", expected["host_identity"]) is None
            or re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", expected["boot_id"]) is None):
        raise ValueError("native binding is not the authenticated execution")


def stage_fixture(native, account, architecture, directory):
    """Only the canonical nonsecret fixture; never a product/tag/mirror fallback."""
    status, _ = native.run("native-observe-fixture-presence",
                          ["podman", "image", "exists", preparation.FIXTURE],
                          user=account["name"], accepted=(0, 1))
    if status:
        auth = directory / "empty-auth.json"
        with diagnostic("prepare-anonymous-registry-auth"):
            auth.write_text('{"auths":{}}\n')
            auth.chmod(0o644)
            certificates = directory / "empty-certificates"
            certificates.mkdir(mode=0o755)
        native.run("native-stage-fixture", ["podman", "pull", "--tls-verify=true",
                   "--authfile", str(auth), "--cert-dir", str(certificates), "--platform",
                   "linux/amd64" if architecture == "x86_64" else "linux/arm64",
                   preparation.FIXTURE], user=account["name"], timeout=300)
    _, raw = native.run("native-observe-fixture-digests",
                        ["podman", "image", "inspect", "--format", "{{json .RepoDigests}}",
                         preparation.FIXTURE], user=account["name"])
    with diagnostic("admit-fixture-digests"):
        child = admit_fixture(raw, architecture)
    return {"input": preparation.FIXTURE, "child": child, "changed": bool(status)}


def snapshot(native, account):
    """Observe only qualification-owned names; never delete or prune here."""
    _, containers = native.run("native-observe-cleanup-containers",
        ["podman", "ps", "--all", "--format", "{{.Names}}"], user=account["name"])
    _, units = native.run("native-observe-cleanup-units",
        ["systemctl", "--user", "list-units", "--all", "--no-legend", "--plain",
         "secpal-host-qualification-*"], user=account["name"])
    with diagnostic("observe-cleanup-paths"):
        paths = [str(p) for root in (Path("/var/tmp"),
                 Path("/etc/containers/systemd/users") / str(account["uid"]))
                 for p in root.glob("secpal-host-qualification-*")]
    return {"containers": sorted(n for n in containers.splitlines()
                                if n.startswith("secpal-host-qualification-")),
            "units": units, "paths": sorted(paths)}


def empty_cleanup(value):
    if value != {"containers": [], "units": "", "paths": []}:
        raise ValueError("qualification resources remain or pre-existed")


def unit_observation(native, unit, output):
    """A root control hook observes the live Quadlet before target assertions."""
    unit = unit.removesuffix(".service")
    if re.fullmatch(r"secpal-host-qualification-[A-Za-z0-9]{6}", unit) is None:
        raise ValueError("unknown fixture unit")
    account = {"name": "secpal-deploy", "uid": 20000, "gid": 20000}
    _, properties = native.run("native-observe-quadlet-properties",
        ["systemctl", "--user", "show", unit + ".service", "--property=FragmentPath",
         "--property=SourcePath", "--property=DropInPaths", "--property=ExecStart"],
        user=account["name"])
    with diagnostic("admit-live-quadlet-authority"):
        normalized = authority.admit_quadlet_authority(properties,
        f"/run/user/{account['uid']}/systemd/generator/{unit}.service",
        f"/etc/containers/systemd/users/{account['uid']}/{unit}.container")
    _, pid = native.run("native-observe-quadlet-pid",
        ["systemctl", "--user", "show", unit + ".service", "--property=MainPID", "--value"],
        user=account["name"])
    if re.fullmatch(r"[1-9][0-9]{0,9}", pid) is None:
        raise ValueError("invalid live Quadlet PID")
    with diagnostic("observe-runtime-identity"):
        runtime_status = Path("/proc") / pid / "status"
        native.run("native-admit-runtime-identity", ["bash", "-c",
            'source "$1"; ids="$(effective_process_ids "$2")"; '
            'runtime_identity_admitted true "${ids%:*}" "${ids#*:}" "$3" "$4"',
            "native-owner", str(HARNESS), str(runtime_status), "20000", "20000"])
    _, status = native.run("native-observe-workload-process",
        ["podman", "exec", unit, "cat", "/proc/1/status"], user=account["name"])
    status_path = output.parent / "workload.status"
    with diagnostic("record-workload-status"):
        status_path.write_text(status + "\n"); status_path.chmod(0o600)
    native.run("native-admit-least-authority", ["bash", "-c",
        'source "$1"; least_authority_process_admitted "$2" 65532 65532',
        "native-owner", str(HARNESS), str(status_path)])
    with diagnostic("record-live-observation"):
        with output.open("x") as stream:
            json.dump({"unit": unit, "properties": properties, "authority": normalized,
                       "workload_status": status}, stream)
        output.chmod(0o600)


def admit_execution(document, expected, directory):
    """Re-admit trusted-channel observations; a host PASS string is insufficient."""
    if set(document) != {"binding", "fixture", "native", "packages", "stdout", "audit",
                          "live", "cleanup_before", "cleanup_after"}:
        raise ValueError("incomplete or unknown native evidence")
    with diagnostic("admit-execution-binding"):
        admit_binding(document["binding"], expected)
    empty_cleanup(document["cleanup_before"])
    empty_cleanup(document["cleanup_after"])
    if document["fixture"] != {"input": preparation.FIXTURE,
                              "child": preparation.FIXTURE_CHILDREN[expected["architecture"]]}:
        raise ValueError("fixture differs from the canonical owner")
    native = document["native"]
    if native["native_observation"]["host"]["architecture"] != expected["architecture"]:
        raise ValueError("package and authenticated host architectures differ")
    live = document["live"]
    if set(live) != {"unit", "properties", "authority", "workload_status"}:
        raise ValueError("live observation is incomplete")
    unit = live["unit"]
    if re.fullmatch(r"secpal-host-qualification-[A-Za-z0-9]{6}", unit) is None:
        raise ValueError("unit identity is invalid")
    with diagnostic("admit-observed-quadlet-authority"):
        observed_authority = authority.admit_quadlet_authority(live["properties"],
        f"/run/user/20000/systemd/generator/{unit}.service",
        f"/etc/containers/systemd/users/20000/{unit}.container")
    if live["authority"] != observed_authority or native["quadlet_authority"] != observed_authority:
        raise ValueError("target and independent Quadlet observations disagree")
    text = document["stdout"]
    pairs = re.findall(r"^(process_a|process_b|storage_a)=([^\r\n]+)$", text, re.MULTILINE)
    facts = dict(pairs)
    if len(pairs) != 3 or set(facts) != {"process_a", "process_b", "storage_a"}:
        raise ValueError("SELinux observation is incomplete")
    with diagnostic("admit-observed-selinux-isolation"):
        observed_isolation = isolation.admit_selinux_isolation(
            **facts, audit_text=document["audit"])
    if observed_isolation != native["selinux_isolation"]:
        raise ValueError("target and independent SELinux observations disagree")
    with diagnostic("write-admission-material"):
        for name, value in (("native.json", native), ("packages.json", document["packages"])):
            (directory / name).write_text(json.dumps(value))
        (directory / "stdout").write_text(text)
        (directory / "workload.status").write_text(live["workload_status"] + "\n")
    phase.Native().run("native-admit-least-authority", ["bash", "-c",
        'source "$1"; least_authority_process_admitted "$2" 65532 65532',
        "native-owner", str(HARNESS), str(directory / "workload.status")])
    control.validate_operator_native_qualification(
        directory / "native.json", directory / "stdout", directory / "packages.json",
        target_sha=expected["source_sha"], control_sha=expected["control_sha"],
        execution_id=expected["execution_id"])


def qualify(native, account, binding, directory):
    """Compose existing observations and owners; no GCP preparation is invoked."""
    with diagnostic("admit-harness-source"):
        if hashlib.sha256(HARNESS.read_bytes()).hexdigest() != HARNESS_SHA256:
            raise ValueError("unreviewed harness")
    before = snapshot(native, account); empty_cleanup(before)
    options = SimpleNamespace(target_sha=binding["source_sha"], control_sha=binding["control_sha"],
                              run_id=binding["execution_id"], run_attempt="1")
    with diagnostic("observe-native-packages"):
        packages = phase.rpm_observer.collect_native_package_admission(
            phase.rpm_observer.Observer(), options)
    live_path = directory / "live.json"
    trace_path = directory / "trace"
    hook = directory / "control-hook.sh"
    # No predicate is replaced. Successful start is observed before returning
    # control to the target. The existing immutable ERR trace owns localization.
    with diagnostic("prepare-control-hook"):
        hook.write_text(
            "source " + shlex.quote(str(ROOT / "scripts/ci-cloud/rocky-target-qualification-trace.sh")) + "\n"
            "runuser() {\n"
            "  local status\n"
            "  if /usr/sbin/runuser \"$@\"; then status=0; else return $?; fi\n"
            "  if [[ $# -eq 15 && $1 == --user && $2 == secpal-deploy && "
            "$3 == -- && ${12} == systemctl && ${13} == --user && ${14} == start ]]; then\n"
            "    /usr/bin/python3 -I " + shlex.quote(str(Path(__file__).resolve())) +
            " --observe-unit \"${15}\" --output " + shlex.quote(str(live_path)) + "\n"
            "  fi\n"
            "  return \"$status\"\n"
            "}\n")
        hook.chmod(0o600)
    _, baseline = native.run("native-observe-audit-checkpoint", ["date", "-u", "+%m/%d/%y %H:%M:%S"])
    # Native.run bounds capture and emits only semantic failures. A private
    # fd 3 carries the existing numeric trace, never command/environment values.
    with diagnostic("prepare-harness-trace"):
        trace_path.touch(mode=0o600, exist_ok=False)
        trace_path.chmod(0o600)
    command = ["bash", "-c", 'exec 3>"$1"; export BASH_ENV="$2"; exec bash "$3" --image "$4" --service-account "$5"',
               "native-owner", str(trace_path), str(hook), str(HARNESS),
               preparation.FIXTURE, account["name"]]
    status, stdout = native.run("native-execute-harness", command,
                               accepted=tuple(range(256)), timeout=2700)
    after = snapshot(native, account)
    with diagnostic("admit-harness-result"):
        if status:
            trace = trace_path.read_text()
            operations, valid = classifier.trace_operations(trace, status)
            if not valid or not operations:
                raise phase.Error("native-harness-diagnostic-unavailable")
            raise phase.Error("native-harness:" + ",".join(sorted(operations)))
        empty_cleanup(after)
    with diagnostic("normalize-harness-observations"):
        facts = {}
        for key, value in re.findall(
                r"^(process_a|process_b|storage_a|seccomp_mode|denial_pid|selinux_isolation_sha256|quadlet_authority_base64)=([^\r\n]+)$",
                stdout, re.MULTILINE):
            if key in facts:
                raise ValueError("duplicate harness fact")
            facts[key] = value
        if set(facts) != {"process_a", "process_b", "storage_a", "seccomp_mode", "denial_pid",
                          "selinux_isolation_sha256", "quadlet_authority_base64"}:
            raise ValueError("incomplete harness observation")
    _, audit = native.run("native-observe-audit-events",
        ["/usr/sbin/ausearch", "--input-logs", "-m", "AVC", "-ts", *baseline.split(), "-i"])
    with diagnostic("admit-audit-correlation"):
        observed = isolation.admit_selinux_isolation(
            process_a=facts["process_a"], process_b=facts["process_b"],
            storage_a=facts["storage_a"], audit_text=audit + "\n")
        if observed["denial"]["pid"] != int(facts["denial_pid"]):
            raise ValueError("AVC process differs")
    with diagnostic("read-live-observation"):
        live = json.loads(live_path.read_text())
    document = {"schema_version": 4, "target_sha": binding["source_sha"],
        "native_observation": packages, "quadlet_authority": live["authority"],
        "exit_status": status, "stdout_sha256": hashlib.sha256((stdout + "\n").encode()).hexdigest(),
        "stdout_bytes": len((stdout + "\n").encode()), "selinux_isolation": observed,
        "seccomp_enforced": facts["seccomp_mode"] == "2", "cleanup_complete": True,
        "classification": "PASS"}
    return {"binding": binding,
        "fixture": {"input": preparation.FIXTURE, "child": preparation.FIXTURE_CHILDREN[binding["architecture"]]},
        "native": document, "packages": packages, "stdout": stdout + "\n",
        "audit": audit + "\n", "live": live, "cleanup_before": before, "cleanup_after": after}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--stage-fixture", action="store_true")
    modes.add_argument("--qualify", action="store_true")
    modes.add_argument("--observe-unit")
    parser.add_argument("--inventory", type=Path)
    parser.add_argument("--firewall", type=Path)
    parser.add_argument("--source-sha")
    parser.add_argument("--control-sha")
    parser.add_argument("--host-identity")
    parser.add_argument("--execution-id")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError("explicit administrator execution required")
    phase.admit_environment()
    with diagnostic("admit-harness-source"):
        if hashlib.sha256(HARNESS.read_bytes()).hexdigest() != HARNESS_SHA256:
            raise ValueError("unreviewed harness")
    native = phase.Native()
    native.trusted(args.output.parent, directory=True)
    if args.observe_unit:
        with diagnostic("observe-live-quadlet"):
            unit_observation(native, args.observe_unit, args.output)
        return 0
    if any(x is None for x in (args.inventory, args.firewall, args.source_sha,
                               args.control_sha, args.host_identity, args.execution_id)):
        raise ValueError("authenticated execution inputs missing")
    native.trusted(args.inventory); native.trusted(args.firewall)
    desired = phase.plan(phase.inventory_owner.read_document(args.inventory, "inventory"),
                         phase.inventory_owner.read_document(args.firewall, "firewall"))
    if {k: desired["account"][k] for k in ("name", "uid", "gid", "home")} != {
            "name": "secpal-deploy", "uid": 20000, "gid": 20000, "home": "/var/lib/secpal"}:
        # This composition deliberately supports the reviewed Phase-1 identity.
        raise ValueError("unsupported Phase-1 service identity")
    with diagnostic("verify-public-base"):
        phase.verify_public_base(native, desired)
    _, architecture = native.run("native-observe-architecture", ["uname", "-m"])
    with diagnostic("observe-boot-identity"):
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    binding = {"source_sha": args.source_sha, "control_sha": args.control_sha,
               "harness_sha256": HARNESS_SHA256, "host_identity": args.host_identity,
               "architecture": architecture, "boot_id": boot, "execution_id": args.execution_id}
    with diagnostic("admit-invocation-binding"):
        admit_binding(binding, binding)
    with tempfile.TemporaryDirectory(prefix="secpal-native-qualification-", dir="/var/tmp") as temporary:
        directory = Path(temporary)
        if args.stage_fixture:
            directory.chmod(0o711)
            try:
                result = {"binding": binding, "fixture": stage_fixture(
                    native, desired["account"], architecture, directory)}
            finally:
                with diagnostic("verify-public-base-after-staging"):
                    phase.verify_public_base(native, desired)
        else:
            _, raw = native.run("native-observe-fixture-digests",
                ["podman", "image", "inspect", "--format", "{{json .RepoDigests}}",
                 preparation.FIXTURE], user=desired["account"]["name"])
            admit_fixture(raw, architecture)
            try:
                with diagnostic("collect-qualification"):
                    result = qualify(native, desired["account"], binding, directory)
                with diagnostic("admit-native-evidence"):
                    admit_execution(result, binding, directory)
            finally:
                with diagnostic("verify-public-base-after-qualification"):
                    phase.verify_public_base(native, desired)
        with diagnostic("publish-native-evidence"):
            with args.output.open("x") as stream:
                json.dump(result, stream, indent=2)
            args.output.chmod(0o600)
    print("FIXTURE_STAGED" if args.stage_fixture else "NATIVE_EVIDENCE_COLLECTED; INDEPENDENT_ADMISSION_REQUIRED")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (phase.Error, ValueError, OSError, KeyError, RecursionError):
        # The semantic phase.Error text is bounded and has no foreign payload.
        error = sys.exc_info()[1]
        print("FAIL: " + (str(error) if isinstance(error, phase.Error)
                         else "native-invalid-observation"), file=sys.stderr)
        raise SystemExit(1)
