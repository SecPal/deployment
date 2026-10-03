#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Administrator-owned #101 policy activation and rootless startup barrier.

Install this immutable helper and its contract together in /usr/local/libexec/
secpal. No activation is authorized merely by invoking its read-only check.
"""

import argparse
import ctypes
import ctypes.util
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
DIRECTORY = Path(__file__).resolve().parent
sys.path.insert(0, str(DIRECTORY))
from product_backend_contract import admit_policy_account, host_policy, policy_digest

STATE = Path("/run/secpal-product-backends")
READY = STATE / "ready.json"
HELPER = Path("/usr/local/libexec/secpal/product-backend-policy")
LIBRARY = HELPER.parent / "product_backend_contract.py"


def trusted_path(path: Path, *, regular=False) -> None:
    current = path
    while True:
        metadata = current.lstat()
        if (stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0
                or metadata.st_gid != 0 or metadata.st_mode & 0o022):
            raise ValueError("policy authority path is not administrator-owned")
        if current == path and regular and not stat.S_ISREG(metadata.st_mode):
            raise ValueError("policy authority is not a regular file")
        if current == Path("/"):
            return
        current = current.parent


def observe_result(operation: str, arguments: list[str], *, input_text=None, accepted=(0,)):
    try:
        result = subprocess.run(arguments, input=input_text, text=True, capture_output=True,
                                timeout=60, check=False,
                                env={"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError(operation) from error
    if result.returncode not in accepted:
        raise ValueError(operation)
    if len(result.stdout.encode()) > 65536 or len(result.stderr.encode()) > 65536:
        raise ValueError(operation)
    return result


def observe(operation: str, arguments: list[str], *, input_text=None, accepted=(0,)) -> str:
    return observe_result(operation, arguments, input_text=input_text, accepted=accepted).stdout


def current_identity() -> int:
    try:
        account = pwd.getpwnam("haproxy")
    except KeyError as error:
        raise ValueError("observe-haproxy-account") from error
    # The production inventory owns runtime identities (serviceAccountId >=
    # 1000). Our dedicated system UID is disjoint; check also compares the
    # actual caller, without introducing a second runtime-account name owner.
    return admit_policy_account(account, os.getuid())


def policy_marker(uid: int) -> dict:
    return {"schema_version": 1, "policy_digest": policy_digest(uid), "haproxy_uid": uid}


def admit_marker(document, uid: int) -> None:
    if (not isinstance(document, dict) or type(document.get("schema_version")) is not int
            or type(document.get("haproxy_uid")) is not int
            or document != policy_marker(uid)):
        raise ValueError("policy startup barrier is absent or stale")


class AccessDecision(ctypes.Structure):
    # Public libselinux av_decision ABI; query the kernel policy rather than
    # interpreting authored module text or maintaining a policy parser.
    _fields_ = [(field, ctypes.c_uint) for field in
                ("allowed", "decided", "auditallow", "auditdeny", "seqno", "flags")]


def effective_decision(source: str, target: str, permission: str) -> dict[str, int]:
    library = ctypes.util.find_library("selinux")
    if library is None:
        raise ValueError("observe-effective-selinux")
    try:
        platform = ctypes.CDLL(library, use_errno=True)
        platform.string_to_security_class.argtypes = [ctypes.c_char_p]
        platform.string_to_security_class.restype = ctypes.c_ushort
        platform.string_to_av_perm.argtypes = [ctypes.c_ushort, ctypes.c_char_p]
        platform.string_to_av_perm.restype = ctypes.c_uint
        platform.security_compute_av_flags.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ushort, ctypes.c_uint,
            ctypes.POINTER(AccessDecision)]
        platform.security_compute_av_flags.restype = ctypes.c_int
        kind = platform.string_to_security_class(b"tcp_socket")
        requested = platform.string_to_av_perm(kind, permission.encode("ascii"))
        decision = AccessDecision()
        result = platform.security_compute_av_flags(
            f"system_u:system_r:{source}:s0".encode("ascii"),
            f"system_u:object_r:{target}:s0".encode("ascii"), kind, requested,
            ctypes.byref(decision))
    except (OSError, AttributeError) as error:
        raise ValueError("observe-effective-selinux") from error
    return {"class": kind, "requested": requested, "result": result,
            "allowed": decision.allowed, "decided": decision.decided, "flags": decision.flags}


def effective_access(source: str, target: str, permission: str) -> bool:
    decision = effective_decision(source, target, permission)
    if (not decision["class"] or not decision["requested"] or decision["result"] != 0
            or decision["decided"] & decision["requested"] != decision["requested"] or decision["flags"]):
        raise ValueError("observe-effective-selinux")
    return decision["allowed"] & decision["requested"] == decision["requested"]


def check_effective_policy() -> None:
    for source, target, permission, expected in (
            ("haproxy_t", "secpal_backend_port_t", "name_connect", True),
            ("container_runtime_t", "secpal_backend_port_t", "name_bind", True),
            ("haproxy_t", "unreserved_port_t", "name_connect", False)):
        if effective_access(source, target, permission) != expected:
            raise ValueError(f"admit-effective-selinux:{source}:{target}:{permission}")


def check() -> None:
    trusted_path(READY, regular=True)
    if READY.stat().st_size > 1024:
        raise ValueError("policy startup barrier is oversized")
    uid = current_identity()
    if uid == os.getuid():
        raise ValueError("product runtime must not use the HAProxy account")
    admit_marker(json.loads(READY.read_text(encoding="utf-8")), uid)
    if observe("observe-enforcing", ["/usr/sbin/getenforce"]).strip() != "Enforcing":
        raise ValueError("SELinux is not Enforcing")
    if observe("observe-connect-any", ["/usr/sbin/getsebool", "haproxy_connect_any"]).strip() != "haproxy_connect_any --> off":
        raise ValueError("HAProxy connect-any is forbidden")
    if observe("observe-bind-all", ["/usr/sbin/getsebool", "pasta_bind_all_ports"]).strip() != "pasta_bind_all_ports --> off":
        raise ValueError("pasta bind-all is forbidden")
    check_effective_policy()


def administrator_authority() -> None:
    if os.getuid() != 0 or Path(__file__).resolve() != HELPER:
        raise ValueError("operation requires the installed administrator helper")
    trusted_path(HELPER, regular=True)
    trusted_path(LIBRARY, regular=True)


def runtime_identity():
    # Consume the existing inventory identity; no new runtime account owner.
    path = Path("/srv/secpal/config/state-contract.json")
    for current in (path, *path.parents):
        info = current.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise ValueError("runtime identity must be administrator-owned")
    if not path.is_file() or not 0 < path.stat().st_size <= 65536:
        raise ValueError("runtime identity contract is invalid")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate runtime contract key")
            result[key] = value
        return result
    document = json.loads(path.read_bytes(), object_pairs_hook=unique)
    uid = document["rootless_mapping"]["service_uid"]
    if type(uid) is not int or not 0 < uid < 2**32 or uid == current_identity():
        raise ValueError("runtime identity is invalid")
    return pwd.getpwuid(uid)


def withdraw() -> None:
    administrator_authority()
    # Synchronous ExecStop runs before nftables stops (reverse After ordering).
    # First prevent restart; then quiesce only the two fixed backend units.
    READY.unlink(missing_ok=True)
    account = runtime_identity()
    observe("stop-product-backends", ["/usr/sbin/runuser", "-u", account.pw_name,
        "--", "/usr/bin/env", "-i", "PATH=/usr/sbin:/usr/bin",
        "HOME=" + account.pw_dir, f"XDG_RUNTIME_DIR=/run/user/{account.pw_uid}",
        f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{account.pw_uid}/bus",
        "/usr/bin/systemctl", "--user", "stop", "secpal-frontend.service", "secpal-api.service"], accepted=(0, 5))
    listeners = observe("verify-backend-withdrawal", ["/usr/sbin/ss", "-H", "-lnt"])
    if any(row.split()[3].rsplit(":", 1)[-1] in {"18080", "18081"} for row in listeners.splitlines()):
        raise ValueError("product backend listeners survived withdrawal")


def activate() -> None:
    administrator_authority()
    STATE.mkdir(mode=0o755, parents=True, exist_ok=True)
    trusted_path(STATE)
    READY.unlink(missing_ok=True)
    runtime_identity()
    uid = current_identity()
    if observe("observe-enforcing", ["/usr/sbin/getenforce"]).strip() != "Enforcing":
        raise ValueError("SELinux is not Enforcing")
    for boolean in ("haproxy_connect_any", "pasta_bind_all_ports"):
        if observe("observe-narrow-booleans", ["/usr/sbin/getsebool", boolean]).strip() != f"{boolean} --> off":
            raise ValueError("broad SELinux policy is forbidden")
    policy = host_policy(uid)
    with tempfile.TemporaryDirectory(prefix="activation-", dir=STATE) as temporary:
        module = Path(temporary) / "secpal_product_backends.cil"
        module.write_text(policy["product-backends.cil"], encoding="utf-8")
        observe("install-backend-selinux", ["/usr/sbin/semodule", "-i", str(module),
                                           "-e", "secpal_product_backends"])
    check_effective_policy()
    table = observe_result("observe-existing-backend-table",
                           ["/usr/sbin/nft", "list", "table", "inet", "secpal_product_backends"],
                           accepted=(0, 1))
    rules = ("delete table inet secpal_product_backends\n" if table.returncode == 0 else "") + policy["product-backends.nft"]
    observe("check-backend-nftables", ["/usr/sbin/nft", "--check", "-f", "-"], input_text=rules)
    observe("activate-backend-nftables", ["/usr/sbin/nft", "-f", "-"], input_text=rules)
    descriptor, name = tempfile.mkstemp(prefix="ready-", dir=STATE)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(policy_marker(uid), handle, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(name, 0o444)
        os.replace(name, READY)
    finally:
        Path(name).unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--check", action="store_true")
    actions.add_argument("--activate", action="store_true")
    actions.add_argument("--withdraw", action="store_true")
    args = parser.parse_args()
    if args.activate:
        activate()
    elif args.withdraw:
        withdraw()
    else:
        check()


if __name__ == "__main__":
    try:
        main()
    except ValueError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
    except (OSError, KeyError, TypeError, subprocess.SubprocessError):
        print("FAIL: product backend policy authority is unavailable or invalid", file=sys.stderr)
        raise SystemExit(1)
