#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT
"""Closed Hetzner host-maintenance capability; never a general API proxy.

Observation: HetznerTransport. Pure normalization/admission: normalize_*,
admit_*. Pure assembly: assemble_reply. Orchestration: execute.
Local custody/IPC: serve. See ADR-023/024 and
docs/evidence-architecture-contract.md in SecPal/.github.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import http.client
import json
import os
import pwd
from pathlib import Path
import re
import signal
import socket
import sqlite3
import ssl
import stat
import struct
import sys
import time
import uuid

ORIGIN = "api.hetzner.cloud"
MAX_RESPONSE = 131072
MAX_REQUEST = 2048
READS = frozenset(
    {"servers list", "server inspect", "server status", "server action-status"}
)
ACTIONS = {
    "server rescue enable": ("enable_rescue", "enable_rescue"),
    "server rescue disable": ("disable_rescue", "disable_rescue"),
    "server reboot": ("reboot", "reboot_server"),
    "server power-on": ("poweron", "poweron_server"),
    "server power-off": ("poweroff", "poweroff_server"),
}
DIAGNOSTICS = frozenset(
    {
        "request.invalid",
        "request.unknown-operation",
        "target.denied",
        "policy.invalid",
        "policy.expired",
        "mutation.disabled",
        "identity.mismatch",
        "protection.invalid",
        "provider.shape",
        "provider.http",
        "provider.transport",
        "provider.timeout",
        "action.mismatch",
        "action.failed",
        "action.pending",
        "target.locked",
        "custody.invalid",
        "caller.denied",
        "socket.invalid",
        "ledger.uncertain",
        "ledger.full",
        "audit.failed",
        "internal.failure",
        "observed",
        "applied",
        "already-satisfied",
        "mutation.unknown",
        "replay.conflict",
    }
)
STAGES = frozenset(
    {
        "request.admission",
        "server.inspect",
        "action.submit",
        "action.inspect",
        "server.readback",
        "ledger.reserve",
        "ledger.finish",
        "custody.source",
        "custody.policy",
        "custody.credential",
        "custody.ledger",
        "socket.activation",
        "socket.peer",
        "socket.receive",
        "socket.reply",
        "socket.accept",
        "audit.admission",
        "audit.result",
        "transport.initialize",
        "ledger.open",
    }
)


class Rejected(Exception):
    def __init__(self, code, stage="request.admission"):
        self.code = code if code in DIAGNOSTICS else "internal.failure"
        self.stage = stage if stage in STAGES else "request.admission"
        super().__init__(self.code)


def require(condition, code):
    if not condition:
        raise Rejected(code)


def at_stage(stage, operation):
    """Bound exceptions by semantic operation, without retaining exception text."""
    try:
        return operation()
    except Rejected as error:
        raise Rejected(error.code, stage) from None
    except Exception:
        raise Rejected("internal.failure", stage) from None


def integer(value):
    return type(value) is int and 0 < value < 2**63


def closed(value, keys, code="request.invalid"):
    require(type(value) is dict and set(value) == set(keys), code)


def decode(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "request.invalid")
            result[key] = value
        return result

    try:
        return json.loads(
            data,
            object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(Rejected("request.invalid")),
        )
    except (ValueError, UnicodeError, RecursionError):
        raise Rejected("request.invalid") from None


@dataclass(frozen=True)
class Policy:
    service_uid: int
    caller_uid: int
    expires_at: int
    allowed_mutations: tuple
    servers: dict
    excluded_server_ids: tuple
    rescue_ssh_key_ids: tuple

    @classmethod
    def from_dict(cls, data):
        closed(
            data,
            {
                "version",
                "service_uid",
                "caller_uid",
                "expires_at",
                "allowed_mutations",
                "servers",
                "excluded_server_ids",
                "rescue_ssh_key_ids",
            },
            "policy.invalid",
        )
        require(type(data["version"]) is int and data["version"] == 2, "policy.invalid")
        for key in ["service_uid", "caller_uid", "expires_at"]:
            require(integer(data[key]), "policy.invalid")
        require(data["service_uid"] != data["caller_uid"], "policy.invalid")
        mutations = data["allowed_mutations"]
        require(
            type(mutations) is list
            and len(mutations) <= len(ACTIONS)
            and all(
                type(operation) is str and operation in ACTIONS
                for operation in mutations
            )
            and len(set(mutations)) == len(mutations),
            "policy.invalid",
        )
        servers = data["servers"]
        require(type(servers) is dict and 1 <= len(servers) <= 64, "policy.invalid")
        for sid, expected in servers.items():
            require(
                type(sid) is str
                and re.fullmatch(r"[1-9][0-9]{0,18}", sid)
                and integer(int(sid)),
                "policy.invalid",
            )
            closed(expected, {"architecture", "server_type"}, "policy.invalid")
            require(
                type(expected["architecture"]) is str
                and expected["architecture"] in {"x86", "arm"}
                and type(expected["server_type"]) is str
                and re.fullmatch(r"[a-z][a-z0-9]{1,15}", expected["server_type"]),
                "policy.invalid",
            )
        for key in ["excluded_server_ids", "rescue_ssh_key_ids"]:
            values = data[key]
            require(
                type(values) is list
                and len(values) <= 64
                and all(integer(v) for v in values)
                and len(set(values)) == len(values),
                "policy.invalid",
            )
        require(
            "server rescue enable" not in mutations or bool(data["rescue_ssh_key_ids"]),
            "policy.invalid",
        )
        require(
            not set(map(int, servers)).intersection(data["excluded_server_ids"]),
            "policy.invalid",
        )
        return cls(
            data["service_uid"],
            data["caller_uid"],
            data["expires_at"],
            tuple(mutations),
            servers,
            tuple(data["excluded_server_ids"]),
            tuple(data["rescue_ssh_key_ids"]),
        )


def admit_request(request, policy):
    require(
        type(request) is dict and type(request.get("operation")) is str,
        "request.invalid",
    )
    operation = request["operation"]
    require(operation in READS or operation in ACTIONS, "request.unknown-operation")
    keys = {"operation"}
    if operation != "servers list":
        keys.add("server_id")
    if operation == "server action-status":
        keys.add("action_id")
    if operation in ACTIONS:
        keys.add("request_id")
    closed(request, keys)
    if "server_id" in request:
        sid = request["server_id"]
        require(
            integer(sid)
            and str(sid) in policy.servers
            and sid not in policy.excluded_server_ids,
            "target.denied",
        )
    if "action_id" in request:
        require(integer(request["action_id"]), "request.invalid")
    if operation in ACTIONS:
        require(operation in policy.allowed_mutations, "mutation.disabled")
        require(
            type(request["request_id"]) is str
            and re.fullmatch(r"[0-9a-f]{32}", request["request_id"]),
            "request.invalid",
        )
    return dict(request)


def normalize_server(raw):
    require(type(raw) is dict and type(raw.get("server")) is dict, "provider.shape")
    s = raw["server"]
    require(integer(s.get("id")), "identity.mismatch")
    kind = s.get("server_type")
    require(
        type(kind) is dict
        and type(kind.get("name")) is str
        and type(kind.get("architecture")) is str,
        "identity.mismatch",
    )
    protection = s.get("protection")
    require(
        type(protection) is dict
        and type(protection.get("delete")) is bool
        and type(protection.get("rebuild")) is bool,
        "protection.invalid",
    )
    require(
        type(s.get("status")) is str
        and s["status"]
        in {
            "running",
            "off",
            "starting",
            "stopping",
            "initializing",
            "migrating",
            "rebuilding",
        },
        "provider.shape",
    )
    require(
        type(s.get("rescue_enabled")) is bool and type(s.get("locked")) is bool,
        "provider.shape",
    )
    return {
        "id": s["id"],
        "server_type": kind["name"],
        "architecture": kind["architecture"],
        "status": s["status"],
        "delete_protection": protection["delete"],
        "rebuild_protection": protection["rebuild"],
        "rescue_enabled": s["rescue_enabled"],
        "locked": s["locked"],
    }


def admit_server(observed, sid, policy):
    expected = policy.servers[str(sid)]
    require(
        observed["id"] == sid
        and observed["server_type"] == expected["server_type"]
        and observed["architecture"] == expected["architecture"],
        "identity.mismatch",
    )
    require(
        observed["delete_protection"] and observed["rebuild_protection"],
        "protection.invalid",
    )
    return observed


def normalize_action(raw):
    require(type(raw) is dict and type(raw.get("action")) is dict, "provider.shape")
    a = raw["action"]
    require(
        integer(a.get("id")),
        "action.mismatch",
    )
    resources = a.get("resources")
    require(
        type(resources) is list
        and len(resources) <= 32
        and all(type(r) is dict for r in resources),
        "action.mismatch",
    )
    require(
        all(integer(r.get("id")) for r in resources if r.get("type") == "server"),
        "action.mismatch",
    )
    require(
        type(a.get("command")) is str and len(a["command"]) <= 64,
        "action.mismatch",
    )
    require(
        type(a.get("status")) is str and a["status"] in {"running", "success", "error"},
        "provider.shape",
    )
    return {
        "id": a["id"],
        "command": a["command"],
        "status": a["status"],
        "server_ids": tuple(r["id"] for r in resources if r.get("type") == "server"),
    }


def admit_action(observed, sid, action_id=None, command=None):
    require(
        (action_id is None or observed["id"] == action_id)
        and set(observed["server_ids"]) == {sid}
        and observed["command"] in {entry[1] for entry in ACTIONS.values()}
        and (command is None or observed["command"] == command),
        "action.mismatch",
    )
    return observed


def assemble_reply(code, server=None, servers=None, action=None):
    """Project admitted facts into the closed, secret-free wire representation."""
    result = {"code": code}
    if server is not None:
        result["server"] = server
    if servers is not None:
        result["servers"] = servers
    if action is not None:
        result["action"] = {key: action[key] for key in ("id", "command", "status")}
    return result


class HetznerTransport:
    """Fixed-origin observation with bounded GET retries and no POST retry.

    No environment proxies, redirects, TLS bypass, raw provider errors or bodies.
    Responses (including generated rescue passwords) are never logged.
    """

    def __init__(self, token, policy):
        require(
            type(token) is str and re.fullmatch(r"[A-Za-z0-9]{64}", token),
            "custody.invalid",
        )
        self._token = token
        self._policy = policy
        self.deadline = time.monotonic() + 30

    def request(self, method, path, body=None):
        require(time.time() < self._policy.expires_at, "policy.expired")
        match = re.fullmatch(
            r"/servers/([1-9][0-9]*)(?:/actions/([a-z_]+|[1-9][0-9]*))?", path
        )
        require(match and match[1] in self._policy.servers, "target.denied")
        suffix = match[2]
        if method == "GET":
            require(
                body is None and (suffix is None or suffix.isdecimal()),
                "request.invalid",
            )
        elif method == "POST":
            require(
                suffix
                in {
                    ACTIONS[operation][0]
                    for operation in self._policy.allowed_mutations
                },
                "mutation.disabled",
            )
            expected = (
                {"type": "linux64", "ssh_keys": list(self._policy.rescue_ssh_key_ids)}
                if suffix == "enable_rescue"
                else {}
            )
            require(body == expected, "request.invalid")
        else:
            raise Rejected("request.invalid")
        for attempt in range(2 if method == "GET" else 1):
            remaining = self.deadline - time.monotonic()
            require(remaining > 0, "provider.timeout")
            connection = http.client.HTTPSConnection(
                ORIGIN, timeout=min(3, remaining), context=ssl.create_default_context()
            )
            try:
                connection.request(
                    method,
                    "/v1" + path,
                    body=None if body is None else json.dumps(body),
                    headers={
                        "Authorization": "Bearer " + self._token,
                        "Content-Type": "application/json",
                        "User-Agent": "SecPal-Hetzner-Maintenance/1",
                    },
                )
                response = connection.getresponse()
                if (
                    method == "GET"
                    and response.status in {429, 502, 503, 504}
                    and attempt == 0
                ):
                    continue
                require(200 <= response.status < 300, "provider.http")
                data = response.read(MAX_RESPONSE + 1)
                require(len(data) <= MAX_RESPONSE, "provider.shape")
                try:
                    return decode(data)
                except Rejected:
                    raise Rejected("provider.shape") from None
            except (OSError, http.client.HTTPException):
                if attempt == 0 and method == "GET":
                    continue
                raise Rejected(
                    "provider.transport" if method == "GET" else "mutation.unknown"
                ) from None
            finally:
                connection.close()
        raise Rejected("provider.timeout")


class Ledger:
    """Durable reserve-before-POST; uncertain operations never get resubmitted."""

    def __init__(self, path):
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA journal_mode=DELETE")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS requests (id TEXT PRIMARY KEY, digest TEXT NOT NULL, result TEXT)"
        )
        self.db.commit()

    def reserve(self, request):
        digest = hashlib.sha256(
            json.dumps(request, sort_keys=True).encode()
        ).hexdigest()
        row = self.db.execute(
            "SELECT digest,result FROM requests WHERE id=?", (request["request_id"],)
        ).fetchone()
        if row:
            require(row[0] == digest, "replay.conflict")
            require(row[1] is not None, "ledger.uncertain")
            return json.loads(row[1])
        require(
            self.db.execute("SELECT count(*) FROM requests").fetchone()[0] < 4096,
            "ledger.full",
        )
        self.db.execute(
            "INSERT INTO requests VALUES (?,?,NULL)", (request["request_id"], digest)
        )
        self.db.commit()
        return None

    def finish(self, request, result):
        self.db.execute(
            "UPDATE requests SET result=? WHERE id=?",
            (json.dumps(result), request["request_id"]),
        )
        self.db.commit()


def execute(request, policy, transport, ledger=None, now=None):
    require((time.time() if now is None else now) < policy.expires_at, "policy.expired")
    request = admit_request(request, policy)
    if type(transport) is HetznerTransport:
        transport.deadline = time.monotonic() + 30
    operation = request["operation"]
    if operation == "servers list":
        # Exact-ID reads; never discover/adopt provider resources by listing.
        servers = [
            at_stage(
                "server.inspect",
                lambda sid=sid: admit_server(
                    normalize_server(transport.request("GET", "/servers/" + sid)),
                    int(sid),
                    policy,
                ),
            )
            for sid in sorted(policy.servers, key=int)
        ]
        return assemble_reply("observed", servers=servers)
    sid = request["server_id"]
    path = "/servers/" + str(sid)
    observed = at_stage(
        "server.inspect",
        lambda: admit_server(
            normalize_server(transport.request("GET", path)), sid, policy
        ),
    )
    if operation in {"server inspect", "server status"}:
        return assemble_reply("observed", server=observed)
    if operation == "server action-status":
        action = at_stage(
            "action.inspect",
            lambda: admit_action(
                normalize_action(
                    transport.request(
                        "GET", path + "/actions/" + str(request["action_id"])
                    )
                ),
                sid,
                request["action_id"],
            ),
        )
        return assemble_reply("observed", server=observed, action=action)
    require(not observed["locked"], "target.locked")
    require(ledger is not None, "ledger.uncertain")
    previous = at_stage("ledger.reserve", lambda: ledger.reserve(request))
    if previous is not None:
        return previous
    desired = {
        "server rescue enable": ("rescue_enabled", True),
        "server rescue disable": ("rescue_enabled", False),
        "server power-on": ("status", "running"),
        "server power-off": ("status", "off"),
    }.get(operation)
    if desired and observed[desired[0]] == desired[1]:
        result = assemble_reply("already-satisfied", server=observed)
    else:
        suffix, command = ACTIONS[operation]
        body = (
            {"type": "linux64", "ssh_keys": list(policy.rescue_ssh_key_ids)}
            if suffix == "enable_rescue"
            else {}
        )
        action = at_stage(
            "action.submit",
            lambda: admit_action(
                normalize_action(
                    transport.request("POST", path + "/actions/" + suffix, body)
                ),
                sid,
                command=command,
            ),
        )
        for _ in range(3):
            action = at_stage(
                "action.inspect",
                lambda: admit_action(
                    normalize_action(
                        transport.request("GET", path + "/actions/" + str(action["id"]))
                    ),
                    sid,
                    action["id"],
                    command,
                ),
            )
            if action["status"] != "running":
                break
        observed = at_stage(
            "server.readback",
            lambda: admit_server(
                normalize_server(transport.request("GET", path)), sid, policy
            ),
        )
        if action["status"] == "error":
            code = "action.failed"
        elif action["status"] == "running" or (
            desired and observed[desired[0]] != desired[1]
        ):
            code = "action.pending"
        else:
            code = "applied"
        result = assemble_reply(code, server=observed, action=action)
    at_stage("ledger.finish", lambda: ledger.finish(request, result))
    return result


def trusted_ancestors(path, owners):
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "custody.invalid")
    for parent in reversed(path.parents):
        info = parent.lstat()
        require(
            stat.S_ISDIR(info.st_mode)
            and info.st_uid in owners
            and info.st_mode & 0o022 == 0,
            "custody.invalid",
        )


def trusted_file(path, owners, *, secret=False, limit=16384, ancestor_owners=None):
    """Check every ancestor, no symlinks, then verify the opened regular inode."""
    path = Path(path)
    trusted_ancestors(path, owners if ancestor_owners is None else ancestor_owners)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid in owners
            and info.st_nlink == 1
            and info.st_mode & (0o077 if secret else 0o022) == 0
            and (limit is None or info.st_size <= limit),
            "custody.invalid",
        )
        return b"" if limit is None else os.read(fd, limit + 1)
    finally:
        os.close(fd)


def admit_custody(policy, effective_uid):
    require(
        effective_uid == policy.service_uid
        and effective_uid != policy.caller_uid
        and effective_uid != 0,
        "custody.invalid",
    )


def authorize_peer(connection, policy):
    _, uid, _ = struct.unpack(
        "3i",
        connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
        ),
    )
    require(uid == policy.caller_uid, "caller.denied")
    return uid


def audit(event):
    # Only broker-created correlation and admitted enums/numeric identities.
    try:
        print(json.dumps(event, sort_keys=True), flush=True)
    except OSError:
        raise Rejected("audit.failed") from None


def receive_request(connection):
    data = bytearray()
    deadline = time.monotonic() + 2
    while not data.endswith(b"\n"):
        require(time.monotonic() < deadline, "request.invalid")
        connection.settimeout(max(0.001, deadline - time.monotonic()))
        chunk = connection.recv(MAX_REQUEST + 1 - len(data))
        require(chunk and len(data) + len(chunk) <= MAX_REQUEST, "request.invalid")
        data.extend(chunk)
    return data


def emit_audit(audit_sink, event, stage):
    try:
        audit_sink(event)
    except Exception:
        raise Rejected("audit.failed", stage) from None


def handle(connection, policy, transport, ledger, audit_sink=audit):
    event = {"audit_id": uuid.uuid4().hex, "code": "internal.failure"}
    response = {"code": "internal.failure"}
    try:
        event["uid"] = at_stage(
            "socket.peer", lambda: authorize_peer(connection, policy)
        )
        data = at_stage("socket.receive", lambda: receive_request(connection))
        request = at_stage(
            "request.admission", lambda: admit_request(decode(data), policy)
        )
        event["operation"] = request["operation"]
        if "server_id" in request:
            event["server_id"] = request["server_id"]
        emit_audit(
            audit_sink,
            {**event, "code": "observed", "phase": "admitted"},
            "audit.admission",
        )
        response = execute(request, policy, transport, ledger)
        event["code"] = response["code"]
    except Rejected as error:
        event["code"] = error.code
        event["stage"] = error.stage
        response = {"code": error.code, "stage": error.stage}
    except Exception:
        event["code"] = "internal.failure"
        event["stage"] = "request.admission"
        response = {"code": "internal.failure", "stage": "request.admission"}
    try:
        emit_audit(audit_sink, {**event, "phase": "result"}, "audit.result")
    except Rejected as error:
        response = {"code": error.code, "stage": error.stage}
    try:
        at_stage(
            "socket.reply",
            lambda: connection.sendall(json.dumps(response).encode() + b"\n"),
        )
    except Rejected as error:
        emit_audit(
            audit_sink,
            {**event, "code": error.code, "stage": error.stage, "phase": "reply"},
            "audit.result",
        )


def inspect_policy_custody(policy, policy_path):
    admit_custody(policy, os.geteuid())
    info = Path(policy_path).stat()
    caller = pwd.getpwuid(policy.caller_uid)
    require(
        info.st_gid == os.getegid()
        and info.st_mode & 0o007 == 0
        and os.getegid() not in os.getgrouplist(caller.pw_name, caller.pw_gid),
        "custody.invalid",
    )


def inspect_ledger_custody(policy, ledger_path):
    trusted_ancestors(ledger_path, {0, policy.service_uid})
    parent = Path(ledger_path).parent
    info = parent.lstat()
    require(
        stat.S_ISDIR(info.st_mode)
        and info.st_uid == policy.service_uid
        and info.st_mode & 0o077 == 0,
        "custody.invalid",
    )
    require(not Path(ledger_path).is_symlink(), "custody.invalid")
    if not Path(ledger_path).exists():
        fd = os.open(
            ledger_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
        os.close(fd)
    trusted_file(
        ledger_path,
        {policy.service_uid},
        secret=True,
        limit=None,
        ancestor_owners={0, policy.service_uid},
    )


def activated_socket():
    require(
        os.environ.get("LISTEN_PID") == str(os.getpid())
        and os.environ.get("LISTEN_FDS") == "1",
        "socket.invalid",
    )
    listener = socket.socket(fileno=3)
    require(
        listener.family == socket.AF_UNIX and listener.type == socket.SOCK_STREAM,
        "socket.invalid",
    )
    return listener


def serve(policy_path, credential_path, ledger_path):
    # Source and policy are administrator-owned; a user checkout cannot serve.
    at_stage(
        "custody.source",
        lambda: trusted_file(Path(__file__), {0}, limit=65536),
    )
    policy = at_stage(
        "custody.policy",
        lambda: Policy.from_dict(decode(trusted_file(policy_path, {0}))),
    )
    at_stage("custody.policy", lambda: inspect_policy_custody(policy, policy_path))
    token = at_stage(
        "custody.credential",
        lambda: trusted_file(credential_path, {0, policy.service_uid}, secret=True)
        .decode()
        .strip(),
    )
    at_stage("custody.ledger", lambda: inspect_ledger_custody(policy, ledger_path))
    listener = at_stage("socket.activation", activated_socket)
    transport = at_stage(
        "transport.initialize", lambda: HetznerTransport(token, policy)
    )
    ledger = at_stage("ledger.open", lambda: Ledger(ledger_path))

    def timed_out(_signum, _frame):
        raise Rejected("provider.timeout")

    signal.signal(signal.SIGALRM, timed_out)
    while True:
        connection, _ = at_stage("socket.accept", listener.accept)
        with connection:
            signal.setitimer(signal.ITIMER_REAL, 40)
            try:
                handle(connection, policy, transport, ledger)
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)


def client_request(words):
    require(len(words) >= 2, "request.invalid")
    if words == ["servers", "list"]:
        return {"operation": "servers list"}
    length = 3 if words[:2] == ["server", "rescue"] else 2
    operation = " ".join(words[:length])
    require(operation in READS or operation in ACTIONS, "request.unknown-operation")
    require(
        len(words) == length + (2 if operation == "server action-status" else 1),
        "request.invalid",
    )
    require(
        all(re.fullmatch(r"[1-9][0-9]{0,18}", v) for v in words[length:]),
        "request.invalid",
    )
    request = {"operation": operation, "server_id": int(words[length])}
    if operation == "server action-status":
        request["action_id"] = int(words[-1])
    if operation in ACTIONS:
        request["request_id"] = uuid.uuid4().hex
    return request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--policy")
    parser.add_argument("--credential")
    parser.add_argument("--ledger")
    parser.add_argument("--socket", default="/run/secpal-hetzner/control.sock")
    parser.add_argument("words", nargs="*")
    args = parser.parse_args()
    try:
        if args.serve:
            require(
                all([args.policy, args.credential, args.ledger]) and not args.words,
                "request.invalid",
            )
            serve(args.policy, args.credential, args.ledger)
        else:
            require(
                not any([args.policy, args.credential, args.ledger]), "request.invalid"
            )
            request = client_request(args.words)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(90)
                connection.connect(args.socket)
                connection.sendall(json.dumps(request).encode() + b"\n")
                data = bytearray()
                while not data.endswith(b"\n"):
                    chunk = connection.recv(MAX_RESPONSE + 1 - len(data))
                    require(
                        chunk and len(data) + len(chunk) <= MAX_RESPONSE,
                        "provider.shape",
                    )
                    data.extend(chunk)
            response = decode(data)
            print(json.dumps(response, sort_keys=True))
            return (
                0
                if response.get("code") in {"observed", "applied", "already-satisfied"}
                else 1
            )
    except Rejected as error:
        print(json.dumps({"code": error.code, "stage": error.stage}))
    except Exception:
        print(json.dumps({"code": "internal.failure"}))
    return 1


if __name__ == "__main__":
    sys.exit(main())
