#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Reviewed fixed HTTP backend exposure owned by deployment#101.

Pure configuration and rendering; installation is administrator authority.
"""

from dataclasses import dataclass
import hashlib
import json
from types import MappingProxyType


@dataclass(frozen=True)
class Backend:
    role: str
    host_port: int
    container_port: int = 8080
    readiness_path: str = "/health/live"

    @property
    def endpoint(self) -> str:
        return f"127.0.0.1:{self.host_port}"

    @property
    def publication(self) -> str:
        return f"PublishPort={self.endpoint}:{self.container_port}/tcp"


# Change ports only through a reviewed configuration change to this owner.
BACKENDS = MappingProxyType({
    "frontend": Backend("frontend", 18080),
    "api": Backend("api", 18081),
})
POLICY_CHECK_COMMAND = (
    "/usr/bin/python3 -I /usr/local/libexec/secpal/product-backend-policy --check"
)


def publish_lines(role: str) -> tuple[str, ...]:
    backend = BACKENDS.get(role)
    return () if backend is None else (backend.publication,)


def host_policy(haproxy_uid: int) -> dict[str, str]:
    """Constrain access to the dedicated service UID and SELinux port type.

    No runtime-account or general local validation exemption is granted. Root
    controls these policies and is outside the local-process isolation claim.
    """
    if type(haproxy_uid) is not int or not 1 <= haproxy_uid < 2**32 - 1:
        raise ValueError("HAProxy must have a dedicated non-root numeric UID")
    ports = ", ".join(str(backend.host_port) for backend in BACKENDS.values())
    nft = f"""table inet secpal_product_backends {{
  chain backend_input {{
    type filter hook input priority -20; policy accept;
    iifname != "lo" tcp dport {{ {ports} }} reject
  }}
  chain backend_output {{
    type filter hook output priority -20; policy accept;
    ip daddr 127.0.0.1 tcp dport {{ {ports} }} meta skuid {haproxy_uid} accept
    ip daddr 127.0.0.0/8 tcp dport {{ {ports} }} reject
    ip6 daddr ::1 tcp dport {{ {ports} }} reject
  }}
}}
"""
    cil = """(type secpal_backend_port_t)
(typeattributeset port_type (secpal_backend_port_t))
(roletype object_r secpal_backend_port_t)
(allow haproxy_t secpal_backend_port_t (tcp_socket (name_connect)))
(allow container_runtime_t secpal_backend_port_t (tcp_socket (name_bind)))
"""
    cil += "".join(
        f"(portcon tcp {backend.host_port} (system_u object_r secpal_backend_port_t ((s0) (s0))))\n"
        for backend in BACKENDS.values()
    )
    return {"product-backends.nft": nft, "product-backends.cil": cil}


def policy_digest(haproxy_uid: int) -> str:
    return hashlib.sha256(json.dumps(host_policy(haproxy_uid), sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def admit_policy_account(account, runtime_uid: int) -> int:
    """Resolve identity at the host boundary; numeric rendering is not admission."""
    if (account.pw_name != "haproxy" or type(account.pw_uid) is not int
            or not 1 <= account.pw_uid < 1000 or account.pw_uid == runtime_uid
            or account.pw_gid <= 0
            or account.pw_shell not in {"/usr/sbin/nologin", "/sbin/nologin"}):
        raise ValueError("HAProxy requires a distinct non-login system account")
    return account.pw_uid


def haproxy_backends() -> str:
    """Consumer fragment only; public routing/TLS remains outside #101."""
    return "\n".join(
        f"""backend secpal_{backend.role}
    mode http
    timeout connect 3s
    timeout server 30s
    option httpchk
    http-check send meth GET uri {backend.readiness_path} ver HTTP/1.1 hdr Host localhost
    http-check expect status 200
    server {backend.role} {backend.endpoint} check inter 5s fall 3 rise 2
"""
        for backend in BACKENDS.values()
    )
