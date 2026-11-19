#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT
"""Prepare a disposable FCOS application stack or an internal restore bundle."""

import argparse
import ipaddress
from pathlib import Path
import re
import runpy
import shutil
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
INTEGRATION = runpy.run_path(str(ROOT / "scripts/render-integration-quadlets.py"))
RESTORE_ROLES = frozenset(
    {
        "secrets-init.container",
        "postgres.container",
        "api.container",
        "php-fpm.container",
        "application.network",
        "secrets.volume",
        "postgres.volume",
        "fpm-socket.volume",
        "private-storage.volume",
    }
)
BACKGROUND_ROLES = ("worker-general", "worker-hash-chain", "scheduler")
ASSETS = {
    "scripts/init-local-secrets.sh": "init-local-secrets.sh",
    "scripts/phase-b-runtime-probe.php": "phase-b-runtime-probe.php",
    "scripts/production-secret-bootstrap.php": "production-secret-bootstrap.php",
    "config/production/php/99-secpal-secrets.ini": "99-secpal-secrets.ini",
    "config/production/php/zz-fpm-session.conf": "zz-fpm-session.conf",
}
PRIVATE_NETWORKS = tuple(
    map(ipaddress.IPv4Network, ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
)
DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def container_lines(content, prefix, root, role):
    lines = []
    for line in content.splitlines():
        if line.startswith("PartOf="):
            members = [
                value
                for value in line.removeprefix("PartOf=").split()
                if value != f"{prefix}.target"
            ]
            if members:
                lines.append("PartOf=" + " ".join(members))
            continue
        dependency = "secrets-init" if role == "postgres" else "migrate"
        if role in ("postgres", "php-fpm", *BACKGROUND_ROLES) and line in (
            f"Requires={prefix}-{dependency}.service",
            f"After={prefix}-{dependency}.service",
        ):
            continue
        if "target=/run/secpal/quadlet-oneshot-entrypoint.sh" in line:
            continue
        if role == "secrets-init" and line.startswith("Exec="):
            continue
        if line.startswith("Entrypoint="):
            if role == "secrets-init":
                line = 'Entrypoint=["/bin/sh","/run/secpal/init-local-secrets.sh"]'
            elif role == "migrate":
                line = 'Entrypoint=["php"]'
        if role == "migrate" and line.startswith("Exec="):
            line = "Exec=artisan migrate --force"
        if line.startswith("Mount=type=bind,source="):
            source, target = line.removeprefix("Mount=type=bind,source=").split(
                ",target="
            )
            if not source.startswith(f"{root}/assets/") or not target.endswith(
                ",ro=true"
            ):
                raise ValueError("unexpected integration fixture bind mount")
            line = f'Volume={source}:{target.removesuffix(",ro=true")}:ro'
        if line.startswith(f"Volume={prefix}-") and "fpm-socket" not in line:
            line += ",z" if line.endswith(":ro") else ":rw,z"
        lines.append(line)
    if role in ("php-fpm", *BACKGROUND_ROLES):
        lines[1:1] = [
            f"Requires={prefix}-postgres.service",
            f"After={prefix}-postgres.service",
        ]
    return lines


def build(instance, domain=None, bind=None, port=18443, https_port=443):
    INTEGRATION["validate_instance"](instance)
    restore = domain is None and bind is None
    if not restore:
        if (
            not domain
            or len(domain) > 249
            or len(domain.split(".")) < 3
            or not all(DNS_LABEL.fullmatch(label) for label in domain.split("."))
        ):
            raise ValueError(
                "a deployment-specific DNS parent with at least three labels is required"
            )
        if not bind or not any(
            ipaddress.IPv4Address(bind) in network for network in PRIVATE_NETWORKS
        ):
            raise ValueError("the gateway requires an RFC 1918 bind address")
        INTEGRATION["validate_port"](str(port))
        if https_port != 443:
            INTEGRATION["validate_port"](str(https_port))
    prefix = f"secpal-int-{instance}"
    root = Path("/var/lib/secpal-application-poc") / instance
    base = INTEGRATION["build_units"](instance, port, root)
    units = {}
    for name, content in base.items():
        role_file = name.removeprefix(f"{prefix}-")
        if name == f"{prefix}.target" or (restore and role_file not in RESTORE_ROLES):
            continue
        role = role_file.split(".")[0]
        lines = container_lines(content, prefix, root, role)
        if role == "api" and restore:
            lines = [
                line.replace(
                    f"Network={prefix}-edge.network",
                    f"Network={prefix}-application.network",
                )
                for line in lines
            ]
        if role == "gateway":
            lines = [
                line
                for line in lines
                if not line.startswith("Mount=type=tmpfs,destination=/data,")
            ]
            lines = [line for line in lines if not line.startswith("StartLimit")]
            lines[1:1] = ["StartLimitIntervalSec=300", "StartLimitBurst=12"]
            lines = [
                "RestartSec=5" if line == "RestartSec=2" else line for line in lines
            ]
            lines = [
                (
                    f"PublishPort={bind}:{port}:8443"
                    if line.startswith("PublishPort=")
                    else (
                        f"HealthCmd=wget -q -T 3 -O /dev/null https://app.{domain}:8443/health/live"
                        if line.startswith("HealthCmd=")
                        else line
                    )
                )
                for line in lines
            ]
            section = lines.index("[Service]")
            lines[section:section] = [
                f"Volume={prefix}-caddy-data.volume:/data:rw,Z,U",
                f"Volume={root}/tls/fullchain.pem:/etc/caddy/test-fullchain.pem:ro",
                f"Volume={root}/tls/leaf.key:/etc/caddy/test-leaf.key:ro",
            ]
        if role in ("gateway", *BACKGROUND_ROLES):
            lines += ["", "[Install]", "WantedBy=default.target"]
        if not restore:
            endpoint_port = "" if https_port == 443 else f":{https_port}"
            for hostname in ("app", "api"):
                marker = f"{hostname}.secpal.example.invalid:{port}"
                lines = [
                    line.replace(marker, f"{hostname}.{domain}{endpoint_port}")
                    for line in lines
                ]
            lines = [
                line.replace(".secpal.example.invalid", f".{domain}") for line in lines
            ]
        units[name] = "\n".join(lines) + "\n"
    if restore:
        return units, None
    units[f"{prefix}-caddy-data.volume"] = f"[Volume]\nVolumeName={prefix}-caddy-data\n"
    caddy = "{\n    admin off\n    auto_https off\n}\n"
    for host, upstream in (("app", "frontend"), ("api", "api")):
        caddy += (
            f"https://{host}.{domain}:8443 {{\n"
            "    tls /etc/caddy/test-fullchain.pem /etc/caddy/test-leaf.key\n"
            f"    reverse_proxy {upstream}:8080\n"
            "}\n"
        )
    return units, caddy


def write_bundle(destination, units, caddy):
    if destination.exists() or destination.is_symlink():
        raise ValueError("output already exists")
    with tempfile.TemporaryDirectory(dir=destination.parent) as directory:
        staged = Path(directory) / "bundle"
        staged.mkdir(mode=0o700)
        (staged / "assets").mkdir()
        (staged / "units").mkdir()
        for source, target in ASSETS.items():
            shutil.copyfile(ROOT / source, staged / "assets" / target)
        for name, content in units.items():
            (staged / "units" / name).write_text(content, encoding="utf-8")
        if caddy is not None:
            (staged / "assets/Caddyfile").write_text(caddy, encoding="utf-8")
            (staged / "gateway").mkdir()
            shutil.copyfile(
                ROOT / "containers/phase-b-gateway/Containerfile",
                staged / "gateway/Containerfile",
            )
        staged.rename(destination)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--instance", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile", choices=("stack", "restore"), required=True)
    parser.add_argument("--domain")
    parser.add_argument("--bind-ipv4")
    parser.add_argument("--port", type=int, default=18443)
    parser.add_argument("--https-port", type=int, default=443)
    args = parser.parse_args()
    if args.profile == "restore" and (
        args.domain or args.bind_ipv4 or args.port != 18443 or args.https_port != 443
    ):
        parser.error("restore has no ingress settings")
    if args.profile == "stack" and not (args.domain and args.bind_ipv4):
        parser.error("stack requires --domain and --bind-ipv4")
    try:
        write_bundle(
            args.output,
            *build(
                args.instance, args.domain, args.bind_ipv4, args.port, args.https_port
            ),
        )
    except (ValueError, OSError) as error:
        parser.exit(1, f"FCOS application PoC bundle preparation failed: {error}\n")


if __name__ == "__main__":
    main()
