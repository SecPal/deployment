#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT
"""Prepare a disposable FCOS application stack or an internal restore bundle."""

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from haproxy_base_contract import Routing, routing_sections, runtime_preamble
import fcos_lab_security

INTEGRATION = runpy.run_path(str(ROOT / "scripts/render-integration-quadlets.py"))
HAPROXY_IMAGE = "docker.io/library/haproxy@sha256:5ddf08c89c95a311f4bfb761d74016597fdca76ecfcdf169ed1bab117f3da1ea"
HAPROXY_CONFIG = "/usr/local/etc/haproxy/haproxy.cfg"
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
DATABASE_ASSETS = {
    "scripts/fcos-poc-db-roles.sh": "fcos-poc-db-roles.sh",
    "scripts/production-migrate.php": "production-migrate.php",
}
DATABASE_DIAGNOSTIC_PREFIX = "fcos-db-roles."
# SecPal/.github protected main a9a502fb8c07580074852fc0689a10cd732ab290.
VALIDATOR_SOURCE = {
    "scripts/secpal-evidence-architecture.py": "75b8b70bf386284ead5a3e92289fdfb07a1fa914580037b0667c28eea8e7222e",
    "scripts/secpal_evidence_architecture/__init__.py": "6f2a2ab09af8a78df93f65e6e3c32df59e3c054468fde0b999b6a9fd6efab096",
    "scripts/secpal_evidence_architecture/execution.py": "997ceb8472f531b3bd427b6cbe6171135c79f07f4b72fd91eb41cbf9f8facc6c",
    "scripts/secpal_evidence_architecture/governance.py": "853c0f813fd356e81c5c00612c4aa6b961c3f8016e498c2537d61dee6e66461f",
    "scripts/secpal_evidence_architecture/markdown_references.mjs": "5952dbd7116e965ec0ee7bbf1c634afea4d0d6a77261670a5f3588ec8f0c2b00",
    "package.json": "ee6cac84272c0806c4e69e6acaef318487e65e1e4cc513c467b78268f19703b8",
    "package-lock.json": "3f5a76b90b0c3403c7b7e25ce20912db79693664a31afab1ccbc3cb77f17dd28",
}


def database_diagnostic_ids(helper, prefix=DATABASE_DIAGNOSTIC_PREFIX):
    stages = re.findall(r"^\s*stage=([a-z][a-z-]+)$", helper, flags=re.MULTILINE)
    if not stages or len(stages) != len(set(stages)):
        raise ValueError("database role diagnostic coverage is incomplete")
    return {prefix + stage for stage in stages}


def validate_database_diagnostics(helper, declaration, prefix=DATABASE_DIAGNOSTIC_PREFIX):
    expected = database_diagnostic_ids(helper, prefix)
    operations = [
        entry
        for entry in declaration["external_operations"]
        if entry["id"].startswith(prefix)
    ]
    observed = {
        entry["id"]
        for entry in operations
        if entry["reachable"] is True
        and entry["fallible"] is True
        and entry["trusted"] is True
        and entry["diagnostic_identity"] == {"id": entry["id"], "kind": "semantic"}
    }
    if len(operations) != len(expected) or observed != expected:
        raise ValueError("database role diagnostic coverage is incomplete")


def admit_database_dispatch(validator, *, schema_rehearsal=False):
    validate_database_diagnostics(
        (ROOT / "scripts/fcos-poc-db-roles.sh").read_text(encoding="utf-8"),
        json.loads(
            (ROOT / ".secpal/evidence-architecture.json").read_text(encoding="utf-8")
        ),
    )
    if schema_rehearsal:
        validate_database_diagnostics(
            (ROOT / "scripts/fcos-lab-compare-restored-schema.sh").read_text(encoding="utf-8"),
            json.loads((ROOT / ".secpal/evidence-architecture.json").read_text(encoding="utf-8")),
            "fcos-schema-rehearsal.",
        )
    if (
        validator is None
        or validator.name != "secpal-evidence-architecture.py"
        or not validator.is_file()
    ):
        raise ValueError(
            "least privilege requires the maintained evidence architecture validator"
        )
    validator = validator.absolute()
    if validator.parent.name != "scripts":
        raise ValueError(
            "database role evidence validator source is outside the pinned layout"
        )
    checkout = validator.parent.parent
    for relative, expected in VALIDATOR_SOURCE.items():
        path = checkout / relative
        if not path.is_file() or path.is_symlink():
            raise ValueError("database role evidence validator source is incomplete")
        with path.open("rb") as source:
            content = source.read(65_537)
        if len(content) > 65_536 or hashlib.sha256(content).hexdigest() != expected:
            raise ValueError(
                "database role evidence validator source differs from the pin"
            )
    try:
        accepted = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                str(validator),
                "--repository-root",
                str(ROOT),
                "--repository",
                "SecPal/deployment",
                "--dispatch",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=60,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise ValueError(
            "database role evidence dispatch admission timed out"
        ) from None
    if accepted.returncode != 0:
        raise ValueError("database role evidence dispatch admission rejected")


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


def database_role_mounts(lines, prefix, root, role):
    source = f"{prefix}-secrets.volume"

    def mount(subpath, destination):
        return (
            f"Mount=type=volume,source={source},target={destination},"
            f"subpath={subpath},ro=true,relabel=shared"
        )

    if role == "postgres":
        old = f"Volume={source}:/run/secpal-secrets:ro,z"
        lines[lines.index(old)] = mount("postgresql", "/run/secpal-secrets/postgresql")
        lines = [
            line.replace("secpal_local", "secpal_fixture_admin").replace(
                "/run/secpal-secrets/postgres-password",
                "/run/secpal-secrets/postgresql/bootstrap-password",
            )
            for line in lines
        ]
        lines.insert(
            lines.index("[Container]") + 1,
            "Label=org.secpal.fcos.database-roles=separated",
        )
        lines = [
            (
                f"{line} -c log_connections=authorization"
                if line.startswith("Exec=")
                else line
            )
            for line in lines
        ]
    if role in ("migrate", "php-fpm", *BACKGROUND_ROLES):
        old = f"Volume={source}:/run/secpal/secrets:ro,z"
        credential = "migration" if role == "migrate" else "runtime"
        index = lines.index(old)
        lines[index : index + 1] = [
            mount("api", "/run/secpal/secrets/api"),
            mount(f"{credential}-database", "/run/secpal/secrets/database"),
            "Environment=DB_SSLMODE=verify-full",
            "Environment=DB_SSLROOTCERT=/run/secpal/secrets/database/postgres-ca.crt",
        ]
        lines = [
            (
                f"Environment=DB_USERNAME=secpal_poc_{'migrate' if role == 'migrate' else 'runtime'}"
                if line.startswith("Environment=DB_USERNAME=")
                else line
            )
            for line in lines
        ]
        if role == "migrate":
            lines[lines.index("Exec=artisan migrate --force")] = (
                "Exec=/run/secpal/production-migrate.php"
            )
            lines.insert(
                lines.index("[Service]"),
                f"Volume={root}/assets/production-migrate.php:/run/secpal/production-migrate.php:ro",
            )
    return lines


def haproxy_gateway(instance, root, domain, bind, port, https_port, *, appsec=False):
    prefix = f"secpal-int-{instance}"
    name = f"{prefix}-gateway"
    section = INTEGRATION["section"]
    logging = ["LogDriver=journald"]
    mounts = []
    if appsec:
        logging = ["LogDriver=k8s-file", f"LogOpt=path={root}/security/audit/haproxy.log",
                   "LogOpt=max-size=16mb"]
        mounts.append(f"Volume={root}/security/spoe:/run/secpal-spoa:ro")
    dependencies = f"{name}.socket {prefix}-api.service {prefix}-frontend.service"
    unit = section("Unit", [
        "Description=SecPal FCOS lab HAProxy",
        f"Requires={dependencies}",
        f"After={dependencies}",
        "StartLimitIntervalSec=300",
        "StartLimitBurst=12",
    ]) + section("Container", [
        f"ContainerName={name}",
        f"Image={HAPROXY_IMAGE}",
        "Pull=never",
        "User=99",
        "Group=99",
        "ReadOnly=true",
        "ReadOnlyTmpfs=false",
        "DropCapability=all",
        "NoNewPrivileges=true",
        *logging,
        "PodmanArgs=--preserve-fds=1",
        "Environment=SECPAL_TLS_SOCKET=fd@3",
        f"Label=org.secpal.integration.instance={instance}",
        "Label=org.secpal.role=gateway",
        f"Network={prefix}-edge.network",
        f"Volume={root}/edge:/usr/local/etc/haproxy:ro",
        f"Volume={root}/tls:/run/secpal-viewer:ro",
        *mounts,
        "Entrypoint=/usr/local/sbin/haproxy",
        f"Exec=-W -db -f {HAPROXY_CONFIG}",
    ]) + section("Service", [
        f"Sockets={name}.socket",
        "Restart=on-failure",
        "RestartSec=5",
        f"ExecReload=/usr/bin/podman exec --user 99:99 --env SECPAL_TLS_SOCKET=127.0.0.1:{port} {name} haproxy -c -f {HAPROXY_CONFIG}",
        f"ExecReload=/usr/bin/podman kill --signal=USR2 {name}",
    ]) + section("Install", ["WantedBy=default.target"])
    socket = section("Unit", ["Description=SecPal FCOS lab HTTPS socket"]) + section(
        "Socket", [f"ListenStream={bind}:{port}", "FreeBind=true", "Accept=false"]
    )
    preamble = runtime_preamble(direct_tcp_peer=True)
    if appsec:
        preamble = preamble.replace("tune.bufsize 16384", "tune.bufsize 65536")
    listener = (
        "resolvers podman\n"
        "    parse-resolv-conf\n"
        "    hold valid 1s\n\n"
        "frontend secpal_viewer\n"
        '    bind "$SECPAL_TLS_SOCKET" ssl crt /run/secpal-viewer/viewer.pem strict-sni ssl-min-ver TLSv1.2 alpn h2,http/1.1\n'
    )
    if appsec:
        listener += ("    option http-buffer-request\n"
                     "    filter spoe engine crowdsec config /usr/local/etc/haproxy/spoe.cfg\n")
    config = preamble + listener + routing_sections(
        Routing(f"app.{domain}", f"api.{domain}"),
        fixture_network=True,
        fixture_https_port=https_port,
        normalize_http2=True,
        inspection_rules=fcos_lab_security.INSPECTION if appsec else (),
        identity_rules=(
            "http-request set-header X-Forwarded-For %[src]",
            "http-request set-header X-Forwarded-Proto https",
            f"http-request set-header X-Forwarded-Port {https_port}",
            "http-request set-header X-Forwarded-Host %[req.hdr(host)]",
            "http-request set-header X-Request-ID %[unique-id]",
        ),
    )
    units = {f"{name}.container": unit, f"{name}.socket": socket}
    if appsec:
        config += "\nbackend secpal_spoa\n    mode tcp\n    server spoa /run/secpal-spoa/spoa.sock\n"
        units.update(fcos_lab_security.render_units(prefix, root / "security", section))
    return units, config


def build(
    instance,
    domain=None,
    bind=None,
    port=18443,
    https_port=443,
    *,
    least_privilege=False,
    gateway="caddy",
    appsec=False,
):
    INTEGRATION["validate_instance"](instance)
    restore = domain is None and bind is None
    if appsec and gateway != "haproxy":
        raise ValueError("AppSec requires the HAProxy profile")
    if gateway not in {"caddy", "haproxy"} or (restore and gateway != "caddy"):
        raise ValueError("invalid gateway for the selected profile")
    if gateway == "haproxy" and not least_privilege:
        raise ValueError("the HAProxy stack requires separate database authorities")
    if restore and least_privilege:
        raise ValueError("least-privilege qualification requires the stack profile")
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
        if role == "gateway" and gateway == "haproxy":
            continue
        lines = container_lines(content, prefix, root, role)
        if least_privilege and name.endswith(".container"):
            lines = database_role_mounts(lines, prefix, root, role)
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
    if gateway == "haproxy":
        edge_units, config = haproxy_gateway(instance, root, domain, bind, port, https_port,
                                             appsec=appsec)
        return units | edge_units, config
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


def write_bundle(destination, units, config, *, least_privilege=False, gateway="caddy", appsec=False):
    if destination.exists() or destination.is_symlink():
        raise ValueError("output already exists")
    with tempfile.TemporaryDirectory(dir=destination.parent) as directory:
        staged = Path(directory) / "bundle"
        staged.mkdir(mode=0o700)
        (staged / "assets").mkdir()
        (staged / "units").mkdir()
        if appsec:
            (staged / "security-units").mkdir()
        assets = ASSETS | DATABASE_ASSETS if least_privilege else ASSETS
        for source, target in assets.items():
            shutil.copyfile(ROOT / source, staged / "assets" / target)
        for name, content in units.items():
            group = "security-units" if name.endswith(fcos_lab_security.SECURITY_UNITS) else "units"
            (staged / group / name).write_text(content, encoding="utf-8")
        if config is not None and gateway == "haproxy":
            (staged / "edge").mkdir()
            (staged / "edge/haproxy.cfg").write_text(config, encoding="utf-8")
            for socket in (staged / "units").glob("*.socket"):
                socket.rename(staged / "edge" / socket.name)
            if appsec:
                shutil.copytree(fcos_lab_security.ASSETS / "config", staged / "security-config")
                shutil.copyfile(fcos_lab_security.ASSETS / "spoe.cfg", staged / "edge/spoe.cfg")
        elif config is not None:
            (staged / "assets/Caddyfile").write_text(config, encoding="utf-8")
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
    parser.add_argument("--gateway", choices=("caddy", "haproxy"), default="caddy")
    parser.add_argument("--appsec", action="store_true")
    parser.add_argument("--least-privilege", action="store_true")
    parser.add_argument("--evidence-validator", type=Path)
    args = parser.parse_args()
    if args.profile == "restore" and (
        args.domain or args.bind_ipv4 or args.port != 18443 or args.https_port != 443
    ):
        parser.error("restore has no ingress settings")
    if args.profile == "stack" and not (args.domain and args.bind_ipv4):
        parser.error("stack requires --domain and --bind-ipv4")
    try:
        bundle = build(
            args.instance,
            args.domain,
            args.bind_ipv4,
            args.port,
            args.https_port,
            least_privilege=args.least_privilege,
            gateway=args.gateway,
            appsec=args.appsec,
        )
        if args.least_privilege:
            admit_database_dispatch(args.evidence_validator)
        write_bundle(args.output, *bundle, least_privilege=args.least_privilege, gateway=args.gateway,
                     appsec=args.appsec)
    except (ValueError, OSError) as error:
        parser.exit(1, f"FCOS application PoC bundle preparation failed: {error}\n")


if __name__ == "__main__":
    main()
