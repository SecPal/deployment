# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""CrowdSec services for the private FCOS application fixture."""

from pathlib import Path


ASSETS = Path(__file__).resolve().parents[1] / "config/quadlet/fcos-security"
ENGINE = "docker.io/crowdsecurity/crowdsec@sha256:a5642c72127ee93aaac830e9f66891573fa7851b2c721987d9fef13d7d05fdfe"
SPOA = "ghcr.io/crowdsecurity/spoa-bouncer@sha256:9d01409b5f9923ee8022800c12dc3cee3d82c1e131f82f4504c909369405bd22"
SECURITY_UNITS = ("-security.network", "-crowdsec.container", "-spoa.container")


def container(section, name, network, image, role, container_options, dependencies=()):
    unit_options = [f"Description=SecPal FCOS lab {role}"]
    if dependencies:
        units = " ".join(dependencies)
        unit_options.extend((f"Wants={units}", f"After={units}"))
    return (
        section("Unit", unit_options)
        + section("Container", [
            f"ContainerName={name}", f"Image={image}", f"Network={network}",
            "Pull=never", "User=65532", "Group=65532", "ReadOnly=true",
            "ReadOnlyTmpfs=false", "DropCapability=all", "NoNewPrivileges=true",
            "PodmanArgs=--image-volume=ignore",
            "LogDriver=journald", f"Label=org.secpal.role={role}",
            *container_options,
        ])
        + section("Service", ["Restart=on-failure", "RestartSec=4"])
        + section("Install", ["WantedBy=default.target"])
    )


def render_units(prefix, root, section):
    engine = f"{prefix}-crowdsec"
    spoa = f"{prefix}-spoa"
    network = f"{prefix}-security.network"
    return {
        network: section("Network", [f"NetworkName={prefix}-security", "Internal=true"]),
        f"{engine}.container": container(section, engine, network, ENGINE, "crowdsec", [
            "NetworkAlias=engine",
            f"Volume={root}/config:/etc/crowdsec:ro",
            f"Volume={root}/state:/state:rw",
            f"Volume={root}/audit:/logs:ro",
            "Tmpfs=/tmp:rw,nosuid,nodev,noexec",
            "Entrypoint=/usr/local/bin/crowdsec",
            "Exec=-c /etc/crowdsec/config.yaml",
        ]),
        f"{spoa}.container": container(section, spoa, network, SPOA, "spoa", [
            f"Volume={root}/spoe:/run/secpal-spoa:rw",
            f"Volume={root}/credentials:/run/secpal-credentials:ro",
            "Exec=-c /run/secpal-credentials/spoa.yaml",
        ], dependencies=(f"{engine}.service",)),
    }


INSPECTION = (
    "acl within_inspection_limit req.body_size le 32768",
    "http-request send-spoe-group crowdsec crowdsec-http-body if within_inspection_limit",
    "http-request send-spoe-group crowdsec crowdsec-http-no-body unless within_inspection_limit",
    "http-request set-var(txn.security) str(appsec_headers_only) unless within_inspection_limit",
    "http-request set-var(txn.security) str(security_degraded) if { var(txn.crowdsec.error) -m found }",
    "http-request set-var(txn.security) str(appsec_blocked) if { var(txn.crowdsec.remediation) -m str ban }",
    "http-request deny deny_status 403 if { var(txn.crowdsec.remediation) -m str ban }",
)
