#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT
"""Render non-secret FCOS bootstrap inputs; never connect to or install a host."""

import argparse
import base64
import ipaddress
import json
from pathlib import Path
import re
import sys


class Invalid(ValueError):
    """A closed preparation input is invalid; values are not diagnostics."""


def check(condition):
    if not condition:
        raise Invalid("fcos.input.invalid")


def admit(settings):
    keys = {
        "architecture",
        "installation_id",
        "hostname",
        "ssh_public_key",
        "mac",
        "ipv4",
        "ipv4_gateway",
        "ipv6",
        "ipv6_gateway",
        "dns_servers",
    }
    check(type(settings) is dict and set(settings) == keys)
    check(
        type(settings["architecture"]) is str
        and settings["architecture"] in {"x86_64", "aarch64"}
    )
    for key, pattern in [
        ("installation_id", r"[0-9a-f]{32}"),
        ("hostname", r"[a-z][a-z0-9-]{0,62}"),
        ("mac", r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}"),
    ]:
        check(type(settings[key]) is str and re.fullmatch(pattern, settings[key]))
    check(settings["installation_id"] != "0" * 32)
    check(
        type(settings["ssh_public_key"]) is str
        and re.fullmatch(
            r"ssh-ed25519 [A-Za-z0-9+/]+={0,2}", settings["ssh_public_key"]
        )
    )
    try:
        public = base64.b64decode(settings["ssh_public_key"].split()[1], validate=True)
        check(
            len(public) == 51
            and public[:19] == b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"
        )
        for name, version in [("ipv4", 4), ("ipv6", 6)]:
            check(
                type(settings[name]) is str
                and re.fullmatch(r"[0-9a-fA-F:.]+/[0-9]{1,3}", settings[name])
            )
            value = ipaddress.ip_interface(settings[name])
            check(
                value.version == version
                and not value.ip.is_unspecified
                and value.network.prefixlen > 0
            )
            check(
                type(settings[name + "_gateway"]) is str
                and re.fullmatch(r"[0-9a-fA-F:.]+", settings[name + "_gateway"])
            )
            gateway = ipaddress.ip_address(settings[name + "_gateway"])
            check(gateway.version == version and not gateway.is_unspecified)
        check(
            type(settings["dns_servers"]) is list
            and 1 <= len(settings["dns_servers"]) <= 4
        )
        for address in settings["dns_servers"]:
            check(
                type(address) is str
                and re.fullmatch(r"[0-9a-fA-F:.]+", address)
                and not ipaddress.ip_address(address).is_unspecified
            )
    except (ValueError, TypeError, KeyError, AttributeError):
        raise Invalid("fcos.input.invalid") from None
    return dict(settings)


def fixture(architecture):
    public = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes(range(32))
    return {
        "architecture": architecture,
        "installation_id": "1" * 32,
        "hostname": "fcos-qualification-fixture",
        "ssh_public_key": "ssh-ed25519 " + base64.b64encode(public).decode(),
        "mac": "02:00:00:00:00:01",
        "ipv4": "192.0.2.10/32",
        "ipv4_gateway": "192.0.2.1",
        "ipv6": "2001:db8:1::1/64",
        "ipv6_gateway": "fe80::1",
        "dns_servers": ["192.0.2.53", "2001:db8::53"],
    }


def render(settings, lock, state):
    s = admit(settings)
    check(s["architecture"] in lock["architectures"])
    mapping = state["rootless_mapping"]
    user = "secpal-runtime"
    files = []

    def file(path, contents, mode=0o644, overwrite=True):
        files.append(
            {
                "path": path,
                "mode": mode,
                "overwrite": overwrite,
                "contents": {"inline": contents},
            }
        )

    file("/etc/hostname", s["hostname"] + "\n")
    file("/etc/secpal/installation-id", s["installation_id"] + "\n")
    # A prefilled machine-id suppresses systemd FirstBoot/preset semantics.
    # Pin the fresh incarnation via the native kernel parameter instead.
    file("/etc/machine-id", "uninitialized\n", 0o444)
    file(
        "/etc/zincati/config.d/90-secpal-controlled.toml",
        "[updates]\nenabled = false\n",
    )
    file(
        "/etc/ssh/sshd_config.d/20-secpal.conf",
        "PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin no\n",
    )
    file("/etc/modules-load.d/secpal-wireguard.conf", "wireguard\n")
    file("/etc/subuid", f"{user}:{mapping['uid_start']}:{mapping['count']}\n")
    file("/etc/subgid", f"{user}:{mapping['gid_start']}:{mapping['count']}\n")
    file("/var/lib/systemd/linger/" + user, "")
    file(
        "/etc/NetworkManager/system-connections/secpal-underlay.nmconnection",
        f"""[connection]
id=secpal-underlay
type=ethernet
autoconnect=true
[ethernet]
mac-address={s['mac']}
[ipv4]
method=manual
address1={s['ipv4']},{s['ipv4_gateway']}
route1={s['ipv4_gateway']}/32,0.0.0.0
dns={';'.join(a for a in s['dns_servers'] if ':' not in a)};
may-fail=false
[ipv6]
method=manual
address1={s['ipv6']},{s['ipv6_gateway']}
dns={';'.join(a for a in s['dns_servers'] if ':' in a)};
may-fail=false
""",
        0o600,
    )
    file(
        "/etc/tmpfiles.d/secpal-foundation.conf",
        # Match production-state.py initialize_production: root-owned public
        # ancestors permit traversal; individual state directories stay private.
        f"""d /srv/secpal 0755 root root -
d /srv/secpal/runtime 0700 {user} {user} -
d /srv/secpal/application-state 0700 root root -
d /var/lib/secpal/bootstrap 0700 root root -
d /etc/containers/systemd/users/{mapping['service_uid']} 0755 root root -
""",
    )
    return {
        "variant": "fcos",
        "version": lock["butane"]["spec"],
        "kernel_arguments": {
            "should_exist": [
                "enforcing=1",
                "systemd.machine_id=" + s["installation_id"],
            ],
            "should_not_exist": ["selinux=0", "enforcing=0"],
        },
        "passwd": {
            "groups": [{"name": user, "gid": mapping["service_gid"]}],
            "users": [
                {
                    "name": user,
                    "uid": mapping["service_uid"],
                    "primary_group": user,
                    "shell": "/usr/sbin/nologin",
                    "no_create_home": False,
                    "home_dir": "/var/home/" + user,
                },
                {"name": "core", "ssh_authorized_keys": [s["ssh_public_key"]]},
            ],
        },
        "storage": {
            "files": files,
            "directories": [],
            "links": [
                {
                    "path": "/etc/systemd/system/multi-user.target.wants/network-online.target",
                    "target": "/usr/lib/systemd/system/network-online.target",
                }
            ],
        },
        "systemd": {"units": []},
    }


def qualification(settings, lock):
    """Prepare the existing disposable fixture; do not activate a workload."""
    s = admit(settings)
    image = lock["installer"][s["architecture"] + "_manifest"]
    check(type(image) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", image))
    return {
        "quadlet": f"""[Unit]
Description=SecPal rootless FCOS persistence qualification
StartLimitIntervalSec=60
StartLimitBurst=3
[Container]
Image=quay.io/coreos/coreos-installer@{image}
Pull=never
ContainerName=secpal-qualification
Entrypoint=/usr/bin/sh
Exec=/state/run.sh
Network=none
Volume=/srv/secpal/runtime/qualification:/state:Z
ReadOnly=true
NoNewPrivileges=true
DropCapability=ALL
[Service]
Restart=on-failure
RestartSec=2
TimeoutStartSec=90
MemoryMax=96M
TasksMax=64
[Install]
WantedBy=default.target
""",
        "script": "#!/usr/bin/sh\nset -eu\numask 077\n"
        "if ! test -e /state/marker; then\n"
        f" printf '%s\\n' '{s['installation_id']}' > /state/marker\n"
        "fi\nexec /usr/bin/sleep infinity\n",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--settings", type=Path)
    parser.add_argument("--fixture", choices=["x86_64", "aarch64"])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        check(bool(args.settings) != bool(args.fixture))
        root = Path(__file__).resolve().parents[1]
        settings = (
            fixture(args.fixture)
            if args.fixture
            else json.loads(args.settings.read_text())
        )
        result = render(
            settings,
            json.loads((root / "config/fcos/artifacts.json").read_text()),
            json.loads((root / "config/production/state-contract.json").read_text()),
        )
        # JSON is also YAML; feed this exact output to pinned Butane --strict.
        with args.output.open("x") as out:
            json.dump(result, out, indent=2)
            out.write("\n")
        print(
            json.dumps(
                {
                    "code": "fcos.prepared",
                    "execution_authorized": False,
                    "qualification_fixture": bool(args.fixture),
                }
            )
        )
        return 0
    except Exception:
        print('{"code":"fcos.prepare.failed"}')
        return 1


if __name__ == "__main__":
    sys.exit(main())
