#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Explicit native #101 HTTP-only fixture using the reviewed product Quadlets.

Requires staged immutable product images, native Quadlet and the user manager.
No image pull, credentials, database, public listener or host policy mutation.
This is product transport evidence; host-native HAProxy/SELinux is separate.
"""

import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from product_backend_contract import BACKENDS


def command(operation: str, arguments: list[str], *, environment=None, accepted=(0,)) -> str:
    try:
        result = subprocess.run(arguments, env=environment, capture_output=True,
                                text=True, timeout=200, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError(operation) from error
    if result.returncode not in accepted:
        raise RuntimeError(operation)
    return result.stdout


def main() -> None:
    runtime_spec = importlib.util.spec_from_file_location("quadlet_integration", ROOT / "scripts/quadlet-integration.py")
    runtime = importlib.util.module_from_spec(runtime_spec)
    sys.modules[runtime_spec.name] = runtime
    runtime_spec.loader.exec_module(runtime)
    if any(name in os.environ for name in runtime.FORBIDDEN_RUNTIME_ENVIRONMENT):
        raise RuntimeError("reject-runtime-overrides")
    environment = dict(os.environ)
    environment["XDG_RUNTIME_DIR"] = f"/run/user/{os.getuid()}"
    environment["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={environment['XDG_RUNTIME_DIR']}/bus"
    if os.getuid() == 0:
        raise RuntimeError("require-rootless-user")
    if command("require-enforcing", ["getenforce"]).strip() != "Enforcing":
        raise RuntimeError("require-enforcing")
    info = json.loads(command("observe-local-runtime", ["podman", "--remote=false", "info", "--format", "{{json .Host}}"], environment=environment))
    if (info["security"]["rootless"] is not True or info["serviceIsRemote"] is not False):
        raise RuntimeError("require-rootless-podman")
    command("require-inactive-runtime-api", ["systemctl", "--user", "is-active", "--quiet",
                                              "podman.socket", "podman.service"],
            environment=environment, accepted=(3, 4))
    for backend in BACKENDS.values():
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", backend.host_port))
    spec = importlib.util.spec_from_file_location("production_renderer", ROOT / "scripts/render-production-quadlets.py")
    renderer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(renderer)
    production = renderer.build_units(renderer.load_contract(renderer.DEFAULT_CONTRACT))
    with tempfile.TemporaryDirectory(prefix="backend101-", dir=ROOT / ".context") as temporary:
        directory = Path(temporary)
        prefix = "secpal-" + directory.name
        quadlets = directory / "quadlets"
        generated = directory / "generated"
        quadlets.mkdir()
        generated.mkdir()
        services = []
        for name, content in production.items():
            if name not in {"secpal-api.container", "secpal-frontend.container",
                            "secpal-application.network", "secpal-edge.network"}:
                continue
            # Fixture-only adaptation of the same product role/network model.
            # HTTP liveness requires none of production's data/secret authority.
            lines = [line for line in content.splitlines() if not line.startswith(
                ("Requires=", "After=", "PartOf=", "ExecStartPre=", "Environment=",
                 "Mount=type=bind,", "LogOpt=", "LogDriver=", "Notify=",
                 "HealthCmd=", "HealthInterval=", "HealthTimeout=", "HealthRetries=",
                 "HealthStartPeriod=", "HealthOnFailure="))]
            if name.endswith(".container"):
                # This fixture grades host HTTP directly, independent of the
                # application-state/runtime-health outcome owned elsewhere.
                lines.insert(lines.index("Pull=never"), "Notify=conmon")
                lines.insert(lines.index("Pull=never"), "LogDriver=k8s-file")
                lines.insert(lines.index("Pull=never"), f"LogOpt=path={directory}/{name}.log")
                lines.insert(lines.index("Pull=never"), "LogOpt=max-size=1mb")
                lines.insert(lines.index("[Service]") + 1, "UnsetEnvironment=" + " ".join(runtime.FORBIDDEN_RUNTIME_ENVIRONMENT))
                if name == "secpal-api.container":
                    # Synthetic transport-only material, never product credentials.
                    lines[lines.index("Pull=never"):lines.index("Pull=never")] = [
                        "Environment=APP_ENV=production", "Environment=APP_DEBUG=false",
                        "Environment=APP_KEY=base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                        "Environment=CACHE_STORE=file", "Environment=SESSION_DRIVER=array",
                        "Environment=LOG_CHANNEL=stderr",
                    ]
                else:
                    lines.insert(lines.index("Pull=never"),
                                 "Environment=SECPAL_API_URL=https://api.secpal.example.invalid")
                services.append(name.replace("secpal", prefix, 1).replace(".container", ".service"))
            fixture_name = name.replace("secpal", prefix, 1)
            text = "\n".join(lines).replace("secpal-", prefix + "-") + "\n"
            (quadlets / fixture_name).write_text(text, encoding="utf-8")
        environment["QUADLET_UNIT_DIRS"] = str(quadlets)
        command("generate-native-quadlets", ["/usr/lib/systemd/user-generators/podman-user-generator",
                                             str(generated), str(generated), str(generated)],
                environment=environment)
        linked = []
        try:
            for unit in generated.glob("*.service"):
                command("link-fixture-service", ["systemctl", "--user", "link", "--runtime", str(unit)], environment=environment)
                linked.append(unit.name)
            command("reload-fixture-services", ["systemctl", "--user", "daemon-reload"], environment=environment)
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            for iteration in range(3):
                if iteration:
                    command("stop-product-fixture", ["systemctl", "--user", "stop", *services], environment=environment)
                for service in services:
                    role = "frontend" if "frontend" in service else "api"
                    command("start-product-" + role, ["systemctl", "--user", "start", service], environment=environment)
                listeners = command("observe-fixed-listeners", ["ss", "-H", "-lnt"])
                for role, backend in BACKENDS.items():
                    matches = [line.split()[3] for line in listeners.splitlines()
                               if line.split()[3].endswith(f":{backend.host_port}")]
                    if matches != [backend.endpoint]:
                        raise RuntimeError("admit-exact-loopback-listeners")
                    try:
                        deadline = time.monotonic() + 30
                        while True:
                            try:
                                with opener.open(f"http://{backend.endpoint}{backend.readiness_path}", timeout=5) as response:
                                    if response.status != 200:
                                        raise RuntimeError("admit-product-http-readiness")
                                break
                            except (OSError, urllib.error.URLError):
                                if time.monotonic() >= deadline:
                                    raise RuntimeError("probe-product-http-readiness")
                                time.sleep(1)
                    except (OSError, urllib.error.URLError) as error:
                        raise RuntimeError("probe-product-http-readiness") from error
                    context = command("observe-product-selinux", ["podman", "--remote=false", "inspect", "--format", "{{.ProcessLabel}}", prefix + "-" + role], environment=environment).strip()
                    if ":container_t:" not in context:
                        raise RuntimeError("admit-product-selinux")
        finally:
            for unit in linked:
                command("stop-fixture-service", ["systemctl", "--user", "stop", unit], environment=environment)
                command("unlink-fixture-service", ["systemctl", "--user", "disable", unit], environment=environment)
                command("clear-fixture-failed-state", ["systemctl", "--user", "reset-failed", unit], environment=environment, accepted=(0, 1))
            command("reload-after-fixture", ["systemctl", "--user", "daemon-reload"], environment=environment)
            for network in ("edge", "application"):
                command("remove-fixture-network", ["podman", "--remote=false", "network", "rm", prefix + "-" + network], environment=environment, accepted=(0, 1))
    print(json.dumps({"result": "PASS", "kind": "PRODUCT_HTTP_TRANSPORT",
                      "selinux": "Enforcing", "iterations": 3,
                      "endpoints": {role: backend.endpoint for role, backend in BACKENDS.items()},
                      "host_haproxy_policy_qualified": False}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
