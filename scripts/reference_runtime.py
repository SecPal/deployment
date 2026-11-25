# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""The fixed host operations for the two public reference workloads."""

from dataclasses import dataclass
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import tempfile
import time
from urllib.error import HTTPError
from urllib.parse import unquote
from urllib.request import HTTPCookieProcessor, HTTPRedirectHandler, ProxyHandler, Request, build_opener

STATE = Path("/var/lib/secpal-reference-update")
QUADLETS = Path("/etc/containers/systemd/users")
EDGE = Path("/etc/haproxy/secpal.cfg")
REFERENCE_CONFIG = Path("/var/lib/secpal-reference/config")
FPM_POOL = REFERENCE_CONFIG / "zz-fpm-session.conf"
SOURCE_OFFER = REFERENCE_CONFIG / "source-offer.json"
# Frontend #1788 records the adopted OpenAPI source. The later OpenPLZ types
# added in #1935 already exist in this published specification.
CONTRACTS_SOURCE = "f8771b74d887b84b84dcc94e2405df7b47222466"
SYNTHETIC_PASSWORD = Path("/etc/secpal/reference-update-witness")
FRONT = "https://app.secpal.dev"
API = "https://api.secpal.dev"
NATIVE = "linux/amd64"
ROLE = {
    "secpal-frontend": "frontend", "secpal-api": "nginx", "secpal-php-fpm": "php-fpm",
    "secpal-scheduler": "php-fpm", "secpal-worker-general": "php-fpm",
    "secpal-worker-hash-chain": "php-fpm", "secpal-migrate": "php-fpm",
}
ACCOUNTS = {"frontend": ("secpal-app", 20004), "api": ("secpal-api", 20005),
            "postgres": ("secpal-pg", 20006), "artifact": ("codex", 1001)}
UNITS = {"frontend": ("secpal-frontend",),
         "api": ("secpal-api", "secpal-php-fpm", "secpal-scheduler", "secpal-worker-general",
                 "secpal-worker-hash-chain", "secpal-migrate")}
ENV = {"PATH": "/usr/sbin:/usr/bin", "HOME": "/root", "LANG": "C.UTF-8"}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def run(arguments, *, data=None, timeout=30, output=subprocess.PIPE):
    return subprocess.run(arguments, input=data, stdin=subprocess.DEVNULL if data is None else None,
                          stdout=output, stderr=subprocess.DEVNULL, env=ENV, timeout=timeout,
                          check=True).stdout


def as_user(target, arguments):
    account, uid = ACCOUNTS[target]
    identity = pwd.getpwnam(account)
    if identity.pw_uid != uid or identity.pw_dir != f"/var/home/{account}":
        raise ValueError("unexpected reference account identity")
    return ["/usr/sbin/runuser", "-u", account, "--", "/usr/bin/env", "-i",
            "PATH=/usr/bin:/bin", "LANG=C.UTF-8", f"HOME=/var/home/{account}",
            f"XDG_RUNTIME_DIR=/run/user/{uid}", f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus",
            *arguments]


def podman(target, *arguments, **options):
    return run(as_user(target, ["/usr/bin/podman", *arguments]), **options)


def unit(target, *arguments, **options):
    return run(as_user(target, ["/usr/bin/systemctl", "--user", *arguments]), **options)


def protected(path):
    details = path.lstat()
    if not stat.S_ISREG(details.st_mode) or details.st_uid != 0 or details.st_mode & 0o022:
        raise ValueError("expected a root-owned, non-writable regular file")
    return path.read_bytes()


def lanepaths(target):
    if target not in UNITS:
        raise ValueError("unknown reference workload")
    folder = QUADLETS / str(ACCOUNTS[target][1])
    meta = folder.lstat()
    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o022:
        raise ValueError("unexpected Quadlet directory attributes")
    return {name: folder / (name + ".container") for name in UNITS[target]}


def render_pin(text, old, new):
    if re.findall(r"(?m)^Image=(.*)$", text) != [old] or re.findall(r"(?m)^Pull=(.*)$", text) != ["never"]:
        raise ValueError("Quadlet image differs from the enrolled runtime")
    return re.sub(r"(?m)^Image=.*$", "Image=" + new, text)


def source_archive(repository, source):
    if re.fullmatch(r"[a-f0-9]{40}", source) is None:
        raise ValueError("invalid corresponding source revision")
    return f"https://codeload.github.com/SecPal/{repository}/tar.gz/{source}"


def api_release(source):
    return {"version": "git." + source, "source_url": source_archive("api", source)}


def source_offer(source):
    return {"version": 1, "repositories": {
        "frontend": {"sourceUrl": source_archive("frontend", source)},
        "contracts": {"sourceUrl": source_archive("contracts", CONTRACTS_SOURCE)},
    }}


def render_api_release(text, source):
    if re.findall(r"(?m)^\[.*\]$", text) != ["[secpal]"]:
        raise ValueError("unexpected reference FPM pool")
    release = api_release(source)
    text = re.sub(r"(?m)^env\[BOOTSTRAP_API_RELEASE_(?:VERSION|SOURCE_URL)\][ 	]*=.*(?:\n|$)", "", text)
    return (text.rstrip() + "\n"
            + "env[BOOTSTRAP_API_RELEASE_VERSION]=" + release["version"] + "\n"
            + "env[BOOTSTRAP_API_RELEASE_SOURCE_URL]=" + release["source_url"] + "\n")


def replace_protected_config(path, content):
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix="." + path.name + ".", delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
            os.chmod(temporary, stat.S_IMODE(path.stat().st_mode))
            run(["/usr/bin/chcon", f"--reference={path}", temporary])
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


@dataclass(frozen=True)
class Container:
    image: str
    source: str
    digest: str


def image_data(target, image):
    if not re.fullmatch(r"(?:sha256:)?[a-f0-9]{64}|ghcr\.io/secpal/(?:frontend|api)@sha256:[a-f0-9]{64}", image):
        raise ValueError("unexpected reference image lookup")
    data = podman(target, "image", "inspect", "--format",
                  '{{.Digest}} {{.Architecture}} {{index .Labels "org.opencontainers.image.revision"}}', image)
    digest, arch, source = data.decode().split()
    if arch != "amd64" or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None or re.fullmatch(r"[a-f0-9]{40}", source) is None:
        raise ValueError("unexpected running OCI image identity")
    return source, digest


def migration_state():
    data = unit("api", "show", "-p", "ActiveState", "-p", "SubState", "-p", "InvocationID", "secpal-migrate.service")
    state = dict(line.split("=", 1) for line in data.decode().splitlines())
    if (state["ActiveState"], state["SubState"]) not in {("inactive", "dead"), ("active", "exited")}:
        raise ValueError("reference migration unit is not idle")
    return state


def observe(target):
    observed = {}
    for name, path in lanepaths(target).items():
        text = protected(path).decode()
        ref, = re.findall(r"(?m)^Image=(.*)$", text)
        repository = f"ghcr.io/secpal/{target}"
        if not re.fullmatch(re.escape(repository) + r"@sha256:[a-f0-9]{64}", ref):
            raise ValueError("unexpected reference pin")
        if name != "secpal-migrate":
            running, config, started = podman(target, "inspect", "--format",
                                              "{{.ImageName}} {{.Image}} {{.State.Running}}", name).decode().split()
            if running != ref or started != "true":
                raise ValueError("running container differs from its Quadlet pin")
            source, digest = image_data(target, config)
            if ref != f"{repository}@{digest}":
                raise ValueError("reference pin is not the running native image")
            item = Container(ref, source, digest)
            role = ROLE[name]
            if role in observed and item != observed[role]:
                raise ValueError("reference runtime roles disagree")
            observed[role] = item
        else:
            migration_state()
    return observed


def exposure(target=None, *, live=True):
    configs = {}
    targets = tuple(UNITS) if target is None else (target,)
    for reference in targets:
        target = reference
        for name, path in lanepaths(target).items():
            text = protected(path).decode()
            ports = re.findall(r"(?m)^PublishPort=(.*)$", text)
            expected = {"secpal-frontend": ["127.0.0.1:18080:8080/tcp"],
                        "secpal-api": ["127.0.0.1:18081:8080/tcp"]}.get(name, [])
            if ports != expected or "NoNewPrivileges=true" not in text.splitlines():
                raise ValueError("reference direct exposure differs")
            configs[name] = hashlib.sha256(re.sub(r"(?m)^Image=.*$", "Image=", text).encode()).hexdigest()
            if live and name != "secpal-migrate":
                port_output = podman(target, "port", name).decode().strip().splitlines()
                expected_runtime = [port.split(":8080/", 1)[0] for port in expected]
                actual_runtime = [item.split(" -> ", 1)[1] for item in port_output]
                if actual_runtime != expected_runtime:
                    raise ValueError("running reference port exposure differs")
    if live:
        listeners = run(["/usr/sbin/ss", "-Hlnt"]).decode().splitlines()
        endpoints = [entry.split()[3] for entry in listeners]
        ports = (5432, 18080, 18081) if len(targets) == 2 else (18080,) if targets == ("frontend",) else (5432, 18081)
        for port in ports:
            if sorted(value for value in endpoints if value.endswith(f":{port}")) != [f"127.0.0.1:{port}"]:
                raise ValueError("reference backend listener is not exclusively on loopback")
    edge = protected(EDGE)
    pid = int(run(["/usr/bin/systemctl", "show", "-p", "MainPID", "--value", "haproxy.service"]))
    if pid < 2 or bytes(EDGE) not in Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0"):
        raise ValueError("reference front door is not using the enrolled configuration")
    configs["edge"] = hashlib.sha256(edge).hexdigest()
    return configs


def public_accept(*, authenticated=False, target=None, source=None):
    cookies = http.cookiejar.CookieJar()
    opener = build_opener(ProxyHandler({}), NoRedirect(), HTTPCookieProcessor(cookies))

    def request(base, path, expected, *, method="GET", body=None, headers=None):
        expected = (expected,) if isinstance(expected, int) else expected
        args = {"Accept": "application/json", "Origin": FRONT, "Referer": FRONT + "/", **(headers or {})}
        params = None if body is None else json.dumps(body).encode()
        if params is not None:
            args["Content-Type"] = "application/json"
        req = Request(base + path, data=params, headers=args, method=method)
        try:
            response = opener.open(req, timeout=8)
        except HTTPError as error:
            if error.code not in expected:
                raise
            response = error
        with response:
            data = response.read(1024 * 1024 + 1)
            if response.status not in expected or len(data) > 1024 * 1024:
                raise ValueError("unexpected reference HTTP response")
            return response.headers, data

    if target == "frontend":
        _, page = request(FRONT, "/login", 200, headers={"Accept": "text/html"})
    if target == "frontend" and authenticated:
        assets = re.findall(rb'<script[^>]+src="(/assets/[^"?#]+\.js)"', page)
        if not assets or len(assets) > 10:
            raise ValueError("reference frontend asset registration differs")
        for asset in assets:
            if not re.fullmatch(rb"/assets/[A-Za-z0-9._/-]+\.js", asset) or b".." in asset or asset.startswith(b"//"):
                raise ValueError("unexpected reference frontend asset path")
            request(FRONT, asset.decode(), 200)
    if target == "frontend":
        _, config = request(FRONT, "/runtime-config.js", 200)
        if re.findall(rb'apiBaseUrl:\s*"([^"]+)"', config) != [FRONT.encode()]:
            raise ValueError("reference frontend API origin differs")
        if source is not None:
            _, payload = request(FRONT, "/source-offer.json", 200)
            if json.loads(payload) != source_offer(source):
                raise ValueError("reference source offer differs from the installed frontend source")
    if target != "frontend":
        request(API, "/health/ready", 200)
        if source is not None:
            release = api_release(source)
            for base in (API, FRONT):
                _, payload = request(base, "/v1/release", 200)
                if json.loads(payload) != {"data": release}:
                    raise ValueError("reference release metadata differs from the installed API source")
        for origin in (FRONT, "https://other.example"):
            headers, _ = request(API, "/v1/auth/login", 204, method="OPTIONS",
                                 headers={"Origin": origin, "Access-Control-Request-Method": "POST"})
            if headers.get("Access-Control-Allow-Origin") != (FRONT if origin == FRONT else None):
                raise ValueError("reference CORS policy differs")
    if not authenticated:
        return
    request(FRONT, "/v1/me", 401)
    request(FRONT, "/sanctum/csrf-cookie", 204)
    auth_cookies = [cookie for cookie in cookies if cookie.name in {"XSRF-TOKEN", "secpal-session"}]
    if ({cookie.name for cookie in auth_cookies} != {"XSRF-TOKEN", "secpal-session"} or
            any(cookie.domain != "app.secpal.dev" or cookie.domain_specified or not cookie.secure or
                cookie.path != "/" for cookie in auth_cookies)):
        raise ValueError("reference browser cookies are not host-only and secure")
    token, = [unquote(cookie.value) for cookie in auth_cookies if cookie.name == "XSRF-TOKEN"]
    headers = {"X-XSRF-TOKEN": token}
    request(FRONT, "/v1/auth/login", 200, method="POST", headers=headers,
            body={"email": "test@example.com", "password": protected(SYNTHETIC_PASSWORD).decode().strip()})
    try:
        _, identity = request(FRONT, "/v1/me", 200)
        profile = json.loads(identity)
        if profile.get("data", profile)["email"] != "test@example.com":
            raise ValueError("reference synthetic account differs")
        _, organization = request(FRONT, "/v1/organizational-units", 200)
        collection = json.loads(organization)
        if not (collection.get("data", collection) if isinstance(collection, dict) else collection):
            raise ValueError("reference organizations are unavailable")
    finally:
        token, = [unquote(cookie.value) for cookie in cookies if cookie.name == "XSRF-TOKEN"]
        request(FRONT, "/v1/auth/logout", (200, 204), method="POST", headers={"X-XSRF-TOKEN": token}, body={})
    request(FRONT, "/v1/me", 401)


def postgres_facts():
    def read(sql):
        return podman("postgres", "exec", "--user", "postgres", "secpal-reference-pg", "/bin/sh", "-ec",
                      'PGPASSWORD=$(cat "$POSTGRES_PASSWORD_FILE"); export PGPASSWORD; '
                      'export PGOPTIONS="-c default_transaction_read_only=on"; '
                      'exec psql -X -w -At -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "$1"',
                      "reference", sql)
    schema = podman("postgres", "exec", "--user", "postgres", "secpal-reference-pg", "/bin/sh", "-ec",
                    'PGPASSWORD=$(cat "$POSTGRES_PASSWORD_FILE"); export PGPASSWORD; '
                    'exec pg_dump -w --schema-only --no-owner --no-privileges -U "$POSTGRES_USER" -d "$POSTGRES_DB"')
    schema_hash = hashlib.sha256(re.sub(rb"(?m)^\\(?:un)?restrict .*\n", b"", schema)).hexdigest()
    ledger = read("SELECT jsonb_agg(to_jsonb(m) ORDER BY id) FROM public.migrations m")
    if not ledger.startswith(b"["):
        raise ValueError("reference migration ledger is missing")
    container = podman("postgres", "inspect", "--format",
                       '{{.Id}} {{.State.StartedAt}} {{range .Mounts}}{{if eq .Destination "/var/lib/postgresql"}}{{.Source}}{{end}}{{end}}',
                       "secpal-reference-pg")
    database = read("SELECT current_setting('server_version_num'), system_identifier FROM pg_control_system()")
    if not re.fullmatch(rb"18[0-9]{4}\|[0-9]+\n", database):
        raise ValueError("reference PostgreSQL identity differs")
    return {"identity": (container + database).decode(), "schema": schema_hash,
            "ledger": hashlib.sha256(ledger).hexdigest()}


def apply(target, before, desired, tarfiles, ready, after, rollback_allowed):
    """Stage the existing image-only switch and restore the admitted predecessor on failure."""
    paths = lanepaths(target)
    previous = {}
    proposed = {}
    for name, path in paths.items():
        current = protected(path)
        role = ROLE[name]
        previous[path] = current
        proposed[path] = render_pin(current.decode(), before[role].image, desired[role].image).encode()
    if target == "api":
        previous[FPM_POOL] = protected(FPM_POOL)
        proposed[FPM_POOL] = render_api_release(previous[FPM_POOL].decode(), desired["php-fpm"].source).encode()
    else:
        previous[SOURCE_OFFER] = protected(SOURCE_OFFER)
        proposed[SOURCE_OFFER] = (json.dumps(source_offer(desired["frontend"].source), sort_keys=True) + "\n").encode()
    for role, tarball in tarfiles.items():
        image = podman(target, "pull", "--quiet", f"oci-archive:{tarball}", timeout=180).decode().strip()
        item = desired[role]
        if image_data(target, image) != (item.source, item.digest):
            raise ValueError("loaded reference image differs from the qualified native subject")
        podman(target, "tag", image, item.image.split("@", 1)[0] + f":candidate-{item.source[:12]}-{role}")
        if image_data(target, item.image) != (item.source, item.digest):
            raise ValueError("rootless image reference differs after import")
    # The generator sees the complete lane with only the staged images changed.
    folder = next(iter(paths.values())).parent
    with tempfile.TemporaryDirectory(prefix="reference-quadlets-") as name:
        staged = Path(name)
        staged.chmod(0o755)
        for file in folder.iterdir():
            if file.suffix not in {".container", ".network", ".volume"}:
                raise ValueError("unexpected reference Quadlet entry")
            output = staged / file.name
            output.write_bytes(proposed.get(file, protected(file)))
            output.chmod(0o644)
        generated = run(as_user(target, ["/usr/bin/env", f"QUADLET_UNIT_DIRS={staged}",
                        "/usr/lib/systemd/system-generators/podman-system-generator", "--user", "--dryrun"]))
        if any(item.image.encode() not in generated for item in desired.values()):
            raise ValueError("Quadlet dry-run cannot resolve the candidate images")

    backup = STATE / (target + "-previous")
    backup.mkdir(mode=0o700, exist_ok=True)
    for path, content in previous.items():
        (backup / path.name).write_bytes(content)
    names = [name + ".service" for name in paths if name != "secpal-migrate"]
    migration = migration_state() if target == "api" else None
    ready()

    def activate(config):
        if target == "api":
            unit(target, "--job-mode=ignore-requirements", "stop", *names, timeout=90)
        for path, content in config.items():
            replace_protected_config(path, content)
        unit(target, "daemon-reload")
        if target == "api":
            unit(target, "--job-mode=ignore-dependencies", "start", "secpal-php-fpm.service", timeout=90)
            unit(target, "--job-mode=ignore-dependencies", "start", *names, timeout=90)
            if migration_state() != migration:
                raise ValueError("reference migration unit invocation changed")
        else:
            unit(target, "restart", *names, timeout=90)

    def verify(expected):
        for attempt in range(45):
            try:
                if observe(target) == expected:
                    public_accept(target=target)
                    return
            except (OSError, ValueError, subprocess.SubprocessError):
                pass
            if attempt < 44:
                time.sleep(2)
        raise ValueError("public reference did not become ready")

    try:
        activate(proposed)
        verify(desired)
        after()
    except BaseException:
        try:
            rollback_allowed()
            activate(previous)
            verify(before)
            print(f"reference-update.rollback: {target}: previous runtime restored", flush=True)
        except BaseException:
            (STATE / (target + ".blocked")).touch(exist_ok=True)
            print(f"reference-update.rollback: {target}: verification failed", flush=True)
        raise
