#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Explicit public host-base installation; never Enrollment or Activation.

#92 owns composition only. #80, #81, #104 and #219/#220 retain policy.
Native owns observations/mutations; plan/admit_platform are bounded admissions.
Independent native/OCI admission is an in-process trusted-control interface,
following host_enrollment._ready, never a caller-authored JSON or CLI assertion.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import grp
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
from urllib.parse import urlsplit
import pwd
import re
import shlex
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "scripts/ci-cloud"))


def owner(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# Check source authority before importing repository code during root execution.
# A private bytecode cache prevents adjacent ignored .pyc from becoming authority.
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
        _cache = tempfile.TemporaryDirectory(prefix="secpal-phase-one-imports-", dir="/tmp")
        sys.pycache_prefix = _cache.name
    except (OSError, ValueError):
        print("FAIL: phase-one:administrator-owned-source-required", file=sys.stderr)
        raise SystemExit(1)


inventory_owner = owner("_phase_one_inventory", "scripts/validate-production-contract.py")
rpm_observer = owner("_phase_one_rpm_observer", "scripts/ci-cloud/collect-rocky-preparation.py")
import rocky_preparation_contract as rocky  # noqa: E402
import postgresql_qualification_contract as postgresql  # noqa: E402
import haproxy_supply_contract as haproxy_supply  # noqa: E402
import haproxy_direct_contract as direct  # noqa: E402
import host_firewall_contract as firewall_owner  # noqa: E402
from haproxy_base_contract import Listener, Routing  # noqa: E402
from host_enrollment import _ready, EnrollmentError  # noqa: E402
from runtime_user_systemd import direct_user_show_environment  # noqa: E402


class Error(ValueError):
    """Bounded semantic diagnostic, never command output or secret content."""


@contextmanager
def diagnostic(operation):
    """Locate an external failure without publishing foreign exception text.

    Existing closed security decisions retain their own identity. The existing
    RPM observer already owns a closed operation enum; retain that identity
    rather than flattening its failures into a bootstrap phase.
    """
    try:
        yield
    except Error:
        raise
    except rpm_observer.ObservationError as error:
        identity = rpm_observer.ObservationOperation(error.operation).value
        raise Error("rpm-" + identity) from None
    except (ValueError, OSError, KeyError, RecursionError, inventory_owner.ContractViolation,
            rocky.ContractError, postgresql.QualificationError):
        raise Error(operation) from None


def admit_environment():
    names = set(os.environ)  # Names only; never read credential values.
    forbidden = {"APP_KEY", "DB_PASSWORD", "DATABASE_URL", "GH_TOKEN", "GITHUB_TOKEN",
                 "AWS_SECRET_ACCESS_KEY", "GOOGLE_APPLICATION_CREDENTIALS",
                 "CONTAINER_HOST", "CONTAINER_CONNECTION", "CONTAINERS_CONF",
                 "CONTAINERS_CONF_OVERRIDE", "CONTAINERS_CONF_MODULES",
                 "CONTAINERS_STORAGE_CONF", "PODMAN_USERNS"}
    if names & forbidden or any(re.search(
            r"(?:^|_)(?:KEYS?|KEK|PASSWORD|SECRET|TOKEN|CREDENTIALS?)(?:_|$)", name)
            or re.fullmatch(r"SECPAL_.*(?:ACTIVATION|ENROLLMENT).*", name)
            for name in names):
        raise Error("secret-environment")


def admit_platform(release, architecture, enforcing, inventory):
    observed = rocky.normalize_os_release(release)
    expected = inventory_owner.RPM_ARCHITECTURES[inventory["host"]["architecture"]]
    if (observed.get("ID") != "rocky"
            or observed.get("VERSION_ID") not in inventory_owner.QUALIFIED_ROCKY_MINORS
            or architecture != expected or enforcing != "Enforcing"):
        raise Error("unsupported-host")


@diagnostic("render-public-plan")
def plan(inventory, firewall, *, synthetic=False):
    """Render public output from existing inputs/owners; no host observation."""
    try:
        inventory_owner.scan_forbidden_input(inventory, root="inventory")
        inventory_owner.validate_inventory(inventory, synthetic=synthetic)
    except inventory_owner.ContractViolation:
        raise Error("admit-public-inventory") from None
    with diagnostic("admit-public-firewall-input"):
        firewall = firewall_owner.configuration(firewall)
    if firewall["edge_mode"] != "DIRECT":
        raise Error("phase-one-direct-only")
    account = inventory["service_account"]
    uid, gid, home = account["uid"], account["gid"], account["home"]
    architecture = inventory_owner.RPM_ARCHITECTURES[inventory["host"]["architecture"]]
    def public_source(relative):
        with diagnostic("read-reviewed-public-source"):
            return (ROOT / relative).read_text()

    with diagnostic("admit-postgresql-declaration"):
        declaration = postgresql.parse_declaration(public_source(postgresql.CANDIDATE_PATH))
    with diagnostic("render-postgresql-public-base"):
        rendered_pg = postgresql.render_configuration(declaration, uid)
    with diagnostic("render-direct-public-preview"):
        rendered_direct = direct.render(direct.Direct(
            Routing(urlsplit(inventory["origins"]["frontend"]).hostname,
                    urlsplit(inventory["origins"]["api"]).hostname),
            (direct.ViewerListener(Listener("127.0.0.1", 18085), "http"),)))
    graphroot = inventory["paths"]["podman_graph_root"]["path"]
    files = {
        "/etc/secpal/host-firewall.json": json.dumps(firewall, sort_keys=True) + "\n",
        "/etc/secpal/host-base/haproxy.cfg": rendered_direct,
        "/etc/systemd/system/nftables.service.d/secpal-host.conf":
            public_source("config/production/host-systemd/nftables.service.d/secpal-host.conf"),
        f"/etc/systemd/system/user@{uid}.service.d/50-secpal-quadlet.conf":
            f"[Service]\nEnvironment=QUADLET_UNIT_DIRS=/etc/containers/systemd/users/{uid}\n",
        "/etc/secpal/host-base/storage.conf":
            '[storage]\ndriver = "overlay"\ngraphroot = ' + json.dumps(graphroot) + "\n",
    }
    # Stage only the public #81 subset. Never install or execute roles.sql.
    for name in ("postgresql.conf", "pg_hba.conf", "loopback.nft", "service.conf"):
        files["/etc/secpal/host-base/" + name] = rendered_pg[name]
    for name in ("host-firewall.py", "host_firewall_contract.py", "cloudfront-origin-prefix-lkg.py"):
        target = "host-firewall" if name == "host-firewall.py" else name
        files["/usr/local/libexec/secpal/" + target] = public_source("scripts/" + name)
    directories = {
        # #80 validate_path_access_facts owns the home metadata.
        home: (0, gid, 0o750),
        f"{home}/.config": (uid, gid, 0o700),
        f"{home}/.cache": (uid, gid, 0o700),
        f"{home}/.local": (uid, gid, 0o700),
        graphroot: (uid, gid, 0o700),
        f"/etc/containers/systemd/users/{uid}": (0, 0, 0o755),
        "/var/lib/secpal/host-firewall": (0, 0, 0o700),
    }
    # Configuration files must never be below a runtime-writable directory.
    for name in files:
        if any((Path(parent) in Path(name).parents or Path(parent) == Path(name)) and ids[0] != 0
               for parent, ids in directories.items()):
            raise Error("configuration-below-runtime-authority")
    packages = list(rocky.PACKAGES) + ["python3-pyyaml", "ca-certificates"]
    packages += [f"{name}-{declaration['package_version']}-{declaration['package_release']}.{architecture}"
                 for name in postgresql.PACKAGES]
    packages.append(f"haproxy-{haproxy_supply.VERSION}-{haproxy_supply.RELEASE}.{architecture}")
    return {"account": account, "inventory": inventory, "firewall": firewall,
            "packages": packages, "files": files, "directories": directories}


# Run only as the service identity: privileged publication never enters XDG.
# Native Podman discovers the root-protected storage file through this link.
XDG_SETUP = r"""
import os, stat, sys
from pathlib import Path
home, storage, mode = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
changed = False
try:
    for relative in (".config", ".config/containers", ".local", ".local/share"):
        path = home / relative
        if mode == "install" and not path.exists() and not path.is_symlink():
            path.mkdir(mode=0o700)
            changed = True
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
                != (os.geteuid(), os.getegid(), 0o700)):
            raise ValueError
    link = home / ".config/containers/storage.conf"
    if mode == "install" and not link.exists() and not link.is_symlink():
        link.symlink_to(storage)
        changed = True
    info = link.lstat()
    if (not stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_gid != os.getegid() or os.readlink(link) != storage):
        raise ValueError
except (OSError, ValueError):
    sys.exit(1)
print("changed" if changed else "unchanged")
"""


class Native:
    """Bounded host observations and explicit mutations; no privilege escalation."""

    def __init__(self, root=Path("/"), *, owner=(0, 0)):
        self.root = root
        self.owner = owner
        self.changes = 0

    def path(self, name):
        path = Path(name)
        if not path.is_absolute() or ".." in path.parts:
            raise Error("invalid-host-path")
        return self.root / str(path).lstrip("/")

    def run(self, operation, arguments, *, user=None, accepted=(0,), timeout=60):
        try:
            if user is not None:
                account = pwd.getpwnam(user)
                arguments = ["runuser", "--user", user, "--", "env",
                             "HOME=" + account.pw_dir, f"XDG_RUNTIME_DIR=/run/user/{account.pw_uid}",
                             f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{account.pw_uid}/bus", *arguments]
            with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
                result = subprocess.run(arguments, stdout=out, stderr=err, timeout=timeout,
                                        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}, cwd="/")
                out.seek(0)
                err.seek(0)
                raw, diagnostic = out.read(1048577), err.read(65537)
            if result.returncode not in accepted or len(raw) > 1048576 or len(diagnostic) > 65536:
                raise Error(operation + "-command-failed")
            return result.returncode, raw.decode("utf-8").strip()
        except (OSError, KeyError, UnicodeError, subprocess.SubprocessError):
            raise Error(operation + "-observation-failed") from None

    def change(self, operation, arguments, **kwargs):
        self.run(operation, arguments, **kwargs)
        self.changes += 1

    @diagnostic("inspect-public-path")
    def trusted(self, path, *, directory=False):
        """Independent enforcement of #104 host-firewall.trusted; agreement-tested."""
        for entry in (path, *path.parents):
            info = entry.lstat()
            if (info.st_uid != self.owner[0] or info.st_mode & 0o022
                    or stat.S_ISLNK(info.st_mode)):
                raise Error("untrusted-public-path")
            if entry == self.root:
                break
        info = path.lstat()
        if directory:
            if not stat.S_ISDIR(info.st_mode):
                raise Error("untrusted-public-directory")
        elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise Error("untrusted-public-file")

    @diagnostic("prepare-public-directory")
    def directory(self, name, uid=0, gid=0, mode=0o755, *, create=True):
        path = self.path(name)
        if not path.parent.exists():
            if not create:
                raise Error("missing-public-directory")
            self.directory("/" + str(path.parent.relative_to(self.root)))
        self.trusted(path.parent, directory=True)
        expected_uid = self.owner[0] if uid == 0 else uid
        expected_gid = self.owner[1] if gid == 0 else gid
        if path.exists() or path.is_symlink():
            info = path.lstat()
            if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                    or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
                    != (expected_uid, expected_gid, mode)):
                raise Error("public-directory-conflict")
            return False
        if not create:
            raise Error("missing-public-directory")
        path.mkdir(mode=mode)
        os.chown(path, expected_uid, expected_gid)
        path.chmod(mode)
        self.changes += 1
        return True

    @diagnostic("verify-public-file")
    def public_file(self, name, text):
        path = self.path(name)
        self.trusted(path)
        if (stat.S_IMODE(path.stat().st_mode) != 0o644
                or path.stat().st_gid != self.owner[1]
                or path.stat().st_size != len(text.encode()) or path.read_bytes() != text.encode()):
            raise Error("public-file-conflict")

    @diagnostic("publish-public-file")
    def publish(self, name, text):
        path = self.path(name)
        if path.exists() or path.is_symlink():
            self.public_file(name, text)
            return False
        if not path.parent.exists():
            self.directory("/" + str(path.parent.relative_to(self.root)))
        self.trusted(path.parent, directory=True)
        # Exclusive publication never replaces an unknown file or follows a link.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(text.encode())
                stream.flush()
                os.fchown(stream.fileno(), *self.owner)
                os.fchmod(stream.fileno(), 0o644)
                os.fsync(stream.fileno())
        except BaseException:
            # A partial file remains a conflict, never silently rewritten.
            raise
        self.changes += 1
        return True

    def xdg(self, desired, *, install=False):
        account = desired["account"]
        _, result = self.run("configure-rootless-xdg" if install else "verify-rootless-xdg",
            ["python3", "-I", "-c", XDG_SETUP, str(self.path(account["home"])),
             str(self.path("/etc/secpal/host-base/storage.conf")),
             "install" if install else "verify"], user=account["name"])
        if result not in {"changed", "unchanged"} or (not install and result != "unchanged"):
            raise Error("rootless-xdg-conflict")
        self.changes += result == "changed"

    @diagnostic("inspect-legacy-xdg")
    def legacy_xdg(self, desired, *, repair=False):
        """Recognize only the exact failed #361 public layout, never arbitrary data.

        All privileged changes precede transfer of the XDG parent to the user.
        No privileged publication or recursive ownership change enters user paths.
        """
        account = desired["account"]
        home = account["home"]
        config = self.path(home + "/.config")
        if not config.exists() or config.is_symlink():
            return False
        info = config.lstat()
        if (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (*self.owner, 0o755):
            return False
        self.directory(home, 0, account["gid"], 0o750, create=False)
        for suffix in ("", "/containers", "/systemd"):
            self.directory(home + "/.config" + suffix, create=False)
        for suffix, names in (("", {"containers", "systemd"}),
                              ("/containers", {"storage.conf"}), ("/systemd", {"user"})):
            if {p.name for p in self.path(home + "/.config" + suffix).iterdir()} != names:
                raise Error("legacy-xdg-conflict")
        user = config / "systemd/user"
        info = user.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
                != (account["uid"], account["gid"], 0o700)):
            raise Error("legacy-xdg-conflict")
        if {p.name for p in user.iterdir()} != {"podman.service", "podman.socket"}:
            raise Error("legacy-xdg-conflict")
        for name in ("podman.service", "podman.socket"):
            link = user / name
            info = link.lstat()
            if (not stat.S_ISLNK(info.st_mode) or info.st_nlink != 1
                    or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
                    != (account["uid"], account["gid"], 0o777)
                    or os.readlink(link) != "/dev/null"):
                raise Error("legacy-xdg-conflict")
        storage = config / "containers/storage.conf"
        text = desired["files"]["/etc/secpal/host-base/storage.conf"]
        self.public_file(home + "/.config/containers/storage.conf", text)
        if repair:
            # Revalidated immediately before mutation; the original ancestors
            # remain root-owned until all root writes have finished.
            self.public_file("/etc/secpal/host-base/storage.conf", text)
            with diagnostic("remove-verified-legacy-storage"):
                storage.unlink()  # Exact public bytes already preserved above.
            self.changes += 1
            for path in (config / "containers", config / "systemd", config):
                with diagnostic("restrict-legacy-xdg-mode"):
                    path.chmod(0o700)
                with diagnostic("transfer-legacy-xdg-owner"):
                    os.chown(path, account["uid"], account["gid"], follow_symlinks=False)
                self.changes += 1
        return True

    @diagnostic("inspect-premature-authority")
    def no_authority(self, desired):
        """Metadata only: no database, key, credential or existing data is read."""
        forbidden = [row["path"] for name, row in desired["inventory"]["paths"].items()
                     if name not in {"configuration", "podman_graph_root", "quadlet_definitions"}]
        forbidden += [postgresql.NATIVE_DATA_DIRECTORY, "/etc/secpal/enrollment",
                      "/etc/secpal/postgresql", "/etc/haproxy/secpal-viewer.pem",
                      "/var/lib/secpal/enrollment", "/run/secpal/activation"]
        for name in forbidden:
            path = self.path(name)
            if path.is_symlink() or (path.exists() and (
                    not path.is_dir() or any(path.iterdir()))):
                raise Error("premature-authority")
        for name in ("/run/podman/podman.sock", "/run/docker.sock"):
            if self.path(name).exists() or self.path(name).is_symlink():
                raise Error("premature-runtime-socket")
        home = desired["account"]["home"]
        for name in (home + "/.config/containers/auth.json", home + "/.docker/config.json",
                     home + "/.env"):
            if self.path(name).exists() or self.path(name).is_symlink():
                raise Error("premature-authority")
        configuration = self.path(desired["inventory"]["paths"]["configuration"]["path"])
        if configuration.exists():
            if configuration.is_symlink() or not configuration.is_dir():
                raise Error("premature-authority")
            for child in configuration.iterdir():
                if child.is_symlink() or child.name.startswith(".env") or re.search(
                        r"secret|credential|enrollment|activation|\.key$", child.name, re.I):
                    raise Error("premature-authority")

    @diagnostic("admit-host-platform")
    def platform(self, desired):
        admit_environment()
        admit_platform(self.path("/etc/os-release").read_text(),
                       self.run("observe-architecture", ["uname", "-m"])[1],
                       self.run("observe-selinux", ["getenforce"])[1], desired["inventory"])
        if "targeted" not in self.run("observe-selinux-policy", ["sestatus"])[1]:
            raise Error("selinux-policy")
        if self.run("observe-cgroup", ["stat", "-fc", "%T", "/sys/fs/cgroup"])[1] != "cgroup2fs":
            raise Error("cgroup-v2-required")
        if desired["inventory"]["host"]["architecture"] == "amd64":
            if "x86-64-v3 (supported, searched)" not in self.run(
                    "observe-cpu", ["/lib64/ld-linux-x86-64.so.2", "--help"])[1]:
                raise Error("cpu-admission")
        repositories = rocky.normalize_repository_ids(
            self.run("observe-repositories", ["dnf4", "-q", "repolist", "--enabled"])[1])
        if set(repositories) != rocky.REPOSITORIES or len(repositories) != 3:
            raise Error("repository-admission")
        hostname = self.run("observe-hostname", ["hostnamectl", "--static"])[1]
        if inventory_owner.validate_hostname(hostname, "observed.hostname") != desired["inventory"]["host"]["hostname"]:
            raise Error("host-identity-conflict")
        rocky.admit_rocky_signing_key(rocky.normalize_rocky_signing_key(
            rpm_observer.Observer().rocky_signing_key()))
        self.no_authority(desired)
        connection = os.environ.get("SSH_CONNECTION")
        if connection is not None:
            try:
                peer, _, _, port = connection.split()
                address = ipaddress.ip_address(peer)
                key = "management_ipv4" if address.version == 4 else "management_ipv6"
                if port != "22" or not any(address in ipaddress.ip_network(network)
                                            for network in desired["firewall"][key]):
                    raise ValueError
            except ValueError:
                raise Error("management-connection-not-admitted") from None
        for unit in rpm_observer.AUTOMATIC_UNITS:
            _, enabled = self.run("observe-automatic-update-enable-state",
                                  ["systemctl", "is-enabled", unit], accepted=(0, 1, 3, 4))
            _, active = self.run("observe-automatic-update-active-state",
                                 ["systemctl", "is-active", unit], accepted=(0, 3, 4))
            if enabled not in {"disabled", "masked", "not-found", ""} or active not in {
                    "inactive", "unknown", "failed"}:
                raise Error("automatic-update-policy-conflict")

    @diagnostic("inspect-dormant-host-services")
    def dormant(self, desired):
        for unit in ("postgresql.service", "haproxy.service", "podman.service", "podman.socket",
                     "firewalld.service"):
            status, state = self.run("observe-dormant-service", ["systemctl", "is-active", unit],
                                     accepted=(0, 3, 4))
            if status == 0 or state not in {"inactive", "unknown", "failed"}:
                raise Error("premature-service-authority")
        _, enabled = self.run("observe-foreign-firewall-enable-state",
                              ["systemctl", "is-enabled", "firewalld.service"], accepted=(0, 1, 3, 4))
        if enabled not in {"disabled", "masked", "not-found", ""}:
            raise Error("foreign-firewall-authority")
        # Do not install a boot policy underneath an unknown administrator override.
        for unit in ("nftables.service", f"user@{desired['account']['uid']}.service", "user@.service"):
            for base in ("/etc/systemd/system/", "/run/systemd/system/"):
                override = self.path(base + unit)
                if override.exists() or override.is_symlink():
                    raise Error("foreign-systemd-authority")
                dropins = self.path(base + unit + ".d")
                if dropins.is_symlink():
                    raise Error("foreign-systemd-authority")
                if dropins.exists() and any(
                        "/" + str(child.relative_to(self.root)) not in desired["files"]
                        for child in dropins.iterdir()):
                    raise Error("foreign-systemd-authority")
        quadlets = self.path(f"/etc/containers/systemd/users/{desired['account']['uid']}")
        if quadlets.is_symlink() or (quadlets.exists() and any(quadlets.iterdir())):
            raise Error("premature-workload-authority")

    @diagnostic("inspect-runtime-account")
    def account(self, desired, *, install=False):
        spec = desired["account"]
        try:
            account = pwd.getpwnam(spec["name"])
        except KeyError:
            if not install:
                raise Error("missing-runtime-account") from None
            # Never take over another identity by numeric collision.
            if any(item.pw_uid == spec["uid"] for item in pwd.getpwall()):
                raise Error("runtime-uid-collision")
            try:
                group = grp.getgrnam(spec["group"])
            except KeyError:
                if any(item.gr_gid == spec["gid"] for item in grp.getgrall()):
                    raise Error("runtime-gid-collision") from None
                self.change("create-runtime-group", ["groupadd", "--system", "--gid",
                            str(spec["gid"]), spec["group"]])
            else:
                if group.gr_gid != spec["gid"]:
                    raise Error("runtime-group-conflict")
            self.change("create-runtime-account", [
                "useradd", "--no-create-home", "--no-user-group", "--no-log-init",
                "--uid", str(spec["uid"]), "--gid", str(spec["gid"]), "--home-dir", spec["home"],
                "--shell", spec["shell"], "-K", "SUB_UID_COUNT=0", "-K", "SUB_GID_COUNT=0", spec["name"]])
            account = pwd.getpwnam(spec["name"])
        if ((account.pw_uid, account.pw_gid, account.pw_dir, account.pw_shell)
                != (spec["uid"], spec["gid"], spec["home"], spec["shell"])
                or os.getgrouplist(spec["name"], spec["gid"]) != [spec["gid"]]):
            raise Error("runtime-account-conflict")
        try:
            if grp.getgrnam(spec["group"]).gr_gid != spec["gid"]:
                raise Error("runtime-group-conflict")
        except KeyError:
            raise Error("runtime-group-conflict") from None
        observer = rpm_observer.Observer()
        if rocky.normalize_sudo_authority(observer.sudo_observation(spec["name"])):
            raise Error("runtime-sudo-authority")
        return account

    @diagnostic("inspect-subordinate-ids")
    def subids(self, desired, *, install=False):
        spec = desired["account"]
        ids = rpm_observer.Observer().effective_ids()
        for kind, option in (("uid", "--add-subuids"), ("gid", "--add-subgids")):
            path = self.path("/etc/sub" + kind)
            if path.exists():
                self.trusted(path)
                text = path.read_text()
            else:
                text = ""
            selected = spec["subordinate_ids"][kind]
            start, count = selected["start"], selected["count"]
            entries = [line for line in text.splitlines()
                       if line.startswith(spec["name"] + ":") or line.startswith(str(spec["uid"]) + ":")]
            ranges = rocky.normalize_all_subid_ranges(text, "normalize-phase-one-subids")
            if not entries:
                if not install:
                    raise Error("missing-subids")
                ranges += [(start, count)]
            elif entries != [f"{spec['name']}:{start}:{count}"]:
                raise Error("subid-conflict")
            # Use #80's overlap/effective-ID owner per independent UID/GID namespace.
            if not rocky.subids_independent((start, count), ranges + [(start, count)], ids):
                raise Error("subid-collision")
            if not entries:
                self.change("allocate-subids", ["usermod", option, f"{start}-{start + count - 1}", spec["name"]])

    @diagnostic("inspect-required-packages")
    def package_requirements(self, desired):
        missing = []
        for item in desired["packages"]:
            name = next((name for name in sorted((*postgresql.PACKAGES, "haproxy"), key=len, reverse=True)
                         if item.startswith(name + "-") and name not in rocky.PACKAGES), item)
            status, _ = self.run("observe-installed-package", ["rpm", "-q", name], accepted=(0, 1))
            if status == 1:
                missing.append(item)
            elif item != name:
                identity = self.run("observe-pinned-package", [
                    "rpm", "-q", "--qf", "%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}", name])[1]
                if identity != item:
                    raise Error("pinned-package-conflict")
        return missing

    @diagnostic("admit-native-packages")
    def packages(self, desired):
        architecture = inventory_owner.RPM_ARCHITECTURES[desired["inventory"]["host"]["architecture"]]
        observer = rpm_observer.Observer()
        facts = rocky.normalize_native_package_observations({
            "os_release": self.path("/etc/os-release").read_text(), "architecture": architecture,
            "packages": [observer.package(name) for name in rocky.PACKAGES],
            "rocky_signing_key": observer.rocky_signing_key()})
        signer = rocky.admit_rocky_signing_key(facts["rocky_signing_key"])
        admitted = [rocky.admit_package(item, signer, architecture) for item in facts["packages"]]
        rocky.admit_runtime_podman_version({"packages_admitted": admitted})
        for name in postgresql.PACKAGES:
            postgresql.admit_postgresql_package(name, observer.installed_package(name),
                                                architecture, signer)
        for name in ("python3-pyyaml", "ca-certificates", "haproxy"):
            rocky.admit_package(rocky.normalize_installed_package(
                name, observer.installed_package(name), architecture), signer, architecture)
        identity = self.run("observe-haproxy-rpm", ["rpm", "-q", "--qf",
                    "%{NAME}|%{EPOCHNUM}|%{VERSION}|%{RELEASE}|%{ARCH}", "haproxy"])[1]
        haproxy_supply.admit_installed_package(
            architecture, identity, hashlib.sha256(self.path("/usr/sbin/haproxy").read_bytes()).hexdigest(),
            haproxy_supply.normalize_features(self.run("observe-haproxy-features", ["haproxy", "-vv"])[1]))
        return admitted

    @diagnostic("verify-storage-label-policy")
    def storage_labels(self, desired, *, install=False):
        """#80 persistent labels, using the installed container-selinux policy.

        Native equivalence preserves the policy's complete subtree semantics;
        this composition defines no SELinux type, permission or module.
        """
        graphroot = desired["inventory"]["paths"]["podman_graph_root"]["path"]
        expected = ["fcontext", "-a", "-e", "/var/lib/containers/storage", graphroot]
        raw = self.run("observe-file-contexts", ["semanage", "export"])[1]
        try:
            rules = [shlex.split(line) for line in raw.splitlines() if line.strip()]
        except ValueError:
            raise Error("file-context-export-invalid") from None
        contexts = [row for row in rules if row[0] == "fcontext" and row != ["fcontext", "-D"]]
        if contexts not in ([], [expected]):
            raise Error("foreign-file-context-authority")
        created = False
        if not contexts:
            if not install:
                raise Error("missing-storage-label-policy")
            if any(self.path(graphroot).iterdir()):
                raise Error("unadmitted-existing-storage")
            self.change("configure-storage-label-policy", ["semanage", *expected])
            created = True
        status, _ = self.run("observe-storage-label", ["matchpathcon", "-V", graphroot],
                             accepted=(0, 1))
        if status != 0:
            if not created or any(self.path(graphroot).iterdir()):
                raise Error("storage-label-conflict")
            self.change("label-empty-storage", ["restorecon", "-F", graphroot])
            self.run("verify-storage-label", ["matchpathcon", "-V", graphroot])

    @diagnostic("inspect-runtime-unit")
    def unit(self, unit, *, user=None, install=False):
        status, active = self.run("observe-unit-active-state",
                                 ["systemctl", *(["--user"] if user else []), "is-active", unit],
                                 user=user, accepted=(0, 3, 4))
        if status == 0 or active not in {"inactive", "unknown", "failed"}:
            raise Error("premature-runtime-service")
        _, state = self.run("observe-unit-enable-state", ["systemctl", *(["--user"] if user else []),
                           "is-enabled", unit], user=user, accepted=(0, 1, 3, 4))
        if state == "masked":
            return
        if not install or state not in {"disabled", "static", "not-found", ""}:
            raise Error("unit-mask-conflict")
        self.change("mask-dormant-unit", ["systemctl", *(["--user"] if user else []), "mask", unit], user=user)

    @diagnostic("admit-native-runtime")
    def runtime(self, desired, packages):
        account = desired["account"]
        uid, user = account["uid"], account["name"]
        environment = self.run("observe-effective-quadlet-search",
            direct_user_show_environment(user, uid, account["home"]))[1]
        # Match the exact single-key observation used by #80's native harness.
        # Private manager output is never emitted in diagnostics or evidence.
        paths = [line.partition("=")[2] for line in environment.splitlines()
                 if line.startswith("QUADLET_UNIT_DIRS=")]
        try:
            inventory_owner.validate_quadlet_search_paths(desired["inventory"], paths)
        except inventory_owner.ContractViolation:
            raise Error("effective-quadlet-search-conflict") from None
        data = rocky.normalize_podman(self.run("observe-runtime", ["podman", "info", "--format=json"], user=user)[1])
        state = self.run("observe-user-manager", ["systemctl", "is-active", f"user@{uid}.service"])[1]
        socket = self.path(f"/run/user/{uid}/podman/podman.sock")
        facts = {"podman_normalized": data, "cgroup_filesystem": "cgroup2fs", "systemd_user": state,
                 "socket_exists": socket.exists() or socket.is_symlink(), "podman_socket_enabled": False,
                 "container_host_present": False, "packages_admitted": packages}
        rocky.admit_runtime(facts)
        if data["store"]["graphRoot"] != desired["inventory"]["paths"]["podman_graph_root"]["path"]:
            raise Error("graphroot-conflict")
        if self.run("observe-containers", ["podman", "ps", "--all", "--quiet"], user=user)[1]:
            raise Error("premature-workload-authority")


def verify_public_base(native, desired):
    native.platform(desired)
    native.dormant(desired)
    native.account(desired)
    native.subids(desired)
    if native.package_requirements(desired):
        raise Error("missing-public-packages")
    packages = native.packages(desired)
    for name, text in desired["files"].items():
        native.public_file(name, text)
    for name, (uid, gid, mode) in desired["directories"].items():
        native.directory(name, uid, gid, mode, create=False)
    native.xdg(desired)
    for unit in ("postgresql.service", "haproxy.service", "podman.service", "podman.socket"):
        native.unit(unit)
    for unit in ("podman.service", "podman.socket"):
        native.unit(unit, user=desired["account"]["name"])
    native.storage_labels(desired)
    native.runtime(desired, packages)
    native.trusted(native.path("/var/lib/systemd/linger/" + desired["account"]["name"]))
    for query, expected in (("is-enabled", "enabled"), ("is-active", "active")):
        _, state = native.run("verify-firewall-persistence", ["systemctl", query, "nftables.service"])
        if state != expected:
            raise Error("firewall-persistence-conflict")
    native.run("verify-host-firewall", ["python3", "-I", "/usr/local/libexec/secpal/host-firewall", "--check"])
    native.run("verify-haproxy-preview", ["haproxy", "-c", "-f", "/etc/secpal/host-base/haproxy.cfg"])


@diagnostic("inspect-public-install-state")
def install_public_base(native, desired):
    native.platform(desired)
    native.dormant(desired)
    legacy = native.legacy_xdg(desired)
    # Detect public-file conflicts before installing anything.
    for name, text in desired["files"].items():
        path = native.path(name)
        if path.exists() or path.is_symlink():
            native.public_file(name, text)
    for name, (uid, gid, mode) in desired["directories"].items():
        if legacy and name == desired["account"]["home"] + "/.config":
            continue
        path = native.path(name)
        if path.exists() or path.is_symlink():
            native.directory(name, uid, gid, mode, create=False)
    missing = native.package_requirements(desired)
    for unit in ("postgresql.service", "haproxy.service", "podman.service", "podman.socket"):
        native.unit(unit, install=True)
    if missing:
        native.change("install-public-packages", ["dnf4", "-y", "--releasever=10",
                      "--disablerepo=*", "--enablerepo=baseos,appstream,extras",
                      "--setopt=*.gpgcheck=1", "--setopt=install_weak_deps=False", "install", *missing],
                      timeout=600)
    native.account(desired, install=True)
    native.subids(desired, install=True)
    changed = native.changes
    for name, (uid, gid, mode) in desired["directories"].items():
        if not (legacy and name == desired["account"]["home"] + "/.config"):
            native.directory(name, uid, gid, mode)
    for name, text in desired["files"].items():
        native.publish(name, text)
    if legacy:
        native.legacy_xdg(desired, repair=True)
    native.xdg(desired, install=True)
    if native.changes != changed:
        native.change("reload-systemd", ["systemctl", "daemon-reload"])
    native.storage_labels(desired, install=True)
    account = desired["account"]
    if not native.path("/var/lib/systemd/linger/" + account["name"]).exists():
        native.change("enable-runtime-linger", ["loginctl", "enable-linger", account["name"]])
    status, _ = native.run("observe-user-manager", ["systemctl", "is-active", f"user@{account['uid']}.service"],
                           accepted=(0, 3))
    if status != 0:
        native.change("start-user-manager", ["systemctl", "start", f"user@{account['uid']}.service"])
    for unit in ("podman.service", "podman.socket"):
        native.unit(unit, user=account["name"], install=True)
    status, _ = native.run("observe-host-firewall", [
        "python3", "-I", "/usr/local/libexec/secpal/host-firewall", "--check"], accepted=(0, 1))
    if status != 0:
        native.change("apply-host-firewall", [
            "python3", "-I", "/usr/local/libexec/secpal/host-firewall", "--apply"])
    _, state = native.run("observe-nftables-enable-state", ["systemctl", "is-enabled", "nftables.service"],
                          accepted=(0, 1))
    if state == "disabled":
        native.change("enable-host-firewall", ["systemctl", "enable", "nftables.service"])
    elif state != "enabled":
        raise Error("firewall-service-conflict")
    status, _ = native.run("observe-nftables-active-state", ["systemctl", "is-active", "nftables.service"],
                          accepted=(0, 3))
    if status != 0:
        native.change("start-host-firewall", ["systemctl", "start", "nftables.service"])
    verify_public_base(native, desired)


def admit_for_enrollment(native, desired, *, conformance=None, artifacts=None):
    """Trusted #241 readiness callback, not a CLI/file/boolean trust assertion.

    Trusted control must supply current source-/host-bound #80 admission and
    current exact-subject OCI policy admission. These owners reject unknown,
    expired and REVIEW_REQUIRED evidence before returning None. No defaults,
    historical integration identities or policy reimplementation live here.
    """
    verify_public_base(native, desired)
    try:
        _ready(conformance)
        _ready(artifacts)
    except EnrollmentError:
        raise Error("independent-native-and-oci-admission-required") from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    for name in ("plan", "install", "verify"):
        mode.add_argument("--" + name, action="store_true")
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--firewall", type=Path, required=True)
    args = parser.parse_args()
    try:
        if not args.plan and os.geteuid() != 0:
            raise Error("explicit-administrator-execution-required")
        native = Native()
        if os.geteuid() == 0:
            for document in (args.inventory, args.firewall):
                native.trusted(native.path(str(document.absolute())))
        with diagnostic("read-public-inventory"):
            inventory = inventory_owner.read_document(args.inventory, "inventory")
        with diagnostic("read-public-firewall"):
            firewall = inventory_owner.read_document(args.firewall, "firewall")
        desired = plan(inventory, firewall)
        if args.plan:
            print(json.dumps(desired, sort_keys=True, indent=2))
            return 0
        if args.install:
            install_public_base(native, desired)
            print("PUBLIC_BASE_INSTALLED" if native.changes else "PUBLIC_BASE_UNCHANGED")
            return 0
        verify_public_base(native, desired)
        # Deliberately no CLI flag or serialized admission can manufacture trust.
        print("PUBLIC_BASE_VERIFIED; NOT_ADMITTED: independent native and OCI admission required")
        return 2
    except Error as error:
        print("FAIL: phase-one:" + str(error), file=sys.stderr)
        return 1
    except (ValueError, OSError, KeyError, inventory_owner.ContractViolation,
            rocky.ContractError, postgresql.QualificationError, rpm_observer.ObservationError):
        print("FAIL: phase-one:canonical-admission-or-observation", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
