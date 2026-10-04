#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Installed administrator-only shared HAProxy config lifecycle.

Fixed reviewed paths/actions; no executable path, shell, provider or runtime API
input. #101 owns effective backend permission and its activation barrier.
"""

import argparse
import fcntl
import http.client
import os
from pathlib import Path
import pwd
import platform
import signal
import stat
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from haproxy_base_contract import decode_document, render, listener_constraints, from_config, generation_id, MAX_CONFIG_BYTES
from haproxy_config_lifecycle import publish
from product_backend_contract import admit_policy_account
from haproxy_supply_contract import admit_installed_package, normalize_features, binary_sha256

HELPER = Path('/usr/local/libexec/secpal/haproxy-config')
LIBRARIES = ('haproxy_base_contract.py', 'haproxy_config_lifecycle.py', 'product_backend_contract.py', 'haproxy_supply_contract.py')
SPEC = Path('/etc/haproxy/secpal-routing.json')
SERVING = Path('/etc/haproxy/secpal.cfg')
LISTENER_UNIT = Path('/etc/systemd/system/haproxy.service.d/secpal-listeners.conf')
BASE_UNIT = Path('/etc/systemd/system/haproxy.service.d/secpal.conf')
RUNTIME = Path('/run/haproxy')
BINARY = Path('/usr/sbin/haproxy')


def trusted(path: Path, *, regular=False):
    for current in (path, *path.parents):
        info = current.lstat()
        if (info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode)
                or (current != path and not stat.S_ISDIR(info.st_mode))):
            raise ValueError('admit-administrator-path')
    info = path.lstat()
    if regular and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
        raise ValueError('admit-administrator-file')


def observe(operation, arguments):
    try:
        result = subprocess.run(arguments, capture_output=True, timeout=15,
                                env={'PATH': '/usr/sbin:/usr/bin', 'LANG': 'C'})
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError(operation) from error
    if result.returncode or len(result.stdout) > 65536 or len(result.stderr) > 65536:
        raise ValueError(operation)
    return result.stdout.decode('utf-8', errors='strict')


def authority(*, desired=True):
    if os.geteuid() != 0 or Path(__file__).resolve() != HELPER:
        raise ValueError('admit-installed-administrator-helper')
    for path in (HELPER, *(HELPER.parent / name for name in LIBRARIES), BINARY, BASE_UNIT, LISTENER_UNIT):
        trusted(path, regular=True)
    architecture = platform.machine()
    identity = observe('observe-haproxy-rpm', ['/usr/bin/rpm', '-q', 'haproxy', '--qf',
                       '%{NAME}|%{EPOCHNUM}|%{VERSION}|%{RELEASE}|%{ARCH}\n']).strip()
    features = normalize_features(observe('observe-haproxy-build', [str(BINARY), '-vv']))
    admit_installed_package(architecture, identity, binary_sha256(BINARY.read_bytes()), features)
    # Reuse #101's effective policy/identity/barrier owner, including broad
    # boolean rejection, rather than defining independent SELinux/nft rules.
    observe('admit-backend-policy', ['/usr/bin/python3', '-I',
            '/usr/local/libexec/secpal/product-backend-policy', '--check'])
    account = pwd.getpwnam('haproxy')
    # #101's check binds it to the real product runtime UID; this is only the
    # reusable dedicated non-login account check, not a second account owner.
    admit_policy_account(account, 0)
    if desired:
        trusted(SPEC, regular=True)
        if SPEC.stat().st_size > MAX_CONFIG_BYTES:
            raise ValueError('admit-routing-size')
        routing, listeners = decode_document(SPEC.read_bytes())
    else:
        trusted(SERVING, regular=True)
        if SERVING.stat().st_size > MAX_CONFIG_BYTES:
            raise ValueError('admit-serving-size')
        routing, listeners = from_config(SERVING.read_bytes())
    if LISTENER_UNIT.read_text() != listener_constraints(listeners):
        raise ValueError('admit-exact-listener-unit')
    return render(routing, listeners).encode('utf-8'), account.pw_uid


def validate(candidate):
    observe('validate-haproxy-candidate', [str(BINARY), '-c', '-q', '-f', str(candidate)])


def prepare(candidate):
    # Stock Rocky /etc/haproxy(/.*)? fcontext applies haproxy_conf_t.
    observe('label-haproxy-candidate', ['/usr/sbin/restorecon', '-F', str(candidate)])


def process_identity(pid, *, master=False):
    if type(pid) is not int or pid <= 1:
        raise ValueError('admit-haproxy-pid')
    process = Path('/proc') / str(pid)
    if master and (process / 'exe').resolve() != BINARY:
        raise ValueError('admit-haproxy-executable')
    status = (process / 'status').read_text()
    uids = next(row.split()[1:] for row in status.splitlines() if row.startswith('Uid:'))
    context = (process / 'attr/current').read_text().strip().split(':')
    if len(context) < 4 or context[2] != 'haproxy_t':
        raise ValueError('admit-haproxy-domain')
    return process, tuple(int(uid) for uid in uids)


def reload_master(pid, worker_uid):
    process, uids = process_identity(pid, master=True)
    if uids != (0, 0, 0, 0):
        raise ValueError('admit-haproxy-master-uid')
    cgroup = (process / 'cgroup').read_text()
    if not any(row.split(':', 2)[-1] == '/system.slice/haproxy.service' for row in cgroup.splitlines()):
        raise ValueError('admit-haproxy-system-unit')
    children = process / 'task' / str(pid) / 'children'
    previous = set(children.read_text().split())
    os.kill(pid, signal.SIGUSR2)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        current = set(children.read_text().split()) - previous
        for child in current:
            try:
                _, ids = process_identity(int(child))
                if ids != (worker_uid,) * 4:
                    continue
                time.sleep(.25)
                _, ids = process_identity(int(child))
                if ids == (worker_uid,) * 4 and probe_generation(int(child)):
                    # Recheck membership/identity after every listener served the
                    # expected generation from this exact worker PID.
                    if child in set(children.read_text().split()):
                        _, ids = process_identity(int(child))
                        if ids == (worker_uid,) * 4:
                            return
            except (OSError, ValueError, StopIteration):
                continue
        time.sleep(.1)
    raise ValueError('verify-haproxy-reload-generation')


def probe_generation(worker_pid):
    data = SERVING.read_bytes()
    routing, listeners = from_config(data)
    expected = generation_id(routing, listeners)
    for listener in listeners:
        address = {'0.0.0.0': '127.0.0.1', '::': '::1'}.get(listener.address, listener.address)
        connection = http.client.HTTPConnection(address, listener.port, timeout=.5)
        try:
            connection.request('GET', '/_secpal/proxy-generation', headers={
                'Host': routing.frontend_host, 'X-SecPal-Runtime-Probe': expected})
            response = connection.getresponse()
            if (response.status != 204 or response.getheader('X-SecPal-Generation') != expected
                    or response.getheader('X-SecPal-Worker') != str(worker_pid)
                    or response.read(1) != b''):
                return False
        except (OSError, http.client.HTTPException):
            return False
        finally:
            connection.close()
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument('--check', action='store_true')
    actions.add_argument('--activate', action='store_true')
    actions.add_argument('--reload', type=int, metavar='SYSTEMD_MAINPID')
    args = parser.parse_args()
    if os.geteuid() != 0 or Path(__file__).resolve() != HELPER:
        raise ValueError('admit-installed-administrator-helper')
    trusted(HELPER, regular=True)
    trusted(RUNTIME.parent)
    RUNTIME.mkdir(mode=0o755, exist_ok=True)
    trusted(RUNTIME)
    # One fixed private root-owned lock serializes activation/reload. Never use
    # the serving inode as lock: replacement would destroy serialization.
    descriptor = os.open(RUNTIME / 'secpal-config.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        if info.st_uid != 0 or info.st_mode & 0o077 or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('admit-config-lock')
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        data, uid = authority(desired=not args.check)
        if args.check:
            trusted(SERVING, regular=True)
            if SERVING.stat().st_size > MAX_CONFIG_BYTES or SERVING.read_bytes() != data:
                raise ValueError('admit-serving-reviewed-config')
            validate(SERVING)
        else:
            if SERVING.exists() or SERVING.is_symlink():
                trusted(SERVING, regular=True)
            if args.reload is not None:
                if not SERVING.is_file():
                    raise ValueError('admit-reload-serving-file')
                # Socket admission is a host construction decision. Reload never
                # widens it or changes listening sockets underneath systemd.
                if SERVING.stat().st_size > MAX_CONFIG_BYTES:
                    raise ValueError('admit-serving-size')
                from_config(SERVING.read_bytes())
                old = [line for line in SERVING.read_text().splitlines() if line.startswith('    bind ')]
                new = [line for line in data.decode().splitlines() if line.startswith('    bind ')]
                if old != new:
                    raise ValueError('admit-reload-unchanged-listeners')
                reload = lambda: reload_master(args.reload, uid)
            else:
                # Activate only while the package service is stopped. Otherwise
                # publishing without reloading would create disk/live drift.
                if observe('observe-haproxy-service-state', ['/usr/bin/systemctl', 'show',
                           'haproxy.service', '--property=ActiveState', '--value']).strip() != 'inactive':
                    raise ValueError('admit-inactive-initial-activation')
                reload = lambda: None
            publish(SERVING, data, validate, reload, prepare,
                    recover=reload if args.reload is not None else lambda: None)
    finally:
        os.close(descriptor)


if __name__ == '__main__':
    try:
        main()
    except ValueError as error:
        print(f'FAIL: {error}', file=sys.stderr)
        raise SystemExit(1)
    except (OSError, UnicodeError, KeyError, TypeError, StopIteration):
        print('FAIL: observe-shared-haproxy-authority', file=sys.stderr)
        raise SystemExit(1)
