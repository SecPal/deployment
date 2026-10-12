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
import ssl
import socket
import struct
import subprocess
import sys
import tempfile
import time

HELPER = Path('/usr/local/libexec/secpal/haproxy-config')
LIBRARIES = ('haproxy_base_contract.py', 'haproxy_direct_contract.py', 'haproxy_direct_policy.py', 'haproxy_composition_contract.py',
             'haproxy_config_lifecycle.py', 'product_backend_contract.py', 'haproxy_supply_contract.py',
             'viewer_tls_contract.py', 'viewer_tls_runtime.py')
SPEC = Path('/etc/haproxy/secpal-routing.json')
SERVING = Path('/etc/haproxy/secpal.cfg')
LISTENER_UNIT = Path('/etc/systemd/system/haproxy.service.d/secpal-listeners.conf')
BASE_UNIT = Path('/etc/systemd/system/haproxy.service.d/secpal.conf')
RUNTIME = Path('/run/haproxy')
BINARY = Path('/usr/sbin/haproxy')
RUNTIME_POLICY = HELPER.parent / 'secpal_haproxy_runtime.cil'
REVIEWED_RPM = HELPER.parent / 'haproxy-reviewed.rpm'


def trusted(path: Path, *, regular=False):
    for current in (path, *path.parents):
        info = current.lstat()
        if (info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode)
                or (current != path and not stat.S_ISDIR(info.st_mode))):
            raise ValueError('admit-administrator-path')
    info = path.lstat()
    if regular and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
        raise ValueError('admit-administrator-file')


def admit_source_before_import():
    if os.geteuid() != 0 or Path(__file__).resolve() != HELPER:
        raise ValueError('admit-installed-administrator-helper')
    for path in (HELPER, *(HELPER.parent / name for name in LIBRARIES)):
        trusted(path, regular=True)


if __name__ == '__main__':
    try:
        admit_source_before_import()
        # Compile admitted source, never an adjacent cache whose ownership was
        # not admitted. This private per-process namespace starts empty.
        temporary = Path('/tmp').lstat()
        if (temporary.st_uid != 0 or not stat.S_ISDIR(temporary.st_mode)
                or (temporary.st_mode & 0o022 and not temporary.st_mode & stat.S_ISVTX)):
            raise ValueError('admit-administrator-temporary-path')
        _source_cache = tempfile.TemporaryDirectory(prefix='secpal-haproxy-imports-', dir='/tmp')
        sys.pycache_prefix = _source_cache.name
        sys.dont_write_bytecode = True
    except (ValueError, OSError):
        print('FAIL: admit-installed-source', file=sys.stderr)
        raise SystemExit(1)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from haproxy_base_contract import MAX_CONFIG_BYTES
from haproxy_composition_contract import decode_document, render, listener_constraints, from_config, generation_id, coordinates
from haproxy_direct_contract import ViewerListener, ProxyListener, VIEWER_PEM
from haproxy_config_lifecycle import publish
from product_backend_contract import admit_policy_account
from haproxy_supply_contract import admit_installed_package, admit_rpm_digest, normalize_features, binary_sha256
from viewer_tls_runtime import boot_admission


def observe(operation, arguments, *, timeout=15):
    try:
        result = subprocess.run(arguments, capture_output=True, timeout=timeout,
                                env={'PATH': '/usr/sbin:/usr/bin', 'LANG': 'C'}, cwd='/')
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError(operation) from error
    if result.returncode or len(result.stdout) > 65536 or len(result.stderr) > 65536:
        raise ValueError(operation)
    return result.stdout.decode('utf-8', errors='strict')


def authority(*, desired=True, construction=False, publication=False):
    if os.geteuid() != 0 or Path(__file__).resolve() != HELPER:
        raise ValueError('admit-installed-administrator-helper')
    for path in (HELPER, *(HELPER.parent / name for name in LIBRARIES), RUNTIME_POLICY, REVIEWED_RPM, BINARY, BASE_UNIT, LISTENER_UNIT, HELPER.parent / 'product-backend-policy'):
        trusted(path, regular=True)
    architecture = platform.machine()
    if not 0 < REVIEWED_RPM.stat().st_size <= 16 * 1024 * 1024:
        raise ValueError('admit-haproxy-rpm-size')
    admit_rpm_digest(architecture, binary_sha256(REVIEWED_RPM.read_bytes()))
    # Exact independently signature-authenticated RPM bytes are the supply
    # anchor. Native verification also checks every installed package file.
    if observe('verify-haproxy-package-files', ['/usr/bin/rpm', '-V', '-p', str(REVIEWED_RPM)]).strip():
        raise ValueError('admit-haproxy-installed-payload')
    admit_loaded_unit(observe('observe-loaded-haproxy-unit', ['/usr/bin/systemctl', 'show',
                      'haproxy.service', '-p', 'NeedDaemonReload,FragmentPath,DropInPaths']))
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
    if any(type(row) is ViewerListener and row.transport == 'https' for row in listeners):
        trusted(Path(VIEWER_PEM), regular=True)
    if listeners and type(listeners[0]) is ViewerListener and listeners[0].tls_lifecycle != 'legacy':
        from haproxy_direct_contract import Direct
        boot_admission(Direct(routing, listeners), allow_pending_reload=publication)
    if any(type(row) is ProxyListener for row in listeners):
        policy = HELPER.parent / 'haproxy-direct-policy'
        trusted(policy, regular=True)
        # The HAProxy sandbox excludes netlink and NET_ADMIN. Reuse the
        # administrator-owned policy service for native kernel observation;
        # do not widen the daemon's runtime privileges or address families.
        if not construction:
            observe('observe-direct-private-policy', ['/usr/bin/systemctl', 'reload', 'secpal-direct-policy.service'])
        observe('admit-direct-private-policy', ['/usr/bin/python3', '-I', str(policy),
                '--check' if construction else '--check-marker', *(['--desired'] if desired else [])])
        if any(row.transport == 'https' for row in listeners):
            trusted(Path(VIEWER_PEM), regular=True)
    if LISTENER_UNIT.read_text() != listener_constraints(listeners):
        raise ValueError('admit-exact-listener-unit')
    return render(routing, listeners).encode('utf-8'), account.pw_uid


def validate(candidate):
    observe('validate-haproxy-candidate', [str(BINARY), '-c', '-q', '-f', str(candidate)])


def prepare(candidate):
    # Use the actual stock Rocky file context (etc_t), not an invented type.
    observe('label-haproxy-candidate', ['/usr/sbin/restorecon', '-F', str(candidate)])


def admit_loaded_unit(output):
    rows = output.strip().splitlines()
    fields = dict(row.split('=', 1) for row in rows)
    if (len(rows) != 3 or set(fields) != {'NeedDaemonReload', 'FragmentPath', 'DropInPaths'}
            or fields['NeedDaemonReload'] != 'no'
            or fields['FragmentPath'] != '/usr/lib/systemd/system/haproxy.service'
            or sorted(fields['DropInPaths'].split()) != sorted((str(BASE_UNIT), str(LISTENER_UNIT)))):
        raise ValueError('admit-loaded-haproxy-unit')


def process_identity(pid, *, master=False):
    if type(pid) is not int or pid <= 1:
        raise ValueError('admit-haproxy-pid')
    process = Path('/proc') / str(pid)
    if (process / 'exe').resolve() != BINARY:
        raise ValueError('admit-haproxy-executable')
    status = (process / 'status').read_text()
    uids = next(row.split()[1:] for row in status.splitlines() if row.startswith('Uid:'))
    context = (process / 'attr/current').read_text().strip().split(':')
    if len(context) < 4 or context[2] != 'haproxy_t':
        raise ValueError('admit-haproxy-domain')
    return process, tuple(int(uid) for uid in uids)


def master_children(pid):
    process, uids = process_identity(pid, master=True)
    if uids != (0, 0, 0, 0):
        raise ValueError('admit-haproxy-master-uid')
    cgroup = (process / 'cgroup').read_text()
    if not any(row.split(':', 2)[-1] == '/system.slice/haproxy.service' for row in cgroup.splitlines()):
        raise ValueError('admit-haproxy-system-unit')
    return process / 'task' / str(pid) / 'children'


def verify_running(pid, worker_uid):
    children = master_children(pid)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        for child in children.read_text().split():
            try:
                _, ids = process_identity(int(child))
                if ids == (worker_uid,) * 4 and probe_generation(int(child)):
                    if child in children.read_text().split():
                        _, ids = process_identity(int(child))
                        if ids == (worker_uid,) * 4:
                            return
            except (OSError, ValueError, StopIteration):
                continue
        time.sleep(.1)
    raise ValueError('verify-haproxy-startup-generation')


def reload_master(pid, worker_uid):
    children = master_children(pid)
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
    for row in listeners:
        listener = coordinates(row)
        address = {'0.0.0.0': '127.0.0.1', '::': '::1'}.get(listener.address, listener.address)
        create_transport = socket.create_connection
        if type(row) is ProxyListener:
            def create_transport(target, timeout, source_address=None, *, all_errors=False):
                family = socket.AF_INET6 if ':' in address else socket.AF_INET
                source = '::1' if family == socket.AF_INET6 else '127.0.0.1'
                connection = socket.create_connection((address, target[1]), timeout)
                binary = socket.inet_pton(family, source) + socket.inet_pton(family, address)
                binary += struct.pack('!HH', connection.getsockname()[1], target[1])
                connection.sendall(b'\r\n\r\n\0\r\nQUIT\n' + bytes((0x21, 0x21 if family == socket.AF_INET6 else 0x11))
                                   + struct.pack('!H', len(binary)) + binary)
                return connection
        if type(row) in (ViewerListener, ProxyListener) and row.transport == 'https':
            context = ssl.create_default_context()
            context.load_verify_locations(cafile=VIEWER_PEM)
            connection = http.client.HTTPSConnection(routing.frontend_host, listener.port, timeout=.5, context=context)
            # Dial the exact admitted socket while retaining DNS-name TLS
            # certificate verification and SNI. No DNS/provider lookup.
            connection._create_connection = lambda target, *args, **kwargs: create_transport(
                (address, target[1]), *args, **kwargs)
        else:
            connection = http.client.HTTPConnection(address, listener.port, timeout=.5)
            connection._create_connection = create_transport
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
    actions.add_argument('--verify-running', type=int, metavar='SYSTEMD_MAINPID')
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
        requested_pid = args.reload if args.reload is not None else args.verify_running
        if requested_pid is not None:
            if observe('observe-exact-haproxy-mainpid', ['/usr/bin/systemctl', 'show',
                       'haproxy.service', '--property=MainPID', '--value']).strip() != str(requested_pid):
                raise ValueError('admit-exact-systemd-mainpid')
        data, uid = authority(desired=not (args.check or args.verify_running is not None), construction=args.activate,
                              publication=args.reload is not None)
        if args.check or args.verify_running is not None:
            trusted(SERVING, regular=True)
            if SERVING.stat().st_size > MAX_CONFIG_BYTES or SERVING.read_bytes() != data:
                raise ValueError('admit-serving-reviewed-config')
            validate(SERVING)
            if args.verify_running is not None:
                verify_running(args.verify_running, uid)
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
                # Fixed reviewed policy only; activation runs outside the
                # hardened service and accepts no policy path or rule input.
                observe('install-haproxy-runtime-policy', ['/usr/sbin/semodule',
                        '-i', str(RUNTIME_POLICY), '-e', 'secpal_haproxy_runtime'], timeout=60)
                observe('label-haproxy-runtime', ['/usr/sbin/restorecon', '-RF', str(RUNTIME)])
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
