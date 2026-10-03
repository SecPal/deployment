#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Fixed accepted-main privileged Rocky #101 observer; never candidate code.

Only the existing identity-free Rocky guest accepts this fixed entrypoint.
No caller ports, source paths, accounts, commands or policy bytes are accepted.
"""

import csv
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import pwd
import re
import selectors
import signal
import socket
import stat
import subprocess
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path('/opt/secpal-control')
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'scripts/ci-cloud')]
import product_backend_qualification_contract as contract
from product_backend_contract import BACKENDS, admit_policy_account, haproxy_backends, host_policy

STATE = Path('/var/lib/secpal-rocky')
MANIFEST = STATE / 'product-backend-policy.json'
BINDING = STATE / 'product-backend-policy-binding.json'
RESULT = STATE / 'evidence/product-backend-policy.json'
FAILURE = STATE / 'evidence/product-backend-policy-diagnostic.json'
HELPER = Path('/usr/local/libexec/secpal/product-backend-policy')
LIBRARY = HELPER.parent / 'product_backend_contract.py'
SERVICE = Path('/etc/systemd/system/secpal-product-backend-policy.service')
READY = Path('/run/secpal-product-backends/ready.json')
HAPROXY_CONFIG = Path('/etc/haproxy/haproxy.cfg')
STATS = Path('/run/haproxy/secpal-backend101.sock')
NETNS = 'secpal-backend101'
HOST_LINK = 'spbackend101h'
PEER_LINK = 'spbackend101p'
ENVIRONMENT = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'LANG': 'C.UTF-8'}


class Failure(ValueError):
    def __init__(self, operation, reason='invariant-failed'):
        self.operation, self.reason = operation, reason
        super().__init__(operation)


def trusted(path, regular=False):
    current = path
    while True:
        info = current.lstat()
        if (info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o022
                or stat.S_ISLNK(info.st_mode)
                or (current == path and regular and not stat.S_ISREG(info.st_mode))):
            raise Failure('validate-authorization', 'identity-mismatch')
        if current == Path('/'):
            return
        current = current.parent


def read(path, maximum=16384):
    trusted(path, regular=True)
    if not 0 < path.stat().st_size <= maximum:
        raise Failure('validate-authorization', 'observation-limit-exceeded')
    return json.loads(path.read_bytes(), object_pairs_hook=contract.unique_keys)


def write(path, raw, mode=0o644, group=0):
    trusted(path.parent)
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, mode)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(raw)
        os.fchmod(stream.fileno(), mode)
        os.fchown(stream.fileno(), 0, group)
        stream.flush()
        os.fsync(stream.fileno())


def process(arguments, *, timeout=60, maximum=262144):
    """Bound both pipes while reading, and kill only the exact child group."""
    child = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, env=ENVIRONMENT, start_new_session=True)
    streams = {child.stdout: bytearray(), child.stderr: bytearray()}
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            for stream in streams:
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            while selector.get_map():
                if time.monotonic() >= deadline:
                    raise subprocess.TimeoutExpired(arguments, timeout)
                for key, _ in selector.select(0.1):
                    chunk = os.read(key.fd, 4096)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        if sum(map(len, streams.values())) + len(chunk) > maximum:
                            raise OverflowError()
                        streams[key.fileobj].extend(chunk)
            status = child.wait(timeout=max(0.1, deadline - time.monotonic()))
        return status, bytes(streams[child.stdout]).decode(), bytes(streams[child.stderr]).decode()
    finally:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait(timeout=5)
        child.stdout.close()
        child.stderr.close()


class Observer:
    def __init__(self, run_id, run_attempt):
        self.operation = 'validate-authorization'
        self.binding = None
        self.authorized = False
        self.mutated = False
        self.netns_owned = False
        self.original_config = None
        self.original_boolean = None
        self.files = []
        self.images = []
        self.runtime = None
        self.unrelated = None
        self.uid = None
        self.quadlets = None
        self.children = []
        self.facts = {}
        self.records = {'portcons': {}, 'av': [], 'recreations': [], 'external': {}, 'barrier': {}}
        self.cleanup_records = None
        self.created_directories = []
        self.run_id, self.run_attempt = run_id, run_attempt

    def run(self, operation, arguments, *, user=None, accepted=(0,), timeout=60):
        if operation not in contract.OPERATIONS:
            raise Failure('validate-authorization', 'identity-mismatch')
        self.operation = operation
        if user:
            account = pwd.getpwnam(user)
            arguments = ['/usr/sbin/runuser', '-u', user, '--', '/usr/bin/env', '-i',
                'PATH=' + ENVIRONMENT['PATH'], 'HOME=' + account.pw_dir,
                f'XDG_RUNTIME_DIR=/run/user/{account.pw_uid}',
                f'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{account.pw_uid}/bus', *arguments]
        try:
            status, stdout, _ = process(arguments, timeout=timeout)
        except OverflowError:
            raise Failure(operation, 'observation-limit-exceeded') from None
        except (OSError, UnicodeError, subprocess.TimeoutExpired):
            raise Failure(operation, 'command-failed') from None
        if status not in accepted:
            raise Failure(operation, 'command-failed')
        return status, stdout.strip()

    def require(self, condition):
        if not condition:
            raise Failure(self.operation)

    def authorize(self):
        self.require(os.geteuid() == 0 and Path(__file__).resolve() == ROOT / contract.SOURCES['backend_qualifier'])
        trusted(Path(__file__), regular=True)
        sources = {}
        for name, relative in contract.SOURCES.items():
            path = ROOT / relative
            trusted(path, regular=True)
            self.require(0 < path.stat().st_size <= 262144)
            sources[name] = path.read_bytes()
        self.authorization = contract.admit_manifest(read(MANIFEST), sources)
        resource = read(BINDING)
        self.require(set(resource) == {'control_sha', 'profile', 'run_id', 'run_attempt', 'instance_id', 'instance_name'})
        self.require(resource['control_sha'] == self.authorization['control_sha']
                     and resource['profile'] == self.authorization['profile']
                     and resource['run_id'] == self.run_id and resource['run_attempt'] == self.run_attempt
                     and contract.NUMBER.fullmatch(resource['instance_id']) is not None
                     and resource['instance_name'] == 'sprk-' + self.authorization['run_id'] + '-' + self.authorization['run_attempt'] + '-instance')
        self.binding = dict(control_sha=resource['control_sha'], profile=resource['profile'],
            preparation_run_id=self.authorization['run_id'], preparation_run_attempt=self.authorization['run_attempt'],
            run_id=self.run_id, run_attempt=self.run_attempt,
            instance_id=resource['instance_id'], instance_name=resource['instance_name'])
        self.host_digest = hashlib.sha256((STATE / 'evidence/qualification.json').read_bytes()).hexdigest()
        self.authorized = True
        self.operation = 'require-clean-host'
        for path in (HELPER, LIBRARY, SERVICE, READY, RESULT, FAILURE, STATS):
            self.require(not path.exists() and not path.is_symlink())
        self.require(self.run('require-clean-host', ['nft', 'list', 'table', 'inet', 'secpal_product_backends'], accepted=(0, 1))[0] == 1)
        modules = self.run('require-clean-host', ['semodule', '-l'])[1]
        self.require(not any(line.split()[0] == 'secpal_product_backends' for line in modules.splitlines()))
        self.require(self.run('require-clean-host', ['systemctl', 'is-active', 'haproxy.service'], accepted=(0, 3, 4))[0] != 0)
        self.require(self.run('require-clean-host', ['pgrep', '-x', 'haproxy'], accepted=(0, 1))[0] == 1)
        self.require(not READY.parent.exists())
        self.require(NETNS not in self.run('require-clean-host', ['ip', 'netns', 'list'])[1].split())
        self.require(HOST_LINK not in self.run('require-clean-host', ['ip', '-o', 'link', 'show'])[1])
        self.runtime = pwd.getpwnam('secpal-runtime')
        self.unrelated = pwd.getpwnam('secpal-cloud')
        self.quadlets = Path(f'/etc/containers/systemd/users/{self.runtime.pw_uid}')
        trusted(self.quadlets)
        self.require(not list(self.quadlets.glob('secpal-backend101-*')))
        for role in BACKENDS:
            self.require(self.run('require-clean-host', ['podman', '--remote=false', 'container', 'exists', 'secpal-backend101-' + role], user=self.runtime.pw_name, accepted=(0, 1))[0] == 1)
        for network in ('edge', 'application'):
            self.require(self.run('require-clean-host', ['podman', '--remote=false', 'network', 'exists', 'secpal-backend101-' + network], user=self.runtime.pw_name, accepted=(0, 1))[0] == 1)
        for port in (18080, 18081, 18082):
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', port))
        self.require(self.run('observe-cloud-identity', ['curl', '--noproxy', '*', '--fail', '--silent', '--max-time', '2', '-H', 'Metadata-Flavor: Google', 'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token'], accepted=(0, 22, 28, 7))[0] != 0)

    def install(self):
        self.mutated = True
        self.run('install-packages', ['dnf4', '--assumeyes', '--releasever=10', '--disablerepo=*', '--enablerepo=baseos,appstream,extras', 'install', 'haproxy', 'setools-console'], timeout=300)
        self.operation = 'observe-packages'
        spec = importlib.util.spec_from_file_location('backend_rpm_observer', ROOT / 'scripts/ci-cloud/collect-rocky-preparation.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        observer = module.Observer()
        self.packages = [observer.installed_package(name) for name in contract.PACKAGES]
        self.signing_key = observer.rocky_signing_key()
        architecture = self.run('observe-packages', ['uname', '-m'])[1]
        self.require(architecture == contract.PROFILES[self.authorization['profile']])
        # Admit the existing authoritative RPM representation, not a new signer rule.
        signer = contract.rpm.admit_rocky_signing_key(contract.rpm.normalize_rocky_signing_key(self.signing_key))
        for package in self.packages:
            fact = contract.rpm.normalize_installed_package(package['name'], package, architecture)
            contract.rpm.admit_package(fact, signer, architecture)
        self.operation = 'install-policy'
        account = pwd.getpwnam('haproxy')
        self.uid = admit_policy_account(account, self.runtime.pw_uid)
        self.records['accounts'] = dict(haproxy=dict(name=account.pw_name, uid=account.pw_uid, gid=account.pw_gid, shell=account.pw_shell),
            runtime=dict(name=self.runtime.pw_name, uid=self.runtime.pw_uid), unrelated=dict(name=self.unrelated.pw_name, uid=self.unrelated.pw_uid))
        self.require(self.uid != self.unrelated.pw_uid)
        if not HELPER.parent.exists():
            self.created_directories.append(HELPER.parent)
        HELPER.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        trusted(HELPER.parent)
        self.mutated = True
        for path, name in ((HELPER, 'backend_policy'), (LIBRARY, 'backend_contract'), (SERVICE, 'backend_service')):
            self.files.append(path)
            write(path, (ROOT / contract.SOURCES[name]).read_bytes())
        self.original_boolean = self.run('observe-booleans', ['getsebool', 'pasta_bind_all_ports'])[1]
        self.require(self.original_boolean in ('pasta_bind_all_ports --> on', 'pasta_bind_all_ports --> off'))
        self.require(self.run('observe-booleans', ['getsebool', 'haproxy_connect_any'])[1] == 'haproxy_connect_any --> off')
        self.run('configure-booleans', ['setsebool', 'pasta_bind_all_ports', 'off'])
        self.run('activate-policy', ['systemctl', 'daemon-reload'])
        self.created_directories.append(READY.parent)
        self.run('activate-policy', ['systemctl', 'start', 'secpal-product-backend-policy.service'])
        self.operation = 'observe-effective-policy'
        # The installed filename intentionally has no .py extension.
        from importlib.machinery import SourceFileLoader
        spec = importlib.util.spec_from_loader('backend_installed_policy', SourceFileLoader('backend_installed_policy', str(HELPER)))
        self.policy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.policy)
        self.policy.check_effective_policy()
        for source, target, permission in (('haproxy_t', 'secpal_backend_port_t', 'name_connect'), ('container_runtime_t', 'secpal_backend_port_t', 'name_bind'), ('haproxy_t', 'unreserved_port_t', 'name_connect')):
            self.records['av'].append(dict(source=source, target=target, permission=permission, decision=self.policy.effective_decision(source, target, permission)))
        self.facts.update(effective_backend_connect=True, effective_runtime_bind=True, effective_unreserved_connect=False)
        self.facts['selinux'] = self.run('observe-selinux', ['getenforce'])[1]
        self.require(self.facts['selinux'] == 'Enforcing')
        self.records['enforcing'] = self.facts['selinux']
        self.records['booleans'] = [self.run('observe-booleans', ['getsebool', name])[1] for name in ('haproxy_connect_any', 'pasta_bind_all_ports')]
        self.facts['haproxy_connect_any'] = self.run('observe-booleans', ['getsebool', 'haproxy_connect_any'])[1].endswith(' --> on')
        self.facts['pasta_bind_all_ports'] = self.run('observe-booleans', ['getsebool', 'pasta_bind_all_ports'])[1].endswith(' --> on')
        for backend in BACKENDS.values():
            raw = self.run('observe-port-labels', ['seinfo', '/sys/fs/selinux/policy', '--portcon=' + str(backend.host_port), '-x'])[1]
            self.records['portcons'][backend.role] = raw
            self.require(re.search(r'portcon tcp ' + str(backend.host_port) + r' system_u:object_r:secpal_backend_port_t:s0(?:\s|$)', raw) is not None)
        self.facts['backend_port_type'] = 'secpal_backend_port_t'
        # Read the installed kernel rules and exercise them below. Marker/text
        # alone never grants nftables admission.
        raw = self.run('observe-nftables', ['nft', '-j', 'list', 'table', 'inet', 'secpal_product_backends'])[1]
        self.records['nftables'] = json.loads(raw)
        contract.admit_nftables(self.records['nftables'], self.uid)
        self.facts['nft_rules_installed'] = True

    def products(self):
        runtime = self.runtime.pw_name
        info = json.loads(self.run('observe-runtime', ['podman', '--remote=false', 'info', '--format', '{{json .Host}}'], user=runtime)[1])
        self.require(info['security']['rootless'] is True and info['serviceIsRemote'] is False)
        for user in (None, runtime):
            arguments = ['systemctl'] + (['--user'] if user else []) + ['is-active', '--quiet', 'podman.socket', 'podman.service']
            self.require(self.run('observe-runtime', arguments, user=user, accepted=(0, 3, 4))[0] != 0)
        self.facts['runtime_api_dependency'] = False
        authfile = Path('/etc/containers/secpal-backend101-auth.json')
        self.operation = 'require-clean-host'
        self.require(not authfile.exists() and not authfile.is_symlink())
        self.files.append(authfile)
        write(authfile, b'{}\n', mode=0o444)
        for role in BACKENDS:
            source = (ROOT / contract.SOURCES['backend_' + role]).read_text()
            image = next(line.removeprefix('Image=') for line in source.splitlines() if line.startswith('Image='))
            self.require(re.fullmatch(r'ghcr.io/secpal/' + role + r'@sha256:[0-9a-f]{64}', image) is not None)
            exists = self.run('observe-runtime', ['podman', '--remote=false', 'image', 'exists', image], user=runtime, accepted=(0, 1))[0] == 0
            if not exists:
                self.images.append(image)
                self.run('pull-product-images', ['podman', '--remote=false', 'pull', '--authfile', str(authfile), image], user=runtime, timeout=300)
            text = contract.fixture_unit(source, role)
            self.operation = 'install-quadlets'
            path = self.quadlets / ('secpal-backend101-' + role + '.container')
            self.files.append(path)
            write(path, text.encode())
        for name in ('edge', 'application'):
            path = self.quadlets / ('secpal-backend101-' + name + '.network')
            self.files.append(path)
            source = (ROOT / contract.SOURCES['backend_' + name + '_network']).read_text()
            write(path, source.replace('secpal-', 'secpal-backend101-').encode())
        self.run('install-quadlets', ['systemctl', '--user', 'daemon-reload'], user=runtime)

    def observe_runtime(self):
        host = json.loads(self.run('observe-runtime', ['podman', '--remote=false', 'info', '--format', '{{json .Host}}'], user=self.runtime.pw_name)[1])
        states = []
        for user in (None, self.runtime.pw_name):
            for unit in ('podman.socket', 'podman.service'):
                args = ['systemctl'] + (['--user'] if user else []) + ['is-active', unit]
                status, output = self.run('observe-runtime', args, user=user, accepted=(0, 3, 4))
                self.require(status != 0)
                states.append(output)
        text = self.run('observe-runtime', ['systemctl', '--user', 'show-environment'], user=self.runtime.pw_name)[1]
        # Retain only forbidden key names, never values or an environment dump.
        forbidden = {'CONTAINER_HOST', 'CONTAINER_CONNECTION', 'DOCKER_HOST', 'DOCKER_CONTEXT', 'PODMAN_CONNECTIONS_CONF',
                     'REGISTRY_AUTH_FILE', 'CONTAINERS_CONF', 'CONTAINERS_CONF_OVERRIDE', 'CONTAINERS_STORAGE_CONF', 'STORAGE_DRIVER', 'STORAGE_OPTS'}
        present = sorted({line.split('=', 1)[0] for line in text.splitlines()} & forbidden)
        return dict(host=host, unit_states=states, manager_override_keys=present,
            enforcing=self.run('observe-selinux', ['getenforce'])[1],
            booleans=[self.run('observe-booleans', ['getsebool', name])[1] for name in ('haproxy_connect_any', 'pasta_bind_all_ports')])

    def observe_products(self):
        self.current_iteration = {'products': {}, 'runtime': self.observe_runtime(), 'http_stats': ''}
        self.records['recreations'].append(self.current_iteration)
        listeners = self.run('observe-products', ['ss', '-H', '-lntp'])[1]
        for role, backend in BACKENDS.items():
            rows = [line for line in listeners.splitlines() if line.split()[3].endswith(':' + str(backend.host_port))]
            self.require(len(rows) == 1 and rows[0].split()[3] == backend.endpoint)
            pid = re.search(r'pid=([1-9][0-9]*)', rows[0])
            self.require(pid is not None)
            context = self.run('observe-products', ['ps', '-o', 'label=', '-p', pid.group(1)])[1]
            self.require(':container_runtime_t:' in context)
            self.facts['runtime_bind_domain'] = 'container_runtime_t'
            label = self.run('observe-products', ['podman', '--remote=false', 'inspect', '--format', '{{.ProcessLabel}}', 'secpal-backend101-' + role], user=self.runtime.pw_name)[1]
            self.require(':container_t:' in label)
            mode = self.run('observe-products', ['podman', '--remote=false', 'inspect', '--format', '{{.HostConfig.NetworkMode}}', 'secpal-backend101-' + role], user=self.runtime.pw_name)[1]
            self.require(mode != 'host')
            networks = self.run('observe-products', ['podman', '--remote=false', 'inspect', '--format', '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}', 'secpal-backend101-' + role], user=self.runtime.pw_name)[1].split()
            env_keys = [item.split('=', 1)[0] for item in json.loads(self.run('observe-products', ['podman', '--remote=false', 'inspect', '--format', '{{json .Config.Env}}', 'secpal-backend101-' + role], user=self.runtime.pw_name)[1])]
            mount_types = [item.get('Type') for item in json.loads(self.run('observe-products', ['podman', '--remote=false', 'inspect', '--format', '{{json .Mounts}}', 'secpal-backend101-' + role], user=self.runtime.pw_name)[1])]
            unit = self.run('observe-products', ['systemctl', '--user', 'show', 'secpal-backend101-' + role + '.service', '-p', 'FragmentPath,SourcePath,DropInPaths,ExecStart,ExecStartPre'], user=self.runtime.pw_name)[1]
            self.current_iteration['products'][role] = dict(listeners=[row.split()[3] for row in rows], forwarder_context=context,
                container_context=label, network_mode=mode, networks=networks, environment_keys=env_keys, mount_types=mount_types, unit=unit)
        self.facts.update(wildcard_product_bind=False, host_networking=False)
        networks = self.run('observe-products', ['podman', '--remote=false', 'inspect', '--format', '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}', 'secpal-backend101-frontend'], user=self.runtime.pw_name)[1].split()
        self.require(networks == ['secpal-backend101-edge'])
        environment = json.loads(self.run('observe-products', ['podman', '--remote=false', 'inspect', '--format', '{{json .Config.Env}}', 'secpal-backend101-frontend'], user=self.runtime.pw_name)[1])
        self.require(not any(item.startswith(('DB_', 'AWS_', 'APP_KEY=', 'SECPAL_SECRET_', 'FILESYSTEM_')) for item in environment))
        mounts = json.loads(self.run('observe-products', ['podman', '--remote=false', 'inspect', '--format', '{{json .Mounts}}', 'secpal-backend101-frontend'], user=self.runtime.pw_name)[1])
        self.require(not any(item.get('Type') == 'bind' for item in mounts))
        self.facts['frontend_private_authority'] = False

    def haproxy(self):
        self.operation = 'configure-haproxy'
        if not STATS.parent.exists():
            self.created_directories.append(STATS.parent)
            STATS.parent.mkdir(mode=0o755)
        trusted(STATS.parent)
        self.run('configure-haproxy', ['restorecon', str(STATS.parent)])
        trusted(HAPROXY_CONFIG, regular=True)
        self.original_config = (HAPROXY_CONFIG.read_bytes(), stat.S_IMODE(HAPROXY_CONFIG.stat().st_mode))
        HAPROXY_CONFIG.unlink()
        configuration = ('global\n    user haproxy\n    group haproxy\n    stats socket ' + str(STATS) + ' mode 600\n'
                         'defaults\n    mode http\n    timeout connect 1s\n    timeout client 5s\n    timeout server 5s\n' + haproxy_backends()
                         + '\nbackend secpal_unrelated\n    option httpchk GET /health/live\n    server unrelated 127.0.0.1:18082 check inter 1s\n')
        write(HAPROXY_CONFIG, configuration.encode())
        self.run('configure-haproxy', ['restorecon', str(HAPROXY_CONFIG)])
        self.run('configure-haproxy', ['haproxy', '-c', '-f', str(HAPROXY_CONFIG)])
        self.run('start-haproxy', ['systemctl', 'start', 'haproxy.service'])
        self.operation = 'observe-haproxy-identity'
        unit = self.run('observe-haproxy-identity', ['systemctl', 'show', 'haproxy.service', '-p', 'FragmentPath,DropInPaths,ExecStart,ControlGroup,ActiveState,Result'])[1]
        group = contract.properties(unit)['ControlGroup']
        self.require(group == '/system.slice/haproxy.service')
        pids = [int(value) for value in Path('/sys/fs/cgroup/system.slice/haproxy.service/cgroup.procs').read_text().split()]
        self.require(1 <= len(pids) <= 16)
        processes = []
        for pid in pids:
            path = Path('/proc') / str(pid)
            status = (path / 'status').read_text()
            ids = next(line.split()[1:] for line in status.splitlines() if line.startswith('Uid:'))
            processes.append(dict(pid=pid, uids=list(map(int, ids)), context=(path / 'attr/current').read_text().strip(),
                                  exe=os.readlink(path / 'exe'), cgroup=(path / 'cgroup').read_text().strip()))
        all_pids = list(map(int, self.run('observe-haproxy-identity', ['pgrep', '-x', 'haproxy'])[1].split()))
        rows = [line.split() for line in Path('/proc/net/unix').read_text().splitlines() if line.endswith(' ' + str(STATS))]
        self.require(len(rows) == 1)
        inode = int(rows[0][6])
        holders = []
        for pid in pids:
            for entry in (Path('/proc') / str(pid) / 'fd').iterdir():
                try:
                    if os.readlink(entry) == f'socket:[{inode}]':
                        holders.append(pid)
                        break
                except FileNotFoundError:
                    pass
        owners = self.run('observe-haproxy-identity', ['rpm', '-qf', '--qf', '%{NAME}\\n', '/usr/sbin/haproxy', '/usr/lib/systemd/system/haproxy.service'])[1].splitlines()
        self.records['haproxy'] = dict(unit=unit, package_owners=owners, processes=processes, all_pids=all_pids,
                                       stats_inode=inode, stats_holders=holders)
        self.facts['haproxy_domain'] = 'haproxy_t'

    def readiness(self):
        self.operation = 'observe-http-readiness'
        deadline = time.monotonic() + 45
        while True:
            trusted(STATS.parent)
            with socket.socket(socket.AF_UNIX) as channel:
                channel.settimeout(3)
                channel.connect(str(STATS))
                channel.sendall(b'show stat\n')
                raw = bytearray()
                while True:
                    chunk = channel.recv(4096)
                    if not chunk:
                        break
                    raw.extend(chunk)
                    self.require(len(raw) <= 65536)
            rows = list(csv.DictReader(io.StringIO(raw.decode().removeprefix('# '))))
            selected = [row for row in rows if row['pxname'] in {'secpal_frontend', 'secpal_api'} and row['svname'] in BACKENDS]
            if len(selected) == 2 and all(row['status'] == 'UP' and row['check_status'] == 'L7OK' and row['check_code'] == '200' for row in selected):
                self.current_iteration['http_stats'] = raw.decode()
                self.facts['haproxy_http_ready'] = True
                return
            self.require(time.monotonic() < deadline)
            time.sleep(1)

    def boundaries(self):
        self.records['unrelated'] = {'local_statuses': [], 'ipv6_statuses': []}
        for backend in BACKENDS.values():
            status, _ = self.run('probe-unrelated-uid', ['curl', '--noproxy', '*', '--fail', '--silent', '--max-time', '2', f'http://{backend.endpoint}{backend.readiness_path}'], user=self.unrelated.pw_name, accepted=(0, 7, 28, 52, 56))
            self.require(status != 0)
            self.records['unrelated']['local_statuses'].append(status)
            status, _ = self.run('probe-unrelated-uid', ['curl', '-g', '--noproxy', '*', '--fail', '--silent', '--max-time', '2', f'http://[::1]:{backend.host_port}/health/live'], accepted=(0, 7, 28, 52, 56))
            self.require(status != 0)
            self.records['unrelated']['ipv6_statuses'].append(status)
        self.facts.update(unrelated_uid_access=False, ipv6_backend_access=False)
        self.netns_owned = True
        self.run('configure-external-probe', ['ip', 'netns', 'add', NETNS])
        self.run('configure-external-probe', ['ip', 'link', 'add', HOST_LINK, 'type', 'veth', 'peer', 'name', PEER_LINK])
        self.run('configure-external-probe', ['ip', 'link', 'set', PEER_LINK, 'netns', NETNS])
        self.run('configure-external-probe', ['ip', 'addr', 'add', '192.0.2.1/30', 'dev', HOST_LINK])
        self.run('configure-external-probe', ['ip', 'link', 'set', HOST_LINK, 'up'])
        for arguments in (['ip', 'addr', 'add', '192.0.2.2/30', 'dev', PEER_LINK], ['ip', 'link', 'set', PEER_LINK, 'up']):
            self.run('configure-external-probe', ['ip', 'netns', 'exec', NETNS, *arguments])
        for backend in BACKENDS.values():
            # Qualification-only private-address listener supplies the positive
            # control. It is never a product or wildcard/public listener.
            code = ('from http.server import HTTPServer, BaseHTTPRequestHandler\n'
                    'class Handler(BaseHTTPRequestHandler):\n'
                    ' def do_GET(self):\n'
                    '  self.send_response(200); self.end_headers()\n'
                    ' def log_message(self, *args): pass\n'
                    f"HTTPServer(('192.0.2.1', {backend.host_port}), Handler).serve_forever()\n")
            server = subprocess.Popen(['/usr/bin/python3', '-I', '-c', code], env=ENVIRONMENT,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            self.children.append(server)
            time.sleep(1)
            positive = self.run('probe-external-interface', ['curl', '--noproxy', '*', '--silent', '--fail', '--max-time', '2', '--output', '/dev/null', '--write-out', '%{http_code}', f'http://192.0.2.1:{backend.host_port}/health/live'])[1]
            self.require(positive == '200')
            status, _ = self.run('probe-external-interface', ['ip', 'netns', 'exec', NETNS, 'curl', '--noproxy', '*', '--silent', '--fail', '--max-time', '2', f'http://192.0.2.1:{backend.host_port}/health/live'], accepted=(0, 7, 28, 52, 56))
            self.require(status != 0)
            self.records['external'][backend.role] = dict(positive_http_code=positive, ingress_status=status)
        self.facts['external_interface_access'] = False
        # Actual unrelated listener is healthy to root, while haproxy_t is
        # refused by SELinux (this port is outside the nft backend port set).
        self.operation = 'observe-unrelated-selinux-denial'
        server = subprocess.Popen(['/usr/bin/python3', '-I', '-m', 'http.server', '18082', '--bind', '127.0.0.1'], env=ENVIRONMENT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        self.children.append(server)
        time.sleep(3)
        positive = self.run('observe-unrelated-selinux-denial', ['curl', '--noproxy', '*', '--fail', '--silent', '--max-time', '3', '--output', '/dev/null', '--write-out', '%{http_code}', 'http://127.0.0.1:18082/'])[1]
        self.require(positive == '200')
        self.records['unrelated']['positive_http_code'] = positive
        audit = self.run('observe-unrelated-selinux-denial', ['ausearch', '-m', 'AVC', '-ts', 'recent', '-c', 'haproxy', '--raw'])[1]
        self.require(any('denied' in line and 'name_connect' in line and 'dest=18082' in line and ':haproxy_t:' in line and ':unreserved_port_t:' in line for line in audit.splitlines()))
        matching = [line for line in audit.splitlines() if 'denied' in line and 'name_connect' in line and 'dest=18082' in line and ':haproxy_t:' in line and ':unreserved_port_t:' in line]
        self.records['unrelated']['avc'] = '\n'.join(matching[-4:])
        self.facts['actual_unrelated_haproxy_access'] = False
        self.run('probe-startup-barrier', ['systemctl', '--user', 'stop', *self.units], user=self.runtime.pw_name)
        saved = READY.read_bytes()
        for kind in ('missing', 'stale'):
            READY.unlink()
            if kind == 'stale':
                marker = json.loads(saved)
                marker['policy_digest'] = '0' * 64
                write(READY, contract.canonical(marker), mode=0o444)
            try:
                self.run('probe-startup-barrier', ['systemctl', '--user', 'reset-failed', self.units[0]], user=self.runtime.pw_name, accepted=(0, 1))
                status, _ = self.run('probe-startup-barrier', ['systemctl', '--user', 'start', self.units[0]], user=self.runtime.pw_name, accepted=(0, 1))
                self.require(status == 1)
                pre = self.run('probe-startup-barrier', ['systemctl', '--user', 'show', self.units[0], '-p', 'ExecStartPre', '--value'], user=self.runtime.pw_name)[1]
                self.require('product-backend-policy --check' in pre and 'status=1' in pre)
                self.records['barrier'][kind + '_start_status'] = status
                self.records['barrier'][kind + '_pre_status'] = int(re.search(r'status=([0-9]+)', pre).group(1))
            finally:
                READY.unlink(missing_ok=True)
                write(READY, saved, mode=0o444)
        self.facts['startup_barrier_refusal'] = True
        self.facts['root_excluded_from_isolation'] = True

    def execute(self):
        self.authorize()
        self.install()
        self.products()
        self.units = ['secpal-backend101-' + role + '.service' for role in BACKENDS]
        for iteration in range(3):
            if iteration:
                self.run('start-products', ['systemctl', '--user', 'stop', *self.units], user=self.runtime.pw_name)
            self.run('start-products', ['systemctl', '--user', 'start', *self.units], user=self.runtime.pw_name, timeout=200)
            self.observe_products()
            if not iteration:
                self.haproxy()
            self.readiness()
        self.facts['fixed_endpoint_recreation'] = True
        self.observe_runtime()
        self.boundaries()

    def observe_cleanup(self):
        paths = [READY, STATS, *self.files, *self.created_directories]
        remaining_paths = [str(path) for path in paths if path.exists() or path.is_symlink()]
        names = self.run('observe-cleanup', ['podman', '--remote=false', 'ps', '-a', '--format', '{{.Names}}'], user=self.runtime.pw_name)[1].splitlines()
        containers = [name for name in names if name.startswith('secpal-backend101-')]
        names = self.run('observe-cleanup', ['podman', '--remote=false', 'network', 'ls', '--format', '{{.Name}}'], user=self.runtime.pw_name)[1].splitlines()
        networks = [name for name in names if name.startswith('secpal-backend101-')]
        images = [image for image in self.images if self.run('observe-cleanup', ['podman', '--remote=false', 'image', 'exists', image], user=self.runtime.pw_name, accepted=(0, 1))[0] == 0]
        services = [self.run('observe-cleanup', ['systemctl', 'is-active', unit], accepted=(0, 3, 4))[1]
                    for unit in ('haproxy.service', 'secpal-product-backend-policy.service')]
        # Removed oneshot unit becomes unknown after reload, which is absence.
        services = ['inactive' if state == 'unknown' else state for state in services]
        runtime = self.observe_runtime()
        table_status = self.run('observe-cleanup', ['nft', 'list', 'table', 'inet', 'secpal_product_backends'], accepted=(0, 1))[0]
        modules = [line.split()[0] for line in self.run('observe-cleanup', ['semodule', '-l'])[1].splitlines() if line.split()[0] == 'secpal_product_backends']
        netns = [line.split()[0] for line in self.run('observe-cleanup', ['ip', 'netns', 'list'])[1].splitlines() if line.split()[0] == NETNS]
        links = [line for line in self.run('observe-cleanup', ['ip', '-o', 'link', 'show'])[1].splitlines() if HOST_LINK in line]
        listeners = [line.split()[3] for line in self.run('observe-cleanup', ['ss', '-H', '-lnt'])[1].splitlines() if line.split()[3].rsplit(':', 1)[-1] in {'18080', '18081', '18082'}]
        current_hash = hashlib.sha256(HAPROXY_CONFIG.read_bytes()).hexdigest() if HAPROXY_CONFIG.is_file() else ''
        original_hash = hashlib.sha256(self.original_config[0]).hexdigest() if self.original_config else current_hash
        boolean = self.run('observe-cleanup', ['getsebool', 'pasta_bind_all_ports'])[1]
        return dict(remaining_paths=remaining_paths, remaining_containers=containers, remaining_networks=networks,
                    remaining_images=images, service_states=services, runtime_unit_states=runtime['unit_states'],
                    nft_table_status=table_status, module_names=modules, netns_names=netns, link_names=links, listeners=listeners,
                    haproxy_config_sha256=current_hash, original_haproxy_config_sha256=original_hash,
                    pasta_boolean=boolean, original_pasta_boolean=self.original_boolean or boolean)

    def cleanup(self):
        if not self.mutated:
            return False
        failures = []
        def attempt(action):
            try:
                action()
            except (OSError, ValueError, subprocess.SubprocessError):
                failures.append(True)
        self.operation = 'cleanup-host'
        for child in self.children:
            attempt(lambda child=child: os.killpg(child.pid, signal.SIGTERM))
            attempt(lambda child=child: child.wait(timeout=5))
        attempt(lambda: self.run('cleanup-host', ['systemctl', 'stop', 'haproxy.service', 'secpal-product-backend-policy.service'], accepted=(0, 5)))
        if self.runtime:
            for role in BACKENDS:
                unit = 'secpal-backend101-' + role + '.service'
                attempt(lambda unit=unit: self.run('cleanup-host', ['systemctl', '--user', 'stop', unit], user=self.runtime.pw_name, accepted=(0, 5)))
                attempt(lambda unit=unit: self.run('cleanup-host', ['systemctl', '--user', 'reset-failed', unit], user=self.runtime.pw_name, accepted=(0, 1)))
            for role in BACKENDS:
                attempt(lambda role=role: self.run('cleanup-host', ['podman', '--remote=false', 'rm', '--force', 'secpal-backend101-' + role], user=self.runtime.pw_name, accepted=(0, 1)))
            for name in ('edge', 'application'):
                attempt(lambda name=name: self.run('cleanup-host', ['podman', '--remote=false', 'network', 'rm', 'secpal-backend101-' + name], user=self.runtime.pw_name, accepted=(0, 1)))
            for image in self.images:
                attempt(lambda image=image: self.run('cleanup-host', ['podman', '--remote=false', 'image', 'rm', image], user=self.runtime.pw_name, accepted=(0, 1)))
        if self.netns_owned:
            attempt(lambda: self.run('cleanup-host', ['ip', 'link', 'delete', HOST_LINK], accepted=(0, 1)))
            attempt(lambda: self.run('cleanup-host', ['ip', 'netns', 'delete', NETNS], accepted=(0, 1)))
        attempt(lambda: self.run('cleanup-host', ['nft', 'delete', 'table', 'inet', 'secpal_product_backends'], accepted=(0, 1)))
        attempt(lambda: self.run('cleanup-host', ['semodule', '-r', 'secpal_product_backends'], accepted=(0, 1)))
        attempt(lambda: self.run('cleanup-host', ['systemctl', 'reset-failed', 'haproxy.service', 'secpal-product-backend-policy.service'], accepted=(0, 1)))
        for path in [READY, STATS, *reversed(self.files)]:
            attempt(lambda path=path: path.unlink(missing_ok=True))
        for directory in reversed(self.created_directories):
            attempt(lambda directory=directory: directory.rmdir())
        if self.original_config:
            attempt(lambda: HAPROXY_CONFIG.unlink(missing_ok=True))
            attempt(lambda: write(HAPROXY_CONFIG, self.original_config[0], mode=self.original_config[1]))
            attempt(lambda: self.run('cleanup-host', ['restorecon', str(HAPROXY_CONFIG)]))
        if self.original_boolean:
            value = 'on' if self.original_boolean.endswith(' --> on') else 'off'
            attempt(lambda: self.run('cleanup-host', ['setsebool', 'pasta_bind_all_ports', value]))
        attempt(lambda: self.run('cleanup-host', ['systemctl', 'daemon-reload']))
        attempt(lambda: self.run('cleanup-host', ['systemctl', '--user', 'daemon-reload'], user=self.runtime.pw_name))
        self.operation = 'observe-cleanup'
        attempt(lambda: self.require(all(not path.exists() and not path.is_symlink() for path in [READY, STATS, *self.files])))
        attempt(lambda: self.require(self.run('observe-cleanup', ['nft', 'list', 'table', 'inet', 'secpal_product_backends'], accepted=(0, 1))[0] == 1))
        attempt(lambda: self.require('secpal_product_backends' not in self.run('observe-cleanup', ['semodule', '-l'])[1]))
        attempt(lambda: self.require(NETNS not in self.run('observe-cleanup', ['ip', 'netns', 'list'])[1].split()))
        attempt(lambda: self.require(HOST_LINK not in self.run('observe-cleanup', ['ip', '-o', 'link', 'show'])[1]))
        for backend in BACKENDS.values():
            attempt(lambda backend=backend: self.require(not any(row.split()[3].endswith(':' + str(backend.host_port)) for row in self.run('observe-cleanup', ['ss', '-H', '-lnt'])[1].splitlines())))
        try:
            self.cleanup_records = self.observe_cleanup()
            contract.admit_cleanup(self.cleanup_records)
        except (ValueError, OSError, KeyError, TypeError):
            failures.append(True)
        return not failures


def main():
    if (len(sys.argv) != 3 or not contract.NUMBER.fullmatch(sys.argv[1])
            or not contract.NUMBER.fullmatch(sys.argv[2]) or len(sys.argv[2]) > 3):
        return 64
    observer = Observer(sys.argv[1], sys.argv[2])
    failure = None
    try:
        observer.execute()
    except Failure as error:
        failure = (error.operation, error.reason)
    except (ValueError, KeyError, TypeError, OSError, ImportError, AttributeError, subprocess.SubprocessError):
        failure = (observer.operation, 'representation-invalid')
    finally:
        cleaned = observer.cleanup()
    if not cleaned and failure is None:
        failure = ('observe-cleanup', 'invariant-failed')
    if failure:
        diagnostic = contract.diagnostic(*failure, cleaned)
        if observer.authorized:
            document = dict(binding=observer.binding, source_sha256=observer.authorization['source_sha256'], diagnostic=diagnostic, cleanup=observer.cleanup_records)
            write(FAILURE, contract.canonical(document) + b'\n', mode=0o440, group=pwd.getpwnam('secpal-cloud').pw_gid)
        print(json.dumps(diagnostic), file=sys.stderr)
        return 1
    observer.facts['host_cleanup_complete'] = cleaned
    observer.records['cleanup'] = observer.cleanup_records
    evidence = dict(schema_version=1, selector=contract.SELECTOR, binding=observer.binding,
        source_sha256=observer.authorization['source_sha256'], observations=contract.required_observations(), records=observer.records,
        haproxy_uid=observer.uid, runtime_uid=observer.runtime.pw_uid, unrelated_uid=observer.unrelated.pw_uid,
        packages=observer.packages, rocky_signing_key=observer.signing_key, host_evidence_sha256=observer.host_digest)
    try:
        contract.admit_evidence(evidence, observer.binding, observer.authorization['source_sha256'])
        write(RESULT, contract.canonical(evidence) + b'\n', mode=0o440, group=pwd.getpwnam('secpal-cloud').pw_gid)
    except (ValueError, OSError, KeyError, TypeError):
        print(json.dumps(contract.diagnostic('admit-evidence', 'invariant-failed', cleaned)), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
