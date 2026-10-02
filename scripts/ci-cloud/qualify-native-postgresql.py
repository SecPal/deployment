#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Accepted-main root applicator/observer for one ephemeral PostgreSQL run.

No candidate code is executed. No provider credentials enter this guest. The
root-owned authorization arrives through the existing trusted startup script.
"""

from __future__ import annotations

import argparse
import base64
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import secrets
import selectors
import signal
import tempfile
import shutil
import socket
import stat
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import postgresql_qualification_contract as contract

ROOT = Path(__file__).resolve().parents[2]
STATE = Path('/var/lib/secpal-rocky')
AUTHORIZATION = STATE / 'postgresql-candidate.json'
OUTPUT = STATE / 'evidence/postgresql-qualification.json'
DIAGNOSTIC = STATE / 'evidence/postgresql-qualification-diagnostic.json'
MATERIAL = Path('/etc/secpal/postgresql/current')
DATA = Path('/var/lib/pgsql/data')
CLIENT = Path('/var/lib/secpal-postgresql-qualification-client')
HOST_TARGET = '402c22b0a1d69a5a3dba74ffb68cf016caba606b'
HOST_HARNESS = '436756f79c7f120d5c4b9fc15b12b2fd91da0fdea5e93ed2907172a73c2861ac'
CONTAINER = 'secpal-native-postgresql-readiness'
APPLICATION_PROBE = 'secpal-native-postgresql-application-probe'
PSQL_CLIENT = CLIENT / 'psql'
APPLICATION_IMAGE_STATE = STATE / 'application-image'


def trusted_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise contract.QualificationError('validate-authorization', 'identity-mismatch')
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def bounded_process(arguments, *, environment, text=None, timeout=60, limit=262144, operation):
    """Collect during execution; terminate the exact process group on overflow."""
    if text is not None and len(text.encode()) > 8192:
        raise contract.QualificationError(operation, 'observation-limit-exceeded')
    with tempfile.TemporaryFile() as input_stream:
        if text is not None:
            input_stream.write(text.encode())
        input_stream.seek(0)
        try:
            process = subprocess.Popen(arguments, stdin=input_stream, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, env=environment, start_new_session=True)
        except OSError:
            raise contract.QualificationError(operation, 'command-failed') from None
        buffers = {process.stdout: bytearray(), process.stderr: bytearray()}
        deadline = time.monotonic() + timeout
        try:
            with selectors.DefaultSelector() as selector:
                for stream in buffers:
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise contract.QualificationError(operation, 'command-failed')
                    for key, _ in selector.select(min(remaining, 0.25)):
                        block = os.read(key.fd, 4096)
                        if not block:
                            selector.unregister(key.fileobj)
                        else:
                            if sum(len(b) for b in buffers.values()) + len(block) > limit:
                                raise contract.QualificationError(operation, 'observation-limit-exceeded')
                            buffers[key.fileobj].extend(block)
                status = process.wait(timeout=max(0.01, deadline - time.monotonic()))
            return subprocess.CompletedProcess(arguments, status,
                bytes(buffers[process.stdout]).decode('utf-8'), bytes(buffers[process.stderr]).decode('utf-8'))
        except (OSError, UnicodeError, subprocess.TimeoutExpired):
            raise contract.QualificationError(operation, 'representation-invalid') from None
        finally:
            # Descendants cannot retain our pipes or survive the bounded command.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
            process.stdout.close()
            process.stderr.close()


def write_evidence(path: Path, content: str, *, owner=0, group=0, mode=0o600):
    """Fixed root-owned output, independent of observer initialization."""
    if path.is_symlink():
        raise contract.QualificationError('write-evidence', 'identity-mismatch')
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    with os.fdopen(descriptor, 'w') as stream:
        stream.write(content)
        os.fchmod(stream.fileno(), mode)
        os.fchown(stream.fileno(), owner, group)


class Observer:
    """All host mutations/observations are fixed accepted-main operations."""
    def __init__(self):
        self.operation = 'validate-authorization'
        self.runtime = pwd.getpwnam('secpal-runtime')
        self.postgres = None
        self.passwords = {}
        self.children = []
        self.mutated = False
        self.data_created = False
        self.logins = {}
        self.application_image_created = False
        self.environment = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'HOME': '/root'}

    def run(self, operation, arguments, *, user=None, sql=None, accepted=(0,), timeout=60):
        if operation not in contract.OPERATIONS:
            raise contract.QualificationError('validate-authorization', 'representation-invalid')
        self.operation = operation
        command = arguments
        if user:
            account = pwd.getpwnam(user)
            command = ['runuser', '-u', user, '--', 'env', '-i',
                       'PATH=/usr/sbin:/usr/bin:/sbin:/bin', f'HOME={account.pw_dir}',
                       f'XDG_RUNTIME_DIR=/run/user/{account.pw_uid}',
                       f'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{account.pw_uid}/bus', *arguments]
        result = bounded_process(command, text=sql, environment=self.environment,
                                 timeout=timeout, operation=operation)
        if result.returncode not in accepted:
            raise contract.QualificationError(operation, 'command-failed')
        return result.returncode, result.stdout.strip(), result.stderr.strip()

    def sql(self, statement, *, role=None, accepted=(0,), database='secpal'):
        prefix = '' if role is None else f'SET ROLE {role};\n'
        return self.run('probe-semantics', ['psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1',
                          '-v', 'VERBOSITY=sqlstate', '-d', database], user='postgres',
                        sql=prefix + statement, accepted=accepted)

    def tcp(self, statement='SELECT 1;', *, role='runtime', host='db.secpal.internal',
            address='127.0.0.1', ca=None, password=None, accepted=(0, 2, 3)):
        self.operation = 'probe-transport'
        env = dict(self.environment, PGHOST=host, PGHOSTADDR=address, PGDATABASE='secpal',
                   PGUSER=self.logins[role]['name'], PGPORT='5432', PGSSLMODE='verify-full', PGCONNECT_TIMEOUT='3',
                   PGSSLROOTCERT=str(ca or MATERIAL / 'ca.crt'),
                   PGPASSWORD=password if password is not None else self.passwords[role])
        result = bounded_process(['psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1',
                                  '-v', 'VERBOSITY=sqlstate'], text=statement,
                                 timeout=15, environment=env, limit=8192, operation='probe-transport')
        if result.returncode not in accepted:
            raise contract.QualificationError('probe-transport', 'command-failed')
        return result.returncode, result.stdout.strip(), result.stderr.strip()

    def write(self, path: Path, content: str, *, owner=0, group=0, mode=0o600):
        self.operation = 'configure-postgresql'
        write_evidence(path, content, owner=owner, group=group, mode=mode)

    def prepare(self, declaration):
        # No destructive operation is reachable against an existing database.
        if (DATA.is_symlink() or (DATA.exists() and (not DATA.is_dir() or any(DATA.iterdir())))
                or MATERIAL.exists() or MATERIAL.is_symlink() or CLIENT.exists() or CLIENT.is_symlink()
                or APPLICATION_IMAGE_STATE.exists() or APPLICATION_IMAGE_STATE.is_symlink()):
            raise contract.QualificationError('initialize-postgresql', 'identity-mismatch')
        self.run('configure-loopback-policy', ['nft', 'list', 'table', 'inet', 'secpal_postgresql'], accepted=(1,))
        self.mutated = True
        # The frozen host result is complete before this separate package change.
        pins = [name + '-' + declaration['package_version'] + '-' + declaration['package_release']
                + '.' + os.uname().machine for name in contract.PACKAGES]
        self.run('install-postgresql', ['dnf4', '-y', '--disablerepo=*',
                 '--enablerepo=baseos,appstream,extras', 'install', *pins], timeout=300)
        self.run('install-postgresql', ['dnf4', '-y', '--disablerepo=*',
                 '--enablerepo=baseos,appstream,extras', 'upgrade', *pins], timeout=300)
        self.postgres = pwd.getpwnam('postgres')
        if DATA.is_symlink() or (DATA.exists() and (not DATA.is_dir() or any(DATA.iterdir()))):
            raise contract.QualificationError('initialize-postgresql', 'identity-mismatch')
        DATA.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.data_created = True
        os.chown(DATA, self.postgres.pw_uid, self.postgres.pw_gid)
        DATA.chmod(0o700)
        self.run('initialize-postgresql', ['initdb', '-D', str(DATA), '--encoding=UTF8',
                 '--locale=C.UTF-8', '--auth-local=peer', '--auth-host=scram-sha-256'], user='postgres')
        MATERIAL.mkdir(mode=0o700, parents=True, exist_ok=False)
        os.chown(MATERIAL, self.postgres.pw_uid, self.postgres.pw_gid)
        CLIENT.mkdir(mode=0o700, exist_ok=False)
        os.chown(CLIENT, self.runtime.pw_uid, self.runtime.pw_gid)
        self.issue_material()
        rendered = contract.render_configuration(declaration, self.runtime.pw_uid)
        for name in ('postgresql.conf', 'pg_hba.conf'):
            self.write(DATA / name, rendered[name], owner=self.postgres.pw_uid, group=self.postgres.pw_gid)
        override = Path('/etc/systemd/system/postgresql.service.d')
        override.mkdir(mode=0o755, exist_ok=False)
        self.write(override / 'secpal.conf', rendered['service.conf'], mode=0o644)
        self.write(STATE / 'postgresql-loopback.nft', rendered['loopback.nft'])
        self.run('configure-loopback-policy', ['nft', '--check', '-f', str(STATE / 'postgresql-loopback.nft')])
        self.run('configure-loopback-policy', ['nft', '-f', str(STATE / 'postgresql-loopback.nft')])
        self.run('observe-selinux', ['semanage', 'fcontext', '-a', '-t', 'postgresql_db_t', '/etc/secpal/postgresql(/.*)?'])
        self.run('observe-selinux', ['restorecon', '-RF', str(DATA), '/etc/secpal/postgresql'])
        self.run('start-postgresql', ['systemctl', 'daemon-reload'])
        self.run('start-postgresql', ['systemctl', 'enable', '--now', 'postgresql.service'])
        self.sql(rendered['roles.sql'], database='postgres')
        for kind, identity in self.logins.items():
            name = identity['name']
            self.passwords[kind] = secrets.token_hex(32)
            expiry = time.strftime('%Y-%m-%d %H:%M:%S+00', time.gmtime(identity['expires_at']))
            inherit = 'INHERIT' if kind == 'runtime' else 'NOINHERIT'
            can_set = 'FALSE' if kind == 'runtime' else 'TRUE'
            # Only this bounded ephemeral test authority issues these identities.
            # Explicit membership inheritance grants CONNECT without inheriting owner DDL.
            self.sql(f"CREATE ROLE {name} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE {inherit} "
                     f"NOREPLICATION NOBYPASSRLS PASSWORD '{self.passwords[kind]}' VALID UNTIL '{expiry}';\n"
                     f"GRANT secpal_{kind} TO {name} WITH ADMIN FALSE, INHERIT TRUE, SET {can_set};")
        self.sql('''SET ROLE secpal_owner;
CREATE TABLE qualification_state (id uuid PRIMARY KEY, value jsonb NOT NULL, sequence integer UNIQUE CHECK (sequence > 0));
INSERT INTO qualification_state VALUES ('00000000-0000-0000-0000-000000000081', '{"persistent":true}', 1);
''')
        PSQL_CLIENT.mkdir(mode=0o700)
        os.chown(PSQL_CLIENT, self.runtime.pw_uid, self.runtime.pw_gid)
        shutil.copyfile(CLIENT / 'ca.crt', PSQL_CLIENT / 'ca.crt')
        os.chown(PSQL_CLIENT / 'ca.crt', self.runtime.pw_uid, self.runtime.pw_gid)
        (PSQL_CLIENT / 'ca.crt').chmod(0o600)
        self.write(PSQL_CLIENT / '.pgpass', f'db.secpal.internal:5432:secpal:{self.logins["runtime"]["name"]}:{self.passwords["runtime"]}\n',
                   owner=self.runtime.pw_uid, group=self.runtime.pw_gid)

    def issue_material(self):
        private = STATE / 'postgresql-test-authority'
        private.mkdir(mode=0o700, exist_ok=False)
        self.run('issue-test-material', ['openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-nodes',
                 '-subj', '/CN=SecPal ephemeral qualification', '-days', '1',
                 '-keyout', str(private / 'ca.key'), '-out', str(MATERIAL / 'ca.crt')])
        self.run('issue-test-material', ['openssl', 'req', '-new', '-newkey', 'rsa:3072', '-nodes',
                 '-subj', '/CN=db.secpal.internal', '-keyout', str(MATERIAL / 'server.key'),
                 '-out', str(private / 'server.csr')])
        self.write(private / 'extensions', 'subjectAltName=DNS:db.secpal.internal\nextendedKeyUsage=serverAuth\n')
        self.run('issue-test-material', ['openssl', 'x509', '-req', '-in', str(private / 'server.csr'),
                 '-CA', str(MATERIAL / 'ca.crt'), '-CAkey', str(private / 'ca.key'), '-CAcreateserial',
                 '-days', '1', '-extfile', str(private / 'extensions'), '-out', str(MATERIAL / 'server.crt')])
        self.run('issue-test-material', ['openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-nodes',
                 '-subj', '/CN=Wrong qualification authority', '-days', '1',
                 '-keyout', str(private / 'wrong.key'), '-out', str(CLIENT / 'wrong-ca.crt')])
        shutil.rmtree(private)  # Exact controller-created path; no CA private key retained.
        for name in ('server.crt', 'ca.crt', 'server.key'):
            path = MATERIAL / name
            os.chown(path, self.postgres.pw_uid, self.postgres.pw_gid)
            path.chmod(0o600)
        shutil.copyfile(MATERIAL / 'ca.crt', CLIENT / 'ca.crt')
        for name in ('ca.crt', 'wrong-ca.crt'):
            os.chown(CLIENT / name, self.runtime.pw_uid, self.runtime.pw_gid)
            (CLIENT / name).chmod(0o600)

    def container(self, command, *, mapping=True, detached=False):
        fixture = trusted_module('integration_runtime_contract', ROOT / 'scripts/integration_runtime_contract.py').POSTGRES_FIXTURE
        network = 'pasta:--no-map-gw,--map-guest-addr,none,--map-host-loopback,' + ('169.254.81.1' if mapping else 'none')
        arguments = ['podman', 'run', '--pull=never', '--read-only', '--cap-drop=all',
                     '--security-opt=no-new-privileges', '--pids-limit=64', '--memory=128m', '--cpus=1',
                     '--network=' + network, '--add-host=db.secpal.internal:169.254.81.1',
                     '--volume=' + str(PSQL_CLIENT) + ':/run/secpal-pg:ro,Z',
                     '--env=PGHOST=db.secpal.internal', '--env=PGPORT=5432', '--env=PGDATABASE=secpal',
                     '--env=PGUSER=' + self.logins['runtime']['name'], '--env=PGSSLMODE=verify-full',
                     '--env=PGSSLROOTCERT=/run/secpal-pg/ca.crt', '--env=PGPASSFILE=/run/secpal-pg/.pgpass',
                     '--env=PGCONNECT_TIMEOUT=3', '--entrypoint=' + command[0]]
        arguments += ['--detach', '--name=' + CONTAINER] if detached else ['--rm']
        return self.run('probe-network', [*arguments, fixture.image, *command[1:]],
                        user='secpal-runtime', accepted=(0, 1, 2, 3), timeout=30)

    def admit_application_image(self):
        self.operation = 'admit-application-image'
        if APPLICATION_IMAGE_STATE.exists() or APPLICATION_IMAGE_STATE.is_symlink():
            raise contract.QualificationError(self.operation, 'identity-mismatch')
        APPLICATION_IMAGE_STATE.mkdir(mode=0o700)
        tooling = trusted_module('image_attestation_runtime', ROOT / 'scripts/image_attestation_runtime.py')
        release = tooling.CLOUD_GH_RELEASES.get(os.uname().machine)
        if release is None:
            raise contract.QualificationError(self.operation, 'identity-mismatch')

        def command(arguments, *, environment):
            if environment != self.environment:
                raise contract.QualificationError('admit-application-image', 'identity-mismatch')
            return self.run('admit-application-image', arguments, timeout=180)

        gh = tooling.stage_gh_cli(APPLICATION_IMAGE_STATE, release, command, self.environment)
        self.run('admit-application-image', [gh, 'version'])
        subject = APPLICATION_IMAGE_STATE / 'index.json'
        bundle = APPLICATION_IMAGE_STATE / 'bundle.json'
        gh_config = APPLICATION_IMAGE_STATE / 'gh-config'
        gh_config.mkdir(mode=0o700)
        # Root observer starts from a closed empty environment, no provider token.
        previous = self.environment
        self.environment = dict(previous, GH_CONFIG_DIR=str(gh_config), GH_PROMPT_DISABLED='1',
                                GH_NO_UPDATE_NOTIFIER='1', GH_NO_EXTENSION_UPDATE_NOTIFIER='1', GH_TELEMETRY='false')
        identity = contract.APPLICATION_RUNTIME
        image, digest = identity['image'].split('@')
        try:
            self.run('admit-application-image', ['python3', str(ROOT / 'scripts/fetch-oci-attestation.py'),
                str(subject), str(bundle), image, digest, 'secpal/api'], timeout=300)
            self.run('admit-application-image', [gh, 'attestation', 'verify', str(subject), '--bundle', str(bundle),
                '--repo', identity['repository'], '--signer-workflow', identity['workflow'],
                '--signer-digest', identity['source_commit'], '--source-ref', identity['source_ref'],
                '--source-digest', identity['source_commit'], '--deny-self-hosted-runners', '--hostname', 'github.com'], timeout=180)
        finally:
            self.environment = previous
        raw = subject.read_bytes()
        if len(raw) > 1048576 or 'sha256:' + hashlib.sha256(raw).hexdigest() != digest:
            raise contract.QualificationError('admit-application-image', 'identity-mismatch')
        index = contract.normalize_json_fact(raw.decode())
        platforms = {item['platform']['architecture']: item['digest'] for item in index['manifests']
                     if item.get('platform', {}).get('os') == 'linux'}
        if platforms != identity['platform_digests']:
            raise contract.QualificationError('admit-application-image', 'identity-mismatch')
        self.run('admit-application-image', ['podman', 'image', 'exists', identity['image']],
                 user='secpal-runtime', accepted=(1,))
        # Mark ownership before a possibly partial pull, so cleanup still owns it.
        self.application_image_created = True
        self.write(CLIENT / 'anonymous-auth.json', '{}\n', owner=self.runtime.pw_uid, group=self.runtime.pw_gid)
        self.run('admit-application-image', ['podman', 'pull', '--authfile=' + str(CLIENT / 'anonymous-auth.json'),
                 identity['image']], user='secpal-runtime', timeout=300)
        _, observed, _ = self.run('admit-application-image', ['podman', 'image', 'inspect', identity['image']], user='secpal-runtime')
        inspected = contract.normalize_json_fact(observed)
        architecture = 'amd64' if os.uname().machine == 'x86_64' else 'arm64'
        if (not isinstance(inspected, list) or len(inspected) != 1
                or inspected[0]['Os'] != 'linux' or inspected[0]['Architecture'] != architecture
                or identity['image'] not in inspected[0]['RepoDigests']
                or image + '@' + identity['platform_digests'][architecture] not in inspected[0]['RepoDigests']):
            raise contract.QualificationError('admit-application-image', 'identity-mismatch')

    def application_material(self):
        code = CLIENT / 'application-code'
        code.mkdir(mode=0o700)
        os.chown(code, self.runtime.pw_uid, self.runtime.pw_gid)
        for label in ('bootstrap', 'probe'):
            self.write(code / (label + '.php'), (ROOT / ('scripts/ci-cloud/postgresql-application-' + label + '.php')).read_text(),
                       owner=self.runtime.pw_uid, group=self.runtime.pw_gid, mode=0o644)
        key = 'base64:' + base64.b64encode(secrets.token_bytes(32)).decode()
        kek = secrets.token_bytes(32)
        for role, directory in (('runtime', 'application'), ('migration', 'application-migration')):
            path = CLIENT / directory
            path.mkdir(mode=0o700)
            os.chown(path, self.runtime.pw_uid, self.runtime.pw_gid)
            self.write(path / 'credentials.json', json.dumps({'APP_KEY': key, 'DB_PASSWORD': self.passwords[role]}),
                       owner=self.runtime.pw_uid, group=self.runtime.pw_gid)
            for name in ('ca.crt', 'wrong-ca.crt'):
                self.write(path / name, (CLIENT / name).read_text(), owner=self.runtime.pw_uid, group=self.runtime.pw_gid)
            self.write(path / 'php.ini', 'auto_prepend_file=/run/secpal-qualification/bootstrap.php\n',
                       owner=self.runtime.pw_uid, group=self.runtime.pw_gid)
            # Same ephemeral app/KEK material; migration password is never mounted
            # into the runtime process or the psql client container.
            descriptor = os.open(path / 'kek', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(kek)
                os.fchown(stream.fileno(), self.runtime.pw_uid, self.runtime.pw_gid)

    def application_command(self, operation, *, scenario='normal', role='runtime', detached=False):
        if (operation not in ('pdo', 'initialize', 'seed', 'serve')
                or scenario not in ('normal', 'wrong-hostname', 'wrong-ca', 'wrong-password',
                                     'plaintext', 'insecure-verification', 'environment-substitution')
                or role not in ('runtime', 'migration')
                or (role == 'migration') != (operation == 'initialize')
                or (detached is not (operation == 'serve'))
                or (operation != 'pdo' and scenario != 'normal')):
            raise contract.QualificationError('probe-application', 'representation-invalid')
        directory = CLIENT / ('application-migration' if role == 'migration' else 'application')
        network = 'pasta:--no-map-gw,--map-guest-addr,none,--map-host-loopback,169.254.81.1'
        runtime = trusted_module('integration_runtime_contract', ROOT / 'scripts/integration_runtime_contract.py')
        arguments = ['podman', 'run', '--pull=never', '--read-only', '--cap-drop=all',
                     '--security-opt=no-new-privileges', '--pids-limit=256', '--memory=512m', '--cpus=1',
                     '--user=10001:10001', '--userns=keep-id:uid=10001,gid=10001', '--network=' + network,
                     '--add-host=db.secpal.internal:169.254.81.1', '--add-host=wrong.secpal.internal:169.254.81.1',
                     '--volume=' + str(directory) + ':/run/secpal-pg/application:ro,Z',
                     '--volume=' + str(directory / 'php.ini') + ':/usr/local/etc/php/conf.d/zz-secpal-qualification.ini:ro,Z',
                     '--volume=' + str(CLIENT / 'application-code/bootstrap.php') + ':/run/secpal-qualification/bootstrap.php:ro,z',
                     '--volume=' + str(CLIENT / 'application-code/probe.php') + ':/run/secpal-qualification/probe.php:ro,z']
        for destination, mount in runtime.role_spec('api').tmpfs.items():
            arguments.append('--tmpfs=' + destination + ':size=' + str(mount.size)
                + ',mode=' + format(mount.mode, '04o') + ',uid=10001,gid=10001,nosuid,nodev'
                + (',noexec' if mount.noexec else ''))
        environment = {'APP_ENV': 'production', 'APP_DEBUG': 'false', 'LOG_CHANNEL': 'stderr',
            'DB_CONNECTION': 'pgsql', 'DB_HOST': 'wrong.secpal.internal' if scenario == 'wrong-hostname' else 'db.secpal.internal',
            'DB_PORT': '5432', 'DB_DATABASE': 'secpal', 'DB_USERNAME': self.logins[role]['name'],
            'DB_SSLMODE': 'disable' if scenario == 'plaintext' else 'require' if scenario == 'insecure-verification' else 'verify-full',
            'DB_SSLROOTCERT': '/run/secpal-pg/application/' + ('wrong-ca.crt' if scenario == 'wrong-ca' else 'ca.crt'),
            'CACHE_STORE': 'database', 'QUEUE_CONNECTION': 'database', 'SESSION_DRIVER': 'database',
            'KEK_PATH': '/run/secpal-pg/application/kek'}
        if scenario == 'environment-substitution':
            environment.update(PGSSLMODE='disable', PGSSLROOTCERT='/nonexistent', PGHOST='wrong.secpal.internal',
                               PGSERVICE='untrusted', PGSERVICEFILE='/nonexistent', PGOPTIONS='-c role=secpal_owner')
        arguments.extend('--env=' + name + '=' + value for name, value in environment.items())
        arguments.extend(['--detach', '--name=' + CONTAINER, '--entrypoint=/usr/local/bin/frankenphp'] if detached else
                         ['--rm', '--name=' + APPLICATION_PROBE, '--entrypoint=/usr/local/bin/php'])
        arguments.append(contract.APPLICATION_RUNTIME['image'])
        arguments.extend(['run', '--config', '/etc/frankenphp/Caddyfile'] if detached else
                         ['/run/secpal-qualification/probe.php', operation])
        return arguments

    def application_http(self, operation):
        if operation not in ('ready', 'live'):
            raise contract.QualificationError('probe-readiness', 'representation-invalid')
        _, raw, _ = self.run('probe-readiness', ['podman', 'exec', CONTAINER, '/usr/local/bin/php',
            '/run/secpal-qualification/probe.php', operation], user='secpal-runtime', timeout=20)
        return contract.normalize_application_http(raw)

    def application_pid(self):
        _, raw, _ = self.run('probe-readiness', ['podman', 'inspect', '--format', '{{.State.Pid}}', CONTAINER], user='secpal-runtime')
        if not raw.isdecimal() or not 1 < int(raw) <= 2147483647:
            raise contract.QualificationError('probe-readiness', 'identity-mismatch')
        return raw

    def application_probes(self):
        self.admit_application_image()
        self.application_material()
        self.run('initialize-application', self.application_command('initialize', role='migration'),
                 user='secpal-runtime', timeout=120)
        self.run('initialize-application', self.application_command('seed'), user='secpal-runtime', timeout=60)
        probes = {}
        for name in contract.APPLICATION_PROBES:
            if name == 'wrong-password':
                file = CLIENT / 'application/credentials.json'
                original = file.read_text()
                changed = json.loads(original)
                changed['DB_PASSWORD'] = '0' * 64
                self.write(file, json.dumps(changed), owner=self.runtime.pw_uid, group=self.runtime.pw_gid)
            try:
                _, raw, _ = self.run('probe-application', self.application_command('pdo', scenario='normal' if name == 'pdo' else name),
                                     user='secpal-runtime', timeout=30)
                probes[name] = contract.normalize_json_fact(raw)
            finally:
                if name == 'wrong-password':
                    self.write(file, original, owner=self.runtime.pw_uid, group=self.runtime.pw_gid)
        self.run('probe-readiness', self.application_command('serve', detached=True), user='secpal-runtime')
        for _ in range(20):
            try:
                live = self.application_http('live')
                if live == contract.APPLICATION_HEALTH['live-up']:
                    break
            except contract.QualificationError:
                pass
            time.sleep(0.5)
        else:
            raise contract.QualificationError('probe-readiness', 'invariant-failed')
        pid = self.application_pid()
        health = {'live-up': live, 'ready-up': self.application_http('ready')}
        self.run('start-postgresql', ['systemctl', 'stop', 'postgresql.service'])
        health.update({'ready-down': self.application_http('ready'), 'live-down': self.application_http('live')})
        same = self.application_pid() == pid
        self.run('start-postgresql', ['systemctl', 'start', 'postgresql.service'])
        health['ready-restored'] = self.application_http('ready')
        application = {'runtime': dict(contract.APPLICATION_RUNTIME), 'probes': probes, 'health': health, 'same_process': same}
        contract.admit_application(application)
        self.run('probe-readiness', ['podman', 'rm', '--force', CONTAINER], user='secpal-runtime')
        return application, same

    def probes(self):
        p = {}
        tls = 'SELECT version FROM pg_stat_ssl WHERE pid=pg_backend_pid() AND ssl;'
        status, version, _ = self.tcp(tls)
        if version not in ('TLSv1.2', 'TLSv1.3'):
            raise contract.QualificationError('probe-transport', 'invariant-failed')
        p['verified-tls'] = status
        p['wrong-hostname'] = self.tcp(host='wrong.secpal.internal')[0]
        p['wrong-ca'] = self.tcp(ca=CLIENT / 'wrong-ca.crt')[0]
        p['wrong-password'] = self.tcp(password='wrong-qualification-password')[0]
        p['server-key-runtime-denied'] = self.run('probe-transport', ['test', '-r', str(MATERIAL / 'server.key')],
                                                 user='secpal-runtime', accepted=(0, 1))[0]
        environment = dict(self.environment, PGHOST='127.0.0.1', PGDATABASE='secpal', PGUSER=self.logins['runtime']['name'],
                           PGPASSWORD=self.passwords['runtime'], PGSSLMODE='disable', PGCONNECT_TIMEOUT='3')
        plain = bounded_process(['psql', '-X', '-qAt', '-c', 'SELECT 1;'], environment=environment,
                                timeout=10, limit=8192, operation='probe-transport')
        p['plaintext'] = plain.returncode
        p['runtime-ddl'] = self.tcp('CREATE TABLE forbidden (id integer);')[0]
        p['runtime-role-escalation'] = self.tcp('SET ROLE secpal_owner;')[0]
        p['migration-ddl'] = self.tcp('SET ROLE secpal_owner; CREATE TABLE migration_probe (id integer);', role='migration')[0]
        p['backup-read'] = self.sql('SELECT count(*) FROM qualification_state;', role='secpal_backup')[0]
        p['backup-ddl'] = self.sql('CREATE TABLE forbidden_backup (id integer);', role='secpal_backup', accepted=(0, 3))[0]
        status, output, _ = self.tcp('''BEGIN;
INSERT INTO qualification_state VALUES (gen_random_uuid(), '{"jsonb":"works"}', 2);
SELECT 1 / (count(*) FILTER (WHERE value->>'jsonb'='works')) FROM qualification_state;
ROLLBACK;
SELECT 1 / (CASE WHEN count(*)=1 THEN 1 ELSE 0 END) FROM qualification_state;
''')
        p['jsonb-uuid-constraints-rollback'] = status if output.splitlines() == ['1', '1'] else 3
        # Constraint rejection is checked inside a transaction by an independent owner query.
        constraint = self.tcp("INSERT INTO qualification_state VALUES (gen_random_uuid(), '{}', 0);")
        if constraint[0] != 3 or '23514' not in constraint[2]:
            raise contract.QualificationError('probe-semantics', 'invariant-failed')
        locks = self.locking()
        p['row-locks'] = 0 if locks['row_sqlstate'] == '55P03' else 3
        p['transaction-advisory-locks'] = 0 if (locks['advisory_held'], locks['advisory_released']) == ('f', 't') else 3
        fixture = trusted_module('integration_runtime_contract', ROOT / 'scripts/integration_runtime_contract.py').POSTGRES_FIXTURE
        self.run('probe-network', ['podman', 'pull', fixture.image], user='secpal-runtime', timeout=300)
        _, digests, _ = self.run('probe-network', ['podman', 'image', 'inspect', '--format', '{{json .RepoDigests}}', fixture.image], user='secpal-runtime')
        architecture = os.uname().machine
        expected_child = fixture.platform_digests['linux/amd64' if architecture == 'x86_64' else 'linux/arm64']
        if fixture.image not in json.loads(digests) or 'docker.io/library/postgres@' + expected_child not in json.loads(digests):
            raise contract.QualificationError('probe-network', 'identity-mismatch')
        p['rootless-verified-tls'] = self.container(['psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-c', tls])[0]
        p['rootless-unmapped'] = self.container(['psql', '-X', '-qAt', '-c', 'SELECT 1;'], mapping=False)[0]
        # A listening sentinel makes this an actual port-boundary test.
        with socket.socket() as sentinel:
            sentinel.bind(('127.0.0.1', 5433))
            sentinel.listen(4)
            with socket.create_connection(('127.0.0.1', 5433), timeout=2):
                sentinel_status = 0
            p['other-loopback-port'] = self.container(['bash', '-c', 'timeout 3 bash -c "exec 3<>/dev/tcp/169.254.81.1/5433"'])[0]
        application, live = self.application_probes()
        p['ready-up'] = 0 if application['health']['ready-up']['http_status'] == 200 else 1
        p['ready-down'] = 1 if application['health']['ready-down']['http_status'] == 503 else 0
        p['liveness-down'] = 0 if application['health']['live-down']['http_status'] == 200 else 1
        _, count, _ = self.sql('SELECT count(*) FROM qualification_state;')
        p['persistence-restart'] = 0 if count == '1' else 3
        self.application = application
        return p, locks, live, sentinel_status, count

    def locking(self):
        result = {}
        for mode in ('row', 'advisory'):
            statement = ('SELECT id FROM qualification_state WHERE sequence=1 FOR UPDATE;' if mode == 'row'
                         else 'SELECT pg_advisory_xact_lock(810081);')
            process = subprocess.Popen(['runuser', '-u', 'postgres', '--', 'psql', '-X', '-qAt',
                                        '-v', 'ON_ERROR_STOP=1', '-d', 'secpal'],
                                       stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       text=True, env=self.environment)
            self.children.append(process)
            process.stdin.write("SET application_name='secpal-qualification-lock'; BEGIN;" + statement + 'SELECT pg_sleep(3);COMMIT;\n')
            process.stdin.close()
            for _ in range(20):
                _, waiting, _ = self.sql("SELECT count(*) FROM pg_stat_activity WHERE application_name='secpal-qualification-lock' AND wait_event='PgSleep';")
                if waiting == '1':
                    break
                time.sleep(0.1)
            else:
                raise contract.QualificationError('probe-semantics', 'command-failed')
            if mode == 'row':
                status, _, error = self.tcp("BEGIN;SET LOCAL lock_timeout='100ms';SELECT id FROM qualification_state WHERE sequence=1 FOR UPDATE;ROLLBACK;")
                if status != 3 or '55P03' not in error:
                    raise contract.QualificationError('probe-semantics', 'invariant-failed')
                result['row_sqlstate'] = '55P03'
            else:
                result['advisory_held'] = self.tcp('SELECT pg_try_advisory_xact_lock(810081);')[1]
            process.wait(timeout=10)
            if process.returncode != 0:
                raise contract.QualificationError('probe-semantics', 'command-failed')
            self.children.remove(process)
        result['advisory_released'] = self.tcp('SELECT pg_try_advisory_xact_lock(810081);')[1]
        return result

    def observations(self):
        probes, locks, live, sentinel, count = self.probes()
        _, unit, _ = self.run('observe-native-service', ['systemctl', 'show', 'postgresql.service',
                '--property=User,Group,ActiveState,UnitFileState,FragmentPath,MainPID'])
        service, pid = contract.normalize_service(unit)
        command = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
        if command != [b'/usr/bin/postgres', b'-D', b'/var/lib/pgsql/data', b'']:
            raise contract.QualificationError('observe-native-service', 'invariant-failed')
        cgroup = Path(f'/proc/{pid}/cgroup').read_text().strip()
        label = Path(f'/proc/{pid}/attr/current').read_text().strip().split(':')[2]
        data_stat = DATA.stat()
        data = {'owner': pwd.getpwuid(data_stat.st_uid).pw_name,
                'group': grp.getgrgid(data_stat.st_gid).gr_name,
                'mode': format(stat.S_IMODE(data_stat.st_mode), 'o'),
                'type': os.getxattr(DATA, 'security.selinux').decode().rstrip('\0').split(':')[2]}
        _, sockets, _ = self.run('observe-listeners', ['ss', '-H', '-ltn', 'sport = :5432'])
        listeners = contract.normalize_listeners(sockets)
        settings = {}
        for setting in ('listen_addresses', 'port', 'ssl', 'ssl_min_protocol_version', 'password_encryption',
                        'data_directory', 'ssl_cert_file', 'ssl_key_file', 'ssl_ca_file'):
            settings[setting] = self.sql('SHOW ' + setting + ';')[1]
        # Fail closed against alternate includes/preloads/executable commands.
        for setting in ('shared_preload_libraries', 'session_preload_libraries', 'local_preload_libraries',
                        'archive_command', 'ssl_passphrase_command'):
            if self.sql('SHOW ' + setting + ';')[1] != '':
                raise contract.QualificationError('observe-native-service', 'invariant-failed')
        roles = contract.normalize_json_fact(self.sql("""SELECT json_object_agg(rolname, json_build_array(rolsuper, rolcreatedb,
rolcreaterole, rolinherit, rolreplication, rolbypassrls, rolcanlogin)) FROM pg_roles WHERE rolname LIKE 'secpal_%' AND rolname NOT LIKE 'secpal_qualification_%';""")[1])
        issued = contract.normalize_json_fact(self.sql("""SELECT coalesce(json_object_agg(rolname, json_build_object('name',rolname,
'attributes',json_build_array(rolsuper,rolcreatedb,rolcreaterole,rolinherit,rolreplication,rolbypassrls,rolcanlogin),
'expires_at',extract(epoch FROM rolvaliduntil)::bigint)), '{}') FROM pg_roles WHERE rolname LIKE 'secpal_qualification_%';""")[1])
        if set(issued) != {identity['name'] for identity in self.logins.values()}:
            raise contract.QualificationError('probe-semantics', 'invariant-failed')
        issued_logins = {kind: issued[identity['name']] for kind, identity in self.logins.items()}
        memberships = contract.normalize_json_fact(self.sql("""SELECT coalesce(json_agg(json_build_array(r.rolname,m.rolname,a.admin_option,a.inherit_option,a.set_option) ORDER BY r.rolname,m.rolname),'[]')
FROM pg_auth_members a JOIN pg_roles r ON r.oid=a.roleid JOIN pg_roles m ON m.oid=a.member WHERE m.rolname LIKE 'secpal_%';""")[1])
        passwords = contract.normalize_json_fact(self.sql("""SELECT json_object_agg(rolname,split_part(rolpassword,'$',1)) FROM pg_authid WHERE rolname LIKE 'secpal_%';""")[1])
        if set(passwords) != set(roles) | set(issued) or any(passwords[name] is not None for name in roles):
            raise contract.QualificationError('probe-semantics', 'invariant-failed')
        algorithms = {kind: passwords[identity['name']] for kind, identity in self.logins.items()}
        hba = contract.normalize_json_fact(self.sql("""SELECT json_agg(json_build_array(type,database,user_name,address,netmask,auth_method,error) ORDER BY rule_number) FROM pg_hba_file_rules;""")[1])
        _, containers, _ = self.run('observe-native-service', ['podman', 'ps', '--all', '--format=json'], user='secpal-runtime')
        # Only clients ran. No persistent container may own a PostgreSQL server.
        servers = [item['Names'] for item in json.loads(containers)
                   if any(word in str(item.get('Command', '')).split() for word in ('postgres', 'postmaster', 'pg_ctl'))]
        tls_material = {}
        for name in ('server.crt', 'server.key', 'ca.crt'):
            facts = (MATERIAL / name).lstat()
            if not stat.S_ISREG(facts.st_mode):
                raise contract.QualificationError('observe-selinux', 'identity-mismatch')
            tls_material[name] = {'owner': pwd.getpwuid(facts.st_uid).pw_name,
                'group': grp.getgrgid(facts.st_gid).gr_name, 'mode': format(stat.S_IMODE(facts.st_mode), 'o'),
                'type': os.getxattr(MATERIAL / name, 'security.selinux').decode().rstrip('\0').split(':')[2]}
        raw = {'application': self.application, 'tls_material': tls_material, 'server_version_num': self.sql('SHOW server_version_num;')[1],
               'service': service, 'data_directory': data, 'process_label': label,
               'listeners': listeners, 'settings': settings, 'roles': roles, 'issued_logins': issued_logins, 'memberships': memberships,
               'password_algorithms': algorithms, 'hba': hba, 'probes': probes, 'locking': locks,
               'rootless_liveness': live, 'container_servers': servers,
               'loopback_sentinel_host': sentinel, 'native_cgroup': cgroup, 'restart_row_count': count}
        runtime = self.logins['runtime']
        return contract.admit_observations(raw, run_id=self.run_id, run_attempt=self.run_attempt,
                                            expires_at=runtime['expires_at'])

    def cleanup(self):
        self.operation = 'cleanup-test-material'
        for process in self.children:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        self.children.clear()
        self.run('cleanup-test-material', ['podman', 'rm', '--force', '--ignore', CONTAINER, APPLICATION_PROBE], user='secpal-runtime')
        if self.application_image_created:
            self.run('cleanup-test-material', ['podman', 'rmi', '--ignore', '--no-prune', contract.APPLICATION_RUNTIME['image']], user='secpal-runtime')
        self.run('cleanup-test-material', ['systemctl', 'stop', 'postgresql.service'], accepted=(0, 5))
        self.run('cleanup-test-material', ['nft', 'delete', 'table', 'inet', 'secpal_postgresql'], accepted=(0, 1))
        # All paths are fixed root-created directories in this exact ephemeral run.
        paths = [CLIENT, MATERIAL, STATE / 'postgresql-test-authority', APPLICATION_IMAGE_STATE]
        if self.data_created:
            paths.append(DATA)
        for path in paths:
            if path.is_symlink():
                raise contract.QualificationError('cleanup-test-material', 'identity-mismatch')
            if path.exists():
                shutil.rmtree(path)
        self.passwords.clear()
        # Admit read-back, not success inferred only from deletion return codes.
        stopped = self.run('cleanup-test-material', ['systemctl', 'is-active', 'postgresql.service'], accepted=(3,))[1]
        self.run('cleanup-test-material', ['nft', 'list', 'table', 'inet', 'secpal_postgresql'], accepted=(1,))
        self.run('cleanup-test-material', ['podman', 'container', 'exists', CONTAINER], user='secpal-runtime', accepted=(1,))
        self.run('cleanup-test-material', ['podman', 'container', 'exists', APPLICATION_PROBE], user='secpal-runtime', accepted=(1,))
        if self.application_image_created:
            self.run('cleanup-test-material', ['podman', 'image', 'exists', contract.APPLICATION_RUNTIME['image']], user='secpal-runtime', accepted=(1,))
        if stopped != 'inactive' or any(path.exists() or path.is_symlink()
                for path in (CLIENT, MATERIAL, STATE / 'postgresql-test-authority', APPLICATION_IMAGE_STATE, DATA)) or self.passwords:
            raise contract.QualificationError('cleanup-test-material', 'invariant-failed')
        return dict(contract.CLEANUP_POSTCONDITIONS)


def resource_binding():
    path = STATE / 'postgresql-resource-binding.json'
    facts = path.lstat()
    if (not stat.S_ISREG(facts.st_mode) or facts.st_uid != 0 or facts.st_gid != 0
            or stat.S_IMODE(facts.st_mode) != 0o600 or facts.st_size > 4096):
        raise contract.QualificationError('validate-authorization', 'identity-mismatch')
    raw = json.loads(path.read_text(), object_pairs_hook=contract.duplicate_keys)
    return contract.admit_resource_binding(raw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--run-attempt', required=True)
    options = parser.parse_args()
    observer = None
    document = None
    failure = None
    admitted_auth = None
    binding = None
    host_digest = None
    cleanup_complete = False
    safe_context = False
    try:
        # This program never doubles as a local/development or production installer.
        if (os.geteuid() != 0 or Path(__file__).resolve() != Path('/opt/secpal-control/scripts/ci-cloud/qualify-native-postgresql.py')
                or STATE.is_symlink() or not STATE.is_dir()):
            raise contract.QualificationError('validate-authorization', 'identity-mismatch')
        safe_context = True
        if (not (STATE / 'prepared').is_file() or AUTHORIZATION.is_symlink()
                or AUTHORIZATION.stat().st_uid != 0 or stat.S_IMODE(AUTHORIZATION.stat().st_mode) != 0o600
                or AUTHORIZATION.stat().st_size > 16384):
            raise contract.QualificationError('validate-authorization', 'identity-mismatch')
        binding = resource_binding()
        observer = Observer()
        prepared = json.loads(AUTHORIZATION.read_text(), object_pairs_hook=contract.duplicate_keys)
        if not isinstance(prepared, dict) or set(prepared) != {'authorization', 'declaration'}:
            raise contract.QualificationError('validate-authorization', 'representation-invalid')
        declaration = contract.admit_declaration(prepared['declaration'])
        auth = prepared['authorization']
        control_sha = binding['control_sha']
        profile = binding['profile']
        admitted_auth = contract.admit_authorization(auth, control_sha=control_sha, profile=profile,
             run_id=auth['run_id'], run_attempt=auth['run_attempt'], now=int(time.time()), declaration=declaration)
        observer.run_id = options.run_id
        observer.run_attempt = options.run_attempt
        observer.logins = contract.qualification_logins(options.run_id, options.run_attempt, auth['expires_at'])
        for field, value in (('access_run_id', options.run_id), ('access_run_attempt', options.run_attempt)):
            if binding[field] != value:
                raise contract.QualificationError('validate-authorization', 'identity-mismatch')
        source = trusted_module('postgresql_control', ROOT / 'scripts/ci-cloud/postgresql-qualification-control.py')
        if auth['probe_sha256'] != source.probe_digest():
            raise contract.QualificationError('validate-authorization', 'identity-mismatch')
        if observer.run('observe-selinux', ['getenforce'])[1] != 'Enforcing':
            raise contract.QualificationError('observe-selinux', 'invariant-failed')
        if os.uname().machine != contract.rpm.PROFILE_ARCHITECTURES[profile]:
            raise contract.QualificationError('validate-authorization', 'identity-mismatch')
        observer.run('validate-authorization', ['python3', str(ROOT / 'scripts/ci-cloud/rocky-control.py'),
                 'validate-native-qualification', str(STATE / 'evidence/qualification.json'),
                 '--stdout', str(STATE / 'evidence/qualification.stdout'),
                 '--native-observation', str(STATE / 'evidence/native-package-observation.json'),
                 '--target-sha', HOST_TARGET, '--control-sha', control_sha,
                 '--run-id', options.run_id, '--run-attempt', options.run_attempt])
        host_digest = hashlib.sha256((STATE / 'evidence/qualification.json').read_bytes()).hexdigest()
        instance_id = binding['instance_id']
        instance_name = binding['instance_name']
        if (contract.RUN.fullmatch(instance_id) is None
                or instance_name != f"sprk-{auth['run_id']}-{auth['run_attempt']}-instance"):
            raise contract.QualificationError('validate-authorization', 'identity-mismatch')
        observer.prepare(declaration)
        collector = trusted_module('postgresql_package_collector', ROOT / 'scripts/ci-cloud/collect-rocky-preparation.py')
        rpm_observer = collector.Observer()
        try:
            signer = contract.rpm.admit_rocky_signing_key(contract.rpm.normalize_rocky_signing_key(rpm_observer.rocky_signing_key()))
            packages = {name: rpm_observer.installed_package(name) for name in contract.PACKAGES}
        except (collector.ObservationError, contract.rpm.ContractError):
            raise contract.QualificationError('observe-packages', 'command-failed') from None
        for name, raw in packages.items():
            package = contract.admit_postgresql_package(name, raw, os.uname().machine, signer)
            if package['version'] != declaration['package_version'] or package['release'] != declaration['package_release']:
                raise contract.QualificationError('observe-packages', 'identity-mismatch')
        observations = observer.observations()
        document = {'schema_version': 1, 'claim': contract.SELECTOR, 'authorization': auth,
                    'qualification_run_id': options.run_id, 'qualification_run_attempt': options.run_attempt,
                    'instance_id': instance_id, 'instance_name': instance_name,
                    'architecture': os.uname().machine, 'host_admission': {'target_sha': HOST_TARGET,
                    'harness_sha256': HOST_HARNESS, 'evidence_sha256': host_digest},
                    'packages': packages, 'signer_fingerprint': signer, 'observations': observations}
    except (contract.QualificationError, KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError) as error:
        failure = (contract.diagnostic(error.operation, error.reason) if isinstance(error, contract.QualificationError)
                   else contract.diagnostic(observer.operation if observer else 'validate-authorization', 'representation-invalid'))
    finally:
        if observer is not None and observer.mutated:
            try:
                cleanup = observer.cleanup()
                cleanup_complete = True
                if document is not None:
                    document['cleanup'] = cleanup
            except (contract.QualificationError, OSError, subprocess.SubprocessError):
                failure = contract.diagnostic('cleanup-test-material', 'command-failed')
    if failure is not None:
        failure = contract.bound_diagnostic(failure['operation'], failure['reason'],
            authorization=admitted_auth, binding=binding, qualification_run_id=options.run_id,
            qualification_run_attempt=options.run_attempt, host_evidence_sha256=host_digest,
            cleanup_complete=cleanup_complete)
        if safe_context:
            try:
                write_evidence(DIAGNOSTIC, json.dumps(failure) + '\n', owner=0,
                               group=pwd.getpwnam('secpal-cloud').pw_gid, mode=0o440)
            except (OSError, KeyError, contract.QualificationError):
                failure = contract.diagnostic('write-evidence', 'command-failed')
        print(json.dumps(failure), file=sys.stderr)
        return 1
    try:
        observer.write(OUTPUT, json.dumps(document, indent=2, sort_keys=True) + '\n',
                       owner=0, group=pwd.getpwnam('secpal-cloud').pw_gid, mode=0o440)
    except (OSError, KeyError, contract.QualificationError):
        print(json.dumps(contract.diagnostic('write-evidence', 'command-failed')), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
