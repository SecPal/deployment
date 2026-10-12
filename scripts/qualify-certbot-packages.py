#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Acquire/qualify only the reviewed Certbot closure; never install packages.

Observation runs standard RPM/DNF/Python primitives. Admission belongs to
rocky_preparation_contract.admit_certbot_exception. Output remains an observation
requiring authenticated native transport, not a caller-supplied admission token.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / 'ci-cloud'))
import rocky_preparation_contract as contract

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / 'config/production/certbot-package-policy.json'
RPM_QUERY = (
    '%{NAME}\\n%{EPOCHNUM}\\n%{VERSION}\\n%{RELEASE}\\n%{ARCH}\\n'
    '%{PAYLOADDIGEST}\\n%{SHA256HEADER}\\n%{RSAHEADER:pgpsig}\\n'
)
IMPORT_SETUP = (
    'import sys,sysconfig; '
    'sys.path.extend([sysconfig.get_path("purelib",scheme="rpm_prefix"),sysconfig.get_path("platlib",scheme="rpm_prefix")]); '
)
TOOLS = {name: '/usr/bin/' + name for name in ('rpm', 'rpmkeys', 'dnf4', 'uname', 'git', 'python3', 'sudo')}
RPM_CONFIGURATION = [
    '--rcfile', '/usr/lib/rpm/rpmrc', '--macros',
    '/usr/lib/rpm/macros:/usr/lib/rpm/macros.d/macros.*:/usr/lib/rpm/platform/%{_target}/macros',
]
PROTECTED_PAYLOAD_PACKAGES = frozenset(('libutempter', 'pam', 'util-linux'))
PAYLOAD_VERIFY = (
    IMPORT_SETUP + 'import rpm; rpm.reloadConfig(); '
    'rpm.addMacro("_dbpath",sys.argv[2]); '
    'transaction=rpm.TransactionSet(); transaction.setVSFlags(0); transaction.setVfyLevel(3); '
    'source=open(sys.argv[1],"rb"); header=transaction.hdrFromFdno(source); '
    'files=rpm.files(header,flags=rpm.RPMFI_FLAGS_VERIFY); '
    'results=[(file,file.verify()) for file in files if not file.fflags & rpm.RPMFILE_CONFIG]; '
    # Match RPM's handling of absent signed %ghost/%missingok entries. These
    # have no mandatory installed payload; all other mismatches fail closed.
    'sys.exit(1 if any(result != 0 and not (result == rpm.RPMVERIFY_LSTATFAIL and '
    'file.fflags & (rpm.RPMFILE_GHOST | rpm.RPMFILE_MISSINGOK)) for file,result in results) else 0)'
)


class QualificationError(RuntimeError):
    def __init__(self, operation: str, reason: str):
        self.operation, self.reason = operation, reason
        super().__init__(f'{operation}:{reason}')


def run(operation: str, arguments: list[str], maximum: int = 65536) -> str:
    """Observe one named bounded non-secret operation; never retain stderr."""
    tool = arguments[0].removeprefix('/usr/bin/')
    if tool not in TOOLS or arguments[0] not in (tool, TOOLS[tool]):
        raise QualificationError(operation, 'tool-invalid')
    arguments = [TOOLS[tool], *(RPM_CONFIGURATION if tool in ('rpm', 'rpmkeys') else []), *arguments[1:]]
    try:
        with tempfile.TemporaryDirectory(prefix='.certbot-tool-home-') as home:
            result = subprocess.run(arguments, capture_output=True, timeout=120, check=False,
                                    env=tool_environment(home))
    except (OSError, subprocess.TimeoutExpired) as error:
        raise QualificationError(operation, 'command-unavailable') from error
    if result.returncode != 0:
        raise QualificationError(operation, 'command-failed')
    if len(result.stdout) > maximum:
        raise QualificationError(operation, 'observation-limit-exceeded')
    try:
        return result.stdout.decode('utf-8').strip()
    except UnicodeError as error:
        raise QualificationError(operation, 'representation-invalid') from error


def tool_environment(home: str) -> dict[str, str]:
    return {'PATH': '/usr/sbin:/usr/bin', 'LC_ALL': 'C', 'LANG': 'C', 'HOME': home}


@contextmanager
def native_environment(home: Path):
    previous = dict(os.environ)
    try:
        os.environ.clear()
        os.environ.update(tool_environment(str(home)))
        yield
    finally:
        os.environ.clear()
        os.environ.update(previous)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        raise QualificationError('acquire-reviewed-source', 'redirect-prohibited')


def fetch(operation: str, url: str, maximum: int) -> bytes:
    if not url.startswith('https://'):
        raise QualificationError(operation, 'https-required')
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with opener.open(url, timeout=60) as response:
            if response.geturl() != url:
                raise QualificationError(operation, 'repository-identity-invalid')
            data = response.read(maximum + 1)
    except (OSError, ValueError) as error:
        raise QualificationError(operation, 'acquisition-failed') from error
    if len(data) > maximum:
        raise QualificationError(operation, 'observation-limit-exceeded')
    return data


def admit_key_bytes(data: bytes, expected: dict) -> None:
    if hashlib.sha256(data).hexdigest() != expected['sha256']:
        raise QualificationError('authenticate-signing-key', 'key-identity-invalid')


def read_regular_file(path: Path, maximum: int) -> bytes:
    try:
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as source:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                raise QualificationError('authenticate-reviewed-file', 'regular-file-required')
            data = source.read(maximum + 1)
    except OSError as error:
        raise QualificationError('authenticate-reviewed-file', 'file-invalid') from error
    if len(data) > maximum:
        raise QualificationError('authenticate-reviewed-file', 'observation-limit-exceeded')
    return data


def write_private(path: Path, data: bytes) -> None:
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as destination:
        destination.write(data)


def snapshot_authenticated_rpm(source: Path, destination: Path, reviewed: dict) -> None:
    data = read_regular_file(source, 64 * 1024 * 1024)
    if hashlib.sha256(data).hexdigest() != reviewed['rpm_sha256']:
        raise QualificationError('authenticate-reviewed-rpm', 'rpm-identity-invalid')
    write_private(destination, data)


@contextmanager
def authenticated_bundle(directory: Path, architecture: str, policy: dict, *, acquire: bool):
    """Isolated RPM keyring; no system RPMDB/key import or repo configuration."""
    if acquire:
        directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    if not directory.is_dir() or directory.is_symlink():
        raise QualificationError('inspect-package-bundle', 'bundle-invalid')
    with tempfile.TemporaryDirectory(prefix='.certbot-authenticated-') as temporary:
        database = Path(temporary) / 'rpmdb'
        database.mkdir(mode=0o700)
        snapshot = Path(temporary) / 'bundle'
        snapshot.mkdir(mode=0o700)
        for family, authority in policy['keys'].items():
            key = directory / f'RPM-GPG-KEY-{family}'
            if acquire:
                authenticated = [fetch('acquire-signing-key', url, 8192) for url in authority['urls']]
                for data in authenticated:
                    admit_key_bytes(data, authority)
                if len(set(authenticated)) != 1:
                    raise QualificationError('authenticate-signing-key', 'sources-disagree')
                write_private(key, authenticated[0])
            key_bytes = read_regular_file(key, 8192)
            admit_key_bytes(key_bytes, authority)
            private_key = snapshot / key.name
            write_private(private_key, key_bytes)
            run('import-isolated-signing-key', ['rpmkeys', '--dbpath', str(database), '--import', str(private_key)])
        rows = []
        for reviewed in policy['closures'][architecture]:
            source = directory / reviewed['url'].rsplit('/', 1)[1]
            if acquire:
                data = fetch('acquire-reviewed-rpm', reviewed['url'], 64 * 1024 * 1024)
                if hashlib.sha256(data).hexdigest() != reviewed['rpm_sha256']:
                    raise QualificationError('authenticate-reviewed-rpm', 'rpm-identity-invalid')
                write_private(source, data)
            path = snapshot / source.name
            snapshot_authenticated_rpm(source, path, reviewed)
            output = run('verify-rpm-signature', ['rpmkeys', '--dbpath', str(database), '--checksig', '--verbose', str(path)])
            expected_line = f"Header V4 RSA/SHA256 Signature, key ID {reviewed['signer_fingerprint'][-8:]}: OK"
            if expected_line not in output.splitlines() and not any(line.strip() == expected_line for line in output.splitlines()):
                raise QualificationError('verify-rpm-signature', 'signer-invalid')
            if not any(line.strip() == 'Payload SHA256 digest: OK' for line in output.splitlines()):
                raise QualificationError('verify-rpm-payload', 'digest-invalid')
            header = run('inspect-signed-rpm-header', ['rpm', '--dbpath', str(database), '-qp', '--qf', RPM_QUERY, str(path)]).splitlines()
            admit_header(header, reviewed)
            rows.append(dict(reviewed, signature_verified=True))
        verify_dependency_closure(snapshot, architecture, policy, Path(temporary))
        yield rows, snapshot


def verified_bundle(directory: Path, architecture: str, policy: dict, *, acquire: bool) -> list[dict]:
    with authenticated_bundle(directory, architecture, policy, acquire=acquire) as (rows, _snapshot):
        return rows


def verify_dependency_closure(directory: Path, architecture: str, policy: dict, temporary: Path) -> None:
    """DNF owns strong dependency solving; only authenticated local RPMs exist."""
    with native_environment(temporary):
        _verify_dependency_closure(directory, architecture, policy, temporary)


def _verify_dependency_closure(directory: Path, architecture: str, policy: dict, temporary: Path) -> None:
    try:
        import dnf
        import rpm
    except ImportError as error:
        raise QualificationError('resolve-exact-dependency-closure', 'native-dnf-unavailable') from error
    try:
        # Discard caller HOME macros even if a native caller already loaded RPM.
        rpm.reloadConfig()
        for subdirectory in ('root', 'cache', 'logs', 'persist'):
            (temporary / subdirectory).mkdir(mode=0o700)
        with dnf.Base() as base:
            base.conf.installroot = str(temporary / 'root')
            base.conf.reposdir = []
            base.conf.cachedir = str(temporary / 'cache')
            base.conf.logdir = str(temporary / 'logs')
            base.conf.persistdir = str(temporary / 'persist')
            base.conf.plugins = False
            base.conf.install_weak_deps = False
            base.conf.arch = architecture
            base.conf.substitutions['basearch'] = architecture
            base.conf.substitutions['releasever'] = '10.2'
            base.fill_sack(load_system_repo=False)
            reviewed = policy['closures'][architecture]
            files = [str(directory / row['url'].rsplit('/', 1)[1]) for row in reviewed]
            packages = base.add_remote_rpms(files)
            certbot = [package for package in packages if package.name == 'certbot']
            if len(certbot) != 1:
                raise QualificationError('resolve-exact-dependency-closure', 'client-cardinality-invalid')
            base.package_install(certbot[0], strict=True)
            base.resolve()
            actual = sorted((p.name, str(p.epoch), p.version, p.release, p.arch) for p in base.transaction.install_set)
            expected = sorted(tuple(row[key] for key in ('name', 'epoch', 'version', 'release', 'architecture')) for row in reviewed)
            if actual != expected:
                raise QualificationError('resolve-exact-dependency-closure', 'closure-invalid')
    except (dnf.exceptions.Error, OSError) as error:
        raise QualificationError('resolve-exact-dependency-closure', 'solver-failed') from error


def admit_header(header: list[str], reviewed: dict) -> None:
    """Compare standard RPM observations with one exact reviewed payload."""
    if (
        len(header) != 8
        or header[:7] != [reviewed[key] for key in (
            'name', 'epoch', 'version', 'release', 'architecture', 'payload_digest', 'header_sha256'
        )]
        or not header[7].lower().endswith(reviewed['signer_fingerprint'][-16:])
    ):
        raise QualificationError('inspect-signed-rpm-header', 'header-identity-invalid')


def verify_installed_payload(row: dict, snapshot: Path, broker: Path | None) -> None:
    """Compare host files to authenticated RPM metadata, not RPMDB file hashes.

    Three ordinary Rocky packages contain protected files. An independently
    authenticated administrator may expose only this bounded read operation;
    its receipt does not authenticate its own controller or transport.
    """
    if broker is not None and row['name'] in PROTECTED_PAYLOAD_PACKAGES:
        if not broker.is_absolute() or broker.is_symlink() or broker.parent.is_symlink():
            raise QualificationError('verify-installed-package-payload', 'broker-invalid')
        for path in (broker, broker.parent):
            metadata = path.stat()
            if metadata.st_uid != 0 or metadata.st_mode & 0o022:
                raise QualificationError('verify-installed-package-payload', 'broker-authority-invalid')
        receipt = json.loads(run('verify-protected-package-payload', [
            'sudo', '-n', str(broker), row['name'], row['rpm_sha256'],
        ]))
        if receipt != {'operation': 'verify-installed-package-payload', 'name': row['name'],
                       'rpm_sha256': row['rpm_sha256'], 'result': 'VERIFIED'}:
            raise QualificationError('verify-installed-package-payload', 'broker-receipt-invalid')
    else:
        # RPM's native file verifier reads the signed reference header through
        # the same isolated keyring. DNF separately proved strong dependencies.
        # No install transaction, dependency-skip flag or scriptlet is involved;
        # unlike rpm -Vp this does not add a second copy of a self-conflicting
        # installed package (zlib-ng-compat) to a dependency-check transaction.
        run('verify-installed-package-payload', [
            '/usr/bin/python3', '-I', '-S', '-c', PAYLOAD_VERIFY,
            str(snapshot / row['url'].rsplit('/', 1)[1]), str(snapshot.parent / 'rpmdb'),
        ])


def observe_installed(directory: Path, architecture: str, policy: dict, broker: Path | None = None) -> dict:
    """Read admitted bytes before executing the installed client/modules."""
    machine = run('observe-native-architecture', ['uname', '-m'])
    if machine != architecture:
        raise QualificationError('observe-native-architecture', 'native-architecture-required')
    release = Path('/etc/os-release').read_text(encoding='utf-8')
    if contract.normalize_os_release(release) != {'ID': 'rocky', 'VERSION_ID': '10.2'}:
        raise QualificationError('observe-native-os', 'rocky-10.2-required')
    with authenticated_bundle(directory, architecture, policy, acquire=False) as (rows, snapshot):
        for row in rows:
            header = run('inspect-installed-rpm-header', ['rpm', '-q', '--qf', RPM_QUERY, row['name']]).splitlines()
            admit_header(header, row)
            # Configuration belongs to #103. No verification scriptlet runs.
            verify_installed_payload(row, snapshot, broker)
            row['installed_payload_verified'] = True
    inventory = run('observe-installed-signers', ['rpm', '-qa', '--qf', '%{NAME}|%{RSAHEADER:pgpsig}\\n'], maximum=1024 * 1024)
    epel_suffix = policy['keys']['epel']['fingerprint'][-16:]
    installed_epel = sorted(
        line.partition('|')[0] for line in inventory.splitlines()
        if line.lower().endswith(epel_suffix)
    )
    global_keys = run('observe-global-signing-keys', ['rpm', '-qa', '--qf', '%{NAME}|%{VERSION}\\n'], maximum=1024 * 1024)
    if 'gpg-pubkey|' + epel_suffix[-8:] in global_keys.splitlines():
        raise QualificationError('observe-global-signing-keys', 'global-epel-key-prohibited')
    repositories = contract.normalize_repository_ids(run('observe-effective-repositories', ['dnf4', '--quiet', 'repolist', '--enabled']))
    runtime = json.loads(run('execute-qualified-python-imports', [
        '/usr/bin/python3', '-I', '-S', '-c',
        IMPORT_SETUP + 'import platform,json,certbot,acme,configargparse,josepy,parsedatetime,OpenSSL,pyrfc3339,pytz; '
        'from importlib.metadata import version; '
        'print(json.dumps({"python_machine":platform.machine(),"python_version":platform.python_version(),"certbot_version":version("certbot")}))',
    ]))
    # Inspect the standalone plugin entry point without ACME, listeners, account
    # state, renewal, certificates, public network or packaged timer activation.
    run('execute-qualified-standalone-plugin', [
        '/usr/bin/python3', '-I', '-S', '-c',
        IMPORT_SETUP + 'from importlib.metadata import entry_points; '
        'plugins=[p for p in entry_points(group="certbot.plugins") if p.name=="standalone"]; '
        'assert len(plugins)==1; plugins[0].load()',
    ])
    cli_version = run('execute-qualified-certbot-client', [
        '/usr/bin/python3', '-I', '-S', '-c',
        IMPORT_SETUP + 'from certbot.main import main; sys.exit(main(["--version"]))',
    ])
    if cli_version != 'certbot 4.2.0':
        raise QualificationError('execute-qualified-certbot-client', 'client-version-invalid')
    provenance = {
        'distribution': 'rocky', 'gpg_key': 'RPM-GPG-KEY-Rocky-10',
        'enabled_repository_ids': repositories, 'rpm_signatures_verified': True,
        'external_repositories_enabled': set(repositories) != contract.REPOSITORIES,
        'certbot_exception': {
            'policy_id': policy['policy_id'], 'host_architecture': architecture,
            'packages': rows, 'installed_epel_names': installed_epel,
            'global_epel_key_present': False,
            'runtime': dict(runtime, machine=machine, imports_status=0, standalone_plugin_status=0),
        },
    }
    contract.admit_certbot_exception(provenance, architecture, policy)
    return provenance


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--acquire', type=Path, help='new workspace-local bundle directory')
    mode.add_argument('--verify-bundle', type=Path, help='authenticate an existing exact bundle without installing')
    mode.add_argument('--installed', type=Path, help='already authenticated RPM bundle')
    parser.add_argument('--architecture', required=True, choices=('x86_64', 'aarch64'))
    parser.add_argument('--target-sha', help='exact clean candidate checkout; required for native observation')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--payload-read-broker', type=Path,
                        help='independently authenticated administrator read-only helper for protected Rocky files')
    options = parser.parse_args()
    os.umask(0o077)
    try:
        policy = json.loads(POLICY.read_text(encoding='utf-8'))
        if options.acquire or options.verify_bundle:
            if options.payload_read_broker:
                raise QualificationError('verify-installed-package-payload', 'installed-mode-required')
            verified_bundle(
                options.acquire or options.verify_bundle, options.architecture, policy,
                acquire=options.acquire is not None,
            )
            print(json.dumps({'result': 'AUTHENTICATED_SUPPLY_ONLY', 'architecture': options.architecture, 'runtime': 'NOT RUN'}))
        else:
            if not options.target_sha or not re.fullmatch(r'[0-9a-f]{40}', options.target_sha):
                raise QualificationError('authenticate-target-checkout', 'target-binding-required')
            head = run('authenticate-target-checkout', ['git', '-C', str(ROOT), 'rev-parse', 'HEAD'])
            dirty = run('authenticate-target-checkout', ['git', '-C', str(ROOT), 'status', '--porcelain', '--untracked-files=normal'])
            if head != options.target_sha or dirty:
                raise QualificationError('authenticate-target-checkout', 'clean-exact-target-required')
            provenance = observe_installed(options.installed, options.architecture, policy, options.payload_read_broker)
            document = {'schema_version': 1, 'evidence_class': 'rocky-native', 'target_sha': head, 'architecture': options.architecture, 'package_provenance': provenance}
            if options.output is None:
                raise QualificationError('assemble-native-observation', 'output-required')
            options.output.write_text(json.dumps(document, indent=2) + '\n', encoding='utf-8')
            options.output.chmod(0o600)
            print(json.dumps({'result': 'NATIVE_OBSERVATION_REQUIRES_AUTHENTICATED_TRANSPORT', 'architecture': options.architecture, 'target_sha': head}))
    except (QualificationError, contract.ContractError) as error:
        print(json.dumps({'result': 'REJECTED', 'operation': error.operation, 'reason': error.reason}), file=sys.stderr)
        return 1
    except (OSError, ValueError) as error:
        print(json.dumps({'result': 'REJECTED', 'operation': 'read-qualification-input', 'reason': 'input-invalid'}), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
