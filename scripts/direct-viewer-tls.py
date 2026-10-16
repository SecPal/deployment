#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Administrator-owned DIRECT single Certbot lifecycle, consuming #308/#219/#220.

Fixed installed source and state; no shell snippets, custom CA/ACME URL, DNS
provider credential, alternate package installation or runtime socket input.
"""

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import pwd
import re
import stat
import sys
import tempfile
import time

SOURCE = Path('/usr/local/libexec/secpal/viewer-tls-source')
HELPER = SOURCE/'scripts/direct-viewer-tls.py'
CONFIG = Path('/etc/haproxy/secpal-acme.json')
ROUTING = Path('/etc/haproxy/secpal-routing.json')
SERVING_CONFIG = Path('/etc/haproxy/secpal.cfg')
PEM = Path('/etc/haproxy/secpal-viewer.pem')
ACME = Path('/srv/secpal/acme')
RUNTIME = Path('/run/secpal-viewer-tls')
JOURNAL = PEM.with_name('.secpal-viewer-pending.json')
RECEIPT = ACME/'activation.json'
RENEWAL = ACME/'renewal.json'
PREVIOUS_RECEIPT = PEM.with_name('.secpal-viewer-previous-receipt.json')
BUNDLE = Path('/var/lib/secpal/certbot-rpm-bundle')
POLICY_READY = Path('/run/secpal-acme-policy/ready.json')
HAPROXY = Path('/usr/local/libexec/secpal/haproxy-config')
LIBRARIES = ('viewer_tls_contract.py','viewer_tls_runtime.py','haproxy_direct_contract.py',
             'haproxy_base_contract.py','product_backend_contract.py','haproxy_direct_policy.py',
             'haproxy_config_lifecycle.py','qualify-certbot-packages.py',
             'ci-cloud/rocky_preparation_contract.py','ci-cloud/certbot_package_admission.py')
HOOK = '/usr/bin/python3 -I -S '+str(HELPER)+' --deploy'


def trusted(path, *, regular=False, private=False):
    for item in (path,*path.parents):
        info=item.lstat()
        if info.st_uid!=0 or stat.S_ISLNK(info.st_mode) or info.st_mode & 0o022 or (item!=path and not stat.S_ISDIR(info.st_mode)):
            raise ValueError('admit-tls-administrator-path')
    info=path.lstat()
    if regular and (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1):
        raise ValueError('admit-tls-administrator-file')
    if private and (info.st_gid!=0 or stat.S_IMODE(info.st_mode)!=(0o700 if stat.S_ISDIR(info.st_mode) else 0o600)):
        raise ValueError('admit-tls-private-state')
    return info


def installed_source():
    if os.geteuid()!=0 or Path(__file__).resolve()!=HELPER:
        raise ValueError('admit-installed-tls-helper')
    for path in (HELPER,*(SOURCE/'scripts'/name for name in LIBRARIES),
                 SOURCE/'config/production/certbot-package-policy.json'):
        trusted(path,regular=True)
    trusted(RUNTIME,private=True)
    sys.dont_write_bytecode=True
    # Never consume adjacent pyc files from a caller-selected cache.
    cache=tempfile.TemporaryDirectory(prefix='imports-',dir=RUNTIME)
    sys.pycache_prefix=cache.name
    sys.path.insert(0,str(SOURCE/'scripts'))
    return cache


if __name__=='__main__':
    try:
        os.umask(0o077)
        _imports=installed_source()
    except (OSError,ValueError):
        print('FAIL: admit-installed-tls-source',file=sys.stderr)
        raise SystemExit(1)

sys.path.insert(0,str(Path(__file__).resolve().parent))
from haproxy_config_lifecycle import publish, stage, sync_directory, recover_publication, admit_publication_record
from haproxy_direct_contract import decode_document, from_config
from haproxy_direct_policy import normalize_table
from viewer_tls_contract import (ACME_PORT, DIRECTORIES, admit_certificate, admit_file, health, policy,
                                 policy_digest, policy_projection, admit_activation)
from viewer_tls_runtime import (TRUST, run, read_certificate, validate_candidate, verify_chain, verify_served)


def atomic_json(path, value):
    candidate=stage(path.parent,json.dumps(value,sort_keys=True).encode(),lambda _:None,mode=0o600)
    os.replace(candidate,path)
    sync_directory(path.parent)


@contextmanager
def serialized(lock):
    descriptor=os.open(lock,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        info=os.fstat(descriptor)
        if (info.st_uid!=0 or info.st_gid!=0 or info.st_nlink!=1 or not stat.S_ISREG(info.st_mode)
                or stat.S_IMODE(info.st_mode)!=0o600):
            raise ValueError('admit-tls-serialization-lock')
        try:
            fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError('admit-exclusive-tls-invocation') from error
        yield
    finally:
        os.close(descriptor)


def label(path):
    value=os.getxattr(path,'security.selinux').decode().rstrip('\0').split(':')
    if len(value)<4:
        raise ValueError('observe-tls-selinux-label')
    return value[2]


def prepare(path):
    run('label-viewer-certificate',['/usr/sbin/restorecon','-F',str(path)])
    admit_file(path.lstat(),private=True,label=label(path))


def configuration(*, desired=False):
    path=ROUTING if desired else SERVING_CONFIG
    trusted(path,regular=True)
    if not 0<path.stat().st_size<=65536:
        raise ValueError('admit-tls-routing-size')
    spec=decode_document(path.read_bytes()) if desired else from_config(path.read_bytes())
    if spec.topology!='single' or spec.listeners[0].tls_lifecycle not in ('http01','hsts'):
        raise ValueError('admit-direct-single-tls-lifecycle')
    return spec


def names(spec):
    return (spec.routing.frontend_host,spec.routing.api_host)


def systemd_package_admission():
    """Consume PID 1's completed prerequisite for this live service activation.

    No caller environment, cached receipt or writable admission file is trusted.
    Descendant deploy hooks stay in the same cgroup even with a closed environment.
    """
    units=('secpal-viewer-health.service','secpal-viewer-renew.service')
    groups=Path('/proc/self/cgroup').read_text().splitlines()
    unit=next((name for name in units
               if '0::/system.slice/'+name in groups),None)
    if unit is None:
        return False
    object_path='/org/freedesktop/systemd1/unit/'+unit.replace('-','_2d').replace('.','_2e')
    def property_(interface,name,signature):
        value=json.loads(run('observe-systemd-package-prerequisite',[
            '/usr/bin/busctl','--system','--json=short','--timeout=5','get-property',
            'org.freedesktop.systemd1',object_path,'org.freedesktop.systemd1.'+interface,name]))
        if type(value) is not dict or set(value)!={'type','data'} or value['type']!=signature:
            raise ValueError('admit-systemd-package-prerequisite')
        return value['data']
    invocation=property_('Unit','InvocationID','ay')
    rows=property_('Service','ExecStartPre','a(sasbttttuii)')
    entered=property_('Unit','InactiveExitTimestampMonotonic','t')
    started=property_('Service','ExecMainStartTimestampMonotonic','t')
    state=property_('Unit','ActiveState','s')
    current=property_('Unit','InvocationID','ay')
    command=['/usr/bin/python3','-I','-S',str(HELPER),'--verify-packages']
    if (type(invocation) is not list or len(invocation)!=16 or not any(invocation)
            or any(type(byte) is not int or not 0<=byte<=255 for byte in invocation)
            or invocation!=current or state!='activating'
            or type(rows) is not list or len(rows)!=1 or type(rows[0]) is not list
            or len(rows[0])!=10 or rows[0][:3]!=['/usr/bin/python3',command,False]
            or rows[0][2] is not False
            or any(type(value) is not int or value<=0 for value in [entered,started,*rows[0][3:8]])
            or any(type(value) is not int for value in rows[0][8:]) or rows[0][8:]!=[1,0]
            or not rows[0][4]<=rows[0][6]<=started or rows[0][6]<entered):
        raise ValueError('admit-systemd-package-prerequisite')
    return True


def package_authority(*, host_view=False):
    # Consume #308's exact observer and semantic owner; no copied identities,
    # enabled EPEL repository, global signing key, or installation operation.
    if host_view:
        # '+' on the fixed ExecStartPre preserves PID 1's host mount view.
        # Never grade sandbox mount masks as installed RPM metadata.
        host=Path('/proc/1/ns/mnt').stat()
        own=Path('/proc/self/ns/mnt').stat()
        if (host.st_dev,host.st_ino)!=(own.st_dev,own.st_ino):
            raise ValueError('admit-package-host-filesystem-view')
    trusted(BUNDLE)
    spec=importlib.util.spec_from_file_location('accepted_certbot_packages',SOURCE/'scripts/qualify-certbot-packages.py')
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    policy_document=json.loads((SOURCE/'config/production/certbot-package-policy.json').read_bytes())
    try:
        if host_view or not systemd_package_admission():
            module.observe_installed(BUNDLE,platform.machine(),policy_document)
    except module.QualificationError as error:
        raise ValueError('certbot-supply-'+error.operation+'-'+error.reason) from error
    import sysconfig
    sys.path.extend([sysconfig.get_path('purelib',scheme='rpm_prefix'),sysconfig.get_path('platlib',scheme='rpm_prefix')])
    rows=run('observe-packaged-renewal-timer',['/usr/bin/systemctl','show','certbot-renew.timer',
            '--property=ActiveState,UnitFileState']).decode().splitlines()
    if len(rows)!=2 or dict(row.split('=',1) for row in rows)!={'ActiveState':'inactive','UnitFileState':'disabled'}:
        raise ValueError('admit-packaged-renewal-disabled')


def infrastructure():
    if run('observe-tls-enforcing',['/usr/sbin/getenforce']).strip()!=b'Enforcing':
        raise ValueError('admit-tls-enforcing')
    context=Path('/proc/self/attr/current').read_text().strip().split(':')
    if len(context)<4 or context[2] not in ('unconfined_service_t','unconfined_t'):
        raise ValueError('admit-administrator-tls-domain')
    trusted(ACME,private=True)
    if label(ACME)!='secpal_acme_state_t':
        raise ValueError('admit-acme-state-label')
    trusted(TRUST,regular=True)
    trusted(HAPROXY,regular=True)
    policy_check()


def policy_check():
    uid=pwd.getpwnam('haproxy').pw_uid
    trusted(POLICY_READY,regular=True)
    if POLICY_READY.stat().st_size>1024 or json.loads(POLICY_READY.read_bytes())!={'policy_sha256':policy_digest(uid)}:
        raise ValueError('admit-acme-policy-marker')
    table=json.loads(run('observe-acme-isolation-table',['/usr/sbin/nft','--json','list','table','inet','secpal_acme']))
    if normalize_table(table)!=policy_projection(uid):
        raise ValueError('admit-effective-acme-isolation')
    # Reuse #101's effective kernel SELinux access primitive, no boolean bypass.
    import runpy
    trusted(HAPROXY.parent/'product-backend-policy',regular=True)
    native=runpy.run_path(str(HAPROXY.parent/'product-backend-policy'))
    if not native['effective_access']('haproxy_t','secpal_acme_port_t','name_connect'):
        raise ValueError('admit-acme-selinux-connect')
    if not native['effective_access']('unconfined_service_t','secpal_acme_port_t','name_bind'):
        raise ValueError('admit-acme-selinux-bind')
    import setools
    # Imported only for privileged policy checking, through the reviewed Rocky
    # interpreter scheme; installation belongs to existing host prerequisites.
    rows=[row for row in setools.SELinuxPolicy().portcons() if str(row.protocol)=='tcp' and row.ports.low<=ACME_PORT<=row.ports.high]
    if not rows or str(min(rows,key=lambda row:row.ports.high-row.ports.low).context.type_)!='secpal_acme_port_t':
        raise ValueError('admit-acme-port-label')


def policy_install():
    # Administrator service construction only; never invoked by renewal/hooks.
    for unit in ('haproxy.service','secpal-viewer-renew.service'):
        if run('observe-inactive-policy-construction',['/usr/bin/systemctl','show',unit,'--property=ActiveState','--value']).strip()!=b'inactive':
            raise ValueError('admit-inactive-acme-policy-construction')
    uid=pwd.getpwnam('haproxy').pw_uid
    compiled=policy(uid)
    # A restart may re-admit an unchanged table, never append duplicate rules
    # or replace unrelated/drifted policy. Observe before any policy mutation.
    tables=json.loads(run('observe-existing-acme-table',['/usr/sbin/nft','--json','list','tables']))
    exists=any(item.get('table',{}).get('name')=='secpal_acme'
               and item['table'].get('family')=='inet' for item in tables['nftables'])
    if exists:
        table=json.loads(run('observe-existing-acme-isolation',['/usr/sbin/nft','--json','list','table','inet','secpal_acme']))
        if normalize_table(table)!=policy_projection(uid):
            raise ValueError('admit-existing-acme-isolation')
    with tempfile.TemporaryDirectory(prefix='policy-',dir=RUNTIME) as directory:
        path=Path(directory)/'secpal_acme.cil'
        state_path=Path(directory)/'secpal_acme_state.cil'
        path.write_text(compiled['cil'])
        state_path.write_text(compiled['state_cil'])
        run('install-acme-selinux-policy',['/usr/sbin/semodule','-i',str(state_path),'-i',str(path),
            '-e','secpal_acme_state','-e','secpal_acme'])
    if not exists:
        run('validate-acme-isolation-table',['/usr/sbin/nft','--check','-f','-'],input_text=compiled['nft'].encode())
        run('install-acme-isolation-table',['/usr/sbin/nft','-f','-'],input_text=compiled['nft'].encode())
    run('label-persistent-acme-state',['/usr/sbin/restorecon','-RF',str(ACME)])
    trusted(POLICY_READY.parent)
    atomic_json(POLICY_READY,{'policy_sha256':policy_digest(uid)})
    policy_check()


def policy_withdraw():
    # Transport authority ends only after its dependent processes stop. Private
    # state labels persist independently; removing them would orphan secrets.
    for unit in ('haproxy.service','secpal-viewer-renew.service','secpal-viewer-health.service'):
        if run('observe-acme-withdrawal-stopped-unit',['/usr/bin/systemctl','show',unit,
                '--property=ActiveState','--value']).strip() not in (b'inactive',b'failed'):
            raise ValueError('admit-acme-withdrawal-stopped-units')
    if run('observe-acme-withdrawal-empty-responder',['/usr/sbin/ss','-H','-lnt',
            'sport = :18084']).strip():
        raise ValueError('admit-acme-withdrawal-empty-responder')
    uid=pwd.getpwnam('haproxy').pw_uid
    if POLICY_READY.exists():
        trusted(POLICY_READY,regular=True,private=True)
        if POLICY_READY.stat().st_size>1024 or json.loads(POLICY_READY.read_bytes())!={'policy_sha256':policy_digest(uid)}:
            raise ValueError('admit-owned-acme-policy-withdrawal')
    tables=json.loads(run('observe-acme-withdrawal-tables',['/usr/sbin/nft','--json','list','tables']))
    exists=any(item.get('table',{}).get('name')=='secpal_acme' and item['table'].get('family')=='inet'
        for item in tables['nftables'])
    if exists:
        table=json.loads(run('observe-owned-acme-withdrawal-table',['/usr/sbin/nft','--json','list','table','inet','secpal_acme']))
        if normalize_table(table)!=policy_projection(uid):
            raise ValueError('admit-owned-acme-policy-withdrawal')
        run('withdraw-acme-isolation-table',['/usr/sbin/nft','delete','table','inet','secpal_acme'])
    modules=run('observe-acme-withdrawal-modules',['/usr/sbin/semodule','-lfull']).decode().splitlines()
    if any(len(row.split())>=3 and row.split()[1]=='secpal_acme' for row in modules):
        run('withdraw-acme-transport-policy',['/usr/sbin/semodule','-r','secpal_acme'])
    remaining=json.loads(run('verify-acme-withdrawal-tables',['/usr/sbin/nft','--json','list','tables']))
    modules=run('verify-acme-withdrawal-modules',['/usr/sbin/semodule','-lfull']).decode().splitlines()
    if (any(item.get('table',{}).get('name')=='secpal_acme' and item['table'].get('family')=='inet'
            for item in remaining['nftables'])
            or any(len(row.split())>=3 and row.split()[1]=='secpal_acme' for row in modules)):
        raise ValueError('verify-acme-withdrawal-empty-transport')
    POLICY_READY.unlink(missing_ok=True)
    sync_directory(POLICY_READY.parent)


def source_material(spec):
    lineage=ACME/'config/live/secpal-viewer'
    archive=ACME/'config/archive/secpal-viewer'
    trusted(archive,private=True)
    trusted(lineage,private=True)
    data=[]
    generation=None
    for role in ('fullchain','privkey'):
        link=lineage/(role+'.pem')
        info=link.lstat()
        target=os.readlink(link)
        match=re.fullmatch(r'../../archive/secpal-viewer/'+role+r'([1-9][0-9]{0,5})\.pem',target)
        if not stat.S_ISLNK(info.st_mode) or info.st_uid!=0 or info.st_gid!=0 or not match:
            raise ValueError('admit-certbot-lineage-link')
        if generation is not None and generation!=match[1]:
            raise ValueError('admit-certbot-lineage-generation')
        generation=match[1]
        path=archive/(role+generation+'.pem')
        info=trusted(path,regular=True,private=role=='privkey')
        admit_file(info,private=role=='privkey',label=label(path),state=True)
        # Snapshot each admitted source once. Root owns all ancestors and the
        # Certbot config lock prevents concurrent issuance into this lineage.
        data.append(path.read_bytes())
    return admit_certificate(*data,names(spec),int(time.time()))


def reload_shared():
    # ExecReload is the sole accepted master/generation controller. Desired
    # configuration must equal serving input before certificate-only renewal.
    serving=configuration()
    if configuration(desired=True)!=serving:
        raise ValueError('admit-certificate-only-reload')
    run('reload-shared-haproxy',['/usr/bin/systemctl','reload','haproxy.service'],timeout=120)


def current_certificate(spec, *, allow_expired=False):
    info=trusted(PEM,regular=True,private=True)
    admit_file(info,private=True,label=label(PEM))
    return read_certificate(PEM,names(spec),int(time.time()),fresh=False,allow_expired=allow_expired)


def accepted_receipt(spec):
    trusted(RECEIPT,regular=True,private=True)
    if RECEIPT.stat().st_size>1024:
        raise ValueError('admit-tls-activation-receipt')
    value=json.loads(RECEIPT.read_bytes())
    return admit_activation(value,names(spec),int(time.time()))


def accept(certificate,spec):
    now=int(time.time())
    previous=accepted_receipt(spec) if RECEIPT.exists() else None
    atomic_json(RECEIPT,{'fingerprint':certificate.fingerprint,'names':sorted(names(spec)),
        'initial_at':previous['initial_at'] if previous else now,
        'renewed_at':now if previous and previous['fingerprint']!=certificate.fingerprint else (previous['renewed_at'] if previous else None)})


def deploy(*, initial=False):
    spec=configuration(desired=initial)
    if os.environ.get('RENEWED_LINEAGE',str(ACME/'config/live/secpal-viewer'))!=str(ACME/'config/live/secpal-viewer'):
        raise ValueError('admit-deploy-hook-lineage')
    if 'RENEWED_DOMAINS' in os.environ and sorted(os.environ['RENEWED_DOMAINS'].split())!=sorted(names(spec)):
        raise ValueError('admit-deploy-hook-domains')
    certificate=source_material(spec)
    verify_chain(certificate)
    from haproxy_direct_contract import render
    config=render(spec).encode()
    if initial:
        if not any(row.transport=='https' for row in spec.listeners):
            raise ValueError('admit-initial-https-construction')
        if RECEIPT.exists() or PEM.exists():
            raise ValueError('admit-uninstalled-initial-certificate')
    else:
        previous=current_certificate(spec,allow_expired=True)
        receipt=accepted_receipt(spec)
        if previous.fingerprint!=receipt['fingerprint']:
            raise ValueError('admit-accepted-serving-certificate')
        # Observed serving proof before mutation also prevents replacing a
        # contradictory or uncertain live predecessor.
        if previous.not_after>int(time.time()):
            verify_served(previous,spec)
        atomic_json(PREVIOUS_RECEIPT,receipt)
    def activate():
        reload_shared()
        verify_served(certificate,spec)
        accept(certificate,spec)
    def recover():
        # Restore the acceptance binding before the shared boot/reload guard,
        # including a failure after journal unlink but before directory fsync.
        atomic_json(RECEIPT,receipt)
        reload_shared()
        if previous.not_after>int(time.time()):
            verify_served(previous,spec)
    publish(PEM,certificate.pem,lambda path:validate_candidate(path,config),activate,prepare,
            recover=recover if not initial else lambda:None,mode=0o600,journal=JOURNAL,prepare_initial=initial)
    if initial:
        print('PENDING: initial-certificate-requires-shared-host-construction')
    else:
        PREVIOUS_RECEIPT.unlink(missing_ok=True)
        sync_directory(PREVIOUS_RECEIPT.parent)
        print('PASS: verified-viewer-certificate-activation')


def accept_initial():
    spec=configuration()
    certificate=current_certificate(spec)
    trusted(JOURNAL,regular=True,private=True)
    record=json.loads(JOURNAL.read_bytes())
    if record!={'previous_sha256':None,'candidate_sha256':hashlib.sha256(PEM.read_bytes()).hexdigest()}:
        raise ValueError('admit-initial-pending-certificate')
    verify_chain(certificate)
    verify_served(certificate,spec)
    accept(certificate,spec)
    JOURNAL.unlink()
    sync_directory(JOURNAL.parent)
    print('PASS: verified-initial-viewer-certificate-activation')


def acme_config():
    trusted(CONFIG,regular=True)
    if CONFIG.stat().st_size>1024:
        raise ValueError('admit-acme-config-size')
    value=json.loads(CONFIG.read_bytes())
    if (type(value) is not dict or set(value)!={'email','directory'} or value['directory'] not in DIRECTORIES
            or type(value['email']) is not str or len(value['email'])>254
            or not re.fullmatch(r'[A-Za-z0-9._+%-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}',value['email'])):
        raise ValueError('admit-acme-config')
    return value


def certbot_arguments(spec,configuration, *, obtain=False):
    # CLI completely selects the standalone seam, endpoints, paths and hooks.
    # No package sysconfig, default ini, stored directory hooks or stop/start.
    base=['certonly' if obtain else 'renew','--non-interactive','--authenticator','standalone',
        '--preferred-challenges','http','--http-01-address','127.0.0.1','--http-01-port',str(ACME_PORT),
        '--config',str(SOURCE/'config/production/certbot-client.ini'),
        '--config-dir',str(ACME/'config'),'--work-dir',str(ACME/'work'),'--logs-dir',str(ACME/'logs'),
        '--cert-name','secpal-viewer','--server',DIRECTORIES[configuration['directory']],
        '--no-directory-hooks','--pre-hook','/usr/bin/true','--post-hook','/usr/bin/true',
        '--deploy-hook',HOOK,'--key-type','ecdsa','--elliptic-curve','secp256r1']
    if obtain:
        # First obtain does not publish/activate before host construction.
        base=base[:base.index('--deploy-hook')]+base[base.index('--deploy-hook')+2:]
        base+=['--agree-tos','--email',configuration['email'],'-d',','.join(names(spec))]
    else:
        base+=['--no-random-sleep-on-renew']
    return base


def renewal_config(config):
    # Certbot's qualified parser owns its persisted syntax. Admit only the
    # native standalone lineage produced by this controller, never alternate
    # plugins, credentials, hidden hooks, extra lineages or arbitrary paths.
    from configobj import ConfigObj, ConfigObjError
    directory=ACME/'config/renewal'
    trusted(directory,private=True)
    if sorted(item.name for item in directory.iterdir())!=['secpal-viewer.conf']:
        raise ValueError('admit-one-viewer-renewal-lineage')
    path=directory/'secpal-viewer.conf'
    trusted(path,regular=True,private=True)
    if not 0<path.stat().st_size<=16384:
        raise ValueError('admit-renewal-config-size')
    try:
        value=ConfigObj(str(path),interpolation=False,raise_errors=True)
    except ConfigObjError as error:
        raise ValueError('decode-standalone-renewal-parameters') from error
    expected={'version':'4.2.0','archive_dir':str(ACME/'config/archive/secpal-viewer'),
        **{role:str(ACME/'config/live/secpal-viewer'/(role+'.pem')) for role in ('cert','privkey','chain','fullchain')}}
    if set(value)!=set(expected)|{'renewalparams'} or any(value[key]!=item for key,item in expected.items()):
        raise ValueError('admit-renewal-lineage-paths')
    params=value['renewalparams']
    selected={'authenticator':'standalone','server':DIRECTORIES[config['directory']],
        'key_type':'ecdsa','elliptic_curve':'secp256r1','http01_address':'127.0.0.1',
        'http01_port':str(ACME_PORT),'pref_challs':['http-01'],
        'config_dir':str(ACME/'config'),'work_dir':str(ACME/'work'),'logs_dir':str(ACME/'logs'),
        'pre_hook':'/usr/bin/true','post_hook':'/usr/bin/true','renew_hook':HOOK}
    if (not isinstance(params,dict) or set(params)-set(selected)-{'account'}
            or any(key in params and params[key]!=item for key,item in selected.items())
            or type(params.get('account')) is not str or not re.fullmatch('[0-9a-f]{32}',params['account'])):
        raise ValueError('admit-standalone-renewal-parameters')


def renew(*, obtain=False):
    atomic_json(RENEWAL,{'status':'UNKNOWN','at':int(time.time())})
    try:
        spec=configuration()
        config=acme_config()
        if not any(row.transport=='http' for row in spec.listeners):
            raise ValueError('admit-http01-listener')
        if obtain and (RECEIPT.exists() or PEM.exists() or JOURNAL.exists()
                       or any(row.transport=='https' for row in spec.listeners)):
            raise ValueError('admit-http-only-initial-issuance')
        if not obtain:
            renewal_config(config)
            previous=current_certificate(spec,allow_expired=True)
            if previous.fingerprint!=accepted_receipt(spec)['fingerprint'] or JOURNAL.exists():
                raise ValueError('admit-renewal-accepted-state')
            if previous.not_after>int(time.time()): verify_served(previous,spec)
        trusted(SOURCE/'config/production/certbot-client.ini',regular=True)
        # Only the #308 payload-admitted RPM interpreter/entrypoint executes.
        arguments=certbot_arguments(spec,config,obtain=obtain)
        code=('import sys,sysconfig; sys.path.extend([sysconfig.get_path("purelib",scheme="rpm_prefix"),'
              'sysconfig.get_path("platlib",scheme="rpm_prefix")]); from certbot.main import main; sys.exit(main(sys.argv[1:]))')
        run('execute-certbot-http01',['/usr/bin/python3','-I','-S','-c',code,*arguments],timeout=600)
        if not obtain:
            with serialized(RUNTIME/'publish.lock'):
                if JOURNAL.exists(): raise ValueError('recover-viewer-certificate-before-renewal')
                lineage=source_material(spec)
                if lineage.fingerprint!=accepted_receipt(spec)['fingerprint']:
                    deploy()
                current=current_certificate(spec)
                verify_served(current,spec)
                if current.fingerprint!=lineage.fingerprint or current.fingerprint!=accepted_receipt(spec)['fingerprint']:
                    raise ValueError('verify-renewal-activation-receipt')
        if not obtain:
            atomic_json(RENEWAL,{'status':'SUCCESS','at':int(time.time())})
    except (OSError,ValueError):
        atomic_json(RENEWAL,{'status':'FAILURE','at':int(time.time())})
        raise


def status():
    now=int(time.time())
    observation={'observed_at':now,'not_after':None,'served':'UNKNOWN','renewal':'UNKNOWN','renewal_at':None}
    try:
        spec=configuration()
        # Parse expiry even after it expires; invalid/expired material is never
        # admitted as a serving candidate. The expiry fact remains observable.
        from cryptography import x509
        info=trusted(PEM,regular=True,private=True)
        admit_file(info,private=True,label=label(PEM))
        leaf=x509.load_pem_x509_certificate(PEM.read_bytes())
        observation['not_after']=int(leaf.not_valid_after_utc.timestamp())
        certificate=current_certificate(spec)
        observation['not_after']=certificate.not_after
        verify_chain(certificate)
        verify_served(certificate,spec,timeout=1)
        observation['served']='MATCH' if certificate.fingerprint==accepted_receipt(spec)['fingerprint'] and not JOURNAL.exists() else 'MISMATCH'
    except (ValueError,OSError):
        pass
    try:
        trusted(RENEWAL,regular=True,private=True)
        value=json.loads(RENEWAL.read_bytes())
        if set(value)=={'status','at'} and value['status'] in ('SUCCESS','FAILURE','UNKNOWN') and type(value['at']) is int and 0<=value['at']<=now:
            observation['renewal'],observation['renewal_at']=value['status'],value['at']
    except (ValueError,OSError):
        pass
    result=health(observation,now)
    print(json.dumps(result,sort_keys=True))
    return 0 if result['state']=='HEALTHY' else 1


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    actions=parser.add_mutually_exclusive_group(required=True)
    for action in ('obtain','renew','deploy','prepare-initial','accept-initial','recover','health','policy-check','policy-install','policy-withdraw','verify-packages'):
        actions.add_argument('--'+action,action='store_true')
    args=parser.parse_args()
    if args.verify_packages:
        package_authority(host_view=True)
        print('PASS: installed-certbot-package-admission')
        return 0
    if args.policy_withdraw:
        with serialized(RUNTIME/'renew.lock'), serialized(RUNTIME/'publish.lock'):
            policy_withdraw()
        return 0
    if args.policy_install:
        package_authority()
        with serialized(RUNTIME/'renew.lock'), serialized(RUNTIME/'publish.lock'):
            policy_install()
        return 0
    try:
        package_authority()
        if args.health:
            infrastructure()
    except (OSError,ValueError,RuntimeError):
        if not args.health:
            raise
        # An unavailable producer remains an explicit UNKNOWN health fact.
        print(json.dumps(health({'observed_at':None,'not_after':None,'served':'UNKNOWN',
            'renewal':'UNKNOWN','renewal_at':None},int(time.time())),sort_keys=True))
        return 1
    if args.policy_check:
        policy_check()
        return 0
    if args.health:
        # Read-only observations cannot hold the publication lock: that lock
        # authorizes the shared runtime's immediate promotion/compensation.
        return status()
    lock=RUNTIME/('renew.lock' if args.renew or args.obtain else 'publish.lock')
    with serialized(lock):
        infrastructure()
        if args.recover:
            if JOURNAL.exists():
                trusted(JOURNAL,regular=True,private=True)
                if not 0<JOURNAL.stat().st_size<=1024:
                    raise ValueError('admit-publication-journal')
                backup=JOURNAL.with_name(JOURNAL.name+'.pem')
                if backup.exists(): trusted(backup,regular=True,private=True)
                record=admit_publication_record(json.loads(JOURNAL.read_bytes()))
                if (record.get('previous_sha256') is None and
                        run('observe-initial-recovery-inactive',['/usr/bin/systemctl','show','haproxy.service',
                            '--property=ActiveState','--value']).strip()!=b'inactive'):
                    raise ValueError('admit-inactive-first-preparation-recovery')
                def compensate():
                    if record['previous_sha256'] is not None:
                        trusted(PREVIOUS_RECEIPT,regular=True,private=True)
                        if not 0<PREVIOUS_RECEIPT.stat().st_size<=1024:
                            raise ValueError('admit-recovered-activation-receipt')
                        old=current_certificate(configuration(),allow_expired=True)
                        old_receipt=admit_activation(json.loads(PREVIOUS_RECEIPT.read_bytes()),
                            names(configuration()),int(time.time()),fingerprint=old.fingerprint)
                        atomic_json(RECEIPT,old_receipt)
                        if run('observe-recovery-service-state',['/usr/bin/systemctl','show','haproxy.service',
                                '--property=ActiveState','--value']).strip()==b'active':
                            reload_shared()
                            if old.not_after>int(time.time()): verify_served(old,configuration())
                recover_publication(PEM,JOURNAL,prepare,compensate)
                PREVIOUS_RECEIPT.unlink(missing_ok=True)
        elif args.obtain or args.renew: renew(obtain=args.obtain)
        elif args.deploy or args.prepare_initial: deploy(initial=args.prepare_initial)
        elif args.accept_initial: accept_initial()
        return 0


if __name__=='__main__':
    try:
        raise SystemExit(main())
    except ValueError as error:
        # Only source-owned operation identities are emitted. Crypto/runtime
        # exceptions and arbitrary Certbot output never reach the journal.
        reason=str(error)
        if not re.fullmatch(r'[a-z][a-z0-9-]{1,79}',reason): reason='observe-direct-viewer-tls'
        print('FAIL: '+reason,file=sys.stderr)
        raise SystemExit(1)
    except (OSError,RuntimeError,KeyError,TypeError,UnicodeError):
        print('FAIL: observe-direct-viewer-tls',file=sys.stderr)
        raise SystemExit(1)
