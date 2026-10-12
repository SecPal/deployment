#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Bounded certificate observation; admission belongs to viewer_tls_contract."""

import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import time

from viewer_tls_contract import admit_certificate, split_serving

TRUST = Path('/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem')


def run(operation, arguments, *, timeout=15, input_text=None):
    """Discard subprocess output on failure; private state is never a diagnostic."""
    try:
        result = subprocess.run(arguments, input=input_text, capture_output=True,
            timeout=timeout, env={'PATH':'/usr/sbin:/usr/bin','LC_ALL':'C','LANG':'C','HOME':'/'}, cwd='/')
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError(operation) from error
    if result.returncode or len(result.stdout) > 65536 or len(result.stderr) > 65536:
        raise ValueError(operation)
    return result.stdout


def verify_chain(certificate, ca_file=TRUST):
    # The production caller admits the fixed system trust file before this
    # observation. Fixtures use an ephemeral CA, never production secret state.
    with tempfile.TemporaryDirectory(prefix='secpal-chain-') as directory:
        leaf, chain = Path(directory)/'leaf', Path(directory)/'chain'
        leaf.write_bytes(certificate.leaf)
        chain.write_bytes(certificate.chain)
        for host in certificate.names:
            run('verify-certificate-chain-and-hostname', ['/usr/bin/openssl','verify','-x509_strict',
                '-purpose','sslserver','-verify_hostname',host,'-CAfile',str(ca_file),
                '-no-CApath','-no-CAstore','-untrusted',str(chain),str(leaf)])


def validate_candidate(candidate, config):
    # Fixed-path projection from regenerated accepted configuration only. No
    # input config fragment, arbitrary certificate pathname or alternate reload.
    from haproxy_direct_contract import VIEWER_PEM, from_config
    from_config(config)
    with tempfile.TemporaryDirectory(prefix='secpal-tls-syntax-', dir=candidate.parent) as directory:
        projected = Path(directory)/'candidate.cfg'
        projected.write_bytes(config.replace(VIEWER_PEM.encode(),str(candidate).encode()))
        run('validate-haproxy-certificate-candidate', ['/usr/sbin/haproxy','-c','-q','-f',str(projected)])


def verify_served(certificate, spec, ca_file=TRUST, *, timeout=10):
    """Dial admitted sockets independently with real trust, SNI and hostname.

    No DNS lookup, certificate-derived trust root, or acceptance based solely on
    filesystem equality. Every HTTPS socket must serve both expected hostnames.
    """
    rows = [row for row in spec.listeners if row.transport=='https']
    if not rows:
        raise ValueError('verify-serving-https-listeners')
    deadline = time.monotonic()+timeout
    while True:
        try:
            for row in rows:
                address = {'0.0.0.0':'127.0.0.1','::':'::1'}.get(row.socket.address,row.socket.address)
                for name in certificate.names:
                    for version in (ssl.TLSVersion.TLSv1_2,ssl.TLSVersion.TLSv1_3):
                        for protocol in ('h2','http/1.1'):
                            context=ssl.create_default_context(cafile=str(ca_file))
                            context.minimum_version=context.maximum_version=version
                            context.set_alpn_protocols([protocol])
                            with socket.create_connection((address,row.socket.port),timeout=1) as connection:
                                with context.wrap_socket(connection,server_hostname=name) as transport:
                                    if (hashlib.sha256(transport.getpeercert(binary_form=True)).hexdigest()!=certificate.fingerprint
                                            or transport.selected_alpn_protocol()!=protocol):
                                        raise ValueError('verify-served-certificate-and-alpn')
            return
        except (OSError,ValueError):
            if time.monotonic()>=deadline:
                raise ValueError('verify-served-certificate-and-alpn') from None
            time.sleep(.1)


def read_certificate(path, names, now, *, fresh=False, allow_expired=False):
    fullchain,key=split_serving(path.read_bytes())
    return admit_certificate(fullchain,key,names,now,fresh=fresh,allow_expired=allow_expired)


def boot_admission(spec, *, allow_pending_reload=False):
    """Read-only #103 seam consumed by the existing #219 runtime authority.

    No cryptography import or independent config/reload controller. Previously
    accepted material is fingerprint-bound and independently checked by native
    OpenSSL; interrupted renewal refuses startup until explicit LKG recovery.
    """
    import re
    import stat
    from viewer_tls_contract import admit_file, admit_activation, admit_hsts, admit_renewal_acceptance
    from haproxy_config_lifecycle import admit_publication_record
    pem=Path('/etc/haproxy/secpal-viewer.pem')
    state=Path('/srv/secpal/acme')
    journal=pem.with_name('.secpal-viewer-pending.json')
    if not any(row.transport=='https' for row in spec.listeners):
        if spec.listeners[0].tls_lifecycle=='hsts':
            raise ValueError('admit-hsts-https-listener')
        return
    def read(path,maximum):
        for item in (path,*path.parents):
            info=item.lstat()
            if info.st_uid!=0 or stat.S_ISLNK(info.st_mode) or info.st_mode & 0o022:
                raise ValueError('admit-tls-startup-authority')
        info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or not 0<info.st_size<=maximum:
            raise ValueError('admit-tls-startup-file')
        return path.read_bytes()
    data=read(pem,65536)
    read(TRUST,2*1024*1024)
    context=os.getxattr(pem,'security.selinux').decode().rstrip('\0').split(':')
    admit_file(pem.lstat(),private=True,label=context[2] if len(context)>=4 else '')
    block=re.search(rb'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',data,re.S)
    if block is None:
        raise ValueError('admit-tls-startup-certificate')
    fingerprint=hashlib.sha256(ssl.PEM_cert_to_DER_cert(block[0].decode())).hexdigest()
    expected_names=sorted((spec.routing.frontend_host,spec.routing.api_host))
    pending=admit_publication_record(json.loads(read(journal,1024))) if journal.exists() else None
    if pending is not None:
        if pending.get('previous_sha256') is not None:
            # Promotion or compensating reload is allowed only during a live,
            # serialized root-owned TLS publication. Boot never replays it.
            import fcntl
            lock=Path('/run/secpal-viewer-tls/publish.lock')
            for item in (lock,*lock.parents):
                info=item.lstat()
                if info.st_uid!=0 or stat.S_ISLNK(info.st_mode) or info.st_mode & 0o022:
                    raise ValueError('admit-tls-promotion-lock')
            descriptor=os.open(lock,os.O_RDWR|os.O_NOFOLLOW)
            try:
                info=os.fstat(descriptor)
                if (info.st_uid!=0 or info.st_gid!=0 or stat.S_IMODE(info.st_mode)!=0o600
                        or info.st_nlink!=1 or not stat.S_ISREG(info.st_mode)):
                    raise ValueError('admit-tls-promotion-lock')
                try:
                    fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
                except BlockingIOError:
                    locked=True
                else:
                    locked=False
                if (not allow_pending_reload or not locked or set(pending)!={'previous_sha256','candidate_sha256'}
                        or hashlib.sha256(data).hexdigest() not in pending.values()):
                    raise ValueError('recover-viewer-certificate-before-startup')
            finally:
                os.close(descriptor)
            from haproxy_direct_contract import from_config
            if from_config(read(Path('/etc/haproxy/secpal.cfg'),65536))!=spec:
                raise ValueError('admit-certificate-only-reload')
            if spec.listeners[0].tls_lifecycle=='hsts':
                receipt=admit_activation(json.loads(read(state/'activation.json',1024)),expected_names,int(time.time()))
                admit_renewal_acceptance(receipt)
        elif pending!={'previous_sha256':None,'candidate_sha256':hashlib.sha256(data).hexdigest()}:
            raise ValueError('admit-initial-certificate-preparation')
        if pending.get('previous_sha256') is None and spec.listeners[0].tls_lifecycle=='hsts':
            raise ValueError('admit-hsts-accepted-renewal')
    else:
        receipt=admit_activation(json.loads(read(state/'activation.json',1024)),expected_names,
                                int(time.time()),fingerprint=fingerprint)
        if spec.listeners[0].tls_lifecycle=='hsts':
            renewal=json.loads(read(state/'renewal.json',1024))
            admit_hsts(receipt,renewal,int(time.time()))
    # Native TLS parser independently checks complete chain/key compatibility.
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(pem))
    for host in expected_names:
        run('verify-startup-certificate-trust',['/usr/bin/openssl','verify','-x509_strict',
            '-purpose','sslserver','-verify_hostname',host,'-CAfile',str(TRUST),
            '-no-CApath','-no-CAstore','-untrusted',str(pem),str(pem)])
