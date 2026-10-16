#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Pure #103 certificate, HTTP-01 policy, and health admission.

#308 owns package provenance; #219 owns publication/reload; #220 owns routing
and Viewer identity. This module defines only DIRECT single TLS invariants.
"""

from dataclasses import dataclass, field
import hashlib
import json
import re

ACME_PORT = 18084
STATE = '/srv/secpal/acme'
PEM = '/etc/haproxy/secpal-viewer.pem'
MAX_PEM = 65536
FRESH_CANDIDATE_SECONDS = 14 * 86400
EXPIRY_WARNING_SECONDS = 30 * 86400
OBSERVATION_FRESHNESS_SECONDS = 86400
DIRECTORIES = {'production':'https://acme-v02.api.letsencrypt.org/directory',
               'staging':'https://acme-staging-v02.api.letsencrypt.org/directory'}


@dataclass(frozen=True)
class Certificate:
    pem: bytes = field(repr=False)
    leaf: bytes = field(repr=False)
    chain: bytes = field(repr=False)
    fingerprint: str
    not_before: int
    not_after: int
    names: tuple[str, ...]


def admit_certificate(fullchain, private_key, names, now, *, fresh=True, allow_expired=False):
    """Parse standard X.509/key representations, then admit the DIRECT contract.

    Chain signatures/trust are observed separately with native OpenSSL. The
    caller must admit #308's installed Python payload before importing it.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID
    if (type(fullchain) is not bytes or type(private_key) is not bytes
            or not 0 < len(fullchain) + len(private_key) <= MAX_PEM):
        raise ValueError('admit-certificate-size')
    blocks = re.findall(rb'-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----', fullchain)
    if not 2 <= len(blocks) <= 5 or re.sub(rb'\s', b'', b''.join(blocks)) != re.sub(rb'\s', b'', fullchain):
        raise ValueError('admit-complete-certificate-chain')
    if not re.fullmatch(rb'-----BEGIN (?:EC |RSA )?PRIVATE KEY-----\s+[A-Za-z0-9+/=\s]+-----END (?:EC |RSA )?PRIVATE KEY-----\s*', private_key):
        raise ValueError('admit-complete-private-key')
    try:
        certificates = x509.load_pem_x509_certificates(fullchain)
        key = serialization.load_pem_private_key(private_key, password=None)
        leaf = certificates[0]
        san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        usage = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        constraints = leaf.extensions.get_extension_for_class(x509.BasicConstraints).value
        key_usage = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
    except (ValueError, TypeError, x509.ExtensionNotFound) as error:
        raise ValueError('decode-certificate-material') from error
    actual_names = tuple(sorted(san.get_values_for_type(x509.DNSName)))
    if len(san) != 2 or actual_names != tuple(sorted(names)):
        raise ValueError('admit-certificate-subjects')
    if constraints.ca or list(usage) != [ExtendedKeyUsageOID.SERVER_AUTH] or not key_usage.digital_signature:
        raise ValueError('admit-server-certificate-purpose')
    if not ((isinstance(key, rsa.RSAPrivateKey) and key.key_size in (2048, 3072, 4096))
            or (isinstance(key, ec.EllipticCurvePrivateKey) and isinstance(key.curve, (ec.SECP256R1, ec.SECP384R1)))):
        raise ValueError('admit-certificate-key-strength')
    if not isinstance(leaf.signature_hash_algorithm, (hashes.SHA256, hashes.SHA384, hashes.SHA512)):
        raise ValueError('admit-certificate-signature-algorithm')
    def public(value):
        return value.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if public(key.public_key()) != public(leaf.public_key()):
        raise ValueError('admit-certificate-key-match')
    before, after = int(leaf.not_valid_before_utc.timestamp()), int(leaf.not_valid_after_utc.timestamp())
    if before > now or (after <= now and not allow_expired) or after - before > 120 * 86400:
        raise ValueError('admit-certificate-validity')
    if fresh and after - now < FRESH_CANDIDATE_SECONDS:
        raise ValueError('admit-certificate-renewal-freshness')
    canonical_chain = b''.join(cert.public_bytes(serialization.Encoding.PEM) for cert in certificates)
    canonical_key = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption())
    return Certificate(canonical_chain + canonical_key,
                       certificates[0].public_bytes(serialization.Encoding.PEM),
                       b''.join(cert.public_bytes(serialization.Encoding.PEM) for cert in certificates[1:]),
                       leaf.fingerprint(hashes.SHA256()).hex(), before, after, actual_names)


def split_serving(pem):
    # No guessing across partial/extra blocks. Admission above owns validation.
    marker = re.search(rb'-----BEGIN (?:EC |RSA )?PRIVATE KEY-----', pem)
    if marker is None:
        raise ValueError('admit-serving-private-key')
    return pem[:marker.start()], pem[marker.start():]


def admit_file(info, *, private, label, state=False):
    """Pure DAC/SELinux facts; no filesystem or process observation here."""
    import stat
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0
            or info.st_gid != 0 or stat.S_IMODE(info.st_mode) not in ((0o600,) if private else (0o600,0o644))
            or not 0 < info.st_size <= MAX_PEM):
        raise ValueError('admit-certificate-file-authority')
    if label != ('secpal_acme_state_t' if state else 'etc_t'):
        raise ValueError('admit-certificate-selinux-label')


def health(observation, now):
    """#129-compatible Security facts; no global deployment health authority."""
    if type(observation) is not dict or set(observation) != {'observed_at','not_after','served','renewal','renewal_at'}:
        raise ValueError('admit-tls-health-observation')
    if observation['served'] not in ('MATCH','MISMATCH','UNKNOWN') or observation['renewal'] not in ('SUCCESS','FAILURE','UNKNOWN'):
        raise ValueError('admit-tls-health-state')
    for key in ('observed_at','not_after','renewal_at'):
        value = observation[key]
        if value is not None and (type(value) is not int or value < 0 or (key != 'not_after' and value > now)):
            raise ValueError('admit-tls-health-time')
    expiry = observation['not_after']
    remaining = expiry - now if expiry is not None else None
    recent = observation['observed_at'] is not None and 0 <= now - observation['observed_at'] <= OBSERVATION_FRESHNESS_SECONDS
    if remaining is not None and remaining <= 0:
        state, reason = 'FAILED','certificate-expired'
    elif recent and observation['served'] == 'MISMATCH':
        state, reason = 'FAILED','served-certificate-mismatch'
    elif not recent or expiry is None or observation['served'] == 'UNKNOWN':
        state, reason = 'UNKNOWN','observation-unavailable'
    elif observation['renewal'] == 'UNKNOWN' or observation['renewal_at'] is None or now - observation['renewal_at'] > 2 * OBSERVATION_FRESHNESS_SECONDS:
        state, reason = 'UNKNOWN','renewal-observation-unavailable'
    elif observation['renewal'] == 'FAILURE':
        state, reason = 'DEGRADED','renewal-failed'
    elif remaining <= EXPIRY_WARNING_SECONDS:
        state, reason = 'DEGRADED','certificate-near-expiry'
    else:
        state, reason = 'HEALTHY','certificate-current'
    return {'schema_version':1,'producer':'direct-viewer-tls','capability':'Security',
            'state':state,'reason':reason,'observed_at':observation['observed_at'],
            'seconds_remaining':remaining,'served':observation['served'],
            'renewal':observation['renewal'],'renewal_at':observation['renewal_at'],
            'freshness_seconds':OBSERVATION_FRESHNESS_SECONDS}


def admit_activation(receipt, names, now, *, fingerprint=None):
    if (type(receipt) is not dict or set(receipt)!={'fingerprint','names','initial_at','renewed_at'}
            or receipt['names']!=sorted(names) or type(receipt['fingerprint']) is not str
            or not re.fullmatch('[0-9a-f]{64}',receipt['fingerprint'])
            or type(receipt['initial_at']) is not int or not 0<=receipt['initial_at']<=now
            or (receipt['renewed_at'] is not None and (type(receipt['renewed_at']) is not int
                or not receipt['initial_at']<=receipt['renewed_at']<=now))
            or (fingerprint is not None and receipt['fingerprint']!=fingerprint)):
        raise ValueError('admit-tls-activation-receipt')
    return receipt


def admit_renewal_acceptance(receipt):
    if receipt['renewed_at'] is None:
        raise ValueError('admit-hsts-accepted-renewal')


def admit_hsts(receipt, renewal, now):
    admit_renewal_acceptance(receipt)
    if (type(renewal) is not dict or set(renewal)!={'status','at'}
            or renewal['status']!='SUCCESS' or type(renewal['at']) is not int
            or not 0<=now-renewal['at']<=OBSERVATION_FRESHNESS_SECONDS
            or renewal['at']<receipt['renewed_at']):
        raise ValueError('admit-hsts-accepted-renewal')


def policy(uid):
    if type(uid) is not int or not 0 < uid < 1000:
        raise ValueError('admit-acme-proxy-account')
    nft = f'''table inet secpal_acme {{
  chain acme_input {{
    type filter hook input priority -22; policy accept;
    iifname != "lo" tcp dport {ACME_PORT} reject
  }}
  chain acme_output {{
    type filter hook output priority -22; policy accept;
    ip daddr 127.0.0.0/8 tcp dport {ACME_PORT} meta skuid != {{ 0, {uid} }} reject
    ip6 daddr ::1 tcp dport {ACME_PORT} reject
  }}
}}
'''
    cil = f'''(type secpal_acme_port_t)
(typeattributeset port_type (secpal_acme_port_t))
(roletype object_r secpal_acme_port_t)
(allow haproxy_t secpal_acme_port_t (tcp_socket (name_connect)))
(allow unconfined_service_t secpal_acme_port_t (tcp_socket (name_bind)))
(portcon tcp {ACME_PORT} (system_u object_r secpal_acme_port_t ((s0) (s0))))
'''
    state_cil = '''(allow init_t unconfined_service_t (process2 (nnp_transition)))
(type secpal_acme_state_t)
(typeattributeset file_type (secpal_acme_state_t))
(roletype object_r secpal_acme_state_t)
(allow init_t secpal_acme_state_t (dir (mounton)))
(filecon "/srv/secpal/acme(/.*)?" any (system_u object_r secpal_acme_state_t ((s0) (s0))))
'''
    return {'nft':nft,'cil':cil,'state_cil':state_cil}


def policy_digest(uid):
    return hashlib.sha256(json.dumps(policy(uid),sort_keys=True,separators=(',',':')).encode()).hexdigest()


def policy_projection(uid):
    policy(uid)
    table={'family':'inet','table':'secpal_acme'}
    result=[{'table':{'family':'inet','name':'secpal_acme'}}]
    for name,hook in (('acme_input','input'),('acme_output','output')):
        result.append({'chain':dict(table,name=name,type='filter',hook=hook,prio=-22,policy='accept')})
    def match(left,right,op='=='): return {'match':{'op':op,'left':left,'right':right}}
    port=match({'payload':{'protocol':'tcp','field':'dport'}},ACME_PORT)
    def rule(chain,expr): result.append({'rule':dict(table,chain=chain,expr=expr)})
    rule('acme_input',[match({'meta':{'key':'iifname'}},'lo','!='),port,{'reject':{'type':'icmpx','expr':'port-unreachable'}}])
    rule('acme_output',[match({'payload':{'protocol':'ip','field':'daddr'}},{'prefix':{'addr':'127.0.0.0','len':8}}),port,
        match({'meta':{'key':'skuid'}},{'set':[0,uid]},'!='),{'reject':{'type':'icmp','expr':'port-unreachable'}}])
    rule('acme_output',[match({'payload':{'protocol':'ip6','field':'daddr'}},'::1'),port,{'reject':{'type':'icmpv6','expr':'port-unreachable'}}])
    return result
