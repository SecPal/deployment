#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Ephemeral private CA and bounded RFC8555 peer; no public ACME evidence."""

import base64
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import ssl
import threading
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID


def decode(value): return base64.urlsafe_b64decode(value+'='*(-len(value)%4))
def encode(value): return base64.urlsafe_b64encode(value).rstrip(b'=').decode()


class Authority:
    def __init__(self,directory):
        self.directory=Path(directory)
        self.key=ec.generate_private_key(ec.SECP256R1())
        subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Disposable local fixture CA')])
        now=datetime.now(timezone.utc)
        self.certificate=(x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(self.key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
            .add_extension(x509.KeyUsage(False,False,False,False,False,True,True,False,False),critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(self.key.public_key()),critical=False)
            .sign(self.key,hashes.SHA256()))
        self.path=self.directory/'ca.pem'
        self.path.write_bytes(self.certificate.public_bytes(serialization.Encoding.PEM))
    def issue(self,key,names,*,days=90,expired=False,purpose=True):
        now=datetime.now(timezone.utc)
        before=now-timedelta(days=100) if expired else now-timedelta(minutes=1)
        after=now-timedelta(days=1) if expired else now+timedelta(days=days)
        subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,names[0])])
        return (x509.CertificateBuilder().subject_name(subject).issuer_name(self.certificate.subject)
            .public_key(key).serial_number(x509.random_serial_number()).not_valid_before(before).not_valid_after(after)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(name) for name in names]),critical=False)
            .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
            .add_extension(x509.KeyUsage(True,False,False,False,False,False,False,False,False),critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if purpose else ExtendedKeyUsageOID.CLIENT_AUTH]),critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()),critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key),critical=False)
            .sign(self.key,hashes.SHA256()).public_bytes(serialization.Encoding.PEM)+self.path.read_bytes())
    def material(self,names,**kwargs):
        key=ec.generate_private_key(ec.SECP256R1())
        private=key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
        return self.issue(key.public_key(),names,**kwargs),private


class AcmeFixture(ThreadingHTTPServer):
    daemon_threads=True
    def __init__(self,authority,challenge_port,names,*,challenge_port6=None):
        self.authority,self.challenge_port,self.names=authority,challenge_port,names
        self.challenge_port6=challenge_port6
        self.challenge_families=set()
        self.orders={}
        self.account=None
        self.requests=[]
        self.nonces=set()
        self.failure=None
        super().__init__(('127.0.0.1',0),Handler)
        self.base=f'https://127.0.0.1:{self.server_port}'
        chain,key=authority.material(('127.0.0.1','fixture.example.test'))
        path=authority.directory/'fixture-server.pem'
        path.write_bytes(chain+key)
        path.chmod(0o600)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(path))
        self.socket=context.wrap_socket(self.socket,server_side=True)
        self.thread=threading.Thread(target=self.serve_forever,daemon=True)
        self.thread.start()
    def stop(self):
        self.shutdown(); self.server_close(); self.thread.join(3)
    def public_key(self,jwk):
        if jwk['kty']=='RSA':
            return rsa.RSAPublicNumbers(int.from_bytes(decode(jwk['e']),'big'),int.from_bytes(decode(jwk['n']),'big')).public_key()
        return ec.EllipticCurvePublicNumbers(int.from_bytes(decode(jwk['x']),'big'),int.from_bytes(decode(jwk['y']),'big'),ec.SECP256R1()).public_key()
    def authorization(self,order,index):
        item=order['challenges'][index]
        return {'identifier':{'type':'dns','value':self.names[index]},'status':item['status'],
                'challenges':[{'type':'http-01','url':self.base+item['path'],'status':item['status'],'token':item['token']}],
                'expires':(datetime.now(timezone.utc)+timedelta(days=1)).isoformat()}
    def order(self,identifier):
        order=self.orders[identifier]
        return {'status':order['status'],'identifiers':[{'type':'dns','value':n} for n in self.names],
                'authorizations':[self.base+f'/auth/{identifier}/{i}' for i in range(2)],
                'finalize':self.base+f'/finalize/{identifier}',
                **({'certificate':self.base+f'/certificate/{identifier}'} if order['status']=='valid' else {})}


class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def respond(self,value=None,status=200,*,location=None,pem=False):
        body=value if pem else json.dumps(value or {}).encode()
        self.send_response(status)
        nonce=secrets.token_urlsafe(24); self.server.nonces.add(nonce)
        self.send_header('Replay-Nonce',nonce)
        self.send_header('Content-Type','application/pem-certificate-chain' if pem else 'application/json')
        self.send_header('Content-Length',str(len(body)))
        if location: self.send_header('Location',location)
        if self.path.startswith('/challenge/'):
            self.send_header('Link','<'+self.server.base+self.path.replace('/challenge/','/auth/',1)+'>;rel="up"')
        self.end_headers()
        if self.command!='HEAD': self.wfile.write(body)
    def do_HEAD(self): self.respond()
    def do_GET(self):
        if self.path=='/directory':
            self.respond({name:self.server.base+path for name,path in [('newNonce','/nonce'),('newAccount','/account'),('newOrder','/new-order'),('revokeCert','/revoke'),('keyChange','/key-change')]})
        else: self.respond(status=404)
    def do_POST(self):
        server=self.server
        try:
            size=int(self.headers['Content-Length'])
            assert 0<size<=32768
            jws=json.loads(self.rfile.read(size)); protected=json.loads(decode(jws['protected']))
            assert protected['url']==server.base+self.path and protected['nonce'] in server.nonces
            server.nonces.remove(protected['nonce'])
            jwk=protected.get('jwk',server.account)
            assert jwk is not None
            public=server.public_key(jwk)
            message=(jws['protected']+'.'+jws['payload']).encode()
            signature=decode(jws['signature'])
            if protected['alg']=='RS256': public.verify(signature,message,padding.PKCS1v15(),hashes.SHA256())
            else:
                from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
                assert protected['alg']=='ES256' and len(signature)==64
                public.verify(encode_dss_signature(int.from_bytes(signature[:32],'big'),int.from_bytes(signature[32:],'big')),message,ec.ECDSA(hashes.SHA256()))
            payload=json.loads(decode(jws['payload'])) if jws['payload'] else {}
            server.requests.append(self.path)
            if self.path=='/account':
                server.account=jwk
                self.respond({'status':'valid','orders':server.base+'/orders'},201,location=server.base+'/account/1')
            elif self.path=='/new-order':
                assert sorted(x['value'] for x in payload['identifiers'])==sorted(server.names)
                identifier=str(len(server.orders)+1)
                server.orders[identifier]={'status':'pending','challenges':[{'token':secrets.token_urlsafe(32),'path':f'/challenge/{identifier}/{i}','status':'pending'} for i in range(2)]}
                self.respond(server.order(identifier),201,location=server.base+'/order/'+identifier)
            elif self.path.startswith('/auth/'):
                _,_,identifier,index=self.path.split('/')
                self.respond(server.authorization(server.orders[identifier],int(index)))
            elif self.path.startswith('/challenge/'):
                _,_,identifier,index=self.path.split('/')
                order=server.orders[identifier]; item=order['challenges'][int(index)]
                digest=hashes.Hash(hashes.SHA256()); digest.update(json.dumps(jwk,sort_keys=True,separators=(',',':')).encode()); thumbprint=encode(digest.finalize())
                ipv6=int(index)==1 and server.challenge_port6 is not None
                destination=f'[::1]:{server.challenge_port6}' if ipv6 else f'127.0.0.1:{server.challenge_port}'
                request=urllib.request.Request(f'http://{destination}/.well-known/acme-challenge/'+item['token'],headers={'Host':server.names[int(index)]})
                opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
                with opener.open(request,timeout=5) as response:
                    assert response.read(4096).decode()==item['token']+'.'+thumbprint
                server.challenge_families.add('IPv6' if ipv6 else 'IPv4')
                item['status']='valid'
                if all(x['status']=='valid' for x in order['challenges']): order['status']='ready'
                self.respond(server.authorization(order,int(index))['challenges'][0])
            elif self.path.startswith('/finalize/'):
                identifier=self.path.rsplit('/',1)[1]; order=server.orders[identifier]
                assert order['status']=='ready'
                csr=x509.load_der_x509_csr(decode(payload['csr']))
                assert csr.is_signature_valid and sorted(csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName))==sorted(server.names)
                order['certificate']=server.authority.issue(csr.public_key(),server.names)
                order['status']='valid'
                self.respond(server.order(identifier),location=server.base+'/order/'+identifier)
            elif self.path.startswith('/order/'):
                self.respond(server.order(self.path.rsplit('/',1)[1]))
            elif self.path.startswith('/certificate/'):
                self.respond(server.orders[self.path.rsplit('/',1)[1]]['certificate'],pem=True)
            else: self.respond(status=404)
        except Exception as error:
            server.failure=(self.path.split('/')[1],type(error).__name__)
            # Never expose JWS, account state, CSR, or private test material.
            self.respond({'type':'urn:ietf:params:acme:error:malformed','detail':'fixture protocol rejected'},400)
