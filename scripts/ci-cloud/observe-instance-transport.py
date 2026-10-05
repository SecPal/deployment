#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Observe locked Google-provider TCP socket metadata around the existing apply.

No packet sockets, application buffers, process environments, argument vectors or memory, DNS lookups,
TLS hooks, provider changes, subprocess output capture, or second Compute client.
"""
from __future__ import annotations

import argparse
import copy
import ctypes
import errno
import hashlib
import ipaddress
import itertools
import json
import os
from pathlib import Path
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time

import instance_transport_contract as contract

RESPONSIBILITY = 'observation,orchestration'
MAX_PROC_BYTES = 1_048_576
MAX_PROCESSES = 128
MAX_FDS = 4096
SAMPLE_INTERVAL = 0.2

# Authority: accepted gcp-rocky lock and its readonly OpenTofu 1.12.5
# installation of registry.opentofu.org/hashicorp/google 7.40.0 linux_amd64.
# The signed, lock-admitted package installs this exact filename and content.
GOOGLE_INSTALL = Path('.terraform/providers/registry.opentofu.org/hashicorp/google/7.40.0/linux_amd64')
GOOGLE_EXECUTABLE = 'terraform-provider-google'
GOOGLE_EXECUTABLE_SHA256 = '70351ed626f69ac84315e8ed5149986eafd7628c8d4b0eda4422f82665ec41e9'
GOOGLE_LOCK_SHA256 = '76f52a817f68fcb058bf499482070b4ff39098628c497a95ff8de2b42363e94c'


def file_identity(metadata):
    return (metadata.st_dev,metadata.st_ino,metadata.st_mode,metadata.st_uid,
            metadata.st_gid,metadata.st_size,metadata.st_mtime_ns,metadata.st_ctime_ns)


class PinnedGoogleProvider:
    """Authenticate one closed installation, retaining its executable inode.

No cache/mirror symlink, executable override or alternative package layout is
authority here. Content pins originate in the accepted lock-admitted package;
they are independent of process names and any caller-selected executable.
"""
    def __init__(self,root):
        self.path = root/GOOGLE_INSTALL/GOOGLE_EXECUTABLE
        self.fd = None
        self.directories = {}
        self.files = {}
        try:
            current = root
            for component in GOOGLE_INSTALL.parts:
                current = current/component
                metadata = current.lstat()
                if not stat.S_ISDIR(metadata.st_mode) or metadata.st_mode & 0o022:
                    raise contract.TransportError('provider installation directory rejected')
                self.directories[current] = (metadata.st_dev,metadata.st_ino,metadata.st_mode,
                                             metadata.st_uid,metadata.st_gid)
            self.package_identity = file_identity(current.lstat())
            entries = list(itertools.islice((root/GOOGLE_INSTALL).iterdir(),33))
            if len(entries)>32:
                raise contract.TransportError('provider installation bound exceeded')
            executables = []
            for entry in entries:
                metadata = entry.lstat()
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o022:
                    raise contract.TransportError('provider package entry rejected')
                if metadata.st_mode & 0o111:
                    executables.append(entry)
            if executables != [self.path]:
                raise contract.TransportError('provider executable missing or ambiguous')
            lock = root/'.terraform.lock.hcl'
            metadata = lock.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o022:
                raise contract.TransportError('provider dependency lock rejected')
            self.files[lock] = file_identity(metadata)
            with os.fdopen(os.open(lock,os.O_RDONLY|os.O_NOFOLLOW),'rb') as source:
                if file_identity(os.fstat(source.fileno()))!=self.files[lock]:
                    raise contract.TransportError('provider dependency lock changed')
                if hashlib.sha256(source.read(16385)).hexdigest()!=GOOGLE_LOCK_SHA256:
                    raise contract.TransportError('provider dependency lock unverified')
            self.fd = os.open(self.path,os.O_RDONLY|os.O_NOFOLLOW)
            metadata = os.fstat(self.fd)
            if not stat.S_ISREG(metadata.st_mode) or not 0<metadata.st_size<=256*1024*1024:
                raise contract.TransportError('provider executable bounds rejected')
            self.files[self.path] = file_identity(metadata)
            with os.fdopen(os.dup(self.fd),'rb') as source:
                digest = hashlib.sha256()
                remaining = metadata.st_size
                while remaining:
                    block = source.read(min(remaining,1_048_576))
                    if not block:
                        raise contract.TransportError('provider executable truncated')
                    digest.update(block)
                    remaining -= len(block)
                if source.read(1) or digest.hexdigest()!=GOOGLE_EXECUTABLE_SHA256:
                    raise contract.TransportError('provider executable unverified')
            self.verify()
        except Exception:
            self.close()
            raise

    def verify(self):
        for path,expected in self.directories.items():
            metadata = path.lstat()
            if (metadata.st_dev,metadata.st_ino,metadata.st_mode,metadata.st_uid,metadata.st_gid)!=expected:
                raise contract.TransportError('provider installation substituted')
        for path,expected in self.files.items():
            if file_identity(path.lstat())!=expected:
                raise contract.TransportError('provider installation identity changed')
        if file_identity(self.path.parent.lstat())!=self.package_identity:
            raise contract.TransportError('provider package inventory changed')
        if file_identity(os.fstat(self.fd))!=self.files[self.path]:
            raise contract.TransportError('provider executable content changed')

    def verify_process(self,pid):
        if file_identity(os.stat(f'/proc/{pid}/exe'))!=self.files[self.path]:
            raise contract.TransportError('provider process executable substituted')

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


class Filter(ctypes.Structure):
    _fields_ = [('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),
                ('jf',ctypes.c_ubyte),('k',ctypes.c_uint)]


class Program(ctypes.Structure):
    _fields_ = [('length',ctypes.c_ushort),('filter',ctypes.POINTER(Filter))]


def set_cookie_filter(listener,cookies):
    """Classic receive BPF: admit only known inet_diag socket cookies, no payload."""
    if len(cookies)>contract.MAX_CONNECTIONS:
        raise contract.TransportError('connection bound exceeded')
    instructions = []
    for low,high in cookies:
        instructions.extend([(0x20,0,0,60),(0x15,0,3,socket.htonl(low)),
                             (0x20,0,0,64),(0x15,0,1,socket.htonl(high)),
                             (0x06,0,0,4096)])
    instructions.append((0x06,0,0,0))
    filters = (Filter*len(instructions))(*(Filter(*row) for row in instructions))
    program = Program(len(filters),filters)
    libc = ctypes.CDLL(None,use_errno=True)
    if libc.setsockopt(listener.fileno(),socket.SOL_SOCKET,26,
                       ctypes.byref(program),ctypes.sizeof(program)):
        raise OSError(ctypes.get_errno(),'cookie receive filter unavailable')


def bounded_read(path,limit=MAX_PROC_BYTES):
    with path.open('rb') as source:
        raw = source.read(limit+1)
    if len(raw)>limit:
        raise contract.TransportError('observation input bound exceeded')
    return raw


def process_ticks(pid):
    # Kernel process identity only; never retain the comm field.
    fields = bounded_read(Path(f'/proc/{pid}/stat'),8192).rsplit(b')',1)[1].split()
    return int(fields[19])


def proc_address(value):
    raw = b''.join(struct.pack('=I',int(value[index:index+8],16))
                   for index in range(0,len(value),8))
    return str(ipaddress.ip_address(raw))


def socket_rows(pid,inodes):
    """Enumerate kernel tuple metadata; query/retain only owned inode matches.

/proc/<pid>/net/tcp is a namespace table, not an ownership table. It never
establishes ownership: /proc/<pid>/fd plus start-time rechecks do that. Unrelated
rows are discarded before tuple decoding, counter querying or notification admission.
"""
    result = []
    for table,family in (('tcp',socket.AF_INET),('tcp6',socket.AF_INET6)):
        for line in bounded_read(Path(f'/proc/{pid}/net/{table}')).splitlines()[1:]:
            fields = line.split()
            if len(fields)<10 or int(fields[9]) not in inodes:
                continue
            source,sport = fields[1].decode('ascii').split(':')
            destination,dport = fields[2].decode('ascii').split(':')
            result.append({'family':family,'local_address':proc_address(source),
                           'remote_address':proc_address(destination),
                           'local_port':int(sport,16),'remote_port':int(dport,16),
                           'inode':int(fields[9])})
    return result


def owned_inodes(pid):
    entries = list(Path(f'/proc/{pid}/fd').iterdir())
    if len(entries)>MAX_FDS:
        raise contract.TransportError('descriptor bound exceeded')
    inodes = set()
    for entry in entries:
        try:
            link = os.readlink(entry)
        except FileNotFoundError:
            continue
        if link.startswith('socket:[') and link.endswith(']'):
            inodes.add(int(link[8:-1]))
    return inodes


def socket_identity(fd,pid):
    inode = int(os.readlink(f'/proc/{pid}/fd/{fd}')[8:-1])
    return next(row for row in socket_rows(pid,{inode}) if row['inode']==inode)


def exact_query(row):
    family = row['family']
    addresses = b''.join(ipaddress.ip_address(row[key]).packed.ljust(16,b'\0')
                         for key in ('local_address','remote_address'))
    sockid = struct.pack('!HH',row['local_port'],row['remote_port'])+addresses
    sockid += struct.pack('=III',0,0xffffffff,0xffffffff)
    request = struct.pack('=BBBBI',family,socket.IPPROTO_TCP,2,0,0xffffffff)+sockid
    with socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,4) as query:
        query.settimeout(1)
        query.send(struct.pack('=IHHII',16+len(request),20,1,1,0)+request)
        raw,_,flags,sender = query.recvmsg(4096)
    if sender[0]!=0 or flags & socket.MSG_TRUNC or len(raw)<16:
        raise contract.TransportError('truncated diagnostic query')
    length,kind,_,sequence,_ = struct.unpack_from('=IHHII',raw)
    if length!=len(raw) or sequence!=1:
        raise contract.TransportError('diagnostic envelope rejected')
    if kind==2:
        if len(raw)<20:
            raise contract.TransportError('short diagnostic error')
        code = -struct.unpack_from('=i',raw,16)[0]
        if code==errno.ENOENT:
            return None
        raise OSError(code,'exact socket query unavailable')
    if kind!=20:
        raise contract.TransportError('unexpected diagnostic type')
    normalized = contract.normalize_diag(raw[16:],time.monotonic_ns())
    for key in ('family','local_address','remote_address','local_port','remote_port','inode'):
        if normalized[key]!=row[key]:
            raise contract.TransportError('exact socket identity mismatch')
    return normalized | normalized['snapshot']


def provider_processes(root_pid,provider_paths,installation=None):
    """Follow children of every thread: Go may fork the provider off the main thread."""
    pending = [root_pid]
    visited = set()
    providers = []
    while pending:
        pid = pending.pop()
        if pid in visited:
            continue
        visited.add(pid)
        if len(visited)>MAX_PROCESSES:
            raise contract.TransportError('process bound exceeded')
        try:
            ticks = process_ticks(pid)
            if Path(os.readlink(f'/proc/{pid}/exe')) in provider_paths:
                if installation is not None:
                    installation.verify_process(pid)
                providers.append((pid,ticks))
            tasks = list(Path(f'/proc/{pid}/task').iterdir())
            if len(tasks)>1024:
                raise contract.TransportError('thread bound exceeded')
            children = set()
            for task in tasks:
                try:
                    children.update(int(child) for child in bounded_read(task/'children',16384).split())
                except FileNotFoundError:
                    continue
            if process_ticks(pid)==ticks:
                pending.extend(children)
        except (FileNotFoundError,ProcessLookupError):
            continue
    return providers


class Observer:
    def __init__(self,root_pid,provider_paths,ports=(443,)):
        self.root_pid = root_pid
        self.root_ticks = process_ticks(root_pid)
        self.provider_paths = provider_paths
        self.installation = None
        self.ports = ports
        self.connections = {}
        self.cookies = {}
        self.status = 'COMPLETE'
        self.operation = 'VERIFY_PROCESS_IDENTITY'
        self.start = time.monotonic_ns()
        self.end = self.start
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.listener = None
        self.thread = None

    def prepare(self):
        self.operation = 'OPEN_DIAGNOSTIC_SOCKET'
        self.listener = socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,4)
        self.operation = 'BOUND_DIAGNOSTIC_BUFFER'
        self.listener.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,65536)
        self.operation = 'ADMIT_NOTIFICATION_SCOPE'
        set_cookie_filter(self.listener,[])
        self.operation = 'SUBSCRIBE_SOCKET_DESTRUCTION'
        self.listener.bind((0,1|4))  # IPv4 and IPv6 TCP destruction groups.
        self.listener.setblocking(False)

    def sample(self):
        self.operation = 'VERIFY_PROCESS_IDENTITY'
        if self.installation is not None:
            self.installation.verify()
        if process_ticks(self.root_pid)!=self.root_ticks:
            raise contract.TransportError('root process identity changed')
        self.operation = 'CORRELATE_PROVIDER_PROCESS'
        for pid,ticks in provider_processes(self.root_pid,self.provider_paths,self.installation):
            try:
                self.operation = 'VERIFY_NETWORK_NAMESPACE'
                if os.readlink(f'/proc/{pid}/ns/net')!=os.readlink('/proc/self/ns/net'):
                    raise contract.TransportError('provider network namespace differs')
                self.operation = 'CORRELATE_PROVIDER_SOCKET'
                inodes = owned_inodes(pid)
                for row in socket_rows(pid,inodes):
                    if row['remote_port'] not in self.ports:
                        continue
                    self.operation = 'QUERY_TCP_COUNTERS'
                    raw = exact_query(row)
                    if raw is None or process_ticks(pid)!=ticks or row['inode'] not in owned_inodes(pid):
                        continue
                    cookie = raw['socket_cookie']
                    with self.lock:
                        if cookie not in self.connections:
                            if len(self.connections)>=contract.MAX_CONNECTIONS:
                                raise contract.TransportError('connection bound exceeded')
                            self.connections[cookie] = contract.new_connection(raw,pid,ticks,len(self.connections)+1)
                            self.cookies[cookie] = raw['cookie_words']
                            self.operation = 'ADMIT_NOTIFICATION_SCOPE'
                            set_cookie_filter(self.listener,list(self.cookies.values()))
                        else:
                            self.operation = 'FOLD_COUNTER_OBSERVATIONS'
                            contract.add_sample(self.connections[cookie],raw['snapshot'],'LIVE_SOCKET')
            except (FileNotFoundError,ProcessLookupError):
                continue

    def drain(self):
        for _ in range(contract.MAX_CONNECTIONS*2):
            try:
                self.operation = 'RECEIVE_FINAL_COUNTERS'
                raw,_,flags,sender = self.listener.recvmsg(4096)
            except BlockingIOError:
                return
            if sender[0]!=0 or flags & socket.MSG_TRUNC or len(raw)<16:
                raise contract.TransportError('truncated destruction observation')
            length,kind,_,_,_ = struct.unpack_from('=IHHII',raw)
            if length!=len(raw) or kind!=20:
                raise contract.TransportError('destruction envelope rejected')
            self.operation = 'NORMALIZE_SOCKET_METADATA'
            normalized = contract.normalize_diag(raw[16:],time.monotonic_ns())
            cookie = normalized['socket_cookie']
            with self.lock:
                if cookie not in self.connections:
                    raise contract.TransportError('uncorrelated destruction event')
                connection = self.connections[cookie]
                if any(normalized[key]!=connection[key] for key in ('local_address','remote_address','local_port','remote_port')):
                    raise contract.TransportError('destruction endpoint mismatch')
                self.operation = 'FOLD_COUNTER_OBSERVATIONS'
                contract.add_sample(connection,normalized['snapshot'],'DESTROY_NOTIFICATION')
        raise contract.TransportError('notification bound exceeded')

    def run(self):
        try:
            while not self.stop_event.is_set():
                if time.monotonic_ns()-self.start>contract.MAX_WINDOW_NS-2_000_000_000:
                    self.status = 'LIMIT_EXCEEDED'
                    return
                self.sample()
                self.drain()
                self.stop_event.wait(SAMPLE_INTERVAL)
            # Producer exit closes sockets; finish while runner-local metadata exists.
            self.drain()
        except Exception:
            self.status = 'FAILED_RUNTIME'
        finally:
            self.end = time.monotonic_ns()

    def start_thread(self):
        self.thread = threading.Thread(target=self.run,daemon=True)
        self.thread.start()

    def finish(self):
        self.stop_event.set()
        if self.thread is not None:
            self.thread.join(2)
            if self.thread.is_alive():
                self.status = 'FAILED_SHUTDOWN'
                self.operation = 'FINALIZE_OBSERVATION'
        if self.listener is not None:
            self.listener.close()
        if self.installation is not None:
            self.installation.close()
        with self.lock:
            connections = copy.deepcopy(list(self.connections.values()))
        for connection in connections:
            if connection['final_snapshot_kind']!='DESTROY_NOTIFICATION':
                connection['final_snapshot_kind']='NO_DESTROY_NOTIFICATION_OBSERVED'
        end = self.end if self.thread is not None and not self.thread.is_alive() else time.monotonic_ns()
        if self.status=='COMPLETE' and not connections:
            self.status='UNAVAILABLE'
            self.operation='CORRELATE_PROVIDER_SOCKET'
        return end,connections


def launch_apply():
    # Identical argv; cwd, environment and all standard streams are inherited.
    # No timeout, retry, output pipe, altered TLS/DNS/HTTP settings or provider patch.
    return subprocess.Popen(['tofu','apply','--auto-approve','--input=false'])


def persist(path,document,identity):
    contract.admit(document,identity)
    raw = json.dumps(document,separators=(',',':')).encode()+b'\n'
    if len(raw)>contract.MAX_DOCUMENT_BYTES:
        raise contract.TransportError('serialized evidence bound exceeded')
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent,prefix='.transport-',delete=False) as output:
            temporary = Path(output.name)
            output.write(raw)
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def observe_apply(identity,output):
    # Metadata and credentials remain consumed solely by the unchanged producer.
    root = Path.cwd()
    collector = Observer(os.getpid(),set())
    code = None
    try:
        collector.installation = PinnedGoogleProvider(root)
        collector.provider_paths = {collector.installation.path}
        collector.prepare()
        collector.start_thread()
    except (OSError,ValueError):
        collector.status = 'FAILED_STARTUP'
    if collector.status=='COMPLETE':
        try:
            code = launch_apply().wait()
        except OSError:
            collector.status = 'FAILED_RUNTIME'
    end,connections = collector.finish()
    document = contract.assemble(identity,collector.start,end,collector.status,
                                 'NOT_RUN' if code is None else 'SUCCESS' if code==0 else 'OTHER',
                                 code,connections,'NONE' if collector.status=='COMPLETE' else collector.operation)
    persist(output,document,identity)
    # Collector failure cannot interrupt apply or conceal provider failure. It
    # fails this job through its existing failure/independent-cleanup paths.
    return code if code not in (None,0) else 0 if collector.status=='COMPLETE' else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--admit',action='store_true')
    parser.add_argument('command',nargs=argparse.REMAINDER)
    parser.add_argument('--output',type=Path,required=True)
    for name in contract.IDENTITY_FIELDS:
        parser.add_argument('--'+name.replace('_','-'),required=True)
    args = parser.parse_args()
    if args.command[:1]==['--']:
        args.command=args.command[1:]
    identity = {key:getattr(args,key) for key in contract.IDENTITY_FIELDS}
    if not args.admit and args.command!=['tofu','apply','--auto-approve','--input=false']:
        parser.error('only the existing closed apply command is supported')
    if args.admit and args.command:
        parser.error('admission cannot execute a producer')
    try:
        # Admit identities before producer/observation startup, without system I/O.
        contract.admit(contract.assemble(identity,0,0,'FAILED_STARTUP','NOT_RUN',None,[]),identity)
        if args.admit:
            contract.admit(contract.decode_document(bounded_read(args.output,contract.MAX_DOCUMENT_BYTES)),identity)
            return 0
        return observe_apply(identity,args.output)
    except (OSError,ValueError,struct.error):
        print('INSTANCE_INSERT_TRANSPORT_EVIDENCE: unavailable or rejected',file=sys.stderr)
        return 1


if __name__=='__main__':
    raise SystemExit(main())
