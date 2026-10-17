#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Real nft/socket acceptance in anonymous disposable network namespaces only."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("firewall_controller", ROOT / "scripts/host-firewall.py")
controller = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controller)
contract = controller.contract
fixture_spec = importlib.util.spec_from_file_location("firewall_admission_fixture", ROOT / "tests/host-firewall-contract.py")
fixture = importlib.util.module_from_spec(fixture_spec)
fixture_spec.loader.exec_module(fixture)

PEER = r"""
import ctypes,json,signal,socket,sys,threading
ctypes.CDLL(None).prctl(1,signal.SIGTERM,0,0,0)
held={}
print("ready",flush=True)
for line in sys.stdin:
    request=json.loads(line)
    try:
        action=request["action"]
        if action in ("probe","open"):
            family=socket.AF_INET6 if ":" in request["source"] else socket.AF_INET
            stream=socket.socket(family,socket.SOCK_STREAM)
            stream.settimeout(.3)
            stream.bind((request["source"],0))
            stream.connect((request["target"],request["port"]))
            stream.sendall(b"X-Forwarded-For: 198.51.100.2\r\n")
            ok=stream.recv(16)==b"ok"
            if action=="open":held["session"]=stream
            else:stream.close()
        else:
            stream=held["session"]
            stream.sendall(b"another request")
            ok=stream.recv(16)==b"ok"
    except OSError:
        ok=False
    print(json.dumps(ok),flush=True)
"""


def command(arguments):
    return subprocess.run(arguments, check=True, capture_output=True, text=True, timeout=10)


class KernelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.peer = subprocess.Popen(["unshare", "--net", sys.executable, "-u", "-c", PEER],
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True)
        if cls.peer.stdout.readline().strip() != "ready":
            diagnostic=cls.peer.stderr.read(4096)
            code=cls.peer.wait(timeout=5)
            if "unshare failed" in diagnostic or "Operation not permitted" in diagnostic:
                reason="peer-network-namespace-denied"
            elif "Permission denied" in diagnostic:
                reason="peer-interpreter-execution-denied"
            else:
                reason="peer-process-startup-failed"
            raise RuntimeError(reason + "; exit=" + str(code))
        command(["/usr/sbin/ip", "link", "set", "lo", "up"])
        command(["/usr/sbin/ip", "link", "add", "fw104", "type", "veth", "peer", "name", "peer104"])
        command(["/usr/sbin/ip", "link", "set", "peer104", "netns", str(cls.peer.pid)])
        cls.enter = ["nsenter", "--net=/proc/" + str(cls.peer.pid) + "/ns/net", "--"]
        for arguments in [
            ["addr", "add", "198.51.100.1/24", "dev", "fw104"],
            ["-6", "addr", "add", "2001:db8::1/64", "dev", "fw104", "nodad"],
            ["-6", "addr", "add", "fe80::1/64", "dev", "fw104", "nodad"],
            ["link", "set", "fw104", "up"],
        ]:
            command(["/usr/sbin/ip", *arguments])
        for arguments in [
            ["link", "set", "lo", "up"], ["link", "set", "peer104", "up"],
            *[["addr", "add", "198.51.100." + str(n) + "/24", "dev", "peer104"] for n in (2,4,5)],
            *[["-6", "addr", "add", "2001:db8::" + str(n) + "/64", "dev", "peer104", "nodad"] for n in (2,4,5)],
            ["-6","addr","add","fe80::2/64","dev","peer104","nodad"],
        ]:
            command([*cls.enter, "/usr/sbin/ip", *arguments])
        cls.listeners = []
        def serve(listener):
            while True:
                try:
                    stream, _ = listener.accept()
                except OSError:
                    return
                def respond(stream):
                    with stream:
                        try:
                            while stream.recv(4096):
                                stream.sendall(b"ok")
                        except OSError:
                            pass
                threading.Thread(target=respond, args=(stream,), daemon=True).start()
        for family, address in [(socket.AF_INET,"0.0.0.0"), (socket.AF_INET6,"::")]:
            for port in (22,80,443,5432,8080,18080,18081,18082,18083,18084,8443):
                listener=socket.socket(family, socket.SOCK_STREAM)
                listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
                if family==socket.AF_INET6:
                    listener.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
                listener.bind((address,port))
                listener.listen()
                cls.listeners.append(listener)
                threading.Thread(target=serve,args=(listener,),daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.peer.terminate()
        cls.peer.communicate(timeout=5)
        for listener in cls.listeners:
            listener.close()

    def setUp(self):
        # Only this test's fixed table, inside this already isolated namespace.
        controller.Nft().run("reset-owned-test-table", ["destroy", "table", "inet", contract.TABLE])
        self.temp = tempfile.TemporaryDirectory(prefix="firewall104-", dir=ROOT / ".context")
        self.addCleanup(self.temp.cleanup)
        self.admin = controller.Controller(Path(self.temp.name) / "state")
        self.direct = fixture.config()
        self.protected = fixture.config("PROTECTED")
        self.prefixes = fixture.prefixes()

    def probe(self, source, port, expected, *, action="probe"):
        target="2001:db8::1" if ":" in source else "198.51.100.1"
        request=dict(action=action,source=source,target=target,port=port)
        self.peer.stdin.write(json.dumps(request)+"\n")
        self.peer.stdin.flush()
        result=json.loads(self.peer.stdout.readline())
        self.assertEqual(result,expected,(source,port,action))

    def test_direct_dual_stack_private_denial_and_specialized_composition(self):
        self.probe("198.51.100.5",8080,True)
        self.probe("2001:db8::5",8080,True)
        self.admin.apply(self.direct)
        for source in ("198.51.100.2","198.51.100.5","2001:db8::2","2001:db8::5"):
            for port in (80,443):
                self.probe(source,port,True)
            for port in (22,5432,8080,18080,18081,18082,18083,18084,8443):
                self.probe(source,port,False)
        for source in ("198.51.100.4","2001:db8::4"):
            self.probe(source,22,True)
            self.probe(source,5432,False)
        # An earlier specialized reject remains authoritative despite baseline accept.
        raw='table inet specialization104 { chain guard { type filter hook input priority -21; tcp dport 443 reject; }; }\n'
        subprocess.run(["/usr/sbin/nft","-f","-"],input=raw,text=True,check=True,capture_output=True)
        self.probe("198.51.100.5",443,False)
        original=command(["/usr/sbin/nft","--json","list","table","inet","specialization104"]).stdout
        self.admin.apply(self.protected,self.prefixes)
        self.admin.apply(self.direct)
        self.assertEqual(command(["/usr/sbin/nft","--json","list","table","inet","specialization104"]).stdout,original)
        command(["/usr/sbin/nft","delete","table","inet","specialization104"])
        self.admin.check()

    def test_protected_mode_switch_drops_existing_unauthorized_connection(self):
        self.admin.apply(self.direct)
        self.probe("198.51.100.5",443,True,action="open")
        self.admin.apply(self.protected,self.prefixes)
        old=dict(self.prefixes,source_sync_token="1792108800",source_create_date="2026-10-16-00-00-00")
        old["candidate_sha256"]=contract.prefixes.candidate_digest(old)
        with self.assertRaises(contract.prefixes.ContractError):
            self.admin.apply(self.protected,old)
        self.admin.apply(self.direct)
        # Retained history must not grant a DIRECT remediation exemption.
        self.admin.remediate("198.51.100.2",ttl=60)
        self.admin.remediate("198.51.100.2",remove=True)
        with self.assertRaises(contract.prefixes.ContractError):
            self.admin.apply(self.protected,old)
        self.admin.apply(self.protected,self.prefixes)
        self.admin.check()
        self.probe("198.51.100.5",443,False,action="exchange")
        for source in ("198.51.100.2","2001:db8::2"):
            self.probe(source,443,True)
            self.probe(source,80,False)
            self.probe(source,5432,False)
        for source in ("198.51.100.5","2001:db8::5"):
            # The probe supplies spoofed trusted XFF: it cannot create peer authority.
            self.probe(source,443,False)
            self.probe(source,80,False)
        for source in ("198.51.100.4","2001:db8::4"):
            self.probe(source,22,True)
            self.probe(source,443,False)
        command(["/usr/sbin/ip","-6","neigh","flush","dev","fw104"])
        self.probe("2001:db8::2",443,True)

    def test_rejected_interrupted_and_lost_ack_updates_keep_safe_policy(self):
        self.admin.apply(self.direct)
        original=self.admin.native.snapshot()
        for bad in [self.direct | {"edge_mode":"BOTH"},
                    self.direct | {"management_ipv4":[]},
                    self.direct | {"dhcp_interfaces":["unused104"]}]:
            with self.assertRaises(ValueError):
                self.admin.apply(bad)
        with patch.object(self.admin.native,"validate",side_effect=ValueError("synthetic check failure")):
            with self.assertRaises(ValueError):
                self.admin.apply(self.protected,self.prefixes)
        self.assertEqual(self.admin.native.snapshot(),original)
        self.probe("198.51.100.4",22,True)
        save=self.admin._save
        with patch.object(self.admin,"_save",side_effect=OSError("synthetic power loss after kernel commit")):
            with self.assertRaises(OSError):
                self.admin.apply(self.protected,self.prefixes)
        self.probe("198.51.100.5",443,False)
        self.admin.apply(self.protected,self.prefixes)  # Exact read-back; no blind mutation.
        self.admin.restore()
        self.admin.check()
        # A native atomic batch error must not partially flush the prior chain.
        invalid=contract.batch(self.direct)
        invalid["nftables"].append({"add":{"rule":{"family":"inet","table":contract.TABLE,
            "chain":"missing104","expr":[{"accept":None}]}}})
        with self.assertRaises(ValueError):
            self.admin.native.commit(invalid)
        self.admin.check()
        self.probe("198.51.100.5",443,False)
        commit=self.admin.native.commit
        def lost_ack(document):
            commit(document)
            raise ValueError("synthetic lost acknowledgement")
        with patch.object(self.admin.native,"commit",side_effect=lost_ack):
            self.admin.apply(self.direct)
        self.admin.check()
        self.probe("198.51.100.5",443,True)
        # Fresh-kernel boot with existing accepted configuration.
        command(["/usr/sbin/nft","delete","table","inet",contract.TABLE])
        with patch.object(self.admin.native,"commit",side_effect=controller.NftFailure("not committed")):
            with self.assertRaises(controller.NftFailure):
                self.admin.restore()
        self.assertIsNone(self.admin.native.snapshot())
        with patch.object(self.admin.native,"commit",side_effect=lost_ack):
            self.admin.restore()
        self.admin.check()

    def test_bounded_remediation_expiry_reload_and_capability_separation(self):
        self.admin.apply(self.direct)
        with patch.object(self.admin.native,"commit",side_effect=controller.NftFailure("not committed")):
            with self.assertRaises(controller.NftFailure):
                self.admin.remediate("198.51.100.5",ttl=60)
        self.probe("198.51.100.5",443,True)
        commit=self.admin.native.commit
        def lost_ack(document):
            commit(document)
            raise controller.NftFailure("synthetic lost remediation acknowledgement")
        with patch.object(self.admin.native,"commit",side_effect=lost_ack):
            self.admin.remediate("198.51.100.5",ttl=60)
            self.admin.remediate("198.51.100.5",remove=True)
        for source in ("198.51.100.5","2001:db8::5"):
            self.admin.remediate(source,ttl=60)
            self.probe(source,443,False)
        self.admin.apply(self.direct)  # Decision sets survive reload and restart.
        self.admin.restore()
        self.probe("198.51.100.5",443,False)
        self.probe("2001:db8::5",443,False)
        for source in ("198.51.100.5","2001:db8::5"):
            self.admin.remediate(source,remove=True)
            # A denied probe may leave a pending neighbor retry. Force fresh
            # resolution in this isolated peer instead of assuming its timer.
            if ":" in source:
                command([*self.enter,"/usr/sbin/ip","-6","neigh","flush","dev","peer104"])
                command(["/usr/sbin/ip","-6","neigh","flush","dev","fw104"])
            self.probe(source,443,True)
        self.admin.remediate("198.51.100.5",ttl=1)
        self.probe("198.51.100.5",443,False)
        time.sleep(1.1)
        self.probe("198.51.100.5",443,True)
        result=subprocess.run(["setpriv","--bounding-set=-all","--no-new-privs",
                               "/usr/sbin/nft","delete","table","inet",contract.TABLE],
                               capture_output=True)
        self.assertNotEqual(result.returncode,0)
        self.admin.check()

    def test_dhcp_client_responses_are_bounded_to_reviewed_uplinks(self):
        # Valid DHCP replies on an unreviewed uplink still receive no admission.
        self.admin.apply(self.direct | {"dhcp_interfaces":["unused104"]})
        for admitted in (False, True):
            if admitted:
                self.admin.apply(self.protected | {"dhcp_interfaces":["fw104","unused104"]},self.prefixes)
            self._dhcp_replies(admitted)

    def _dhcp_replies(self, admitted):
        for family,source,target,sport,dport,expected in [
            (socket.AF_INET,"198.51.100.2","198.51.100.1",67,68,True),
            (socket.AF_INET6,"fe80::2","fe80::1",547,546,True),
            (socket.AF_INET,"198.51.100.2","198.51.100.1",6667,68,False),
            (socket.AF_INET6,"2001:db8::2","2001:db8::1",547,546,False),
        ]:
            with self.subTest(source=source,sport=sport,dport=dport):
                listener=socket.socket(family,socket.SOCK_DGRAM)
                listener.settimeout(.4)
                listener.bind(("" if family==socket.AF_INET else "::",dport))
                code=(
                    "import socket;"
                    f"s=socket.socket({int(family)},socket.SOCK_DGRAM);"
                    "i=socket.if_nametoindex('peer104');"
                    f"s.bind(({source!r},{sport})" +
                    ("+(0,i)" if family==socket.AF_INET6 and source.startswith("fe80:") else "") + ");"
                    f"s.sendto(b'dhcp-client-probe',({target!r},{dport})" +
                    ("+(0,i)" if family==socket.AF_INET6 and target.startswith("fe80:") else "") + ")"
                )
                try:
                    command([*self.enter,sys.executable,"-c",code])
                    try:
                        received=listener.recv(64)==b"dhcp-client-probe"
                    except TimeoutError:
                        received=False
                    self.assertEqual(received,expected and admitted)
                finally:
                    listener.close()


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--parent-network")
    args=parser.parse_args()
    (ROOT / ".context").mkdir(exist_ok=True)
    if args.parent_network is None:
        result=subprocess.run(["unshare","--user","--map-auto","--map-root-user","--net",
            sys.executable,str(Path(__file__).resolve()),
            "--parent-network",os.readlink("/proc/self/ns/net")],timeout=120)
        raise SystemExit(result.returncode)
    if os.geteuid()!=0 or os.readlink("/proc/self/ns/net")==args.parent_network:
        raise RuntimeError("refusing non-isolated network namespace")
    capabilities=int(next(line.split()[1] for line in
        Path("/proc/self/status").read_text().splitlines() if line.startswith("CapEff:")),16)
    print("Native:",command(["/usr/sbin/nft","--version"]).stdout.strip(),
          "kernel:",os.uname().release,
          "CAP_NET_ADMIN:",bool(capabilities & (1 << 12)),
          "CAP_SYS_ADMIN:",bool(capabilities & (1 << 21)),flush=True)
    unittest.main(argv=[sys.argv[0]],verbosity=2)


if __name__=="__main__":
    main()
