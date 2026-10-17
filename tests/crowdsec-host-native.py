#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Actual pinned CrowdSec/LAPI + #104 in one disposable network namespace.

This is native process/ABI evidence, not a systemd/SELinux host installation.
Event files are explicit acquisition replay fixtures, never real sshd evidence.
"""
import argparse
from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
import yaml

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import crowdsec_host_runtime as runtime
spec=importlib.util.spec_from_file_location("accepted_firewall",ROOT/"scripts/host-firewall.py")
firewall=importlib.util.module_from_spec(spec)
spec.loader.exec_module(firewall)


class Native(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.arch=platform.machine()
        cls.package=ROOT/".context/crowdsec-supply"/("payload-"+cls.arch)
        cls.source=ROOT/"config/production/crowdsec"
        cls.temporary=tempfile.TemporaryDirectory(prefix="secpal105-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root=Path(cls.temporary.name)
        cls.config=cls.root/"config"
        shutil.copytree(cls.source,cls.config)
        (cls.config/"patterns").symlink_to(cls.package/"etc/crowdsec/patterns",target_is_directory=True)
        runtime.verify_inputs(cls.config,cls.package)
        for path in ("state/data","run","home","config/notifications","config/plugins"):
            (cls.root/path).mkdir(parents=True,exist_ok=True)
        cls.credentials=cls.root/"local-api.yaml"
        config=yaml.safe_load((cls.config/"secpal.yaml").read_text())
        substitutions={"/usr/share/secpal/crowdsec":str(cls.config),
            "/srv/secpal/crowdsec":str(cls.root/"state"),
            "/run/secpal-crowdsec":str(cls.root/"run"),
            "/run/credentials/crowdsec.service/local-api":str(cls.credentials)}
        def paths(value):
            if isinstance(value,dict):return {k:paths(v) for k,v in value.items()}
            if isinstance(value,list):return [paths(v) for v in value]
            if isinstance(value,str):
                for old,new in substitutions.items():value=value.replace(old,new)
            return value
        cls.config_file=cls.root/"runtime.yaml"
        cls.config_file.write_text(yaml.safe_dump(paths(config)))
        cls.ssh=cls.root/"ssh.log";cls.ssh.touch()
        cls.edge=cls.root/"edge.log";cls.edge.touch()
        # Only the acquisition transport is replaced for replay. The reviewed
        # native parsers/scenarios/profiles remain identical.
        acquisition={"source":"file","filenames":[str(cls.ssh),str(cls.edge)],
            "labels":{"type":"syslog","secpal_source":"host-security-v1"}}
        (cls.config/"acquis.json").write_text(json.dumps(acquisition))
        cls.env={"PATH":"/usr/bin:/usr/sbin","LANG":"C","LC_ALL":"C","HOME":str(cls.root/"home")}
        cls.run_native("register-native-test-agent","cscli","machines","add","--auto","--force")
        cls.key=cls.run_native("register-native-read-only-client","cscli","bouncers","add","secpal-test105").strip()
        if not cls.key or "\n" in cls.key:raise RuntimeError("admit-native-test-client-output")
        cls.run_native("validate-native-crowdsec-configuration","crowdsec","-t")
        cls.lapi=runtime.Lapi(cls.root/"run/lapi.sock",os.getuid(),cls.key)
        cls.addClassCleanup(cls.stop)
        cls.start()
        (ROOT/".context").mkdir(exist_ok=True)
        cls.firewall_temp=tempfile.TemporaryDirectory(prefix="crowdsec105-",dir=ROOT/".context")
        cls.addClassCleanup(cls.firewall_temp.cleanup)
        cls.authority=firewall.Controller(Path(cls.firewall_temp.name)/"firewall")
        cls.configuration={"edge_mode":"DIRECT","management_ipv4":["192.0.2.4/32"],
                           "management_ipv6":["2001:db8::4/128"],"dhcp_interfaces":["uplink105"]}
        cls.authority.apply(cls.configuration)
        cls.accepted={"configuration":cls.configuration,"prefixes":None}

    @classmethod
    def run_native(cls,operation,program,*arguments):
        result=subprocess.run([str(cls.package/"usr/bin"/program),"-c",str(cls.config_file),
                               *arguments],env=cls.env,text=True,capture_output=True,timeout=20)
        if result.returncode:
            # Configuration diagnostics run before any secret-bearing process;
            # later native command output is never printed.
            if operation=="validate-native-crowdsec-configuration":
                print(result.stderr[:2000],file=sys.stderr)
            raise RuntimeError(operation)
        return result.stdout

    @classmethod
    def start(cls):
        cls.log=(cls.root/"process.log").open("ab")
        notification=cls.root/"notify.sock"
        notification.unlink(missing_ok=True)
        cls.notify=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)
        cls.notify.settimeout(20)
        cls.notify.bind(str(notification))
        cls.process=subprocess.Popen(["setpriv","--bounding-set=-all","--no-new-privs",
            str(cls.package/"usr/bin/crowdsec"),"-c",str(cls.config_file)],
            env=cls.env | {"NOTIFY_SOCKET":str(notification)},stdout=cls.log,stderr=cls.log)
        try:
            ready=cls.notify.recv(4096)
            if b"READY=1" not in ready:
                raise RuntimeError("admit-native-systemd-ready-notification")
        finally:
            cls.notify.close()
        deadline=time.monotonic()+20
        while time.monotonic()<deadline:
            if cls.process.poll() is not None:
                # No credential values are embedded in the configuration.
                raise RuntimeError("start-native-crowdsec-process")
            try:
                cls.lapi.decisions()
                return
            except (ValueError,OSError):
                time.sleep(.1)
        raise RuntimeError("authenticate-native-lapi-startup")

    @classmethod
    def stop(cls):
        if getattr(cls,"process",None) is not None and cls.process.poll() is None:
            cls.process.terminate()
            cls.process.wait(timeout=10)
        if getattr(cls,"log",None):cls.log.close()

    @classmethod
    def tearDownClass(cls):
        cls.stop()

    def database_snapshot(self):
        # SQLite serialization observes the committed pager state, including
        # WAL. Never print the image or credential hashes on assertion failure.
        path=self.root/"state/crowdsec.db"
        with sqlite3.connect("file:"+str(path)+"?mode=ro",uri=True) as database:
            return database.serialize()

    def test_01_private_lapi_and_read_only_client(self):
        self.assertTrue((self.root/"run/lapi.sock").is_socket())
        with self.assertRaises(runtime.SecurityError):
            runtime.Lapi(self.lapi.path,os.getuid()+1,self.key).decisions()
        with self.assertRaises(runtime.SecurityError):
            runtime.Lapi(self.lapi.path,os.getuid(),"0"*32).decisions()
        for family,target in ((socket.AF_INET,("127.0.0.1",8080)),
                               (socket.AF_INET6,("::1",8080))):
            with socket.socket(family,socket.SOCK_STREAM) as client:
                client.settimeout(.2)
                self.assertNotEqual(client.connect_ex(target),0)
        connection=runtime._UnixConnection(self.lapi.path,os.getuid())
        connection.request("POST","/v1/alerts",body="[]",
            headers={"X-Api-Key":self.key,"Content-Type":"application/json"})
        response=connection.getresponse()
        self.assertIn(response.status,(401,403))
        response.read()
        connection.close()
        # An unrelated real mapped UID cannot cross the private socket path.
        code=("import socket,sys,errno; s=socket.socket(socket.AF_UNIX); "
              "result=s.connect_ex(sys.argv[1]); sys.exit(0 if result==errno.EACCES else 1)")
        result=subprocess.run(["setpriv","--reuid","65534","--regid","65534","--clear-groups",
            "--bounding-set=-all","--no-new-privs",sys.executable,"-c",code,str(self.lapi.path)],
            capture_output=True,timeout=5)
        self.assertEqual(result.returncode,0)
        status=Path("/proc/"+str(self.process.pid)+"/status").read_text()
        capability=next(line.split()[1] for line in status.splitlines() if line.startswith("CapEff:"))
        self.assertEqual(int(capability,16),0)

    def test_02_actual_detection_canonical_identity_privacy_and_projection(self):
        stamp=time.strftime("%b %d %H:%M:%S",time.gmtime())
        with self.ssh.open("a") as stream:
            for address in ("192.0.2.5","2001:db8::5"):
                for _ in range(8):
                    stream.write(stamp+" host sshd[101]: Failed password for invalid user "
                        "SYNTHETIC_PRIVATE_USERNAME from 203.0.113.99 port 1 ssh2 from "+address+" port 41234 ssh2\n")
        with self.edge.open("a") as stream:
            for _ in range(8):
                stream.write(stamp+" host secpal-haproxy[102]: peer=203.0.113.6 client=203.0.113.6 "
                    "request_id=synthetic method=POST origin=api backend=secpal_api server=api "
                    "status=401 bytes=0 duration_ms=1 termination=---- security=accepted\n")
                # Additional untrusted forwarding text is not the producer's
                # closed canonical shape and cannot choose a victim address.
                stream.write(stamp+" host secpal-haproxy[102]: X-Forwarded-For: 203.0.113.99\n")
        expected={"192.0.2.5","2001:db8::5","203.0.113.6"}
        deadline=time.monotonic()+20
        values=[]
        while time.monotonic()<deadline:
            values,_=self.lapi.decisions()
            if {v["value"] for v in values or []}>=expected:break
            time.sleep(.2)
        self.assertEqual({v["value"] for v in values or []},expected)
        started=time.monotonic()
        desired=runtime.contract.select_decisions(values,self.configuration,None,
            direct_single=True,allowlist=[])
        with self.assertRaises(runtime.SecurityError):
            runtime.admit_projection(desired,self.authority,started_at=started)
        result=runtime.synchronize(self.lapi,self.authority,self.accepted,direct_single=True,allowlist=[])
        runtime.admit_projection(desired,self.authority,started_at=started)
        self.assertEqual(result["security"],"DECISIONS_SYNCHRONIZED")
        self.assertEqual(result["desired_count"],3)
        observed={entry["elem"]["val"] for name in ("remediation4","remediation6")
                  for entry in self.authority.native.decisions(name)}
        self.assertEqual(observed,expected)
        self.assertFalse(b"SYNTHETIC_PRIVATE_USERNAME" in self.database_snapshot())
        # The accepted #209 consumer shape is compatible replay evidence, not
        # qualification of an authenticated live PROTECTED Origin.
        fixture_spec=importlib.util.spec_from_file_location("accepted_prefix_fixture",ROOT/"tests/host-firewall-contract.py")
        fixture=importlib.util.module_from_spec(fixture_spec)
        fixture_spec.loader.exec_module(fixture)
        source=fixture.prefixes()
        type(self).configuration=self.configuration | {"edge_mode":"PROTECTED"}
        type(self).accepted={"configuration":self.configuration,"prefixes":source}
        self.authority.apply(self.configuration,source)
        with self.edge.open("a") as stream:
            for _ in range(8):
                stream.write(stamp+" host secpal-haproxy[102]: peer=198.51.100.2 client=203.0.113.7 "
                    "request_id=synthetic method=POST origin=api backend=secpal_api server=api "
                    "status=401 bytes=0 duration_ms=1 termination=---- security=accepted\n")
        deadline=time.monotonic()+10
        while time.monotonic()<deadline:
            values,_=self.lapi.decisions()
            if "203.0.113.7" in {v["value"] for v in values or []}:break
            time.sleep(.1)
        self.assertIn("203.0.113.7",{v["value"] for v in values or []})
        result=runtime.synchronize(self.lapi,self.authority,self.accepted,direct_single=False,allowlist=[])
        self.assertEqual(result["desired_count"],2)
        observed={entry["elem"]["val"] for name in ("remediation4","remediation6")
                  for entry in self.authority.native.decisions(name)}
        self.assertEqual(observed,{"192.0.2.5","2001:db8::5"})
        database=self.database_snapshot()
        self.assertTrue(b"network_peer" in database)
        self.assertTrue(b"198.51.100.2" in database)

    def test_03_allowlist_recovery_and_restart_without_a_shadow_decision_store(self):
        result=runtime.synchronize(self.lapi,self.authority,self.accepted,direct_single=False,
                                  allowlist=["192.0.2.5/32"])
        self.assertEqual(result["desired_count"],1)  # IPv6 SSH; HTTP stays L7.
        self.stop()
        with self.assertRaises(runtime.SecurityError):
            self.lapi.decisions()
        self.authority.check()  # Engine loss never withdraws baseline authority.
        self.start()
        self.run_native("remove-owned-false-positive","cscli","decisions","delete","--ip","2001:db8::5")
        result=runtime.synchronize(self.lapi,self.authority,self.accepted,direct_single=False,
                                  allowlist=["192.0.2.5/32"])
        self.assertEqual(result["desired_count"],0)
        self.authority.check()


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--parent-network")
    args,tests=parser.parse_known_args()
    if args.parent_network is None:
        result=subprocess.run(["unshare","--user","--map-auto","--map-root-user","--net",
            sys.executable,str(Path(__file__).resolve()),"--parent-network",os.readlink("/proc/self/ns/net"),*tests],
            timeout=120)
        raise SystemExit(result.returncode)
    if os.geteuid()!=0 or os.readlink("/proc/self/ns/net")==args.parent_network:
        raise RuntimeError("refuse-nonisolated-crowdsec-qualification")
    subprocess.run(["/usr/sbin/ip","link","set","lo","up"],check=True,capture_output=True)
    print("Native CrowdSec 1.8.1;",platform.machine(),"; kernel",os.uname().release,flush=True)
    unittest.main(argv=[sys.argv[0],*tests],verbosity=2)


if __name__=="__main__":
    main()
