#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""One bounded administrator projection from local CrowdSec into #104."""
from contextlib import contextmanager
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys
import tempfile
import time

HERE=Path("/usr/local/libexec/secpal")
ROOT=Path("/usr/share/secpal/crowdsec")
HELPER=HERE/"crowdsec-host"
SERVICE="crowdsec.service"



class ObservationFailure(RuntimeError):
    """A fixed operation identity, never external stderr or secret values."""


@contextmanager
def observing(operation):
    try:
        yield
    except ObservationFailure:
        raise
    except (OSError,ValueError,RuntimeError,KeyError,StopIteration,UnicodeError,
            subprocess.SubprocessError,ImportError):
        raise ObservationFailure(operation) from None


def bootstrap_paths():
    # Independent pre-import enforcement of #104's trusted-source invariant.
    for path in (HELPER,HERE/"host-firewall",HERE/"crowdsec_host_runtime.py",
                 HERE/"crowdsec_host_contract.py",HERE/"host_firewall_contract.py",
                 HERE/"cloudfront-origin-prefix-lkg.py"):
        for entry in (path,*path.parents):
            value=entry.lstat()
            if value.st_uid!=0 or value.st_mode & 0o022 or stat.S_ISLNK(value.st_mode):
                raise ValueError("admit-crowdsec-administrator-source")


def _systemd(unit):
    if unit not in (SERVICE,"crowdsec-hubupdate.service","crowdsec-hubupdate.timer"):
        raise ValueError("admit-crowdsec-native-unit")
    try:
        result=subprocess.run(["/usr/bin/systemctl","show",unit,
            "--property=LoadState,ActiveState,SubState,MainPID,ControlGroup"],
            env={"PATH":"/usr/bin:/usr/sbin","LC_ALL":"C"},
            text=True,capture_output=True,timeout=5)
    except (OSError,subprocess.SubprocessError):
        raise ValueError("observe-crowdsec-native-unit") from None
    if result.returncode or len(result.stdout)>8192:
        raise ValueError("observe-crowdsec-native-unit")
    rows=[row.split("=",1) for row in result.stdout.splitlines()]
    if any(len(row)!=2 for row in rows) or len(dict(rows))!=len(rows):
        raise ValueError("normalize-crowdsec-native-unit")
    return dict(rows)



def systemd(unit):
    if unit not in (SERVICE,"crowdsec-hubupdate.service","crowdsec-hubupdate.timer"):
        raise ObservationFailure("admit-crowdsec-native-unit")
    with observing("observe-"+unit):
        return _systemd(unit)


def services(uid):
    """Observe only this fixed unit's cgroup and native acquisition process."""
    engine=systemd(SERVICE)
    active=(engine.get("LoadState")=="loaded" and engine.get("ActiveState")=="active"
            and engine.get("SubState")=="running")
    masked=all((state.get("LoadState")=="masked" and state.get("ActiveState")=="inactive")
               for state in (systemd("crowdsec-hubupdate.service"),
                             systemd("crowdsec-hubupdate.timer")))
    if not active:
        return {"engine_active":False,"updater_masked":masked,"acquisition_live":False}
    group=engine.get("ControlGroup","")
    if not group.startswith("/") or ".." in Path(group).parts:
        raise ValueError("admit-crowdsec-cgroup")
    raw=(Path("/sys/fs/cgroup")/group[1:]/"cgroup.procs").read_bytes()
    if len(raw)>4096:
        raise ValueError("admit-crowdsec-process-bound")
    pids=raw.decode("ascii").splitlines()
    if len(pids)>64 or any(not value.isdecimal() or int(value)<1 for value in pids):
        raise ValueError("admit-crowdsec-process-bound")
    filters=json.loads((ROOT/"acquis.json").read_text())["journalctl_filter"]
    expected=["--follow","-n","0",*filters]
    acquisition=False
    for pid in pids:
        try:
            process=Path("/proc")/pid
            status=(process/"status").read_text()
            owners=next(row.split()[1:] for row in status.splitlines() if row.startswith("Uid:"))
            with (process/"cmdline").open("rb") as stream:
                command=stream.read(8193)
            if len(command)>8192:
                raise ValueError("admit-crowdsec-process-command-bound")
            args=command.rstrip(b"\0").decode("utf-8").split("\0")
            if (owners==[str(uid)]*4 and args[0] in ("journalctl","/usr/bin/journalctl")
                    and args[1:]==expected):
                acquisition=True
        except FileNotFoundError:
            continue  # A vanished reader never becomes healthy evidence.
    return {"engine_active":active,"updater_masked":masked,"acquisition_live":acquisition}


def _main():
    with observing("authenticate-crowdsec-installed-source"):
        if (Path(__file__).resolve()!=HELPER or len(sys.argv)>2
                or sys.argv[1:] not in ([],["--health"],["--check-inputs"])):
            raise ValueError("admit-crowdsec-entrypoint")
        bootstrap_paths()
    with observing("load-crowdsec-native-boundaries"):
        sys.path.insert(0,str(HERE))
        import crowdsec_host_runtime as runtime
        loader=importlib.machinery.SourceFileLoader("secpal_host_firewall",str(HERE/"host-firewall"))
        spec=importlib.util.spec_from_loader(loader.name,loader)
        firewall=importlib.util.module_from_spec(spec)
        loader.exec_module(firewall)
        for path in (ROOT/"supply.json",HERE/"crowdsec_host_contract.py",HERE/"crowdsec_host_runtime.py"):
            firewall.trusted(path)
    if sys.argv[1:]==["--check-inputs"]:
        with observing("admit-crowdsec-exact-inputs"):
            runtime.verify_inputs()
        print('{"security":"INPUTS_VERIFIED"}')
        return
    with observing("authenticate-crowdsec-administrator"):
        if os.geteuid()!=0:
            raise ValueError("admit-crowdsec-administrator")
        uid=pwd.getpwnam("secpal-crowdsec").pw_uid
    with observing("admit-pinned-security-configuration"):
        runtime.verify_inputs(payload=False)
    with observing("observe-crowdsec-acquisition"):
        health=services(uid)
    if not all(health.values()):
        print(json.dumps({"security":"SECURITY_DEGRADED",**health,
                          "application_readiness":"independent"}))
        raise SystemExit(1)
    with observing("read-readonly-lapi-credential"):
        directory=Path(os.environ["CREDENTIALS_DIRECTORY"])
        credential=directory/"bouncer"
        firewall.trusted(credential)
        with credential.open("r",encoding="ascii") as stream:
            key=stream.read(257).strip()
        client=runtime.Lapi(runtime.LAPI,uid,key)
    with observing("admit-current-host-firewall"):
        authority=firewall.Controller(firewall.STATE)
        authority.check()
        accepted=firewall._read(authority.directory)
    with observing("admit-canonical-edge-producer"):
        direct=False
        if accepted["configuration"]["edge_mode"]=="DIRECT":
            path=Path("/etc/haproxy/secpal.cfg")
            firewall.trusted(path)
            with path.open("r") as stream:
                first=stream.readline(65537)
            if len(first)>65536 or not first.startswith("# secpal-direct "):
                raise ValueError("admit-canonical-edge-producer")
            # Authenticate the existing pure owner and its source closure before
            # import; no sandboxed whole-RPM verifier or replacement schema.
            for path in HERE.glob("*_contract.py"):
                firewall.trusted(path)
            import haproxy_direct_contract
            direct=haproxy_direct_contract.from_document(
                json.loads(first.removeprefix("# secpal-direct "))).topology=="single"
    with observing("read-protected-operator-allowlist"):
        allowlist=Path("/etc/secpal/crowdsec/allowlist.json")
        firewall.trusted(allowlist)
        if allowlist.stat().st_size>65536:
            raise ValueError("admit-security-allowlist-bound")
        local=json.loads(allowlist.read_text())
        if type(local) is not dict or local.keys()!={"allowlist"}:
            raise ValueError("admit-security-allowlist")
    if sys.argv[1:]==["--health"]:
        with observing("authenticate-current-local-decisions"):
            started=time.monotonic()
            decisions,_=client.decisions()
            desired=runtime.contract.select_decisions(decisions,accepted["configuration"],
                firewall._source(accepted),direct_single=direct,allowlist=local["allowlist"])
            runtime.admit_projection(desired,authority,started_at=started)
    else:
        with observing("reconcile-bounded-host-remediation"):
            runtime.synchronize(client,authority,accepted,direct_single=direct,allowlist=local["allowlist"])
    with observing("admit-stable-firewall-generation"):
        if firewall._read(authority.directory)!=accepted:
            raise ValueError("admit-stable-firewall-generation")
    print(json.dumps({"security":"SECURITY_READY",**health,"application_readiness":"independent"}))


def main():
    # Preserve #104's private bytecode view before importing shared root code.
    with observing("prepare-private-host-security-imports"):
        with tempfile.TemporaryDirectory(prefix="secpal-crowdsec-code-") as cache:
            sys.pycache_prefix=cache
            sys.dont_write_bytecode=True
            return _main()


if __name__=="__main__":
    try:
        main()
    except ObservationFailure as error:
        print(json.dumps({"security":"SECURITY_DEGRADED","operation":str(error),
                          "application_readiness":"independent"}))
        raise SystemExit(1)
