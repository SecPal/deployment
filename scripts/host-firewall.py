#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Administrator-owned #104 native nft boundary; no daemon or provider authority."""
import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

HELPER = Path("/usr/local/libexec/secpal/host-firewall")
LIBRARIES = ("host_firewall_contract.py", "cloudfront-origin-prefix-lkg.py")
DESIRED = Path("/etc/secpal/host-firewall.json")
STATE = Path("/var/lib/secpal/host-firewall")
PREFIX_STATE = Path("/var/lib/secpal/cloudfront-origin-prefixes")


def trusted(path, *, regular=True):
    for entry in (path, *path.parents):
        info = entry.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise ValueError("admit-host-firewall-source")
    info = path.lstat()
    if regular and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
        raise ValueError("admit-host-firewall-source")


if __name__ == "__main__":
    try:
        if os.geteuid() != 0 or Path(__file__).resolve() != HELPER:
            raise ValueError("admit-host-firewall-administrator")
        for item in (HELPER, *(HELPER.parent / name for name in LIBRARIES)):
            trusted(item)
        # Do not import an unchecked adjacent bytecode cache.
        temporary = Path("/tmp").lstat()
        if temporary.st_uid != 0 or not stat.S_ISDIR(temporary.st_mode) or (
                temporary.st_mode & 0o022 and not temporary.st_mode & stat.S_ISVTX):
            raise ValueError("admit-firewall-temporary-directory")
        _cache = tempfile.TemporaryDirectory(prefix="secpal-host-firewall-imports-", dir="/tmp")
        sys.pycache_prefix = _cache.name
        sys.dont_write_bytecode = True
    except (ValueError, OSError):
        print("FAIL: admit-host-firewall-source", file=sys.stderr)
        raise SystemExit(1)

sys.path.insert(0, str(Path(__file__).resolve().parent))
import host_firewall_contract as contract

MAX_OUTPUT = 32 * 1024 * 1024


class NftFailure(ValueError):
    """Closed operation identity from fixed native-call sites, never stderr."""


class Nft:
    """Only the fixed native nft binary; bounded non-secret operation errors."""
    def run(self, operation, arguments, document=None):
        try:
            result = subprocess.run(
                ["/usr/sbin/nft", *arguments],
                input=None if document is None else json.dumps(document),
                text=True, capture_output=True, timeout=30,
                env={"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"})
        except (OSError, subprocess.SubprocessError):
            raise NftFailure(operation) from None
        if (result.returncode != 0 or len(result.stdout.encode()) > MAX_OUTPUT
                or len(result.stderr.encode()) > 4096):
            raise NftFailure(operation)
        return result.stdout

    def snapshot(self):
        tables = json.loads(self.run("observe-firewall-tables", ["--json", "list", "tables"]))
        present = any(row.get("table", {}).get("family") == "inet"
                      and row.get("table", {}).get("name") == contract.TABLE
                      for row in tables["nftables"])
        if not present:
            return None
        return json.loads(self.run("observe-host-firewall",
            ["--json", "--terse", "list", "table", "inet", contract.TABLE]))

    def validate(self, document):
        self.run("validate-host-firewall", ["--check", "--json", "--file", "-"], document)

    def commit(self, document):
        self.run("apply-host-firewall", ["--json", "--file", "-"], document)

    def decisions(self, name):
        observed = json.loads(self.run("observe-remediation",
            ["--json", "list", "set", "inet", contract.TABLE, name]))
        sets = [row["set"] for row in observed["nftables"] if "set" in row]
        if len(sets) != 1:
            raise ValueError("admit-remediation-observation")
        return sets[0].get("elem", [])


def _read(directory):
    path = contract.prefixes._state_file(directory, "accepted.json", required=False)
    if path is None:
        return None
    with path.open("rb") as stream:
        raw = stream.read(contract.prefixes.MAX_STATE_BYTES + 1)
    if len(raw) > contract.prefixes.MAX_STATE_BYTES:
        raise ValueError("admit-firewall-state-bound")
    value = contract.prefixes._decode_json(raw)
    if type(value) is not dict or value.keys() != {"configuration", "prefixes"}:
        raise ValueError("admit-firewall-state")
    contract.policy(value["configuration"], value["prefixes"])
    return value


def _same(observed, document):
    if observed is None:
        return False
    return contract.normalize_table(observed) == contract.policy(
        document["configuration"], document["prefixes"])


def _management_transition(previous, candidate):
    """Never remove currently authorized management networks during a reload."""
    if previous is None:
        return
    for key in ("management_ipv4", "management_ipv6"):
        new = list(contract.ipaddress.collapse_addresses(
            contract.ipaddress.ip_network(value) for value in candidate[key]))
        for value in previous["configuration"][key]:
            old = contract.ipaddress.ip_network(value)
            if not any(old.subnet_of(network) for network in new):
                raise ValueError("admit-management-preservation")


class Controller:
    def __init__(self, directory, native=None):
        self.directory = contract.prefixes._assert_safe_directory(Path(directory), create=True)
        self.native = Nft() if native is None else native

    def _save(self, value):
        try:
            contract.prefixes._atomic_write(self.directory, "accepted.json",
                                            contract.prefixes._canonical_bytes(value))
        except contract.prefixes.CommitStateUncertain:
            raise
        except (OSError, contract.prefixes.ContractError):
            raise NftFailure("persist-accepted-host-firewall") from None

    def _admit_decisions(self, document):
        for name in ("remediation4", "remediation6"):
            entries = self.native.decisions(name)
            if len(entries) > contract.MAX_DECISIONS:
                raise ValueError("admit-remediation-capacity")
            for entry in entries:
                if (type(entry) is not dict or entry.keys() != {"elem"}
                        or type(entry["elem"]) is not dict
                        or not {"val", "timeout", "expires"} <= entry["elem"].keys()):
                    raise ValueError("admit-remediation-element")
                value = entry["elem"]
                if (type(value["timeout"]) is not int or not 0 < value["timeout"] <= contract.MAX_TTL
                        or type(value["expires"]) is not int
                        or not 0 <= value["expires"] <= value["timeout"]):
                    raise ValueError("admit-remediation-lifetime")
                actual, _ = contract.remediation(document["configuration"], document["prefixes"],
                                                 value["val"], ttl=1)
                if name != actual:
                    raise ValueError("admit-remediation-family")

    def apply(self, config, source=None):
        config = contract.configuration(config)
        source = contract.deepcopy(source)
        value = {"configuration": config, "prefixes": source}
        contract.policy(config, source)  # Reject before kernel/cache publication.
        with contract.prefixes._state_lock(self.directory):
            previous = _read(self.directory)
            _management_transition(previous, config)
            if previous is not None and previous["prefixes"] is not None and source is not None:
                contract.prefixes.admit_successor(previous["prefixes"], source)
            observed = self.native.snapshot()
            if observed is not None:
                self._admit_decisions(value)
                if _same(observed, value):
                    # Exact desired-input/read-back reconciliation, including
                    # kernel commit followed by interrupted accepted-file write.
                    self._save(value)
                    return
                if previous is None or not _same(observed, previous):
                    raise ValueError("admit-prior-firewall")
            commands = contract.batch(config, source, initial=observed is None)
            self.native.validate(commands)
            try:
                self.native.commit(commands)
            except ValueError:
                # An unknown acknowledgement never authorizes a blind replay.
                # Independent native read-back must prove this exact candidate.
                if not _same(self.native.snapshot(), value):
                    raise
            if not _same(self.native.snapshot(), value):
                raise ValueError("admit-applied-firewall")
            self._admit_decisions(value)
            self._save(value)

    def restore(self):
        with contract.prefixes._state_lock(self.directory):
            value = _read(self.directory)
            if value is None:
                raise ValueError("admit-accepted-firewall-required")
            observed = self.native.snapshot()
            if observed is None:
                commands = contract.batch(value["configuration"], value["prefixes"], initial=True)
                self.native.validate(commands)
                self.native.commit(commands)
            if not _same(self.native.snapshot(), value):
                raise ValueError("admit-restored-firewall")
            self._admit_decisions(value)

    def check(self):
        with contract.prefixes._state_lock(self.directory):
            value = _read(self.directory)
            if value is None or not _same(self.native.snapshot(), value):
                raise ValueError("admit-effective-host-firewall")
            self._admit_decisions(value)

    def remediate(self, address, *, ttl=60, remove=False):
        with contract.prefixes._state_lock(self.directory):
            value = _read(self.directory)
            if value is None or not _same(self.native.snapshot(), value):
                raise ValueError("admit-effective-host-firewall")
            name, peer = contract.remediation(value["configuration"], value["prefixes"], address, ttl=ttl)
            self._admit_decisions(value)
            identity = {"family": "inet", "table": contract.TABLE, "name": name}
            element = dict(**identity, elem=[peer])
            commands = [{"destroy": {"element": element}}]
            if not remove:
                element = dict(**identity, elem=[{"elem": {"val": peer, "timeout": ttl}}])
                commands.append({"add": {"element": element}})
            document = {"nftables": commands}
            self.native.validate(document)
            self.native.commit(document)
            entries = self.native.decisions(name)
            found = any(entry.get("elem", {}).get("val") == peer for entry in entries)
            if found == remove:
                raise ValueError("admit-remediation-readback")
            self._admit_decisions(value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group(required=True)
    for option in ("apply", "restore", "check"):
        actions.add_argument("--" + option, action="store_true")
    actions.add_argument("--add")
    actions.add_argument("--remove")
    parser.add_argument("--ttl", type=int, default=60)
    args = parser.parse_args()
    try:
        trusted(STATE.parent, regular=False)
        controller = Controller(STATE)
        if args.apply:
            trusted(DESIRED)
            if not 0 < DESIRED.stat().st_size <= 65536:
                raise ValueError("admit-desired-firewall-size")
            config = contract.prefixes._decode_json(DESIRED.read_bytes())
            config = contract.configuration(config)
            source = None
            if config["edge_mode"] == "PROTECTED":
                # The caller cannot submit a prefix JSON as its own authority.
                trusted(PREFIX_STATE, regular=False)
                source = contract.prefixes.read_lkg(PREFIX_STATE)
            controller.apply(config, source)
        elif args.restore:
            controller.restore()
        elif args.check:
            controller.check()
        else:
            controller.remediate(args.add or args.remove, ttl=args.ttl, remove=args.remove is not None)
    except contract.prefixes.CommitStateUncertain:
        print("COMMITTED_DURABILITY_UNCONFIRMED", file=sys.stderr)
        return 2
    except NftFailure as error:
        print("FAIL: " + str(error), file=sys.stderr)
        return 1
    except (ValueError, OSError, contract.prefixes.ContractError):
        print("FAIL: admit-host-firewall-authority", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
