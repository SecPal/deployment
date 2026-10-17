#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""#105 decision admission; native engine evidence is kept distinct."""
from pathlib import Path
import sys
import configparser
import hashlib
import importlib.util
import json
import os
import platform
import tempfile
from types import SimpleNamespace
from unittest.mock import patch
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import crowdsec_host_contract as contract
import crowdsec_host_runtime as runtime

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("crowdsec_dispatcher",ROOT/"scripts/crowdsec-host.py")
dispatcher=importlib.util.module_from_spec(spec)
spec.loader.exec_module(dispatcher)


def firewall(mode="DIRECT"):
    return {"edge_mode": mode, "management_ipv4": ["192.0.2.4/32"],
            "management_ipv6": ["2001:db8::4/128"], "dhcp_interfaces": ["ens3"]}


def decision(ip="192.0.2.5", **changes):
    return {"id": 1, "origin": "crowdsec", "scenario": "crowdsecurity/ssh-bf",
            "scope": "Ip", "type": "ban", "value": ip, "duration": "9m59.500000001s"} | changes


class Decisions(unittest.TestCase):
    def select(self, values, **options):
        return contract.select_decisions(values, firewall(), None, direct_single=True,
                                         allowlist=[], **options)

    def test_exact_native_decision_and_remaining_lifetime(self):
        self.assertEqual(self.select([decision()], elapsed=1.6), {"192.0.2.5": 597})
        self.assertEqual(self.select([decision("2001:db8::5")]), {"2001:db8::5": 599})
        self.assertEqual(self.select(None), {})
        self.assertEqual(self.select([decision(duration="0.5s")]), {})
        self.assertEqual(self.select([decision(duration="999.999ms")]), {})
        for change in ({"duration": "1h1s"}, {"duration": "4h"}, {"duration":"-1s"},
                       {"duration":"nan"}, {"scope":"Range"}, {"origin":"CAPI"},
                       {"scenario":"attacker/chosen"}, {"type":"captcha"},
                       {"id":True}, {"value":"192.0.2.0/24"}, {"simulated":True}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.select([decision(**change)])

    def test_duplicates_collisions_and_capacity_fail_closed(self):
        with self.assertRaises(ValueError):
            self.select([decision(), decision()])
        with self.assertRaises(ValueError):
            self.select([decision(id=i+1) for i in range(contract.firewall.MAX_DECISIONS+1)])
        combined=self.select([decision(duration="10s"), decision(id=2,duration="20s")])
        self.assertEqual(combined, {"192.0.2.5":20})

    def test_allowlist_protected_peers_and_http_transport_scope(self):
        self.assertEqual(self.select([decision("192.0.2.4")]), {})
        self.assertEqual(contract.select_decisions([decision()],firewall(),None,
            direct_single=True,allowlist=["192.0.2.0/24"]), {})
        web=decision(scenario="secpal/haproxy-auth-v1")
        self.assertEqual(self.select([web]), {"192.0.2.5":599})
        self.assertEqual(contract.select_decisions([web],firewall(),None,
            direct_single=False,allowlist=[]), {})
        source=contract.firewall.prefixes.build_candidate({
            "syncToken":"1792195200","createDate":"2026-10-17-00-00-00",
            "prefixes":[{"ip_prefix":"198.51.100.0/24","region":"GLOBAL",
                         "service":"CLOUDFRONT_ORIGIN_FACING","network_border_group":"GLOBAL"}],
            "ipv6_prefixes":[{"ipv6_prefix":"2001:db8:1::/48","region":"GLOBAL",
                         "service":"CLOUDFRONT_ORIGIN_FACING","network_border_group":"GLOBAL"}],
        },retrieved_at="2026-10-17T00:00:00Z")
        self.assertEqual(contract.select_decisions([web],firewall("PROTECTED"),source,
            direct_single=True,allowlist=[]), {})
        self.assertEqual(contract.select_decisions([decision("198.51.100.5")],
            firewall("PROTECTED"),source,direct_single=False,allowlist=[]), {})

    def test_operator_allowlist_is_closed_and_canonical(self):
        for entries in (["0.0.0.0/0"],["192.0.2.1/24"],["192.0.2.0/24"]*2,
                        ["http://example.test"],"192.0.2.0/24"):
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                contract.validate_allowlist(entries)

    def test_reconciliation_removes_stale_and_allowlisted_decisions_without_a_shadow_store(self):
        operations=[]
        contract.reconcile({"192.0.2.5":10},{"192.0.2.6":30},lambda ip,ttl:
            operations.append(("add",ip,ttl)),lambda ip:operations.append(("remove",ip)),clock=lambda:0)
        self.assertEqual(operations,[("remove","192.0.2.6"),("add","192.0.2.5",10)])
        with self.assertRaises(OSError):
            contract.reconcile({"192.0.2.5":10},{},lambda *args:
                (_ for _ in ()).throw(OSError("synthetic interruption")),lambda ip:None)

    def test_existing_shorter_ban_is_not_rewritten_and_revoked_lifetime_is_shortened(self):
        operations=[]
        contract.reconcile({"192.0.2.5":10},{"192.0.2.5":9},
            lambda ip,ttl:operations.append((ip,ttl)),lambda ip:None,clock=lambda:0)
        self.assertEqual(operations,[])
        contract.reconcile({"192.0.2.5":10},{"192.0.2.5":30},
            lambda ip,ttl:operations.append((ip,ttl)),lambda ip:None,clock=lambda:0)
        self.assertEqual(operations,[("192.0.2.5",10)])

    def test_duration_never_extends_after_observation_or_partial_progress(self):
        operations=[]
        ticks=iter([100.0,103.1,111.0])
        contract.reconcile({"192.0.2.5":10,"192.0.2.6":10},{},
            lambda ip,ttl:operations.append((ip,ttl)),lambda ip:None,clock=lambda:next(ticks))
        self.assertEqual(operations,[("192.0.2.5",6)])


class NativeInputBoundaries(unittest.TestCase):
    def test_payload_configuration_and_pattern_targets_fail_on_tampering(self):
        # Authored bytes test observer behavior only, never RPM/vendor evidence.
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            config=root/"config";config.mkdir()
            package=root/"package"
            patterns=package/"etc/crowdsec/patterns";patterns.mkdir(parents=True)
            (config/"patterns").symlink_to(patterns,target_is_directory=True)
            (package/"usr/bin").mkdir(parents=True)
            (package/"usr/bin/crowdsec").write_bytes(b"fixture executable")
            (patterns/"fixture").write_bytes(b"fixture grok")
            (config/"secpal.yaml").write_bytes(b"fixture: true")
            files={str(p.relative_to(package)):hashlib.sha256(p.read_bytes()).hexdigest()
                   for p in (package/"usr/bin/crowdsec",patterns/"fixture")}
            policy={"version":"fixture","packages":{platform.machine():{"files":files}},
                    "configuration_files":{"secpal.yaml":hashlib.sha256(b"fixture: true").hexdigest()}}
            (config/"supply.json").write_text(json.dumps(policy))
            runtime.verify_inputs(config,package)
            (package/"usr/bin/crowdsec").write_bytes(b"altered")
            with self.assertRaises(runtime.SecurityError):
                runtime.verify_inputs(config,package)
            (package/"usr/bin/crowdsec").write_bytes(b"fixture executable")
            (config/"moving.yaml").write_text("unreviewed: true")
            with self.assertRaises(runtime.SecurityError):
                runtime.verify_inputs(config,package)
            (config/"moving.yaml").unlink()
            (patterns/"moving").write_bytes(b"unreviewed pattern")
            with self.assertRaises(runtime.SecurityError):
                runtime.verify_inputs(config,package)

    def test_security_health_rejects_missing_or_stale_effective_bans(self):
        entries=[]
        authority=SimpleNamespace(native=SimpleNamespace(decisions=lambda name:
            entries if name=="remediation4" else []))
        with patch.object(runtime.time,"monotonic",return_value=0):
            with self.assertRaises(runtime.SecurityError):
                runtime.admit_projection({"192.0.2.5":10},authority,started_at=0)
            entries.append({"elem":{"val":"192.0.2.5","expires":9}})
            runtime.admit_projection({"192.0.2.5":10},authority,started_at=0)
            with self.assertRaises(runtime.SecurityError):
                runtime.admit_projection({},authority,started_at=0)

    def test_stopped_engine_or_missing_reader_cannot_claim_security_health(self):
        def states(unit):
            return ({"LoadState":"loaded","ActiveState":"inactive","SubState":"dead"}
                    if unit=="crowdsec.service" else {"LoadState":"masked","ActiveState":"inactive"})
        with patch.object(dispatcher,"systemd",side_effect=states):
            facts=dispatcher.services(os.getuid())
        self.assertFalse(facts["engine_active"])
        self.assertFalse(facts["acquisition_live"])
        def active(unit):
            return ({"LoadState":"loaded","ActiveState":"active","SubState":"running",
                     "ControlGroup":"/crowdsec-fixture.service"}
                    if unit=="crowdsec.service" else {"LoadState":"masked","ActiveState":"inactive"})
        with patch.object(dispatcher,"systemd",side_effect=active), \
                patch.object(dispatcher,"ROOT",ROOT/"config/production/crowdsec"), \
                patch.object(Path,"read_bytes",return_value=b""):
            facts=dispatcher.services(os.getuid())
        self.assertTrue(facts["engine_active"])
        self.assertFalse(facts["acquisition_live"])

    def test_bounded_diagnostics_never_include_external_error_values(self):
        with self.assertRaises(dispatcher.ObservationFailure) as caught:
            with dispatcher.observing("read-fixture-input"):
                raise OSError("synthetic-private-value")
        self.assertEqual(str(caught.exception),"read-fixture-input")

    def test_service_roles_preserve_the_existing_privilege_boundary(self):
        folder=ROOT/"config/production/host-systemd"
        engine=configparser.ConfigParser(strict=False,interpolation=None)
        engine.read(folder/"crowdsec.service.d/secpal.conf")
        helper=configparser.ConfigParser(strict=False,interpolation=None)
        helper.read(folder/"secpal-crowdsec-remediation.service")
        self.assertEqual(engine["Service"]["User"],"secpal-crowdsec")
        self.assertEqual(engine["Service"]["CapabilityBoundingSet"],"")
        self.assertEqual(engine["Service"]["RestrictAddressFamilies"],"AF_UNIX")
        self.assertEqual(helper["Service"]["CapabilityBoundingSet"],"CAP_NET_ADMIN")
        self.assertEqual(helper["Service"]["ReadWritePaths"],"/var/lib/secpal/host-firewall")
        for unit in (engine,helper):
            self.assertEqual(unit["Service"]["NoNewPrivileges"],"true")
            self.assertIn("-/etc/secpal/credentials",unit["Service"]["InaccessiblePaths"].split())


if __name__=="__main__":
    unittest.main()
