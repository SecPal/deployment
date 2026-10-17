#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Pure #104 admission; native network evidence lives in host-firewall-native.py."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import host_firewall_contract as contract


def config(mode="DIRECT"):
    return {"edge_mode": mode, "management_ipv4": ["198.51.100.4/32"],
            "management_ipv6": ["2001:db8::4/128"], "dhcp_interfaces": ["fw104"]}


def prefixes():
    # Explicit source fixture, not live-provider provenance evidence.
    return contract.prefixes.build_candidate({
        "syncToken": "1792195200", "createDate": "2026-10-17-00-00-00",
        "prefixes": [{"ip_prefix": "198.51.100.0/30", "region": "GLOBAL",
                      "service": "CLOUDFRONT_ORIGIN_FACING", "network_border_group": "GLOBAL"}],
        "ipv6_prefixes": [{"ipv6_prefix": "2001:db8::/126", "region": "GLOBAL",
                           "service": "CLOUDFRONT_ORIGIN_FACING", "network_border_group": "GLOBAL"}],
    }, retrieved_at="2026-10-17T00:00:00Z")


class AdmissionTests(unittest.TestCase):
    def test_modes_and_unambiguous_management_are_closed(self):
        for bad in [config("direct"), config("BOTH"), config() | {"extra": True},
                    config() | {"dhcp_interfaces": []},
                    config() | {"dhcp_interfaces": ["lo"]},
                    config() | {"dhcp_interfaces": ["fw104", "fw104"]},
                    config() | {"dhcp_interfaces": ["bad interface"]},
                    config() | {"management_ipv4": ["0.0.0.0/0"]},
                    config() | {"management_ipv4": ["198.51.100.4/24"]},
                    config() | {"management_ipv4": ["198.51.100.4/32"] * 2},
                    config() | {"management_ipv4": [], "management_ipv6": []}]:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    contract.policy(bad)
        self.assertEqual(contract.policy(config()), contract.policy(config()))

    def test_protected_consumes_exact_existing_prefix_admission(self):
        source = prefixes()
        for change in [None, source | {"ipv6_prefixes": []},
                       source | {"service": "CLOUDFRONT"},
                       source | {"candidate_sha256": "0" * 64}]:
            with self.assertRaises(ValueError):
                contract.policy(config("PROTECTED"), change)
        self.assertTrue(contract.policy(config("PROTECTED"), source))
        with self.assertRaises(ValueError):
            contract.policy(config(), source)

    def test_remediation_is_exact_address_time_bounded_and_cannot_lock_out_management(self):
        for address, ttl in [("0.0.0.0/0", 60), ("198.51.100.4", 60),
                             ("2001:db8::4", 60), ("198.51.100.3", 0),
                             ("198.51.100.3", 3601), ("198.51.100.3", True)]:
            with self.assertRaises(ValueError):
                contract.remediation(config(), None, address, ttl=ttl)
        for address in ["198.51.100.2", "2001:db8::2"]:
            with self.assertRaises(ValueError):
                contract.remediation(config("PROTECTED"), prefixes(), address, ttl=60)
        self.assertTrue(contract.remediation(config(), None, "198.51.100.3", ttl=60))

    def test_normalization_rejects_unreviewed_extra_authority(self):
        spec = contract.policy(config())
        with self.assertRaises(ValueError):
            contract.admit_table({"nftables": spec + [{"chain": {"name": "extra"}}]}, config())


if __name__ == "__main__":
    unittest.main()
