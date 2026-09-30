#!/usr/bin/env python3

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from nvx_tools.common import ScriptError  # noqa: E402
from nvx_tools.egress_policy import compile_policy_file  # noqa: E402


class EgressPolicyTests(unittest.TestCase):
    def compile(self, value: object):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "policy.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            return compile_policy_file(path)

    def test_compiles_inclusive_tcp_and_udp_ranges(self):
        compiled = self.compile(
            {
                "allow": [
                    {
                        "cidr": "192.0.2.7",
                        "protocol": "tcp",
                        "port": 8000,
                        "endPort": 8002,
                    },
                    {
                        "cidr": "198.51.100.0/24",
                        "protocol": "udp",
                        "port": 5000,
                        "endPort": 5001,
                    },
                ]
            }
        )

        self.assertEqual(
            compiled.allow,
            (
                "192.0.2.7/32:tcp:8000",
                "192.0.2.7/32:tcp:8001",
                "192.0.2.7/32:tcp:8002",
                "198.51.100.0/24:udp:5000",
                "198.51.100.0/24:udp:5001",
            ),
        )
        self.assertEqual(compiled.deny, ())

    def test_rejects_invalid_port_shapes_and_values(self):
        invalid_rules = (
            {"cidr": "192.0.2.0/24", "protocol": "tcp", "endPort": 80},
            {"cidr": "192.0.2.0/24", "protocol": "tcp"},
            {
                "cidr": "192.0.2.0/24",
                "protocol": "tcp",
                "port": 81,
                "endPort": 80,
            },
            {"cidr": "192.0.2.0/24", "protocol": "tcp", "port": 0},
            {"cidr": "192.0.2.0/24", "protocol": "udp", "port": 65536},
            {"cidr": "192.0.2.0/24", "protocol": "tcp", "port": True},
            {"cidr": "192.0.2.0/24", "port": 80},
            {"cidr": "192.0.2.0/24", "protocol": "icmp", "port": 8},
        )

        for rule in invalid_rules:
            with self.subTest(rule=rule), self.assertRaises(ScriptError):
                self.compile({"allow": [rule]})

    def test_subtracts_rule_local_cidr_exclusions(self):
        compiled = self.compile(
            {
                "allow": [
                    {
                        "cidr": "192.0.2.0/24",
                        "except": ["192.0.2.128/25"],
                    },
                    {"cidr": "192.0.2.200/32"},
                ],
                "deny": [
                    {
                        "cidr": "198.51.100.0/24",
                        "except": ["198.51.100.128/25"],
                    }
                ],
            }
        )

        self.assertEqual(
            compiled.allow,
            ("192.0.2.0/25", "192.0.2.200/32"),
        )
        self.assertEqual(compiled.deny, ("198.51.100.0/25",))

    def test_deduplicates_overlapping_exclusions_and_collapses_safe_prefixes(self):
        compiled = self.compile(
            {
                "allow": [
                    {
                        "cidr": "192.0.2.0/24",
                        "except": [
                            "192.0.2.128/25",
                            "192.0.2.128/25",
                            "192.0.2.192/26",
                        ],
                        "protocol": "tcp",
                        "port": 443,
                    },
                    {
                        "cidr": "198.51.100.0/25",
                        "protocol": "udp",
                        "port": 53,
                    },
                    {
                        "cidr": "198.51.100.128/25",
                        "protocol": "udp",
                        "port": 53,
                    },
                ]
            }
        )

        self.assertEqual(
            compiled.allow,
            (
                "192.0.2.0/25:tcp:443",
                "198.51.100.0/24:udp:53",
            ),
        )

    def test_rejects_exclusions_outside_parent_or_wrong_family(self):
        for excluded in ("198.51.100.0/24", "2001:db8::/32"):
            with (
                self.subTest(excluded=excluded),
                self.assertRaisesRegex(ScriptError, "except"),
            ):
                self.compile(
                    {
                        "allow": [
                            {
                                "cidr": "192.0.2.0/24",
                                "except": [excluded],
                            }
                        ]
                    }
                )

    def test_rejects_unknown_and_malformed_fields(self):
        invalid: tuple[object, ...] = (
            [],
            {"unknown": []},
            {"allow": {}},
            {"allow": ["192.0.2.0/24"]},
            {"allow": [{"cidr": "192.0.2.0/24", "unknown": 1}]},
            {"allow": [{"cidr": 7}]},
            {"allow": [{"cidr": "192.0.2.0/24", "except": "192.0.2.1"}]},
        )

        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ScriptError):
                self.compile(value)

    def test_accepts_exact_256_rule_boundaries(self):
        compiled = self.compile(
            {
                "allow": [
                    {
                        "cidr": "192.0.2.1",
                        "protocol": "tcp",
                        "port": 1,
                        "endPort": 256,
                    }
                ],
                "deny": [
                    {
                        "cidr": "198.51.100.1",
                        "protocol": "udp",
                        "port": 1,
                        "endPort": 256,
                    }
                ],
            }
        )

        self.assertEqual(len(compiled.allow), 256)
        self.assertEqual(len(compiled.deny), 256)

    def test_rejects_257_rules_before_materializing_large_ranges(self):
        for category in ("allow", "deny"):
            with (
                self.subTest(category=category),
                self.assertRaisesRegex(ScriptError, "at most 256"),
            ):
                self.compile(
                    {
                        category: [
                            {
                                "cidr": "192.0.2.1",
                                "protocol": "tcp",
                                "port": 1,
                                "endPort": 65535,
                            }
                        ]
                    }
                )

    def test_bounds_exclusion_times_range_expansion(self):
        accepted = self.compile(
            {
                "allow": [
                    {
                        "cidr": "192.0.2.0/24",
                        "except": ["192.0.2.128/25"],
                        "protocol": "tcp",
                        "port": 1,
                        "endPort": 256,
                    }
                ]
            }
        )
        self.assertEqual(len(accepted.allow), 256)

        with self.assertRaisesRegex(ScriptError, "at most 256"):
            self.compile(
                {
                    "allow": [
                        {
                            "cidr": "192.0.2.0/24",
                            "except": ["192.0.2.128/25"],
                            "protocol": "tcp",
                            "port": 1,
                            "endPort": 257,
                        }
                    ]
                }
            )


if __name__ == "__main__":
    unittest.main()
