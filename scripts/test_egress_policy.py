#!/usr/bin/env python3
# pyright: reportPrivateUsage=false

import ipaddress
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent))
import nvx_tools.egress_policy as egress_policy  # noqa: E402
from nvx_tools.common import ScriptError  # noqa: E402
from nvx_tools.egress_policy import (
    MAX_POLICY_FILE_SIZE,  # noqa: E402
    compile_policy_file,  # noqa: E402
)


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

    def test_normalizes_host_bits_like_the_native_cidr_parser(self):
        compiled = self.compile({"allow": [{"cidr": "10.0.0.5/24"}]})
        self.assertEqual(compiled.allow, ("10.0.0.0/24",))

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
            {"allow": [{"cidr": "192.0.2.0/24", "protocol": None}]},
        )

        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ScriptError):
                self.compile(value)

    def test_rejects_duplicate_json_fields(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "policy.json"
            for text in (
                '{"deny":[{"cidr":"0.0.0.0/0"}],"deny":[]}',
                '{"allow":[{"cidr":"192.0.2.0/24","port":80,"port":443,"protocol":"tcp"}]}',
            ):
                with self.subTest(text=text):
                    path.write_text(text, encoding="utf-8")
                    with self.assertRaisesRegex(ScriptError, "duplicate JSON property"):
                        compile_policy_file(path)

    def test_empty_destination_does_not_expand_port_range(self):
        compiled = self.compile(
            {
                "allow": [
                    {
                        "cidr": "192.0.2.0/24",
                        "except": ["192.0.2.0/24"],
                        "protocol": "tcp",
                        "port": 1,
                        "endPort": 65535,
                    }
                ]
            }
        )
        self.assertEqual(compiled.allow, ())
        self.assertEqual(compiled.deny, ())

    def test_limits_the_actual_policy_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "policy.json"
            path.write_bytes(b" " * (MAX_POLICY_FILE_SIZE + 1))
            with mock.patch.object(Path, "stat") as stat:
                stat.return_value.st_size = 0
                with self.assertRaisesRegex(ScriptError, "byte limit"):
                    compile_policy_file(path)

    def test_reports_oversized_json_integer_rejection(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "policy.json"
            path.write_text(
                '{"allow":[{"cidr":' + ("9" * 10000) + "}]}",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                ScriptError, "^JSON integer exceeds 64-digit limit$"
            ):
                compile_policy_file(path)

    def test_many_source_networks_can_collapse_within_native_budget(self):
        start = int(ipaddress.IPv4Address("192.0.2.0"))
        compiled = self.compile(
            {
                "allow": [
                    {
                        "cidr": str(ipaddress.IPv4Address(start + offset)),
                        "protocol": "tcp",
                        "port": 80,
                    }
                    for offset in range(512)
                ]
            }
        )
        self.assertEqual(compiled.allow, ("192.0.2.0/23:tcp:80",))

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

    def test_delays_fragment_conversion_until_after_covering_union(self):
        exclusions = [
            str(ipaddress.IPv4Address(int(ipaddress.IPv4Address("192.0.0.1")) + 2 * i))
            for i in range(4096)
        ]
        fragmented = {
            "cidr": "192.0.0.0/16",
            "except": exclusions,
            "protocol": "tcp",
            "port": 80,
            "endPort": 81,
        }
        covering = {
            "cidr": "192.0.0.0/16",
            "protocol": "tcp",
            "port": 80,
            "endPort": 81,
        }

        original_summarize = ipaddress.summarize_address_range
        with mock.patch.object(
            ipaddress,
            "summarize_address_range",
            wraps=original_summarize,
        ) as summarize:
            for rules in ([fragmented, covering], [covering, fragmented]):
                with self.subTest(order=rules):
                    compiled = self.compile({"allow": rules})
                    self.assertEqual(
                        compiled.allow,
                        ("192.0.0.0/16:tcp:80", "192.0.0.0/16:tcp:81"),
                    )

        self.assertEqual(summarize.call_count, 2)

    def test_validates_redundant_rules_before_canonicalization(self):
        with self.assertRaisesRegex(ScriptError, "unknown field"):
            self.compile(
                {
                    "allow": [
                        {"cidr": "192.0.2.0/24"},
                        {"cidr": "192.0.2.1", "unknown": True},
                    ]
                }
            )

    def test_address_only_rule_covers_large_protocol_range(self):
        for rules in (
            [
                {
                    "cidr": "192.0.2.0/24",
                    "protocol": "tcp",
                    "port": 1,
                    "endPort": 65535,
                },
                {"cidr": "192.0.2.0/24"},
            ],
            [
                {"cidr": "192.0.2.0/24"},
                {
                    "cidr": "192.0.2.0/24",
                    "protocol": "tcp",
                    "port": 1,
                    "endPort": 65535,
                },
            ],
        ):
            with self.subTest(rules=rules):
                compiled = self.compile({"allow": rules})
                self.assertEqual(compiled.allow, ("192.0.2.0/24",))

    def test_address_only_rule_prunes_redundant_port_events_before_sweep(self):
        covering = {"cidr": "0.0.0.0/0"}
        protocol_rules = [
            {
                "cidr": "192.0.2.1",
                "protocol": "tcp",
                "port": start,
                "endPort": 2001 - start,
            }
            for start in range(1, 1001)
        ]
        original_convert = egress_policy._intervals_to_networks

        for rules in (
            [covering, *protocol_rules],
            [*protocol_rules, covering],
        ):
            with (
                self.subTest(covering_first=rules[0] is covering),
                mock.patch.object(
                    egress_policy,
                    "_intervals_to_networks",
                    wraps=original_convert,
                ) as convert,
            ):
                compiled = self.compile({"allow": rules})
                self.assertEqual(compiled.allow, ("0.0.0.0/0",))
                self.assertEqual(convert.call_count, 2)


if __name__ == "__main__":
    unittest.main()
