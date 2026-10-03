#!/usr/bin/env python3
"""Classification must partition rules by their original protocol."""
import sys
import argparse
import unittest
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from extract_original_rules import matches_mode
from run_intervals import summary_intervals


class RuleGroupsTest(unittest.TestCase):
    def test_every_protocol_has_exactly_one_group(self):
        for group, protocols in {
            'application': ('http', 'ssh', 'smb'),
            'transport': ('tcp', 'udp', 'tcp-pkt', 'tcp-stream', 'sctp'),
            'ip': ('ip', 'ipv6', 'icmp', 'icmpv6', 'pkthdr'),
        }.items():
            for protocol in protocols:
                with self.subTest(protocol=protocol):
                    rule = f'alert {protocol} any any -> any any (sid:1;)'
                    self.assertEqual(
                        [g for g in ('application', 'transport', 'ip') if matches_mode(rule, g)],
                        [group],
                    )

    def test_messages_and_flowbit_names_do_not_change_the_group(self):
        rule = ('alert udp any any -> any any '
                '(msg:"IPv4 IPv6 http.example"; flowbits:isset,ms.rdp.synack; sid:2;)')
        self.assertTrue(matches_mode(rule, 'transport'))
        self.assertFalse(matches_mode(rule, 'ip'))
        self.assertFalse(matches_mode(rule, 'application'))

    def test_executor_reads_group_summary_and_handles_no_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'summary.txt'
            path.write_text('Merged:\n4-183\n\nAdjusted:\n0-179\n')
            self.assertEqual(summary_intervals(path), [(4, 183)])
            path.write_text('Merged:\n(nenhum)\n\nAdjusted:\n(nenhum)\n')
            self.assertEqual(summary_intervals(path), [(0, 0)])
            path.write_text('Merged:\n0-2048\n\n')
            with self.assertRaises(argparse.ArgumentTypeError):
                summary_intervals(path)


if __name__ == '__main__':
    unittest.main()
