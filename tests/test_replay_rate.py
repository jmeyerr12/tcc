#!/usr/bin/env python3
"""Test the offered-load calculations used by the experiment scripts."""

import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LIBRARY = ROOT / "experiments" / "replay_rate.sh"


def call(function, *arguments):
    command = (
        f"source {LIBRARY}; "
        f"{function} "
        + " ".join(str(argument) for argument in arguments)
    )
    return subprocess.run(
        ["bash", "-c", command],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


class ReplayRateTest(unittest.TestCase):
    def test_calculates_pps_equivalent_to_7_5_gbps(self):
        self.assertEqual(
            call("equivalent_target_pps", 7500, 185441374, 265848),
            "1343996",
        )

    def test_distributes_every_target_packet_between_generators(self):
        self.assertEqual(
            call("split_target_pps", 1343996, 3),
            "447999 447999 447998",
        )

    def test_batches_only_the_7_5_gbps_load(self):
        self.assertEqual(call("replay_pps_multi", 5000), "1")
        self.assertEqual(call("replay_pps_multi", 7500), "32")

    def test_rejects_a_run_below_99_percent_of_target_pps(self):
        self.assertEqual(call("target_pps_reached", 1343996, 1331000), "yes")
        self.assertEqual(call("target_pps_reached", 1343996, 1330000), "no")


if __name__ == "__main__":
    unittest.main()
