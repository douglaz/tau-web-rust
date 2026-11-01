#!/usr/bin/env python3
"""Absolute build clocks retain their parent envelope and actual exit checks."""
import copy
import sys
import unittest

sys.dont_write_bytecode = True
import tracer_timing as timing


class BuildClock(unittest.TestCase):
    def test_valid_build_receipts_do_not_depend_on_host_uptime(self):
        for origin in [0, timing.MAX_NS, timing.MAX_NS + 1, timing.MAX_CLOCK_NS - 3]:
            receipt = dict(schema=1, phase="prepare_served", start_ns=origin + 1,
                           end_ns=origin + 2, exit=0)
            with self.subTest(origin=origin):
                timing.build(receipt, "served", origin, origin + 3, 0)
        # Execution and preparation durations keep the existing tighter bound.
        with self.assertRaises(ValueError):
            timing._number(timing.MAX_NS + 1)

    def test_large_absolute_clocks_still_refuse_forged_receipts(self):
        origin = timing.MAX_NS + 1
        receipt = dict(schema=1, phase="prepare_served", start_ns=origin + 1,
                       end_ns=origin + 2, exit=0)
        changes = [dict(start_ns=origin - 1), dict(end_ns=origin + 4),
                   dict(start_ns=origin + 2, end_ns=origin + 1), dict(exit=1),
                   dict(phase="prepare_tracer"), dict(schema=True)]
        for field in ["start_ns", "end_ns"]:
            changes.extend({field: value} for value in
                           [True, float(origin + 1), -1, timing.MAX_CLOCK_NS + 1])
        for change in changes:
            bad = copy.deepcopy(receipt)
            bad.update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                timing.build(bad, "served", origin, origin + 3, 0)
        timing.build(receipt, "served", origin, origin + 3, 0)


if __name__ == "__main__":
    unittest.main()
