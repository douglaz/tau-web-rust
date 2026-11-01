#!/usr/bin/env python3
"""Original-predicate examples and source-impossible finite operand controls."""
import json
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
from tracer_fixture_predicates import replay


class Predicates(unittest.TestCase):
    def test_original_examples_and_impossible_operands(self):
        path = Path(__file__).resolve().parent.parent / 'tracer/testdata/fixture-predicates.json'
        for row in json.loads(path.read_text()):
            with self.subTest(row['name']):
                if row['result'] is None:
                    with self.assertRaises(ValueError):
                        replay(row['site'], row['operands'])
                else:
                    self.assertIs(replay(row['site'], row['operands']), row['result'])


if __name__ == '__main__':
    unittest.main()
