import copy
import json
from pathlib import Path
import unittest

import tracer_operation_windows


class OriginalOperationWindows(unittest.TestCase):
    def test_each_real_operation_brackets_original_observations(self):
        fixture = json.loads((Path(__file__).resolve().parents[1] / 'tracer/testdata/operation-windows.json').read_text())
        report, key = fixture['report'], fixture['inventory']
        tracer_operation_windows.validate(report, key)
        for path, value in [
            (('file_captures', 1, 'at_ns'), 21),
            (('file_captures', 2, 'at_ns'), 20),
            (('file_dump_queries', 1, 'start_ns'), 20),
            (('operation_windows', 1, 'start_ns'), 19),
            (('operation_windows', 1, 'page'), 8),
            (('operation_windows', 1, 'worker'), 4),
            (('operation_windows', 1, 'input_ok'), False),
            (('operation_windows', 1, 'completed'), False),
            (('operation_windows', 1, 'call_count'), 2),
            (('operation_windows', 1, 'end_cursor'), 12),
        ]:
            bad = copy.deepcopy(report)
            bad[path[0]][path[1]][path[2]] = value
            with self.subTest(path=path), self.assertRaises(ValueError):
                tracer_operation_windows.validate(bad, key)
        for action in ('missing', 'extra', 'duplicate', 'order'):
            bad = copy.deepcopy(report)
            rows = bad['operation_windows']
            if action == 'missing':
                rows.pop()
            elif action == 'extra':
                rows.append(dict(rows[-1], source=4))
            elif action == 'duplicate':
                rows[1] = dict(rows[0], source=2)
            else:
                rows[0], rows[1] = rows[1], rows[0]
            with self.subTest(action=action), self.assertRaises(ValueError):
                tracer_operation_windows.validate(bad, key)
        left = copy.deepcopy(report)
        for row in left['file_comparisons']:
            row['left'], row['right'] = row['right'], row['left']
        left_key = copy.deepcopy(key)
        left_key['file_action_windows']['goal_cases.a008.1'][0] = 'left'
        tracer_operation_windows.validate(left, left_key)
        with self.assertRaises(ValueError):
            tracer_operation_windows.validate(left, key)
        empty = copy.deepcopy(key)
        empty['file_action_windows']['goal_cases.a008.1'][2] = []
        with self.assertRaises(ValueError):
            tracer_operation_windows.validate(report, empty)
        tracer_operation_windows.validate(report, key)


if __name__ == '__main__':
    unittest.main()
