import copy
import json
from pathlib import Path
import unittest

import tracer_view_domains


class ViewInputs(unittest.TestCase):
    def test_original_attempt_and_consumer(self):
        fixture = json.loads((Path(__file__).resolve().parents[1] / 'tracer/testdata/view-inputs.json').read_text())
        report, key = fixture['report'], fixture['inventory']
        tracer_view_domains.validate(report, key)
        for path, value in [
            (('captures', 0, 'query_ok'), False),
            (('captures', 0, 'page'), 8),
            (('captures', 0, 'in_use'), True),
            (('captures', 0, 'attempt'), 2),
            (('uses', 1, 'sources'), [2]),
            (('uses', 1, 'result'), False),
            (('uses', 2, 'at_ns'), 9),
            (('uses', 0, 'history_cursor'), 5),
        ]:
            changed = copy.deepcopy(report)
            changed['view_inputs'][path[0]][path[1]][path[2]] = value
            with self.subTest(path=path), self.assertRaises(ValueError):
                tracer_view_domains.validate(changed, key)
        for field in ('captures', 'uses'):
            for extra in (False, True):
                changed = copy.deepcopy(report)
                if extra:
                    changed['view_inputs'][field].append(changed['view_inputs'][field][0])
                else:
                    changed['view_inputs'][field].pop()
                with self.subTest(field=field, extra=extra), self.assertRaises(ValueError):
                    tracer_view_domains.validate(changed, key)


if __name__ == '__main__':
    unittest.main()
