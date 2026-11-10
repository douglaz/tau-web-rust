import copy
import json
from pathlib import Path
import unittest

import tracer_file_windows


class RestoredGoalPreparations(unittest.TestCase):
    def test_only_original_job_preparations_refuse_duplicate_acts(self):
        from tracer_goal_inputs import _restored_goal_preparation
        for ordinal in range(1, 7):
            for phase in ('inside', 'after'):
                for scope in ('goal_admission_cases.run', 'goal_cases.run'):
                    owner = (scope, phase, f'goal_admission_cases.c001.p{ordinal:03}', 1)
                    with self.subTest(owner=owner):
                        self.assertEqual(_restored_goal_preparation(owner),
                                         scope == 'goal_admission_cases.run' and
                                         phase == 'after' and ordinal in (3, 4, 5))


class RefusalWindows(unittest.TestCase):
    def test_saved_and_fresh_sides_must_bracket_real_request(self):
        fixture = json.loads((Path(__file__).resolve().parents[1] / 'tracer/testdata/file-refusal-windows.json').read_text())
        report, key = fixture['report'], fixture['inventory']
        tracer_file_windows.validate(report, key)
        for path, value in [
            (('file_captures', 1, 'at_ns'), 21),
            (('file_captures', 2, 'at_ns'), 20),
            (('file_requests', 0, 'end_ns'), 23),
            (('file_requests', 0, 'page'), 8),
            (('file_requests', 0, 'worker'), 4),
            (('file_requests', 0, 'receiver_ok'), False),
            (('file_requests', 0, 'input_source', 'source'), 1),
            (('file_requests', 0, 'input_source', 'source'), 2.0),
            (('file_requests', 0, 'input_source', 'kind'), 'rebind'),
            (('file_requests', 0, 'response_ok'), False),
            (('file_requests', 0, 'input_ok'), False),
            (('file_requests', 0, 'refused'), True),
            (('file_comparisons', 1, 'right', 'source'), 8),
        ]:
            bad = copy.deepcopy(report)
            target = bad
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(ValueError):
                tracer_file_windows.validate(bad, key)
        bad = copy.deepcopy(report)
        bad['file_requests'].pop()
        with self.assertRaises(ValueError):
            tracer_file_windows.validate(bad, key)
        tracer_file_windows.validate(report, key)


    def test_saved_baseline_precedes_unlock_start(self):
        fixture = json.loads((Path(__file__).resolve().parents[1] / 'tracer/testdata/file-unlock-windows.json').read_text())
        report, key = fixture['report'], fixture['inventory']
        tracer_file_windows.validate(report, key)
        for path, value in [
            (('file_captures', 1, 'at_ns'), 21),
            (('file_captures', 2, 'at_ns'), 20),
            (('submissions', 0, 'passphrase_role'), 'tracer'),
            (('submissions', 0, 'kind'), 'create'),
        ]:
            bad = copy.deepcopy(report)
            target = bad
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(ValueError):
                tracer_file_windows.validate(bad, key)
        tracer_file_windows.validate(report, key)

class DeclarationInputSources(unittest.TestCase):
    fixture="declaration-refusal-inputs.json"
    def test_original_pending_source_and_finite_refusal_inputs(self):
        fixture=json.loads((Path(__file__).resolve().parents[1]/'tracer/testdata'/self.fixture).read_text())
        report,key=fixture['report'],fixture['inventory']
        tracer_file_windows.validate(report,key)
        for path,value in [
            (('file_pending_inputs',0,'query_ok'),False),
            (('file_pending_inputs',0,'worker'),4),
            (('file_pending_inputs',0,'end_ns'),21),
            (('file_requests',0,'input_source'),2),
            (('file_requests',0,'input_ok'),False),
            (('file_requests',0,'refused'),False),
            (('file_requests',0,'domain'),'stale_candidate'),
        ]:
            bad=copy.deepcopy(report);bad[path[0]][path[1]][path[2]]=value
            with self.subTest(path=path),self.assertRaises(ValueError):tracer_file_windows.validate(bad,key)
        tracer_file_windows.validate(report,key)


class LateDeclarationInputSources(DeclarationInputSources):
    fixture="declaration-late-inputs.json"


if __name__ == '__main__':
    unittest.main()
