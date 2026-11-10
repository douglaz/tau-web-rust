import copy
import json
from pathlib import Path
import unittest

import tracer_state_inputs


class WorkerResultUses(unittest.TestCase):
    def test_original_operations_outside_comparisons_are_accounted_once(self):
        f=json.loads((Path(__file__).resolve().parents[1]/'tracer/testdata/state-inputs.json').read_text())
        report,key=f['report'],f['inventory']
        key['cases'][1]['assertions'].append('goal_cases.a009')
        key['state_operation_rules'].append(['fixture.second','fixture.second','collect','goal_cases.run',['goal_cases.c004.p001'],'inside','goal_cases.a009','all',0,'tracer',0])
        report['primary_history'].append(dict(report['primary_history'][0],id='goal_cases.a009.i001',at_ns=35))
        report['state_inputs']['operations'].append(dict(report['state_inputs']['operations'][0],site='fixture.second',source=2,start_ns=30,end_ns=31))
        tracer_state_inputs.validate(report,key)
        for action in ('missing','duplicate','extra_after','same_total','cancelled'):
            bad=copy.deepcopy(report);rows=bad['state_inputs']['operations']
            if action=='missing':rows.pop()
            elif action=='duplicate':rows[1]=dict(rows[0],source=2)
            elif action=='extra_after':rows.append(dict(rows[1],source=3,start_ns=40,end_ns=41))
            elif action=='same_total':rows[1]['site']='fixture.collect'
            else:rows[1]['completed']=False
            with self.subTest(action=action),self.assertRaises(ValueError):tracer_state_inputs.validate(bad,key)
            tracer_state_inputs.validate(report,key)

    def test_failed_append_consumes_three_original_queries_across_cases(self):
        fixture = json.loads((Path(__file__).resolve().parents[1] / 'tracer/testdata/state-failed-append-inputs.json').read_text())
        report, key = fixture['report'], fixture['inventory']
        tracer_state_inputs.validate(report, key)
        for path, value in [
            (('uses', 0, 'sources'), [2,2,1]),
            (('uses', 0, 'sources'), [3,1,2]),
            (('uses', 0, 'paths'), [[''],[''],['/standing']]),
            (('captures', 0, 'case'), 'main.c008.p001'),
            (('captures', 1, 'site'), 'state.fixture.completed'),
        ]:
            bad = copy.deepcopy(report)
            bad['state_inputs'][path[0]][path[1]][path[2]] = value
            with self.subTest(path=path), self.assertRaises(ValueError):
                tracer_state_inputs.validate(bad,key)
        bad=copy.deepcopy(report)
        bad['state_inputs']['uses'][0]['comparisons'][0]['transform']='identity'
        with self.assertRaisesRegex(ValueError, 'inner comparison'):
            tracer_state_inputs.validate(bad,key)
        bad=copy.deepcopy(report)
        bad['state_inputs']['uses'][0]['comparisons'].pop()
        with self.assertRaisesRegex(ValueError, 'inner comparison'):
            tracer_state_inputs.validate(bad,key)
        bad=copy.deepcopy(report)
        bad['state_inputs']['captures'][0].update(start_ns=817,end_ns=818)
        with self.assertRaises(ValueError):tracer_state_inputs.validate(bad,key)
        tracer_state_inputs.validate(report,key)

    def test_saved_query_keeps_original_checkpoint_for_parameterized_fields(self):
        fixture = json.loads((Path(__file__).resolve().parents[1] / 'tracer/testdata/state-inputs.json').read_text())
        report, key = fixture['report'], fixture['inventory']
        rule = key['state_comparison_sources']['goal_cases.a008']
        rule['sources'][0][1] = 'saved'
        rule['paths'] = {'by_instance': [[['/records'], ['/records']], [['/standing'], ['/standing']]]}
        report['state_inputs']['uses'][0]['paths'] = [['/records'], ['/records']]
        report['state_inputs']['uses'][0]['comparisons'] = [dict(sources=[2,1],paths=['/records','/records'],transform='identity',result=True)]
        used = copy.deepcopy(report['state_inputs']['uses'][0])
        used.update(paths=[['/standing'], ['/standing']], comparisons=[dict(sources=[2,1],paths=['/standing','/standing'],transform='identity',result=True)], at_ns=26, check_ns=27, instance=2)
        report['state_inputs']['uses'].append(used)
        check = dict(report['primary_history'][0], at_ns=27, id='goal_cases.a008.i002')
        report['primary_history'].append(check)
        tracer_state_inputs.validate(report, key)
        for path, value in [('sources', [1, 1]), ('paths', [['/records'], ['/records']])]:
            bad = copy.deepcopy(report)
            bad['state_inputs']['uses'][1][path] = value
            with self.assertRaises(ValueError): tracer_state_inputs.validate(bad, key)
        bad = copy.deepcopy(report)
        bad['state_inputs']['captures'][1]['start_ns'] = 26
        with self.assertRaises(ValueError): tracer_state_inputs.validate(bad, key)
        tracer_state_inputs.validate(report, key)

    def test_query_source_fields_and_real_operation_are_required(self):
        fixture = json.loads((Path(__file__).resolve().parents[1] / 'tracer/testdata/state-inputs.json').read_text())
        report, key = fixture['report'], fixture['inventory']
        tracer_state_inputs.validate(report, key)
        for path, value in [
            (('uses', 0, 'sources'), [1, 1]),
            (('uses', 0, 'sources'), [2, 1, 3]),
            (('captures', 1, 'query_ok'), False),
            (('uses', 0, 'sources'), [1, 2]),
            (('uses', 0, 'paths'), [['/standing'], ['/standing']]),
            (('uses', 0, 'transform'), 'clear_sessions'),
            (('captures', 0, 'end_ns'), 21),
            (('captures', 1, 'start_ns'), 20),
            (('captures', 1, 'page'), 8),
            (('operations', 0, 'worker'), 4),
            (('operations', 0, 'end_ns'), 23),
        ]:
            bad = copy.deepcopy(report)
            bad['state_inputs'][path[0]][path[1]][path[2]] = value
            with self.subTest(path=path), self.assertRaises(ValueError):
                tracer_state_inputs.validate(bad, key)
        for domain in ('captures', 'uses', 'operations'):
            bad = copy.deepcopy(report)
            bad['state_inputs'][domain].pop()
            with self.subTest(domain=domain), self.assertRaises(ValueError):
                tracer_state_inputs.validate(bad, key)
        tracer_state_inputs.validate(report, key)


if __name__ == '__main__':
    unittest.main()
