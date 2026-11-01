import copy
import json
from pathlib import Path
import unittest
import tracer_state_reloads

class ReloadSources(unittest.TestCase):
    def test_exact_source_and_original_helper_interval_are_required(self):
        fixture=json.loads((Path(__file__).resolve().parents[1]/'tracer/testdata/reload-inputs.json').read_text())
        report,key=fixture['report'],fixture['inventory']
        tracer_state_reloads.validate(report,key)
        for field,value in [('site','main.rs::reload#2'),('start_cursor',1),('end_cursor',9),('page',2),('worker',2),('successor',1)]:
            bad=copy.deepcopy(report);bad['state_inputs']['operations'][0][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):tracer_state_reloads.validate(bad,key)
            tracer_state_reloads.validate(report,key)
        for action in ('missing','duplicate','direct'):
            bad=copy.deepcopy(report)
            if action=='missing':bad['state_inputs']['operations']=[]
            elif action=='duplicate':bad['state_inputs']['operations'].append(copy.deepcopy(bad['state_inputs']['operations'][0]))
            else:bad['plan']['invocation_root_sequences'][1]['reload_sources'][0]=None
            with self.subTest(action=action),self.assertRaises(ValueError):tracer_state_reloads.validate(bad,key)
            tracer_state_reloads.validate(report,key)

if __name__=='__main__':unittest.main()
