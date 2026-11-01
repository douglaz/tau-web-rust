#!/usr/bin/env python3
"""Component controls for the independent helper-history consumer."""
import copy
import json
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
from tracer_history import validate_history


class History(unittest.TestCase):
    def test_displayed_comparison_result_partner_and_primary_use_are_required(self):
        from tracer_history import _validate_displayed_words
        key={'displayed_phrase_comparisons':{
            'seed.failed_append.initial_phrase':{'operands':[],'predicate':None,'partner':None},
            'seed.failed_append.reopened_phrase':{'operands':['self','seed.failed_append.initial_phrase'],'predicate':'seed_cases.a029','partner':None}}}
        report={'observer_calls':[
            dict(kind='seed.phrase',site='seed.failed_append.initial_phrase',page=1,start_ns=10,end_ns=20,start_cursor=1,end_cursor=1),
            dict(kind='seed.phrase',site='seed.failed_append.reopened_phrase',page=1,start_ns=50,end_ns=60,start_cursor=1,end_cursor=1)],
            'displayed_word_captures':[dict(call=1,page=1,ok=True,at_ns=15,history_cursor=1),dict(call=2,page=1,ok=True,at_ns=55,history_cursor=1)],
            'displayed_word_uses':[dict(call=source,other=other,partner=None,result=True,ok=True,at_ns=at,history_cursor=1,case='seed_cases.c004.p001',predicate='seed_cases.a029',instance=1,check_ns=80,check_cursor=1) for source,other,at in [(2,1,70),(1,2,71)]],
            'primary_history':[dict(case='seed_cases.c004.p001',id='seed_cases.a029.i001',at_ns=80,history_cursor=1)],
            'cases':[dict(id='seed_cases.c004.p001',start_ns=0,end_ns=100)],'helper_history':[dict(at_ns=0),dict(at_ns=100)]}
        _validate_displayed_words(report,key)
        for field,value in [('result',False),('other',2),('other',1.0),('predicate','seed_cases.a018'),('check_ns',81),('instance',2)]:
            bad=copy.deepcopy(report);bad['displayed_word_uses'][0][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):_validate_displayed_words(bad,key)
        _validate_displayed_words(report,key)

        read = copy.deepcopy(report)
        read['observer_calls'] = read['observer_calls'][:1]
        read['observer_calls'][0]['site'] = 'seed.create.initial_phrase'
        read['displayed_word_captures'] = read['displayed_word_captures'][:1]
        read['displayed_word_uses'] = read['displayed_word_uses'][:1]
        read['displayed_word_uses'][0].update(call=1, other=None, predicate='seed_cases.a014', partner=dict(kind='reader',source=1, site='reader.aux.call.seed.created.mnemonic', ok=True))
        read['primary_history'][0]['id'] = 'seed_cases.a014.i001'
        read['reader_roots'] = [dict(site='reader.call.seed.created', start_ns=25, end_ns=60)]
        key['displayed_phrase_comparisons']['seed.create.initial_phrase'] = dict(operands=['self'], predicate='seed_cases.a014', partner=['reader', 'reader.call.seed.created', 'reader.aux.call.seed.created.mnemonic'])
        _validate_displayed_words(read,key)
        for field,value in [('source',2),('source',1.0),('site','reader.aux.call.seed.envelope_finished.mnemonic'),('ok',False)]:
            bad=copy.deepcopy(read);bad['displayed_word_uses'][0]['partner'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):_validate_displayed_words(bad,key)
        _validate_displayed_words(read,key)

        collision=copy.deepcopy(read);identity='seed_cases.c001.p001'
        collision['cases'][0]['id']=identity
        collision['observer_calls'][0]['site']='seed.collision.initial_phrase'
        collision['displayed_word_uses'][0].update(case=identity,predicate='seed_cases.a001',partner=dict(kind='collision',index=1,ok=True))
        collision['primary_history'][0].update(case=identity,id='seed_cases.a001.i001')
        collision['reader_roots']=[]
        key['cases']=[dict(id=identity,site_id='seed_cases.c001',invocation=1)]
        key['displayed_phrase_comparisons']['seed.collision.initial_phrase']=dict(operands=['self'],predicate='seed_cases.a001',partner=['collision'])
        _validate_displayed_words(collision,key)
        for field,value in [('index',2),('index',1.0),('ok',False),('kind','reader')]:
            bad=copy.deepcopy(collision);bad['displayed_word_uses'][0]['partner'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):_validate_displayed_words(bad,key)

    def test_original_dom_query_and_result_must_reach_poll(self):
        from tracer_history import validate_page_queries
        key={'page_query_sources':{'goal.card.accept_visible':'true'}}
        base={'observer_calls':[{'site':'goal.card.accept_visible','page':1,'polls':[{'attempt':1,'ready':True,'start_ns':1,'end_ns':5,'start_cursor':3,'end_cursor':3}]}],
              'page_query_inputs':[{'source':1,'call':1,'attempt':1,'kind':'true','page':1,'start_ns':2,'end_ns':3,'history_cursor':3,'query_ok':True,'ready':True,'used_ns':4,'operand_ok':True,'comparison_ns':3,'comparison_count':1,'comparison_result':True}]}
        validate_page_queries(base,key)
        for field,value in [('query_ok',False),('operand_ok',False),('comparison_count',0),('comparison_count',2),('comparison_result',False),('comparison_ns',1),('ready',False),('call',2),('history_cursor',4)]:
            bad=copy.deepcopy(base);bad['page_query_inputs'][0][field]=value
            with self.assertRaisesRegex(ValueError,'query/value/predicate'):validate_page_queries(bad,key)
        bad=copy.deepcopy(base);bad['page_query_inputs']=[]
        with self.assertRaisesRegex(ValueError,'query/value/predicate'):validate_page_queries(bad,key)
        validate_page_queries(base,key)

    def test_file_observation_census_and_actual_operands(self):
        from tracer_history import validate_file_inputs
        root = Path(__file__).resolve().parent.parent
        fixture = json.loads((root / 'tracer/testdata/file-comparisons.json').read_text())
        base, key = fixture['report'], fixture['key']
        validate_file_inputs(base, key)
        mutants=[]
        missing=copy.deepcopy(base); missing['file_comparisons']=[]; mutants.append(missing)
        unused=copy.deepcopy(base); unused['file_comparisons'][0]['left']=copy.deepcopy(unused['file_comparisons'][0]['right']); mutants.append(unused)
        wrong_check=copy.deepcopy(base);wrong_check['file_comparisons'][0]['check_instance']=2;mutants.append(wrong_check)
        moved=copy.deepcopy(base);moved['file_comparisons'][0]['check_cursor']=6;mutants.append(moved)
        early=copy.deepcopy(base);early['file_captures'][2]['at_ns']=early['file_captures'][3]['at_ns']=6;mutants.append(early)
        missing=copy.deepcopy(base);missing['file_captures']=missing['file_captures'][2:]
        missing['file_captures'][0]['source']=1;missing['file_captures'][1].update(source=2,parent=1)
        mutants.append(missing)
        duplicate=copy.deepcopy(base);duplicate['file_captures'][0]['site']=duplicate['file_captures'][1]['site']='file.seed_cases.dump.005';mutants.append(duplicate)
        for bad in mutants:
            with self.assertRaisesRegex(ValueError, 'file (invocation/comparison|source checkpoint/window)'):
                validate_file_inputs(bad,key)
        validate_file_inputs(base,key)

    def test_required_file_checkpoint_and_page(self):
        from tracer_history import validate_file_inputs
        root = Path(__file__).resolve().parent.parent
        fixture = json.loads((root / 'tracer/testdata/file-checkpoints.json').read_text())
        key, base = fixture['key'], fixture['report']
        validate_file_inputs(base, key)
        old = copy.deepcopy(base)
        old['reader_roots'][0]['file_input'] = dict(source=2,kind='browser.store',site='file.seed_cases.dump.003',page=1,ok=True)
        with self.assertRaisesRegex(ValueError, 'checkpoint/page/window'):
            validate_file_inputs(old, key)
        wrong_page = copy.deepcopy(base)
        for capture in wrong_page['file_captures']: capture['page'] = 999
        wrong_page['reader_roots'][0]['file_input']['page'] = 999
        with self.assertRaisesRegex(ValueError, 'checkpoint/page/window'):
            validate_file_inputs(wrong_page, key)
        validate_file_inputs(base, key)

    def test_conditional_original_input_controls_applicability(self):
        from tracer_history import validate_settle_inputs
        root = Path(__file__).resolve().parent.parent
        fixture = json.loads((root / 'tracer/testdata/settle-inputs.json').read_text())
        for branch in ('empty','nonempty'):
            base = fixture[branch]
            validate_settle_inputs(base, fixture['key'])
            if branch == 'nonempty':
                for field, value in [('input',dict(site='file.main.dump.017',source=2,kind='browser.store',page=1,ok=True)),('page',999),('history_cursor',0)]:
                    bad=copy.deepcopy(base);bad['settle_inputs'][0]['puts'][0][field]=value
                    with self.assertRaisesRegex(ValueError, 'conditional disposition'):
                        validate_settle_inputs(bad,fixture['key'])
                bad=copy.deepcopy(base);bad['settle_inputs'][0]['puts']=[]
                with self.assertRaisesRegex(ValueError, 'conditional disposition'):
                    validate_settle_inputs(bad,fixture['key'])
            for field, value in [('settle_inputs', [])]:
                bad = copy.deepcopy(base); bad[field] = value
                with self.assertRaisesRegex(ValueError, 'conditional disposition'):
                    validate_settle_inputs(bad, fixture['key'])
            for field, value in [('empty', branch != 'empty'),('page',999),('empty_tests',0),('constructor_uses',2)]:
                bad = copy.deepcopy(base); bad['settle_inputs'][0][field] = value
                with self.assertRaisesRegex(ValueError, 'conditional disposition'):
                    validate_settle_inputs(bad, fixture['key'])
            validate_settle_inputs(base, fixture['key'])

    def setUp(self):
        root = Path(__file__).resolve().parent.parent
        self.base = json.loads((root / "tracer/testdata/helper-history.json").read_text())
        import tracer_requirements
        self.inventory = tracer_requirements.read(root / "tracer/inventory.json")

    def test_repeated_scope_boundary_cannot_reassign_a_case(self):
        root = Path(__file__).resolve().parent.parent
        base = json.loads((root / "tracer/testdata/invocation-boundary.json").read_text())
        validate_history(base, self.inventory)
        moved = copy.deepcopy(base)
        end, start = moved['helper_history'].pop(3), moved['helper_history'].pop(3)
        end['at_ns'] = start['at_ns'] = 2
        moved['helper_history'][1:1] = [end, start]
        moved['scenario_spans'][0]['end_ns'] = 2
        moved['scenario_spans'][1]['start_ns'] = 2
        with self.assertRaisesRegex(ValueError, 'caller/history owner'):
            validate_history(moved, self.inventory)
        validate_history(base, self.inventory)

    def test_file_input_pages_are_exact_integers(self):
        from tracer_history import validate_file_shapes as validate_file_inputs
        base = {'duration_ns':10, 'helper_history':[], 'file_captures':[
            {'source':1,'kind':'browser.dump','site':'','page':1,'parent':None,'ok':True,'case':None,'at_ns':1,'history_cursor':0},
            {'source':2,'kind':'browser.store','site':'','page':1,'parent':1,'ok':True,'case':None,'at_ns':2,'history_cursor':0},
            {'source':3,'kind':'constructor','site':'','page':0,'parent':None,'ok':True,'case':None,'at_ns':3,'history_cursor':0}],
            'reader_roots':[{'site':'reader.call.test','start_ns':4,'file_input':{'source':2,'kind':'browser.store','site':'','page':1,'ok':True}}]}
        validate_file_inputs(base)
        for index, values in [(0,(True,1.0)), (1,(True,1.0)), (2,(False,0.0))]:
            for value in values:
                bad = copy.deepcopy(base)
                bad['file_captures'][index]['page'] = value
                with self.assertRaisesRegex(ValueError,'reader input provenance'):
                    validate_file_inputs(bad)
        for value in (True,1.0):
            bad = copy.deepcopy(base)
            bad['reader_roots'][0]['file_input']['page'] = value
            with self.assertRaisesRegex(ValueError,'reader input provenance'):
                validate_file_inputs(bad)
        validate_file_inputs(base)

    def test_reader_cannot_cross_repeated_invocation_boundary(self):
        from tracer_history import validate_reader_callers
        key = {'cases': [{'id':'mode_cases.c001.p001','invocation':1}, {'id':'mode_cases.c001.p002','invocation':2}],
               'scenario_scopes': {'mode_cases.run':2}, 'helper_owner_sequences': [], 'invocation_root_sequences': [],
               'reader_caller_rules': [{'site':'reader.call.mode.original','scenario':'mode_cases.run','position':'before','case':'mode_cases.c001.p002','include_if':{'case':'mode_cases.c001.p002'},'within_owner_order':1,'after_prepare':0,'role':'only'}]}
        events = [dict(event=e, id=i, at_ns=t, **({'invocation':v} if v else {})) for e,i,t,v in [
            ('scenario_start','mode_cases.run',0,1), ('case_start','mode_cases.c001.p001',10,0),
            ('case_end','mode_cases.c001.p001',20,0), ('scenario_end','mode_cases.run',30,1),
            ('scenario_start','mode_cases.run',40,2), ('case_start','mode_cases.c001.p002',60,0),
            ('case_end','mode_cases.c001.p002',70,0), ('scenario_end','mode_cases.run',80,2)]]
        base = {'mode':'full','helper_history':events,'reader_roots':[{'site':'reader.call.mode.original','start_ns':50,'end_ns':51,'history_cursor':5}]}
        validate_reader_callers(base, key)
        moved = copy.deepcopy(base)
        moved['reader_roots'][0].update(start_ns=25,end_ns=26,history_cursor=3)
        with self.assertRaisesRegex(ValueError, 'reader source caller'):
            validate_reader_callers(moved,key)
        validate_reader_callers(base,key)

    def test_order_owner_domain_and_poll_controls(self):
        validate_history(self.base, self.inventory)

        bad = copy.deepcopy(self.base)
        bad["prerequisites"].sort(key=lambda item: item["id"])
        with self.assertRaisesRegex(ValueError, "caller/history order"):
            validate_history(bad, self.inventory)
        bad = copy.deepcopy(self.base)
        next(e for e in bad["helper_history"] if e["event"] == "call_start" and e["kind"] == "binding.page.bound")["worker"] = 2
        with self.assertRaisesRegex(ValueError, "foreign worker owner"):
            validate_history(bad, self.inventory)
        bad = copy.deepcopy(self.base)
        index = next(i for i, e in enumerate(bad["helper_history"]) if e["event"] == "poll" and e["call"] == 2)
        del bad["helper_history"][index]
        with self.assertRaisesRegex(ValueError, "grammar mismatch"):
            validate_history(bad, self.inventory)
        bad = copy.deepcopy(self.base)
        next(e for e in bad["helper_history"] if e["event"] == "poll" and e["call"] == 2)["ready"] = True
        with self.assertRaisesRegex(ValueError, "termination history"):
            validate_history(bad, self.inventory)
        bad = copy.deepcopy(self.base)
        next(e for e in bad["helper_history"] if e["event"] == "prepare_input")["classes"] = [True]
        with self.assertRaisesRegex(ValueError, "binding domain"):
            validate_history(bad, self.inventory)
        validate_history(self.base, self.inventory)

    def test_scenario_cannot_end_inside_its_helper(self):
        bad = copy.deepcopy(self.base)
        events = bad["helper_history"]
        end = events.pop()
        end["at_ns"] = events[-1]["at_ns"]
        events.insert(len(events) - 1, end)
        bad["scenario_spans"][0]["end_ns"] = end["at_ns"]
        with self.assertRaisesRegex(ValueError, "scenario boundary crosses active case/helper"):
            validate_history(bad, self.inventory)

    def test_source_page_lifetime(self):
        root = Path(__file__).resolve().parent.parent
        reload = json.loads((root / "tracer/testdata/helper-page-reload.json").read_text())
        replacement = json.loads((root / "tracer/testdata/helper-page-replacement.json").read_text())
        validate_history(reload, self.inventory)
        validate_history(replacement, self.inventory)
        for base, page, reason in [(reload, 2, "source page lineage relationship"), (replacement, 1, "source page lineage birth")]:
            bad = copy.deepcopy(base)
            for event in bad['helper_history']:
                if event['event'] == 'call_start' and event['call'] >= 3:
                    event['page'] = page
            with self.assertRaisesRegex(ValueError, reason):
                validate_history(bad, self.inventory)


if __name__ == "__main__":
    unittest.main()
