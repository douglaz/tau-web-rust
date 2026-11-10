"""Independent finite worker-result field comparisons and their original operation windows."""


def validate(report, inventory):
    from tracer_history import _observer_sources
    from tracer_file_domains import checkpoint
    error = 'original worker query/field/operation correspondence mismatch'
    value = report['state_inputs']
    if type(value) is not dict or set(value) != {'captures', 'uses', 'operations'}:
        raise ValueError(error)
    captures, uses, operations = (value[k] for k in ('captures', 'uses', 'operations'))
    if any(type(v) is not list for v in (captures, uses, operations)):
        raise ValueError(error)
    rules = inventory['state_comparison_sources']
    def valid_paths(paths):
        def pair(v): return type(v) is list and 2 <= len(v) <= 3 and all(type(side) is list and all(type(p) is str for p in side) for side in v)
        return pair(paths) or type(paths) is dict and set(paths) == {'by_instance'} and type(paths['by_instance']) is list and bool(paths['by_instance']) and all(pair(v) for v in paths['by_instance'])
    def valid_phase(phase):
        return phase in ('inside', 'outside') or type(phase) is str and phase.startswith('case:') and any(c['id'] == phase[5:] for c in inventory['cases'])
    kinds = ('run', 'collect', 'reload', 'goal.drive', 'goal.turn', 'declaration.outcome', 'binding.prepare', 'file:setup.request', 'file:setup.message', 'window:hold.evidence', 'window:main.hidden')
    for rule in rules.values():
        if type(rule) is not dict or set(rule) != {'sources', 'paths', 'transform', 'result', 'operation', 'page_role', 'operations'} or type(rule['sources']) is not list or not 2 <= len(rule['sources']) <= 3 or not valid_paths(rule['paths']) or type(rule['result']) is not bool or rule['transform'] not in ('identity', 'goal_usage', 'failed_append') or rule['page_role'] not in ('tracer', 'served', 'invocation') or rule['operation'] not in kinds:
            raise ValueError(error)
        for source in rule['sources']:
            if type(source) is not list or not 3 <= len(source) <= 4 or type(source[0]) is not str or source[1] not in ('once', 'each', 'saved') or not valid_phase(source[2]) or len(source) == 4 and type(source[3]) is not str:
                raise ValueError(error)
    states, pages, workers = _observer_sources(report, inventory)
    events = report['helper_history']
    invocations, stack = [0], []
    for event in events:
        if event['event'] == 'scenario_start':
            stack.append(event['invocation'])
        elif event['event'] == 'scenario_end':
            stack.pop()
        invocations.append(stack[-1] if stack else 0)

    def interval(row):
        if any(type(row[k]) is not int for k in ('page', 'worker', 'start_ns', 'end_ns', 'start_cursor', 'end_cursor')):
            raise ValueError(error)
        cursor, end_cursor, start, end, page = (row[k] for k in ('start_cursor', 'end_cursor', 'start_ns', 'end_ns', 'page'))
        if not 0 <= cursor <= end_cursor < len(states) or not 0 <= start <= end <= report['duration_ns'] or page <= 0 or row['worker'] <= 0 or row['worker'] != workers[cursor].get(page) or row['receiver_ok'] is not True:
            raise ValueError(error)
        if cursor and events[cursor-1]['at_ns'] > start or end_cursor < len(events) and events[end_cursor]['at_ns'] < end:
            raise ValueError(error)

    fields = {'site', 'source', 'page', 'worker', 'case', 'start_ns', 'end_ns', 'start_cursor', 'end_cursor', 'receiver_ok', 'query_ok'}
    previous = 0
    for index, row in enumerate(captures, 1):
        if type(row) is not dict or set(row) != fields or type(row['source']) is not int or type(row['site']) is not str:
            raise ValueError(error)
        interval(row)
        owner = states[row['start_cursor']][0]
        if row['query_ok'] is not True or not owner or row['source'] != index or row['case'] != (owner[2] if owner[1] == 'inside' else None) or row['start_cursor'] != row['end_cursor'] or row['start_ns'] < previous:
            raise ValueError(error)
        previous = row['end_ns']
    fields = {'source','site','kind','page','worker','case','start_ns','end_ns','start_cursor','end_cursor','receiver_ok','input_ok','completed','dispatches','successor','session','script_items'}
    previous_operation_end=0
    for index,row in enumerate(operations,1):
        if type(row) is not dict or set(row)!=fields or type(row['source']) is not int or row['source']!=index or type(row['site']) is not str or row['kind'] not in ('run','collect','reload','goal.drive','goal.turn') or row['completed'] is not True or row['input_ok'] is not True or type(row['dispatches']) is not int or row['dispatches']!=1 or type(row['script_items']) is not int or row['script_items']<0:
            raise ValueError(error)
        interval(row)
        cursor,until=row['start_cursor'],row['end_cursor'];owner=states[cursor][0]
        if not owner or row['case']!=(owner[2] if owner[1]=='inside' else None) or states[until][0]!=owner or invocations[until]!=invocations[cursor] or row['start_ns']<previous_operation_end:
            raise ValueError(error)
        if row['kind']=='reload':
            if row['site'] not in inventory['state_reload_sites'] or type(row['successor']) is not int or row['successor']<=0 or row['successor']==row['worker'] or row['successor']!=workers[until].get(row['page']) or row['script_items']!=0 or row['session'] is not None:
                raise ValueError(error)
        elif row['successor'] is not None:raise ValueError(error)
        previous_operation_end=row['end_ns']
    from tracer_state_reloads import validate as validate_reloads
    validate_reloads(report,inventory)
    from tracer_state_operations import validate as validate_operations
    resolved_operations=validate_operations(report,inventory)
    primary = report['primary_history']
    expected = [(p, p['id'].rsplit('.i', 1)[0], rules[p['id'].rsplit('.i', 1)[0]]) for p in primary if p['id'].rsplit('.i', 1)[0] in rules]
    if len(uses) != len(expected):
        raise ValueError(error)
    fields = {'predicate', 'sources', 'paths', 'transform', 'result', 'comparisons', 'case', 'at_ns', 'history_cursor', 'check_ns', 'check_cursor', 'instance'}
    previous, consumed = 0, set()
    for row, (check, predicate, rule) in zip(uses, expected, strict=True):
        if type(row) is not dict or set(row) != fields or any(type(row[k]) is not int for k in ('instance', 'at_ns', 'history_cursor', 'check_ns', 'check_cursor')) or type(row['result']) is not bool:
            raise ValueError(error)
        instance, at, cursor = (row[k] for k in ('instance', 'at_ns', 'history_cursor'))
        paths = rule['paths']
        if type(paths) is dict:
            if not 1 <= instance <= len(paths['by_instance']): raise ValueError(error)
            paths = paths['by_instance'][instance-1]
        if row['predicate'] != predicate or row['case'] != check['case'] or instance < 1 or check['id'] != f'{predicate}.i{instance:03}' or row['check_ns'] != check['at_ns'] or row['check_cursor'] != check['history_cursor'] or row['paths'] != paths or row['transform'] != rule['transform'] or row['result'] is not rule['result'] or rule['transform'] not in ('identity', 'goal_usage', 'failed_append'):
            raise ValueError(error)
        if not previous <= at <= check['at_ns'] or cursor != row['check_cursor'] or not 0 <= cursor < len(states):
            raise ValueError(error)
        owner, invocation = states[cursor][0], invocations[cursor]
        inputs = []
        for side, descriptor in enumerate(rule['sources']):
            site, mode, phase = descriptor[:3]
            if mode not in ('once', 'each', 'saved') or not valid_phase(phase):
                raise ValueError(error)
            candidates = []
            for capture in captures:
                c = capture['start_cursor']
                o = states[c][0]
                if capture['site'] == site and invocations[c] == invocation and o and o[0] == owner[0] and (o[1] == 'inside' and o[2] == owner[2] if phase == 'inside' else o[1] == 'after' if phase == 'outside' else o[1] == 'inside' and o[2] == phase[5:]):
                    candidates.append(capture)
            n = instance-1 if mode == 'each' else 0
            if n >= len(candidates):
                raise ValueError(error)
            capture = candidates[n]
            if type(row['sources']) is not list or len(row['sources']) != len(rule['sources']) or type(row['sources'][side]) is not int or row['sources'][side] != capture['source'] or capture['end_ns'] > at:
                raise ValueError(error)
            if len(descriptor)==4:
                checkpoint(report, {'kind':'worker.state','at_ns':capture['end_ns'],'history_cursor':capture['end_cursor']}, capture['case'], descriptor[3], instance if mode=='each' else 1)
            consumed.add(capture['source'])
            inputs.append(capture)
        if len({c['source'] for c in inputs}) != len(inputs):
            raise ValueError(error)
        role = ('served' if invocation == 2 else 'tracer') if rule['page_role'] == 'invocation' else rule['page_role']
        if role not in ('tracer', 'served') or any(c['page'] != pages[c['start_cursor']].get(role) for c in inputs):
            raise ValueError(error)
        if row['comparisons'] != expected_comparisons(rule, row):
            raise ValueError(f'{error}: original inner comparison {predicate}')
        if rule['sources'][0][2] == 'inside' and len(rule['sources'][0])==3:
            anchor, ordinal = (rule['sources'][0][3] if len(rule['sources'][0]) == 4 else predicate), instance
            if rule['sources'][0][1] == 'saved':
                first = next(p for p in primary if p['case'] == check['case'] and rules.get(p['id'].rsplit('.i', 1)[0], {}).get('sources', [[None]])[0][0] == rule['sources'][0][0])
                anchor, ordinal = first['id'].rsplit('.i', 1)
                ordinal = int(ordinal)
            checkpoint(report, {'kind':'worker.state', 'at_ns':inputs[0]['end_ns'], 'history_cursor':inputs[0]['end_cursor']}, check['case'], anchor, ordinal)
        before, after = inputs[1]['end_ns'], inputs[0]['start_ns']
        operation = rule['operation']
        if before > after or operation not in kinds:
            raise ValueError(error)
        if operation == 'binding.prepare':
            matching=[]
            for n,event in enumerate(events):
                if event['event'] != 'call_start' or event['kind'] != operation or event['page'] != inputs[1]['page'] or event['at_ns'] < before or invocations[n] != invocation or states[n][0] != owner: continue
                end=next(((i,e) for i,e in enumerate(events[n+1:],n+1) if e['event']=='call_end' and e['call']==event['call']),None)
                if end is not None and end[1]['at_ns'] <= after and workers[end[0]+1].get(inputs[0]['page']) == inputs[0]['worker']: matching.append(event)
            if len(matching) != 1: raise ValueError(f'{error}: {predicate}')
        elif operation in ('file:setup.request', 'file:setup.message', 'window:hold.evidence', 'window:main.hidden'):
            candidates = [op for op in report['operation_windows' if operation.startswith('window:') else 'file_requests'] if op['case'] == check['case'] and (op['site'] == operation[7:] if operation.startswith('window:') else op['kind'] in ('setup.run', 'setup.collect') if operation == 'file:setup.request' else op['kind'] == 'setup.message')]
            if instance > len(candidates):
                raise ValueError(error)
            op = candidates[instance-1]
            if op['page'] != inputs[1]['page'] or op['worker'] != inputs[1]['worker'] or not before <= op['start_ns'] <= op['end_ns'] <= after:
                raise ValueError(f'{error}: {predicate}')
        else:
            if operation=='declaration.outcome':
                candidates=report['observer_calls']
                if not any(op['kind']==operation and op['page']==inputs[1]['page'] and before<=op['start_ns']<=op['end_ns']<=after for op in candidates):raise ValueError(f'{error}: {predicate}')
            else:
                references=rule['operations']
                if type(references) is not list or not references:raise ValueError(error)
                indices=set();previous_end=before
                for reference in references:
                    if type(reference) is not list or not 2<=len(reference)<=3 or any(type(p) is not str for p in reference):raise ValueError(error)
                    source,mode=reference[:2]
                    n={'once':1,'each':instance,'first_of_pair':instance*2-1,'second_of_pair':instance*2}.get(mode)
                    if n is None:raise ValueError(error)
                    case=reference[2] if len(reference)==3 else check['case']
                    if source.startswith('reload_site:'):
                        matching=[i for i,op in enumerate(operations) if op['kind']=='reload' and op['site']==source[12:] and op['case']==case]
                        if len(matching)!=1 or n!=1:raise ValueError(error)
                        index=matching[0]
                    else:
                        matching=[r['index'] for r in resolved_operations if r['source']==source and r['case']==case and r['instance']==n]
                        if len(matching)!=1:raise ValueError(error)
                        index=matching[0]
                    op=operations[index]
                    if index in indices or op['page']!=inputs[1]['page'] or op['worker']!=inputs[1]['worker'] or not previous_end<=op['start_ns']<=op['end_ns']<=after:
                        raise ValueError(f'{error}: {predicate}')
                    indices.add(index);previous_end=op['end_ns']
        previous = at
    if len(consumed) != len(captures):
        raise ValueError(error)


def expected_comparisons(rule, row):
    sources, paths = row['sources'], row['paths']
    def component(a,b,left,right,transform,result):
        return dict(sources=[sources[a],sources[b]],paths=[left,right],transform=transform,result=result)
    if rule['transform']=='failed_append':
        if len(sources)!=3 or len(paths)!=3 or any(len(p)!=1 for p in paths) or rule['result'] is not True:
            raise ValueError('invalid original failed-append comparison domain')
        expected=[component(0,1,paths[0][0],paths[1][0],'append_fail_stop',True),component(0,2,paths[0][0]+'/records',paths[2][0],'identity',True)]
    else:
        if len(sources)!=2 or len(paths)!=2 or not paths[0] or len(paths[0])!=len(paths[1]) or rule['result'] is False and len(paths[0])!=1:
            raise ValueError('invalid original field comparison domain')
        expected=[component(0,1,l,r,rule['transform'],rule['result']) for l,r in zip(paths[0],paths[1],strict=True)]
    values=row['comparisons']
    if type(values) is not list or any(type(v) is not dict or set(v)!={'sources','paths','transform','result'} or type(v['sources']) is not list or len(v['sources'])!=2 or any(type(n) is not int for n in v['sources']) or type(v['paths']) is not list or len(v['paths'])!=2 or any(type(p) is not str for p in v['paths']) or type(v['transform']) is not str or type(v['result']) is not bool for v in values):
        raise ValueError('invalid original comparison evidence')
    return expected
