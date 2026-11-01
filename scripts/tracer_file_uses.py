"""Independent required installation operands and operation observation windows."""


def validate(report, inventory):
    from tracer_operation_windows import dump_start
    from tracer_history import _observer_sources, _same_json
    error = 'original constructor installation/operation window mismatch'
    states, pages, workers = _observer_sources(report, inventory)
    events, captures = report['helper_history'], report['file_captures']
    value = report['file_uses']
    if type(value) is not dict or set(value) != {'puts', 'operations', 'binding'}:
        raise ValueError(error)
    puts, previous = value['puts'], 0
    if type(puts) is not list:
        raise ValueError(error)
    for row in puts:
        if type(row) is not dict or set(row) != {'input', 'provenance', 'page', 'case', 'at_ns', 'history_cursor', 'end_ns', 'end_cursor', 'operation'} or any(type(row[k]) is not int for k in ('page', 'at_ns', 'history_cursor')):
            raise ValueError(error)
        at, cursor, operand = row['at_ns'], row['history_cursor'], row['input']
        if any(type(row[k]) is not int for k in ('end_ns','end_cursor')) or row['end_cursor']!=cursor or not at<=row['end_ns']<=report['duration_ns'] or not _same_json(row['operation'],dict(recipe_ok=True,completed=True)):raise ValueError(error)

        if not 0 <= cursor < len(states) or not previous <= at <= report['duration_ns'] or row['page'] <= 0:
            raise ValueError(error)
        owner = states[cursor][0]
        case = owner[2] if owner and owner[1] == 'inside' else None
        if row['case'] != case or type(operand) is not dict or set(operand) != {'site', 'source', 'kind', 'page', 'ok'} or type(operand['ok']) is not bool or any(type(operand[k]) is not str for k in ('kind', 'site')):
            raise ValueError(error)
        if operand['kind']=='unbound':
            if not _same_json(operand,dict(site='',source=None,kind='unbound',page=None,ok=False)):raise ValueError(error)
        elif operand['kind'] not in ('constructor','browser.store','browser.dump') or type(operand['source']) is not int or operand['source']<1 or type(operand['page']) is not int or operand['page']<0:raise ValueError(error)
        if cursor and events[cursor-1]['at_ns'] > at or cursor < len(events) and events[cursor]['at_ns'] < at:
            raise ValueError(error)
        previous = at
    invocations, stack = [0], []
    for event in events:
        if event['event'] == 'scenario_start':
            stack.append(event['invocation'])
        elif event['event'] == 'scenario_end':
            stack.pop()
        invocations.append(stack[-1] if stack else 0)
    windows, consumed = set(), set()
    for capture in captures:
        site = capture['site']
        if capture['kind'] != 'constructor' or site not in inventory['file_put_windows']:
            continue
        cursor = capture['history_cursor']
        role = inventory['file_put_windows'][site]
        if role == 'invocation':
            role = 'served' if invocations[cursor] == 2 else 'tracer'
        if role=='prepare':
            calls=[]
            for event in events[:cursor]:
                if event['event']=='call_start':calls.append(event)
                elif event['event']=='call_end':calls.pop()
            if not calls or calls[-1]['kind']!='binding.prepare':raise ValueError(error)
            page=calls[-1]['page']
        else:
            page = pages[cursor][role]
        matching = [p for p in puts if p['input']['source'] == capture['source']]
        if len(matching) != 1 or (site, cursor) in windows or cursor >= len(events):
            raise ValueError(error)
        windows.add((site, cursor))
        next_event = events[cursor]
        if next_event['event'] != 'call_start' or next_event['kind'] != 'runtime.worker' or next_event['page'] != page:
            raise ValueError(error)
        row = matching[0]
        index=puts.index(row)
        if index in consumed:raise ValueError(error)
        consumed.add(index)
        operand = dict(site=site, source=capture['source'], kind='constructor', page=0, ok=True)
        if not _same_json(row['input'], operand) or row['history_cursor'] != cursor or row['page'] != page or row['case'] != capture['case'] or not capture['at_ns'] <= row['at_ns'] <= next_event['at_ns']:
            raise ValueError(error)
    execution = [c['id'] for c in inventory['cases']] if report['mode'] == 'full' else report['plan']['expected_execution']
    count = inventory['file_operation_sources']['goal.harness_job_refusal'] if any(c.startswith('goal_cases.c004.') for c in execution) else 0
    operations = value['operations']
    if type(operations) is not list or len(operations) != count:
        raise ValueError(error)
    saved_session=None
    if count:
        first=next(c for c in report['cases'] if c['id']=='goal_cases.c001.p001')
        original=[]
        for n,row in enumerate(report['goal_session_inputs'],1):
            cursor=row['end_cursor'];owner=states[cursor][0]
            if row['end_ns']<=first['start_ns'] and owner and owner[0]=='goal_cases.run' and owner[1]=='after':original.append((n,row))
        if len(original)!=1 or original[0][1]['present'] is not True or original[0][1]['receiver_ok'] is not True or original[0][1]['document'] is not None:raise ValueError(error)
        saved_session=original[0][0]
    previous = 0
    fields = {'source', 'site', 'page', 'worker', 'case', 'start_ns', 'end_ns', 'start_cursor', 'end_cursor', 'ok', 'refused', 'session_source'}
    for n, operation in enumerate(operations, 1):
        if type(operation) is not dict or set(operation) != fields or any(type(operation[k]) is not int for k in ('source', 'page', 'worker', 'start_ns', 'end_ns', 'start_cursor', 'end_cursor', 'session_source')):
            raise ValueError(error)
        start, end, cursor = (operation[k] for k in ('start_ns', 'end_ns', 'start_cursor'))
        if not 0 <= cursor < len(states):
            raise ValueError(error)
        page = pages[cursor].get('tracer')
        if operation['source'] != n or operation['session_source'] != saved_session or operation['site'] != 'goal.harness_job_refusal' or operation['case'] != 'goal_cases.c004.p001' or page is None or operation['page'] != page or operation['worker'] != workers[cursor].get(page) or operation['ok'] is not True or operation['refused'] is not True or operation['end_cursor'] != cursor or not previous <= start <= end <= report['duration_ns']:
            raise ValueError(error)
        if cursor and events[cursor-1]['at_ns'] > start or cursor < len(events) and events[cursor]['at_ns'] < end:
            raise ValueError(error)
        comparison = next(c for c in report['file_comparisons'] if c['site'] == 'goal_cases.a036.1' and c['check_instance'] == n)
        before, after = (captures[comparison[side]['source']-1] for side in ('right', 'left'))
        dump = captures[after['parent']-1]
        if before['at_ns'] > start or dump_start(report, dump) < end or comparison['at_ns'] < after['at_ns'] or any(c['history_cursor'] != cursor or c['page'] != page for c in (before, after, dump)) or comparison['history_cursor'] != cursor or comparison['case'] != operation['case']:
            raise ValueError(error)
        previous = end
    expected = [(case,n) for case in inventory['cases'] if case['site_id']=='binding_cases.c002' and case['id'] in execution for n in range(1,inventory['file_operation_sources']['binding.authentication'][case['invocation']-1]+1)]
    rows=value['binding']
    if type(rows) is not list or len(rows)!=len(expected):raise ValueError(error)
    previous=0
    for index,(row,(case,ordinal)) in enumerate(zip(rows,expected),1):
        fields={'source','ordinal','page','worker','case','start_ns','end_ns','start_cursor','end_cursor','ok'}
        if type(row) is not dict or set(row)!=fields or any(type(row[k]) is not int for k in fields-{'case','ok'}):raise ValueError(error)
        start,end,cursor=(row[k] for k in ('start_ns','end_ns','start_cursor'))
        if not 0<=cursor<len(states):raise ValueError(error)
        role='served' if case['invocation']==2 else 'tracer'
        page=pages[cursor].get(role)
        if row['source']!=index or row['ordinal']!=ordinal or row['case']!=case['id'] or page is None or row['page']!=page or row['worker']!=workers[cursor].get(page) or row['ok'] is not True or row['end_cursor']!=cursor or not previous<=start<=end<=report['duration_ns']:raise ValueError(error)
        if cursor and events[cursor-1]['at_ns']>start or cursor<len(events) and events[cursor]['at_ns']<end:raise ValueError(error)
        if role=='tracer':
            for site in ('reader.call.binding.authentication_index','reader.call.binding.authentication_journal'):
                reads=[r for r in report['reader_roots'] if r['site']==site and states[r['history_cursor']][0][2]==case['id']]
                read=reads[ordinal-1]
                capture=captures[read['file_input']['source']-1];dump=captures[capture['parent']-1]
                check=next(p for p in report['primary_history'] if p['case']==case['id'] and p['id']==f'binding_cases.a007.i{ordinal:03}')
                read_cursor=cursor+int(site=='reader.call.binding.authentication_journal')
                if events[cursor]['event']!='check' or events[cursor]['id']!='binding.machine_identity.schema' or dump_start(report, dump)<end or read['end_ns']>check['at_ns'] or any(c['history_cursor']!=read_cursor or c['page']!=page for c in (dump,capture)) or read['history_cursor']!=read_cursor or check['history_cursor']!=cursor+1:raise ValueError(error)
        previous=end

    import tracer_installations
    tracer_installations.validate(report, inventory, consumed)
