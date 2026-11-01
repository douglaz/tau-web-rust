"""Source-derived original page-view query and consumer correspondence."""


def validate(report, inventory):
    from tracer_history import _observer_sources
    from tracer_file_domains import checkpoint

    error = 'original page view query/input/predicate correspondence mismatch'
    states, pages, _ = _observer_sources(report, inventory)
    expected, uses, runtime, stack = {}, {}, {}, []

    def owner_case(cursor):
        owner = states[cursor][0]
        return owner[2] if owner and owner[1] == 'inside' else None

    def capture_key(row):
        return tuple(row[k] for k in ('kind', 'site', 'call', 'attempt', 'slot', 'case'))

    def source(kind, site, call, attempt, slot, in_use, page, cursor, start, end, anchor=None):
        fields = dict(kind=kind, site=site, call=call, attempt=attempt, slot=slot,
                      in_use=in_use, page=page, case=owner_case(cursor))
        descriptor = capture_key(fields)
        if descriptor in expected:
            raise ValueError(error)
        expected[descriptor] = fields, start, end, cursor, anchor

    def use(kind, call, attempt, sources, result, start, end, cursor):
        descriptor = kind, call, attempt
        if descriptor in uses:
            raise ValueError(error)
        bound=kind in ('main.a004','main.a014','main.a093','main.a097','main.a100','seed_cases.a022')
        uses[descriptor] = dict(kind=kind, call=call, attempt=attempt, sources=sources,
                                result=result, ok=True, check_ns=end if bound else None,
                                check_cursor=cursor if bound else None,
                                check_instance=(attempt if kind=='main.a100' else 1) if bound else None), start, end, cursor, None

    for index, event in enumerate(report['helper_history']):
        kind = event['event']
        if kind == 'call_start':
            stack.append((event['call'], event['kind']))
            if event['kind'] == 'runtime.settled':
                inputs = next(r for r in report['runtime_inputs'] if r['call'] == event['call'])
                runtime[event['call']] = dict(page=event['page'], in_use=inputs['parameters']['in_use'], attempts=[])
        elif kind == 'call_end':
            call, name = stack.pop()
            if name == 'runtime.settled':
                runtime[call].update(end=event['at_ns'], cursor=index)
        elif kind in ('attempt', 'check', 'poll') and stack and stack[-1][1] == 'runtime.settled':
            frame = runtime[stack[-1][0]]
            if kind == 'attempt':
                frame['attempts'].append(dict(number=event['ordinal'], start=event['at_ns'], cursor=index+1))
            elif kind == 'poll':
                frame['attempts'][-1].update(poll=event['at_ns'], poll_cursor=index, ready=event['ready'])
            elif event['id'] == 'runtime.store.not_failed':
                frame['attempts'][-1]['check'] = event['at_ns']
            elif event['id'] == 'runtime.store.ready_nontransient':
                frame['ready_check'] = event['at_ns']
    for call, frame in runtime.items():
        for a in frame['attempts']:
            source('runtime', None, call, a['number'], None, frame['in_use'], frame['page'], a['cursor'], a['start'], a['check'])

    calls, rules = report['observer_calls'], inventory['view_observer_sources']
    for index, call in enumerate(calls, 1):
        if call['site'] not in rules:
            continue
        direction, slots = rules[call['site']]
        inputs = iter(call['page_inputs'])
        for n, poll in enumerate(call['polls']):
            if direction == 'after' and poll['ready']:
                continue
            lower = poll['start_ns'] if direction == 'before' else poll['end_ns']
            upper = poll['end_ns'] if direction == 'before' else call['polls'][n+1]['start_ns'] if n+1 < len(call['polls']) else call['end_ns']
            for slot in slots:
                item = next(inputs)
                if item['slot'] != slot:
                    raise ValueError(error)
                source('observer', None, index, poll['attempt'], slot, None, item['page'], item['history_cursor'], max(lower, item['at_ns']), upper)
        if next(inputs, None) is not None:
            raise ValueError(error)
    for index, row in enumerate(report['observer_prior_inputs'], 1):
        source('prior', row['site'], index, None, None, None, row['page'], row['start_cursor'], row['start_ns'], row['end_ns'])

    execution = {c['id'] for c in inventory['cases']} if report['mode'] == 'full' else set(report['plan']['expected_execution'])

    def primary(case, predicate, n=1):
        return next(r for r in report['primary_history'] if r['case'] == case and r['id'] == f'{predicate}.i{n:03}')

    for site, (case_site, role, predicate) in inventory['view_direct_sources'].items():
        for case in inventory['cases']:
            if case['site_id'] != case_site or case['id'] not in execution:
                continue
            actual = next(c for c in report['cases'] if c['id'] == case['id'])
            target = primary(case['id'], predicate)
            page_role = ('served' if case['invocation'] == 2 else 'tracer') if role == 'invocation' else role
            source('direct', site, None, None, None, None, pages[target['history_cursor']][page_role], target['history_cursor'], actual['start_ns'], target['at_ns'], (case['id'], predicate))

    value = report['view_inputs']
    if type(value) is not dict or set(value) != {'captures', 'uses'}:
        raise ValueError(error)

    def match(row, want, fields, previous):
        required, start, end, cursor, anchor = want
        if type(row) is not dict or set(row) != fields or any(type(row[k]) is not int for k in ('start_ns', 'end_ns', 'start_cursor', 'end_cursor') if k in row):
            raise ValueError(error)
        if any(type(row[k]) is not type(v) or row[k] != v for k, v in required.items()):
            raise ValueError(error)
        if 'at_ns' in row:
            if type(row['at_ns']) is not int or type(row['history_cursor']) is not int or not max(previous, start) <= row['at_ns'] <= end or row['history_cursor'] != cursor:
                raise ValueError(error)
            return row['at_ns']
        if not max(previous, start) <= row['start_ns'] <= row['end_ns'] <= end or row['start_cursor'] != cursor or row['end_cursor'] != cursor or row['query_ok'] is not True:
            raise ValueError(error)
        if anchor:
            checkpoint(report, dict(kind='view', at_ns=row['start_ns'], history_cursor=cursor), *anchor, 1)
        return row['end_ns']

    captures, previous = {}, 0
    for index, row in enumerate(value['captures'], 1):
        descriptor = capture_key(row)
        if descriptor not in expected or type(row['source']) is not int or row['source'] != index:
            raise ValueError(error)
        want = expected.pop(descriptor)
        previous = match(row, want, set(want[0]) | {'source', 'start_ns', 'end_ns', 'start_cursor', 'end_cursor', 'query_ok'}, previous)
        captures[descriptor] = row
    if expected:
        raise ValueError(error)

    def find(kind, site=None, call=None, attempt=None, slot=None):
        rows = [v for k, v in captures.items() if k[:5] == (kind, site, call, attempt, slot)]
        if len(rows) != 1:
            raise ValueError(error)
        return rows[0]

    for call, frame in runtime.items():
        for a in frame['attempts']:
            row = find('runtime', call=call, attempt=a['number'])
            use('failed', call, a['number'], [row['source']], False, row['end_ns'], a['check'], a['cursor'])
            use('ready', call, a['number'], [row['source']], a['ready'], a['check'], a['poll'], a['poll_cursor'])
        row = find('runtime', call=call, attempt=frame['attempts'][-1]['number'])
        use('returned', call, None, [row['source']], True, frame['ready_check'], frame['end'], frame['cursor'])
    finals = {}
    for index, call in enumerate(calls, 1):
        site = call['site']
        if site not in rules:
            continue
        direction, slots = rules[site]
        last = []
        for n, poll in enumerate(call['polls']):
            last = []
            for slot in slots:
                if direction == 'before':
                    row = find('observer', call=index, attempt=poll['attempt'], slot=slot)
                elif n:
                    row = find('observer', call=index, attempt=call['polls'][n-1]['attempt'], slot=slot)
                else:
                    p, prior = next((i, p) for i, p in enumerate(report['observer_prior_inputs'], 1) if p['site'] == site and p['end_cursor'] == call['start_cursor'])
                    row = find('prior', site=site, call=p)
                    if prior['view_source'] != row['source']:
                        raise ValueError(error)
                last.append(row['source'])
            use('observer', index, poll['attempt'], last, poll['ready'], poll['start_ns'], poll['end_ns'], poll['end_cursor'])
        if direction == 'after' and not call['polls'][-1]['ready']:
            last = [find('observer', call=index, attempt=call['polls'][-1]['attempt'], slot='source')['source']]
        finals.setdefault(site, []).extend((call, source) for source in last)
    for site, predicate in (('main.writer.waiter_unlocked', 'main.a097'), ('main.persistence.shown', 'main.a100')):
        for n, (call, source) in enumerate(finals.get(site, []), 1):
            check = primary(owner_case(call['end_cursor']), predicate, n)
            use(predicate, None, n, [source], True, call['end_ns'], check['at_ns'], check['history_cursor'])
    if 'main.writer.holder_and_waiter' in finals:
        pair = finals['main.writer.holder_and_waiter']
        if len(pair) != 2:
            raise ValueError(error)
        row = find('direct', site='view.main.waiter_current')
        check = primary('main.c020.p001', 'main.a094')
        use('equal', None, None, [row['source'], pair[1][1]], True, row['end_ns'], check['at_ns'], check['history_cursor'])
    direct_counts = {}
    for row in value['captures']:
        if row['kind'] != 'direct':
            continue
        predicate = inventory['view_direct_sources'][row['site']][2]
        if predicate == 'main.a094':
            continue
        n = direct_counts[predicate] = direct_counts.get(predicate, 0) + 1
        check = primary(row['case'], predicate)
        use(predicate, None, n, [row['source']], True, row['end_ns'], check['at_ns'], check['history_cursor'])
    previous = 0
    for row in value['uses']:
        descriptor = row['kind'], row['call'], row['attempt']
        if descriptor not in uses:
            raise ValueError(error)
        want = uses.pop(descriptor)
        previous = match(row, want, set(want[0]) | {'at_ns', 'history_cursor'}, previous)
    if uses:
        raise ValueError(error)
