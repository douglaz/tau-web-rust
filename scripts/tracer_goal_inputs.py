"""Independent requirements for original session operands and actual goal operations."""


def _policy(kind, scope, case, n):
    if kind == 'goal.configure':
        return ('runtime_configuration', False) if scope == 'goal_cases.run' and case == 'goal_cases.c001.p001' and 1 <= n <= 4 else None
    if kind == 'goal.accept':
        if case == 'goal_cases.c009.p001':
            return {1: ('accept_pending', True), 2: ('accept_settled', False)}.get(n)
        return 'accept', False
    if kind != 'goal.request':
        return None
    if scope == 'goal_admission_cases.run':
        return 'goal', False
    if case == 'goal_cases.c001.p001':
        return ('invalid_url', True) if 1 <= n <= 3 else ('runtime_field', True) if 4 <= n <= 7 else ('wrong_session', True) if n == 8 else ('second_goal', True) if n == 9 else None
    if case == 'goal_cases.c012.p001':
        return ('old_session', True) if n == 1 else ('document_goal', False) if n in (2, 3) else None
    if case == 'goal_cases.c007.p001':
        return 'document_goal', False
    if case in ('goal_cases.c004.p001', 'goal_cases.c005.p001', 'goal_cases.c006.p001', 'goal_cases.c008.p001'):
        return 'goal', False
    return None


def _restored_goal_preparation(owner):
    return owner[0] == 'goal_admission_cases.run' and owner[1] == 'after' and owner[2] in (
        'goal_admission_cases.c001.p003', 'goal_admission_cases.c001.p004',
        'goal_admission_cases.c001.p005')


def validate(report, key):
    from tracer_history import _observer_sources
    from tracer_history import _same_json
    error = 'original file before/operation/after window mismatch'
    states, pages, workers = _observer_sources(report, key)
    events = report['helper_history']
    invocations, stack = [0], []
    for e in events:
        if e['event'] == 'scenario_start': stack.append(e['invocation'])
        elif e['event'] == 'scenario_end': stack.pop()
        invocations.append(stack[-1] if stack else 0)
    def context(cursor):
        owner = states[cursor][0]
        if owner is None: raise ValueError(error)
        return (*owner, invocations[cursor])
    selected = None if report['mode'] == 'full' else report['plan']['expected_execution']
    cases = [c for c in key['cases'] if selected is None or c['id'] in selected]
    rebind = report['goal_rebind_inputs']
    expected = [c for c in cases if c['site_id'] == 'goal_admission_cases.c001']
    if type(rebind) is not list or len(rebind) != len(expected): raise ValueError(error)
    fields = {'source', 'page', 'worker', 'start_ns', 'end_ns', 'start_cursor', 'end_cursor', 'present', 'receiver_ok', 'query_ok'}
    for n, (row, case) in enumerate(zip(rebind, expected), 1):
        if type(row) is not dict or set(row) != fields or any(type(row[k]) is not int for k in fields - {'present', 'receiver_ok', 'query_ok'}): raise ValueError(error)
        start, end, cursor, page = (row[k] for k in ('start_ns', 'end_ns', 'start_cursor', 'page'))
        position = cases.index(case)
        before = cases[position-1]['id'] if position else ''
        actual = next(c for c in report['cases'] if c['id'] == case['id'])
        if not 0 <= cursor < len(states) or row['source'] != n or row['end_cursor'] != cursor or any(row[k] is not True for k in ('present', 'receiver_ok', 'query_ok')) or page <= 0 or row['worker'] <= 0 or workers[cursor].get(page) != row['worker'] or pages[cursor].get('tracer') != page or context(cursor) != ('goal_admission_cases.run', 'after', before, case['invocation']) or not 0 <= start <= end <= actual['start_ns'] or cursor and events[cursor-1]['at_ns'] > start or cursor < len(events) and events[cursor]['at_ns'] < end: raise ValueError(error)
    pool = sorted([(row['start_ns'], row['end_ns'], {'kind': kind, 'source': n}, row) for kind, rows in [('query', report['goal_session_inputs']), ('rebind', rebind)] for n, row in enumerate(rows, 1)], key=lambda p: p[1])
    previous = 0
    for start, end, _, row in pool:
        if type(start) is not int or type(end) is not int or not previous <= start <= end: raise ValueError(error)
        previous = end
    required = {}
    for rule in key['file_goal_operation_sources']:
        if type(rule) is not list or len(rule) != 4 or any(type(v) is not str for v in rule[:3]) or type(rule[3]) is not list or len(rule[3]) != 2: raise ValueError(error)
        scope, site, phase, (program, count) = rule
        if program not in ('pairs', 'requests', 'accepts', 'old_then_pairs', 'successor', 'card') or phase not in ('inside', 'before') or type(count) is not int or count < 0: raise ValueError(error)
        for position, case in enumerate(cases):
            if case['site_id'] != site: continue
            if program == 'successor' and int(case['id'].rsplit('.p', 1)[1]) % 3 == 1: continue
            owner, anchor = ('after', cases[position-1]['id'] if position else '') if phase == 'before' else ('inside', case['id'])
            entries = required.setdefault((scope, owner, anchor, case['invocation']), [])
            if program == 'old_then_pairs': entries.append('goal.request')
            for _ in range(count):
                if program == 'card': entries.extend(['goal.request']*3 + ['goal.request','goal.configure']*4 + ['goal.request']*2)
                else: entries.extend(['goal.request', 'goal.accept'] if program in ('pairs', 'successor', 'old_then_pairs') else ['goal.request'] if program == 'requests' else ['goal.accept'])
    observed, ordinals = {}, {}
    for row in report['file_requests']:
        if not row['kind'].startswith('goal.'): continue
        kind, cursor = row['kind'], row['start_cursor']
        owner = context(cursor)
        observed.setdefault(owner, []).append(kind)
        index = owner, kind
        ordinals[index] = ordinals.get(index, 0) + 1
        policy = _policy(kind, owner[0], owner[2] if owner[1] == 'inside' else '', ordinals[index])
        if policy is None: raise ValueError(error)
        domain, fresh_refused = policy
        refused = fresh_refused or _restored_goal_preparation(owner)
        origin = next((p for p in reversed(pool) if p[1] <= row['start_ns']), None)
        if origin is None or not _same_json(row['input_source'], origin[2]) or row['domain'] != domain or row['input_ok'] is not True or row['refused'] is not refused or row['response_ok'] is not True or origin[3]['page'] != row['page']: raise ValueError(error)
        if domain == 'old_session':
            if origin[2]['kind'] != 'query' or context(origin[3]['start_cursor'])[2] != 'goal_cases.c011.p001' or origin[3]['worker'] == row['worker']: raise ValueError(error)
        elif origin[3]['worker'] != row['worker']: raise ValueError(error)
    if observed != required: raise ValueError(error + ': goal operation source program')
