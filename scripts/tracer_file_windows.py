"""Independent saved-baseline / real-operation / fresh-observation requirements."""


def validate(report, inventory):
    from tracer_operation_windows import dump_start
    from tracer_history import _observer_sources
    from tracer_file_domains import checkpoint
    from tracer_refusal_inputs import KINDS
    states, _, workers = _observer_sources(report, inventory)
    rows, events = report['file_requests'], report['helper_history']
    error = 'original file before/operation/after window mismatch'
    fields = {'source', 'kind', 'page', 'worker', 'case', 'start_ns', 'start_cursor', 'end_ns', 'end_cursor', 'receiver_ok', 'input_source', 'domain', 'input_ok', 'refused', 'response_ok'}
    if type(rows) is not list:
        raise ValueError(error)
    invocations, scopes = [0], []
    for event in events:
        if event['event']=='scenario_start':scopes.append(event['invocation'])
        elif event['event']=='scenario_end':scopes.pop()
        invocations.append(scopes[-1] if scopes else 0)
    pending, calls = report['file_pending_inputs'], report['observer_calls']
    if type(pending) is not list or any(v not in ('initial', 'observer') for v in inventory['file_pending_sources'].values()):
        raise ValueError(error)
    required = {('declaration.initial.pending', None)} if any(c['id'] == 'declaration_cases.c001.p001' for c in report['cases']) else set()
    required.update((c['site'], n) for n,c in enumerate(calls, 1) if c['kind'] == 'declaration.wait_card')
    pending_end = 0
    for n, row in enumerate(pending, 1):
        keys = {'source', 'site', 'call', 'page', 'worker', 'case', 'start_ns', 'end_ns', 'start_cursor', 'end_cursor', 'query_ok', 'receiver_ok'}
        if type(row) is not dict or set(row) != keys or any(type(row[k]) is not int for k in keys-{'site', 'call', 'case', 'query_ok', 'receiver_ok'}) or (row['call'] is not None and type(row['call']) is not int):
            raise ValueError(error)
        start, end, cursor, page = (row[k] for k in ('start_ns', 'end_ns', 'start_cursor', 'page'))
        identity = row['site'], row['call']
        if not 0 <= cursor < len(states) or identity not in required or row['source'] != n or row['start_cursor'] != row['end_cursor'] or not 0 <= start <= end <= report['duration_ns'] or page <= 0 or row['worker'] <= 0 or row['worker'] != workers[cursor].get(page) or row['query_ok'] is not True or row['receiver_ok'] is not True:
            raise ValueError(error)
        required.remove(identity)
        rule = inventory['file_pending_sources'].get(row['site'])
        owner=states[cursor][0]
        if row['case'] != (owner[2] if owner and owner[1]=='inside' else None) or start<pending_end or cursor and events[cursor-1]['at_ns']>start or cursor<len(events) and events[cursor]['at_ns']<end:
            raise ValueError(error)
        pending_end=end

        if row['call'] is None:
            if rule != 'initial' or row['case'] != 'declaration_cases.c001.p001':
                raise ValueError(error)
            checkpoint(report, {'kind':'worker.state', 'at_ns':end, 'history_cursor':cursor}, 'declaration_cases.c001.p001', 'declaration_cases.a001', 1)
        else:
            if not 1 <= row['call'] <= len(calls):
                raise ValueError(error)
            parent = calls[row['call']-1]
            inputs=parent['inputs']
            if len(inputs)!=1 or inputs[0]['page']!=page or inputs[0]['worker']!=row['worker'] or inputs[0]['history_cursor']!=cursor or inputs[0]['at_ns']>start:
                raise ValueError(error)
            if rule != 'observer' or parent['site'] != row['site'] or parent['kind'] != 'declaration.wait_card' or parent['page'] != page or not parent['start_ns'] <= start <= end <= parent['end_ns']:
                raise ValueError(error)
    if required:
        raise ValueError(error)
    previous = 0
    for index, row in enumerate(rows, 1):
        if type(row) is not dict or set(row) != fields or any(type(row[k]) is not int for k in fields-{'kind', 'case', 'receiver_ok', 'input_source', 'domain', 'input_ok', 'refused', 'response_ok'}):
            raise ValueError(error)
        start, end, cursor, page = (row[k] for k in ('start_ns', 'end_ns', 'start_cursor', 'page'))
        if not 0 <= cursor < len(states):
            raise ValueError(error)
        owner = states[cursor][0]
        case = owner[2] if owner and owner[1] == 'inside' else None
        if row['source'] != index or row['kind'] not in ('declaration.answer', 'goal.request', 'goal.accept', 'goal.configure') + KINDS or row['case'] != case or page <= 0 or row['worker'] != workers[cursor].get(page) or row['receiver_ok'] is not True or row['end_cursor'] != cursor or not previous <= start <= end <= report['duration_ns']:
            raise ValueError(error)
        if cursor and events[cursor-1]['at_ns'] > start or cursor < len(events) and events[cursor]['at_ns'] < end:
            raise ValueError(error)
        if row['kind'] == 'declaration.answer':
            if type(row['input_source']) is not int or not 1 <= row['input_source'] <= len(pending):
                raise ValueError(error)
            original = pending[row['input_source']-1]
            ordinal = sum(r['kind'] == 'declaration.answer' and r['case'] == row['case'] for r in rows[:index])
            if case == 'declaration_cases.c001.p001' and 1 <= ordinal <= 4:
                domain = ('wrong_machine', 'stale_candidate', 'replacement_data', 'duplicate_approval')[ordinal-1]
            elif case in ('declaration_cases.c003.p001', 'declaration_cases.c003.p002') and ordinal == 1:
                domain = 'late_approval'
            else:
                raise ValueError(error)
            site = 'declaration.cancel.wait_card' if domain == 'late_approval' else 'declaration.initial.pending'
            original_owner=states[original['start_cursor']][0]
            if domain=='late_approval':
                index=next(n for n,c in enumerate(report['cases']) if c['id']==row['case'])
                anchor=report['cases'][index-1]['id'] if index else ''
                owner_ok=invocations[original['start_cursor']]==invocations[cursor] and original['case'] is None and original_owner and original_owner[0]==owner[0] and original_owner[1]=='after' and original_owner[2]==anchor
            else:
                owner_ok=original['case']==row['case']
            if row['response_ok'] is not True or row['input_ok'] is not True or row['refused'] is not True or row['domain'] != domain or original['site'] != site or not owner_ok or original['page'] != page or original['worker'] != row['worker'] or original['end_ns'] > start:
                raise ValueError(error)
        previous = end
    if any(k not in ('declaration.answer', 'goal.request', 'goal.accept', 'goal.configure', 'submit.wrong_unlock', 'setup.request') + KINDS for k in inventory['file_request_windows'].values()):
        raise ValueError(error)
    captures, primary, consumed = report['file_captures'], report['primary_history'], set()
    for comparison in report['file_comparisons']:
        kind = inventory['file_request_windows'].get(comparison['site'])
        if kind is None:
            continue
        if kind not in ('declaration.answer', 'goal.request', 'goal.accept', 'goal.configure', 'submit.wrong_unlock', 'setup.request') + KINDS:
            raise ValueError(error)
        check = next(n for n,p in enumerate(primary) if p['case'] == comparison['case'] and p['id'] == f"{comparison['predicate']}.i{comparison['check_instance']:03}")
        lower = primary[check-1]['at_ns'] if check and primary[check-1]['case'] == comparison['case'] else 0
        upper = comparison['at_ns']
        operations = []
        if kind == 'submit.wrong_unlock':
            for n,event in enumerate(events):
                if event['event'] != 'call_start' or event['kind'] != 'runtime.submit':
                    continue
                end = next(e for e in events if e['event'] == 'call_end' and e['call'] == event['call'])
                owner = states[n][0]
                if event['at_ns'] >= lower and end['at_ns'] <= upper and owner and owner[2] == comparison['case']:
                    submission = next(s for s in report['submissions'] if s['call'] == event['call'])
                    if submission['kind'] != 'unlock' or submission['passphrase_role'] != 'wrong':
                        raise ValueError(error)
                    operations.append((event['at_ns'], end['at_ns'], event['page'], ('submit', event['call'])))
        else:
            operations = [(r['start_ns'],r['end_ns'],r['page'],('request',r['source'])) for r in rows if (r['kind'] == kind or kind == 'setup.request' and r['kind'] in ('setup.run','setup.collect')) and r['case'] == comparison['case'] and r['start_ns'] >= lower and r['end_ns'] <= upper]
        if len(operations) != 1:
            raise ValueError(f"{error}: {comparison['site']}")
        start, end, page, identity = operations[0]
        if identity in consumed:
            raise ValueError(error)
        consumed.add(identity)
        before, after = (captures[comparison[side]['source']-1] for side in ('right', 'left'))
        dump = captures[after['parent']-1] if after['kind'] == 'browser.store' else after
        if before['at_ns'] > start or dump_start(report, dump) < end or after['at_ns'] > upper or any(c['page'] != page for c in (before, after, dump)):
            raise ValueError(f"{error}: {comparison['site']}")

    from tracer_goal_inputs import validate as validate_goals
    validate_goals(report, inventory)

    from tracer_refusal_inputs import validate as validate_setup
    validate_setup(report, inventory)
