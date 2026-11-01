"""Independent validation of retained file baselines against original operation spans."""


def validate(report, inventory):
    from tracer_history import _observer_sources
    relations = inventory['file_comparison_relations']
    if type(relations) is not dict or set(relations) != set(inventory['file_comparison_sources']):
        raise ValueError('unclassified original file comparison')
    for site, relation in relations.items():
        valid = (relation == 'request' and site in inventory['file_request_windows'] or
                 relation == 'action' and site in inventory['file_action_windows'] or
                 relation == 'goal_refusal' and site == 'goal_cases.a036.1' and type(inventory['file_operation_sources'].get('goal.harness_job_refusal')) is int and inventory['file_operation_sources']['goal.harness_job_refusal'] > 0 or
                 relation == 'canonical_transform' and site in ('binding.contracts.observe', 'binding.contracts.branch') or
                 relation == 'pending_query' and inventory['coverage']['complete'] is False)
        if not valid:
            raise ValueError('unclassified or unverified original file comparison: ' + site)
    states, pages, workers = _observer_sources(report, inventory)
    rows, events = report['operation_windows'], report['helper_history']
    error = 'original operation/file observation window mismatch'
    fields = {'site', 'source', 'case', 'page', 'worker', 'receiver_ok', 'input_ok', 'completed', 'call_count', 'timeout_ns', 'start_ns', 'start_cursor', 'end_ns', 'end_cursor'}
    if type(rows) is not list:
        raise ValueError(error)
    invocations, stack = [0], []
    for event in events:
        if event['event'] == 'scenario_start':
            stack.append(event['invocation'])
        elif event['event'] == 'scenario_end':
            stack.pop()
        invocations.append(stack[-1] if stack else 0)
    queries = report['file_dump_queries']
    dumps = [c for c in report['file_captures'] if c['kind'] == 'browser.dump']
    if type(queries) is not list or len(queries) != len(dumps):
        raise ValueError(error)
    previous = 0
    for query, capture in zip(queries, dumps, strict=True):
        if type(query) is not dict or set(query) != {'source', 'page', 'start_ns', 'end_ns', 'start_cursor', 'end_cursor', 'query_ok', 'completed'} or any(type(query[k]) is not int for k in ('source', 'page', 'start_ns', 'end_ns', 'start_cursor', 'end_cursor')):
            raise ValueError(error)
        start, end, cursor, until = (query[k] for k in ('start_ns', 'end_ns', 'start_cursor', 'end_cursor'))
        if query['source'] != capture['source'] or query['page'] != capture['page'] or query['query_ok'] is not True or query['completed'] is not True or not previous <= start <= end <= capture['at_ns'] or not 0 <= cursor <= until <= capture['history_cursor'] < len(states):
            raise ValueError(error)
        if states[cursor][0] != states[until][0] or invocations[cursor] != invocations[until] or cursor and events[cursor-1]['at_ns'] > start or until < len(events) and events[until]['at_ns'] < end:
            raise ValueError(error)
        previous = end
    previous = 0
    for index, row in enumerate(rows, 1):
        if type(row) is not dict or set(row) != fields or type(row['site']) is not str or any(type(row[k]) is not int for k in ('source', 'page', 'worker', 'call_count', 'start_ns', 'end_ns', 'start_cursor', 'end_cursor')):
            raise ValueError(error)
        start, end, cursor, until, page = (row[k] for k in ('start_ns', 'end_ns', 'start_cursor', 'end_cursor', 'page'))
        if not 0 <= cursor <= until < len(states):
            raise ValueError(error)
        owner = states[cursor][0]
        if not owner or row['source'] != index or row['case'] != (owner[2] if owner[1] == 'inside' else None) or any(row[k] is not True for k in ('receiver_ok', 'input_ok', 'completed')) or page <= 0 or row['worker'] <= 0 or workers[cursor].get(page) != row['worker'] or not (previous <= start < end <= report['duration_ns']):
            raise ValueError(error)
        if cursor and events[cursor-1]['at_ns'] > start or until < len(events) and events[until]['at_ns'] < end:
            raise ValueError(error)
        if states[until][0] != owner or invocations[until] != invocations[cursor]:
            raise ValueError(error)
        previous = end
    consumed = set()
    rules = inventory['file_action_windows']
    captures = report['file_captures']
    for comparison in report['file_comparisons']:
        rule = rules.get(comparison['site'])
        if rule is None:
            continue
        if type(rule) is not list or len(rule) != 3 or rule[0] not in ('left', 'right') or rule[1] not in ('same', 'successor') or type(rule[2]) is not list or not rule[2]:
            raise ValueError(error)
        def capture(side):
            source = comparison[side]['source']
            if type(source) is not int or not 1 <= source <= len(captures):
                raise ValueError(error)
            return captures[source-1]
        before, after = capture(rule[0]), capture('right' if rule[0] == 'left' else 'left')
        dump = captures[after['parent']-1] if after['kind'] == 'browser.store' else after
        cursor, instance = comparison['history_cursor'], comparison['check_instance']
        owner = states[cursor][0]
        prior_end = before['at_ns']
        for descriptor in rule[2]:
            if type(descriptor) is not list or len(descriptor) != 4 or descriptor[1] not in ('once', 'each') or descriptor[2] not in ('inside', 'before'):
                raise ValueError(error)
            matching = []
            for index, row in enumerate(rows):
                c = row['start_cursor']
                original = states[c][0]
                if row['site'] != descriptor[0] or invocations[c] != invocations[cursor] or not original or original[0] != owner[0]:
                    continue
                if descriptor[2] == 'inside':
                    valid_owner = original[1] == 'inside' and original[2] == owner[2]
                else:
                    n = next(n for n, case in enumerate(report['cases']) if case['id'] == comparison['case'])
                    anchor = report['cases'][n-1]['id'] if n else ''
                    valid_owner = original[1] == 'after' and original[2] == anchor
                if valid_owner:
                    matching.append((index, row))
            n = 0 if descriptor[1] == 'once' else instance-1
            if not 0 <= n < len(matching):
                raise ValueError(error)
            index, operation = matching[n]
            if descriptor[1] == 'each' and instance > 1:
                previous_comparison = next(c for c in report['file_comparisons'] if c['site'] == comparison['site'] and c['case'] == comparison['case'] and c['check_instance'] == instance-1)
                if operation['start_ns'] < previous_comparison['at_ns']:
                    raise ValueError(error)
            expected_calls = descriptor[3]
            if expected_calls == 'seed.trigger':
                slot = int(comparison['case'].rsplit('.p', 1)[1])
                expected_calls = 4 if (slot-1)%6 == 1 else 2 if (slot-1)%6 == 5 else 1
            if type(expected_calls) is not int or expected_calls <= 0 or operation['call_count'] != expected_calls or operation['timeout_ns'] != inventory['file_action_timeouts'].get(descriptor[0]):
                raise ValueError(error)
            if not prior_end <= operation['start_ns'] <= operation['end_ns'] <= dump_start(report, dump) or before['page'] != operation['page'] or rule[1] == 'same' and after['page'] != operation['page']:
                raise ValueError(f"{error}: {comparison['site']}")
            role = 'served' if owner[0] == 'seed_cases.run' and invocations[cursor] == 2 else 'tracer'
            if rule[1] == 'successor' and after['page'] != pages[after['history_cursor']].get(role):
                raise ValueError(error)
            consumed.add(index)
            prior_end = operation['end_ns']
    for used in report['state_inputs']['uses']:
        operation=inventory['state_comparison_sources'].get(used['predicate'],{}).get('operation','')
        if not operation.startswith('window:'):continue
        site=operation[7:]
        count=inventory['state_operation_windows'].get(site)
        if type(count) is not int or count<=0:raise ValueError(error)
        matching=[(i,r) for i,r in enumerate(rows) if r['site']==site and r['case']==used['case']]
        instance=used['instance']
        if type(instance) is not int or not 1<=instance<=len(matching):raise ValueError(error)
        index,row=matching[instance-1]
        if row['call_count']!=count or row['timeout_ns']!=inventory['file_action_timeouts'].get(site):raise ValueError(error)
        consumed.add(index)
    if len(consumed) != len(rows):
        raise ValueError(f'{error}: unmatched operation')


def dump_start(report, dump):
    matches = [q for q in report['file_dump_queries'] if q['source'] == dump['source']]
    if len(matches) != 1 or type(matches[0]['start_ns']) is not int or type(matches[0]['end_ns']) is not int or not 0 <= matches[0]['start_ns'] <= matches[0]['end_ns'] <= dump['at_ns']:
        raise ValueError('original dump query source/start mismatch')
    return matches[0]['start_ns']
