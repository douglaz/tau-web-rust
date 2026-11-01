"""Independent consumer for original fixture captures, triggers, uses and retirements."""


def _fields(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        raise ValueError('invalid original fixture input schema')


def _number(value):
    if type(value) is not int or not 0 <= value <= 18446744073709551615:
        raise ValueError('invalid original fixture input coordinate')
    return value


def _array(value):
    if type(value) is not list:
        raise ValueError('invalid original fixture input sequence')
    return value


def validate(report, inventory, states, positions, pages, workers):
    execution = [case['id'] for case in inventory['cases']] if report['mode'] == 'full' else report['plan']['expected_execution']
    program = [group for group in inventory['fixture_source_program'] if group['case'] in execution]
    expected = [(group, source) for group in program for source in group['sources']]
    sources = _array(report.get('fixture_inputs'))
    if len(sources) != len(expected):
        raise ValueError('original fixture input capture multiplicity mismatch')
    history = report['helper_history']
    calls = report['observer_calls']
    stamps, events, retired = [], [], {}

    def location(value, owner=None, root=None):
        at, cursor, order = (_number(value[key]) for key in ('at_ns', 'history_cursor', 'order'))
        if cursor >= len(states) or at > report['duration_ns'] or cursor and history[cursor-1]['at_ns'] > at or cursor < len(history) and history[cursor]['at_ns'] < at or owner is not None and states[cursor][0] != owner or root is not None and positions[cursor] != (root, True):
            raise ValueError('original fixture input caller/cursor mismatch')
        return cursor

    def receiver(value, owner, root):
        cursor = location(value, owner, root)
        page, worker = _number(value['page']), _number(value['worker'])
        if value['ok'] is not True or pages[cursor].get('tracer') != page or workers[cursor].get(page) != worker:
            raise ValueError('original fixture input receiver/page/worker mismatch')

    for ordinal, (source, (group, want)) in enumerate(zip(sources, expected), 1):
        _fields(source, ('source', 'name', 'case', 'capture', 'value', 'triggers', 'uses', 'retired'))
        name, case, scenario = want['name'], group['case'], group['scenario']
        if _number(source['source']) != ordinal or source['name'] != name or source['case'] != case:
            raise ValueError('original fixture input source/order mismatch')
        case_index = execution.index(case)

        def owner(position):
            if position == 'before':
                return scenario, 'after', execution[case_index-1] if case_index else ''
            return scenario, position, case

        capture = source['capture']
        _fields(capture, ('order', 'at_ns', 'history_cursor', 'worker', 'page', 'ok'))
        receiver(capture, owner(want['capture_owner']), want['capture_root'])
        if retired.get(name, 0) >= capture['order']:
            raise ValueError('original fixture input source lifetime overlaps successor')
        stamps.append(capture)
        events.append((capture['order'], case + ':' + name + '.capture'))
        last_order, last_time = capture['order'], capture['at_ns']
        triggers = _array(source['triggers'])
        if len(triggers) != len(want['triggers']):
            raise ValueError('original fixture input trigger multiplicity mismatch')
        for trigger, expected_trigger in zip(triggers, want['triggers']):
            _fields(trigger, ('order', 'at_ns', 'history_cursor', 'worker', 'page', 'ok', 'event', 'payload_ok', 'operation'))
            if trigger['payload_ok'] is not True or trigger['operation'] != expected_trigger['operation']:
                raise ValueError('original fixture dispatch payload/operation mismatch')
            receiver(trigger, owner(expected_trigger['owner']), expected_trigger['root'])
            if trigger['event'] != expected_trigger['event'] or trigger['worker'] != capture['worker'] or trigger['page'] != capture['page'] or trigger['order'] <= last_order or trigger['at_ns'] < last_time:
                raise ValueError('original fixture input capture/trigger lineage mismatch')
            events.append((trigger['order'], case + ':' + name + '.' + expected_trigger['event']))
            stamps.append(trigger)
            last_order, last_time = trigger['order'], trigger['at_ns']
        value = source['value']
        if name in ('relay', 'packet', 'execs', 'probes'):
            _number(value)
        elif name == 'gate':
            if type(value) is not str or value != want['value']:
                raise ValueError('original fixture gate arm parameter mismatch')
        elif name in ('command', 'key', 'end', 'refusal', 'exec', 'socket', 'read.stop', 'read.actual', 'read.later'):
            if value is not None:
                raise ValueError('unsafe original fixture private operand output')
        else:
            raise ValueError('unknown original fixture input name')
        uses = _array(source['uses'])
        if want['active']:
            inside = name in ('relay', 'packet') or want['capture_owner'] == 'inside'
            use_owner = owner('inside' if inside else want['capture_owner'])
            found = [(index, call) for index, call in enumerate(calls, 1) if call['site'] == want['use_site'] and states[call['start_cursor']][0] == use_owner]
            if len(found) != 1:
                raise ValueError('original fixture input use caller multiplicity mismatch')
            call_index, call = found[0]
            if len(uses) != len(call['polls']):
                raise ValueError('original fixture input use multiplicity mismatch')
            for usage, poll in zip(uses, call['polls']):
                _fields(usage, ('order', 'at_ns', 'history_cursor', 'call', 'attempt', 'ok'))
                cursor = location(usage, use_owner, want["use_root"])
                _number(usage['call'])
                attempt = _number(usage['attempt'])
                if usage['ok'] is not True or usage['call'] != call_index or attempt != poll['attempt'] or usage['order'] <= last_order or usage['at_ns'] < last_time or not poll['start_ns'] <= usage['at_ns'] <= poll['end_ns'] or usage['history_cursor'] != poll['start_cursor'] or pages[cursor].get('tracer') != capture['page'] or capture['page'] not in workers[cursor] or (workers[cursor].get(capture['page']) == capture['worker']) == want['successor_worker']:
                    raise ValueError('original fixture input use/operand/lifetime mismatch')
                predicate = call['causal_matches'][attempt-1]
                if predicate['at_ns'] < usage['at_ns']:
                    raise ValueError('fixture input after original predicate')
                operands = predicate['operands']
                binding = 'from' if name in ('relay', 'packet') else 'baseline' if name in ('execs', 'probes') else None
                if binding is not None and (type(operands[binding]) is not int or operands[binding] != value):
                    raise ValueError('original fixture captured operand substitution')
                stamps.append(usage)
                last_order, last_time = usage['order'], usage['at_ns']
            if name == 'execs':
                occurrence = want['value']['occurrence']
                producers = [call for call in calls if call['kind'] == 'job.wait_launch' and call['causal_input'][0]['source_job'] == 'inference.sent_read' and call['causal_input'][0]['occurrence'] == occurrence]
                if len(producers) != 1 or producers[0]['end_ns'] > capture['at_ns']:
                    raise ValueError('sent-read capture without original job producer')
        elif uses:
            raise ValueError('inactive original fixture operand was used')
        retirement = source['retired']
        _fields(retirement, ('order', 'at_ns', 'history_cursor'))
        cursor = location(retirement)
        if retirement['order'] <= last_order or retirement['at_ns'] < last_time or states[cursor][0] not in (owner('inside'), owner('after')):
            raise ValueError('original fixture input retirement outside source lifetime')
        stamps.append(retirement)
        retired[name] = retirement['order']
    expected_events = [group['case'] + ':' + event for group in program for event in group['events']]
    if [event for _, event in sorted(events)] != expected_events:
        raise ValueError('original fixture source capture/trigger event order mismatch')
    previous = 0
    for ordinal, stamp in enumerate(sorted(stamps, key=lambda value: value['order']), 1):
        if stamp['order'] != ordinal or stamp['at_ns'] < previous:
            raise ValueError('original fixture input event multiplicity/monotonicity mismatch')
        previous = stamp['at_ns']
