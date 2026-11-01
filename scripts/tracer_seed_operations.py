"""Independent source rules for seed-gate allocation and refusal operations."""


def validate(report, inventory, states, pages, workers):
    def fail():
        raise ValueError('original seed operation source, operand or invocation mismatch')
    cases = {case['id']: case for case in inventory['cases']}
    execution = list(cases) if report['mode'] == 'full' else report['plan']['expected_execution']
    expected = {}
    for identity in execution:
        case, program = cases[identity], []
        counters = {'seed_cases.a012': 0, 'seed_cases.a023': 0, 'seed_cases.a026': 0, 'seed_cases.a013': 0}
        for predicate in case['assertions']:
            if predicate not in counters:
                continue
            index = counters[predicate]
            counters[predicate] += 1
            if predicate == 'seed_cases.a013':
                site = 'seed.create.refused_dispatch' if case['site_id'] == 'seed_cases.c002' else 'seed.reentry.displayed_refusal' if index == 0 else 'seed.reentry.answering_refusal'
                program.extend((site, operation, None) for operation in ('inspect','run','collect','inspect'))
            else:
                if predicate == 'seed_cases.a012':
                    site = 'seed.failed_append.allocations' if case['site_id'] == 'seed_cases.c004' else 'seed.create.display_allocations' if index < 3 else 'seed.create.mismatch_allocations'
                    index %= 3
                else:
                    site = 'seed.completion.first_allocations' if predicate == 'seed_cases.a023' else 'seed.completion.next_allocations'
                if index >= 3:
                    fail()
                program.append((site, 'allocate', ('machines','passes','handoffs')[index]))
        expected[identity] = program
    history, invocations, stack = report['helper_history'], [0], []
    for event in history:
        if event['event'] == 'scenario_start':
            stack.append(event['invocation'])
        elif event['event'] == 'scenario_end':
            stack.pop()
        invocations.append(stack[-1] if stack else 0)
    previous = 0
    operations = report.get('seed_operations')
    if type(operations) is not list:
        fail()
    for event in operations:
        if type(event) is not dict or set(event) != {'site','operation','family','worker','page','ok','case','at_ns','history_cursor'}:
            fail()
        at, cursor, identity, page = event['at_ns'], event['history_cursor'], event['case'], event['page']
        if type(at) is not int or type(cursor) is not int or not 0 <= cursor < len(states) or not previous <= at <= report['duration_ns'] or event['ok'] is not True or type(page) is not int or type(event['worker']) is not int:
            fail()
        if identity not in cases or states[cursor][0] != ('seed_cases.run','inside',identity) or invocations[cursor] != cases[identity]['invocation'] or pages[cursor].get('tracer' if cases[identity]['invocation'] == 1 else 'served') != page or workers[cursor].get(page) != event['worker']:
            fail()
        if cursor and history[cursor-1]['at_ns'] > at or cursor < len(history) and history[cursor]['at_ns'] < at:
            fail()
        program = expected.get(identity, [])
        if not program or (event['site'], event['operation'], event['family']) != program.pop(0):
            fail()
        previous = at
    if any(expected.values()):
        fail()
