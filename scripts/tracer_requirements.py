"""Independent shell consumer of compact source placements and selection requirements."""
import copy
import json


def _applies(patterns, name):
    return any(p == name or p.endswith('.*') and name.startswith(p[:-1]) for p in patterns)


def _call(key, index, stack=()):
    if type(index) is not int or not 0 <= index < len(key['call_rules']) or index in stack:
        raise ValueError('unknown/cyclic source-call rule')
    record = key['call_rules'][index]
    fields = key['call_shapes'][record[0]]
    if len(record) != len(fields)+1:
        raise ValueError('invalid source-call arity')
    node = copy.deepcopy(dict(zip(fields, record[1:], strict=True)))
    if 'children' in node:
        node['children'] = [_call(key, child, (*stack, index)) for child in node['children']]
    if 'then' in node:
        node['then'] = _call(key, node['then'], (*stack, index))
    return node


def placements(key, name):
    result = {f: [] for f in ('helper_owner_sequences', 'observer_owner_sequences', 'submission_sources', 'runtime_source_domains')}
    programs = {}
    invocation_roots, invocation_observers = [], []
    def helper(owner, roots):
        domains = []
        for root in roots:
            if root[0] == 'call:binding.prepare':
                if len(root) < 3 or not isinstance(root[2], list) or len(root[2]) != 5:
                    raise ValueError('missing preparation source domain')
                domains.append(dict(zip(('active', 'classes', 'contracts', 'pass', 'bindings'), root[2], strict=True)))
        if any(root[0]=='call:runtime.worker' and len(root)!=6 for root in roots):raise ValueError('missing original worker source')
        return dict(owner, tokens=[r[0] for r in roots], page_operations=[r[1] if len(r)>1 else None for r in roots], reload_sources=[r[5] if len(r)>5 else None for r in roots], prepare_domains=domains)
    for modes, scenario, invocation, phase, case, root_ids, observers in key['placements']:
        roots = _roots(key, root_ids)
        if not _applies(modes, name):
            continue
        owner = dict(scenario=scenario, owner=phase, case=case)
        if roots:
            invocation_roots.append(dict(helper(owner, roots), invocation=invocation))
        if observers:
            invocation_observers.append(dict(owner, invocation=invocation, calls=[_call(key, node) for node in observers]))
        program = programs.setdefault((scenario, phase, case), ([], []))
        program[0].extend(roots)
        program[1].extend(observers)
    for (scenario, phase, case), (roots, observers) in programs.items():
        owner = dict(scenario=scenario, owner=phase, case=case)
        arguments, kinds, roles = {}, {}, {}
        for index, root in enumerate(roots):
            token, page, *rest = root + [None] * max(0, 2 - len(root))
            domain, runtime, submission = (rest + [None] * 3)[:3]
            if token != 'call:binding.prepare' and domain is not None:
                raise ValueError('preparation domain on another root')
            if runtime is not None:
                arguments[str(index)] = runtime
            if submission is not None:
                kinds[str(index)], roles[str(index)] = submission
        if roots:
            result['helper_owner_sequences'].append(helper(owner, roots))
        if observers:
            result['observer_owner_sequences'].append(dict(owner, calls=[_call(key, node) for node in observers]))
        if kinds:
            result['submission_sources'].append(dict(owner, kinds=kinds, roles=roles))
        if arguments:
            result['runtime_source_domains'].append(dict(owner, arguments=arguments))
    scopes = {}
    for modes, scope, count in key['scopes']:
        if _applies(modes, name):
            if scope in scopes:
                raise ValueError('conflicting scenario count rule')
            scopes[scope] = count
    return dict(result, invocation_root_sequences=invocation_roots, invocation_observer_sequences=invocation_observers, scenario_scopes=scopes, assertion_overrides={})


def _roots(key, references):
    result = []
    for reference in references:
        if type(reference) is not int or not 0 <= reference < len(key['root_rules']):
            raise ValueError('unknown closed root rule')
        result.append(copy.deepcopy(key['root_rules'][reference]))
    return result


def _predicate(node):
    if isinstance(node, str):
        return {'guard': node}
    if not isinstance(node, list) or not node:
        raise ValueError('unknown closed predicate rule')
    op, *args = node
    if op == 's':
        return {'seq': [_predicate(child) for child in args]}
    if op == 'c' and len(args) == 2:
        return {'call': args[0], 'at': args[1]}
    if op == 'x' and len(args) == 3:
        return {'scope': args[0], 'index': args[1], 'do': _predicate(args[2])}
    if op == '?' and len(args) == 3:
        return {'if': args[0], 'then': _predicate(args[1]), 'else': _predicate(args[2])}
    if op == '|' and len(args) == 3:
        return {'switch': args[0], 'cases': {name: _predicate(child) for name, child in args[1].items()}, 'unknown': args[2]}
    if op == '*' and len(args) == 3:
        return {'each': args[0], 'slot': args[1], 'do': _predicate(args[2])}
    raise ValueError('unknown closed predicate rule')


def _domain_type(node):
    if isinstance(node, str):
        if node not in ('boolean', 'integer', 'number', 'string', 'null'):
            raise ValueError('unknown closed domain type')
        return {'type': node}
    if not isinstance(node, list) or not node:
        raise ValueError('unknown closed domain type')
    op, *args = node
    if op in ('r', '=') and len(args) == 1:
        return {'$ref' if op == 'r' else 'const': args[0]}
    if op == 'e':
        return {'enum': args}
    if op == '|':
        return {'anyOf': [_domain_type(child) for child in args]}
    if op == 'o' and len(args) == 3:
        result = {'type': 'object', 'properties': {name: _domain_type(child) for name, child in args[0].items()}, 'required': args[1]}
        if args[2] is not None:
            result['additionalProperties'] = args[2]
        return result
    if op == 'a' and len(args) == 4:
        result = {'type': 'array', 'items': args[0] if type(args[0]) is bool else _domain_type(args[0])}
        if args[1] is not None:
            result['minItems'] = args[1]
        if args[2] is not None:
            result['maxItems'] = args[2]
        if args[3]:
            result['prefixItems'] = [_domain_type(child) for child in args[3]]
        return result
    raise ValueError('unknown closed domain type')


def read(path):
    key = json.loads(path.read_text())
    if key['schema'] != 2:
        raise ValueError('unknown independent key schema')
    key['semantic_rules'] = {name: _predicate(node) for name, node in key['predicate_rules'].items()}
    key['semantic_domain_schemas'] = {name: _domain_type(node) for name, node in key['domain_types'].items()}
    key['session_owner_templates'] = []
    for scenario, position, case, references in key['session_roots']:
        roots = _roots(key, references)
        domains = [dict(zip(('active','classes','contracts','pass','bindings'), root[2], strict=True)) for root in roots if root[0] == 'call:binding.prepare']
        key['session_owner_templates'].append(dict(scenario=scenario,position=position,case=case,tokens=[root[0] for root in roots],page_operations=[root[1] for root in roots],reload_sources=[root[5] if len(root)>5 else None for root in roots],prepare_domains=domains))
    key['fixture_source_program'] = []
    for case, scenario, operands, timeline in key['fixture_rules']:
        sources = []
        for name, owner, capture, use_site, use_root, flags, value, triggers in operands:
            if type(flags) is not int or not 0 <= flags < 4:
                raise ValueError('unknown fixture source flags')
            sources.append(dict(name=name,capture_owner=owner,capture_root=capture,use_site=use_site,use_root=use_root,active=bool(flags&1),successor_worker=bool(flags&2),value=value,triggers=[dict(zip(('event','owner','root','operation'), trigger, strict=True)) for trigger in triggers]))
        events = [sources[source]['name']+'.'+('capture','dispatch','start','end')[event] for source,event in timeline]
        key['fixture_source_program'].append(dict(case=case,scenario=scenario,sources=sources,events=events))
    for case in key['cases']:
        sites = []
        for site, count in case['predicates']:
            if type(count) is not int or not 0 < count < 100000:
                raise ValueError('invalid predicate run')
            sites.extend([site] * count)
        case['assertions'] = sites
        if 'variants' in case:
            case['variants']['sequences'] = {name: [site for site, count in runs for _ in range(count)] for name, runs in case['variants']['runs'].items()}
    for name in ('direct_observer_source_rows', 'causal_observer_sources'):
        for row in key[name]:
            row['calls'] = [_call(key, index) for index in row['calls']]
    for rows in key['observer_compositions'].values():
        for row in rows:
            row['calls'] = [_call(key, index) for index in row['calls']]
    key.update(placements(key, 'full'))
    return key


def execution_plan(selected, key):
    """Expected projection from the independent key; this never dispatches the executable."""
    selected = {name: 'all' if name in ('TAU_TRACER_MODE_CASE', 'TAU_TRACER_GOALS', 'TAU_TRACER_DELIVERY', 'TAU_TRACER_INFERENCE') else value for name, value in selected.items()}
    get = lambda name, default=None: selected.get('TAU_TRACER_' + name, default)
    family = next((name for name in ('HOLD_CASE', 'SEED_CASE', 'SETUP_CASE', 'MODE_CASE', 'GOALS', 'DELIVERY', 'INFERENCE') if get(name) is not None), None)
    if family is None:
        raise ValueError('missing selection root')
    primary, support = set(), set()
    cases = key['cases']
    for case in cases:
        identity, site = case['id'], case['site_id']
        module = site.split('.')[0]
        slot = int(identity.rsplit('p', 1)[1])
        number = int(site.rsplit('c', 1)[1])
        chosen = required = False
        if family == 'HOLD_CASE':
            choices = {'hold_cases.c001.p001': 'drop', 'hold_cases.c002.p001': 'simultaneous', 'hold_cases.c003.p001': 'stop', 'hold_cases.c004.p001': 'writer-stop', 'hold_cases.c004.p002': 'append-error', 'hold_cases.c005.p001': 'shared-stop', 'hold_cases.c006.p001': 'legacy', 'hold_cases.c007.p001': 'unreachable', 'hold_cases.c008.p001': 'destructive'}
            parts = get(family).split(',')
            name = 'hold.union' if len(parts) > 1 else 'hold.' + parts[0]
            chosen = module == 'hold_cases' and ('all' in parts or choices.get(identity) in parts)
            required = site in ('main.c001', 'main.c002')
        elif family == 'SEED_CASE':
            focus = get(family)
            name = 'seed.' + focus
            chosen = module == 'seed_cases' and (focus == 'all' or number == (4 if focus == 'failed-append' else 2))
            required = site in ('main.c001', 'main.c002') or site == 'seed_cases.c001' and focus != 'all'
        elif family == 'SETUP_CASE':
            focus = get(family)
            name = 'setup.' + focus
            chosen = module == 'setup_cases' if focus == 'all' else module in ('main', 'typed_cases', 'job_cases', 'hold_cases', 'binding_cases') and site not in ('main.c001', 'main.c002', 'main.c022')
            required = site in ('main.c001', 'main.c002')
        elif family == 'MODE_CASE':
            name = 'mode.all'
            chosen, required = module == 'mode_cases', site in ('main.c001', 'main.c002')
        elif family == 'DELIVERY':
            focus = get('DELIVERY_CASE', 'all')
            name = 'delivery.' + focus
            chosen = module == 'delivery_cases' and (focus == 'all' or focus == 'reports' and number in (9, 10) or focus == 'incomplete' and number == 7)
        elif family == 'GOALS':
            focus = get('GOAL_CASE', 'all')
            name = 'goals.' + focus
            stop = {'card': 1, 'context': 2, 'outcome': 3, 'hold': 5, 'barrier': 7, 'credential': 8, 'document_pending': 9, 'document_end': 10}.get(focus, 0)
            if focus == 'all':
                chosen = module in ('goal_admission_cases', 'goal_cases', 'declaration_cases', 'delivery_cases')
            elif focus in ('declaration', 'admission'):
                chosen = module == ('declaration_cases' if focus == 'declaration' else 'goal_admission_cases')
            else:
                chosen = module == 'goal_cases' and (number in (6, 7) if focus == 'barrier' else number == stop)
            required = bool(stop) and (module == 'goal_admission_cases' or module == 'goal_cases' and number < stop)
        else:
            phase, end, parts = get('INFERENCE_PHASE', ''), get('INFERENCE_END'), get('SESSION_END')
            name = 'inference.session-end.selection' if parts is not None else 'inference.end.' + end if end is not None else 'inference.' + (phase or 'all')
            core = site in ('inference_cases.c004', 'inference_cases.c005', 'inference_cases.c006')
            if end is not None:
                chosen = site == 'inference_cases.c007' and slot == ('lock', 'hidden', 'pagehide', 'reload', 'bfcache', 'redisplay').index(end) + 1
            elif phase == 'session-end':
                chosen = module == 'session_end_cases' and (parts is None or any(case['label'] == p[1:] if p.startswith('=') else p in case['label'] for p in parts.split(',')))
            elif phase in ('lifecycle', 'lifecycle-core', 'lifecycle-boundaries', 'lifecycle-expiry', 'lifecycle-locked', 'lifecycle-repairs'):
                chosen = {'lifecycle': module in ('lifecycle_cases', 'lifecycle_repairs'), 'lifecycle-core': module == 'lifecycle_cases', 'lifecycle-boundaries': module == 'lifecycle_cases' and number in (4, 5, 6, 11), 'lifecycle-expiry': site == 'lifecycle_cases.c010', 'lifecycle-locked': site == 'lifecycle_cases.c013', 'lifecycle-repairs': module == 'lifecycle_repairs'}[phase]
            else:
                chosen = {'': module in ('inference_cases', 'session_end_cases', 'lifecycle_cases', 'lifecycle_repairs'), 'core': core, 'dispatch': module in ('session_end_cases', 'lifecycle_cases', 'lifecycle_repairs') or site in ('inference_cases.c001', 'inference_cases.c002', 'inference_cases.c003'), 'cutoff': site in ('inference_cases.c012', 'inference_cases.c013'), 'command-intent': site == 'inference_cases.c001', 'sent-reads': site == 'inference_cases.c003'}.get(phase, False)
            required = not chosen and (core or site == 'inference_cases.c014')
        if chosen:
            primary.add(identity)
        elif required:
            support.add(identity)
    if not primary:
        raise ValueError('selection has no required cases')
    execution = [c['id'] for c in cases if c['id'] in primary | support]
    requirements = placements(key, name)
    if name == 'hold.union':
        requirements = placements(key, 'hold.all')
        last = next(i for i in reversed(execution) if i.startswith('hold_cases.'))
        for field in ('helper_owner_sequences', 'invocation_root_sequences', 'submission_sources', 'runtime_source_domains'):
            requirements[field] = [r for r in requirements[field] if r['owner'] != 'inside' or r['case'] in execution]
            for row in requirements[field]:
                if row['scenario'] == 'hold_cases.run' and row['owner'] == 'after' and (row['case'] or '').startswith('hold_cases.'):
                    row['case'] = last
        requirements['observer_owner_sequences'] = key['observer_compositions']['hold']
    elif name == 'inference.session-end.selection':
        requirements['submission_sources'] = []
        requirements['runtime_source_domains'] = []
        last = next(i for i in reversed(execution) if i.startswith('session_end_cases.'))
        owners = {('main.run', 'after', ''): dict(tokens=['call:runtime.worker'], page_operations=['new:tracer'], reload_sources=[None], prepare_domains=[])}
        for row in key['session_owner_templates']:
            position, case = row['position'], row['case']
            if position == 'after_last_selected':
                owner, anchor = 'after', last
            elif case in execution:
                index = execution.index(case)
                owner, anchor = ('after', execution[index - 1] if index else '') if position == 'before' else ('inside' if position == 'within' else 'after', case)
            else:
                continue
            target = owners.setdefault((row['scenario'], owner, anchor), dict(tokens=[], page_operations=[], reload_sources=[], prepare_domains=[]))
            for field in ('tokens', 'page_operations', 'reload_sources', 'prepare_domains'):
                target[field].extend(row[field])
        requirements['helper_owner_sequences'] = [dict(row, scenario=s, owner=o, case=c) for (s, o, c), row in sorted(owners.items())]
        requirements['invocation_root_sequences'] = [dict(row, invocation=1) for row in requirements['helper_owner_sequences']]
        requirements['observer_owner_sequences'] = key['observer_compositions']['session']
        requirements['scenario_scopes'] = {'main.run': 1, 'inference_cases.run': 1, 'session_end_cases.run': 1, 'inference_cases.no_plaintext': 1}
    if name in ('hold.union', 'inference.session-end.selection'):
        requirements['invocation_observer_sequences'] = [dict(row, invocation=1) for row in requirements['observer_owner_sequences']]
    return dict(requirements, name=name, selection=selected, expected_execution=execution, selected=[i for i in execution if i in primary], support=[i for i in execution if i in support])


def prerequisite_counts(requirements):
    counts = {}
    def add(identity, count=1):
        counts[identity] = counts.get(identity, 0) + count
    for row in requirements['helper_owner_sequences']:
        domains = iter(row['prepare_domains'])
        for token in row['tokens']:
            if token.startswith('check:'):
                add(token[6:])
            elif token == 'call:runtime.worker':
                add('runtime.worker.ready')
                add('runtime.store.ready_nontransient')
            elif token in ('call:runtime.submit', 'call:runtime.settled'):
                add('runtime.store.ready_nontransient')
            elif token == 'call:binding.prepare':
                source = next(domains)
                if source['active']:
                    if source['contracts']:
                        add('runtime.worker.ready')
                        add('runtime.store.ready_nontransient', 2)
                    add('binding.fixture_class.ready', sum(source['classes']))
                    add('binding.page.bound', source['bindings'].count(False))
                    if source['pass']:
                        add('binding.pass.allocation_identity')
            else:
                raise ValueError('unknown independent prerequisite root')
    return counts
