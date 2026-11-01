"""Independent original file observation and comparison requirements."""


def validate(report, inventory):
    from tracer_history import _observer_sources, validate_reader_callers
    validate_primary(report,inventory)
    error = 'original file invocation/comparison domain mismatch'
    requirements = inventory if report['mode'] == 'full' else report['plan']
    execution = [c['id'] for c in inventory['cases']] if report['mode'] == 'full' else requirements['expected_execution']
    states, pages, _ = _observer_sources(report, inventory)
    events = report['helper_history']
    contexts, stack, preparation_pages = [None], [], {}
    for index, event in enumerate(events):
        if event['event'] == 'scenario_start': stack.append(event['invocation'])
        elif event['event'] == 'scenario_end': stack.pop()
        owner, prepare = states[index+1]
        contexts.append(owner+(stack[-1],prepare) if owner else None)
        if event['event']=='call_start' and event['kind']=='binding.prepare':
            preparation_pages[contexts[-1]]=event['page']

    def before(owner):
        scenario, _, case, invocation, prepare = owner
        index = execution.index(case)
        return scenario, 'after', execution[index-1] if index else '', invocation, prepare

    expected = {}
    def captures(owner, site, kind, count=1, once=False):
        for kind in ('browser.dump','browser.store') if kind == 'browser.store' else (kind,):
            key = owner, site, kind
            expected[key] = max(expected.get(key,0),count) if once else expected.get(key,0)+count

    for source in validate_reader_callers(report, inventory):
        site, window = inventory['file_read_sources'][source['site']][:2]
        if window in ('current','reload'):
            captures(source['owner']+(source['invocation'],source['prepare']),site,'browser.store')
    comparisons, rules = {}, inventory['file_comparison_sources']
    for case in inventory['cases']:
        if case['id'] not in execution: continue
        scenario = case['site_id'].split('.')[0]+'.run'
        if scenario == 'lifecycle_cases.run' and scenario not in requirements['scenario_scopes']:
            scenario = 'lifecycle_cases.selected'
        owner = scenario, 'inside', case['id'], case['invocation'], None
        for predicate in case['assertions']:
            for site, rule in sorted(rules.items()):
                if rule['predicate'] != predicate: continue
                comparisons.setdefault(owner,[]).append(site)
                for side in ('left','right'):
                    origin, kind, mode, phase = rule[side][:4]
                    if mode in ('constructor','reader'): continue
                    captures(before(owner) if phase=='before' else owner,origin,kind,once=mode=='once')
    preparation_counts, contracts = {}, {}
    for row in requirements['invocation_root_sequences']:
        base = row['scenario'],row['owner'],row['case'] or '',row['invocation'],None
        for domain in row['prepare_domains']:
            ordinal = preparation_counts[base] = preparation_counts.get(base,0)+1
            if domain['active']:
                owner = base[:4]+(ordinal,)
                comparisons[owner] = ['binding.contracts.observe','binding.contracts.branch']
                contracts[owner] = domain['contracts']
    for rule in inventory['file_observation_sources']:
        site, kind, scenario = rule[:3]
        if kind == 'scope':
            for invocation in range(1,requirements['scenario_scopes'].get(scenario,0)+1):
                case = next((c for c in inventory['cases'] if c['invocation']==invocation and c['id'] in execution and c['site_id'].split('.')[0] in rule[3]),None)
                if case: captures(before((scenario,'inside',case['id'],invocation,None)),site,rule[4])
        elif kind == 'case':
            for case in inventory['cases']:
                if case['site_id']==rule[3] and case['id'] in execution:
                    captures((scenario,rule[4],case['id'],case['invocation'],None),site,rule[6],rule[5])
        else:
            raise ValueError(error)
    observed = {}
    for capture in report['file_captures']:
        cursor, at = capture['history_cursor'],capture['at_ns']
        owner, kind = contexts[cursor],capture['kind']
        if owner is None or capture['case']!=(owner[2] if owner[1]=='inside' else None) or cursor and events[cursor-1]['at_ns']>at or cursor<len(events) and events[cursor]['at_ns']<at:
            raise ValueError(error)
        if kind!='constructor':
            role = 'served' if (owner[0] in ('seed_cases.run','setup_cases.run','mode_cases.run','binding_cases.run') and owner[3]==2 or owner[2]=='main.c022.p001') else 'tracer'
            expected_page = preparation_pages.get(owner) if owner[4] is not None else pages[cursor].get(role)
            if capture['page']!=expected_page: raise ValueError(error)
        observed.setdefault((owner,capture['site'],kind),[]).append(capture)
    actual = {k:len(v) for k,v in observed.items() if k[2]!='constructor'}
    if actual!=expected:
        different = [str((k,expected.get(k,0),actual.get(k,0))) for k in expected.keys() | actual.keys() if expected.get(k,0)!=actual.get(k,0)]
        raise ValueError(error+': capture census '+', '.join(sorted(different)[:3]))
    for (owner,site,kind), stores in observed.items():
        if kind!='browser.store': continue
        dumps = observed.get((owner,site,'browser.dump'),[])
        if len(stores)!=len(dumps) or any(s['parent']!=d['source'] for s,d in zip(stores,dumps)): raise ValueError(error)
    previous, occurrences = 0, {}
    fields = {'site','predicate','left','right','result','name_ok','controls','control_ok','case','at_ns','history_cursor','check_ns','check_cursor','check_instance'}
    if type(report.get('file_comparisons')) is not list: raise ValueError(error)
    for comparison in report['file_comparisons']:
        if type(comparison) is not dict or set(comparison)!=fields or any(type(comparison[k]) is not int for k in ('at_ns','history_cursor','check_ns','check_cursor','check_instance')): raise ValueError(error)
        cursor, checked, at, check_at = (comparison[k] for k in ('history_cursor','check_cursor','at_ns','check_ns'))
        if not 0<=cursor<=checked<len(contexts): raise ValueError(error)
        owner, site = contexts[cursor],comparison['site']
        want = comparisons.get(owner,[])
        rule = rules.get(site)
        if not want or site!=want.pop(0) or rule is None or comparison['predicate']!=rule['predicate'] or comparison['name_ok'] is not True or comparison['control_ok'] is not True or not previous<=at<=check_at<=report['duration_ns'] or contexts[checked]!=owner or comparison['case']!=(owner[2] if owner[1]=='inside' else None):
            raise ValueError(error)
        changed = contracts.get(owner,False)
        if type(comparison['result']) is not bool or comparison['result']!=(not (rule['policy']=='contracts' and changed)): raise ValueError(error)
        n = occurrences.get((owner,site),0)
        if comparison['controls']!=([None,n+1] if rule['policy']=='variant' else [None,None]): raise ValueError(error)
        if comparison['check_instance']!=(n+1 if rule['predicate'] else 0): raise ValueError(error)
        operands = []
        for side in ('left','right'):
            origin, kind, mode, phase = rule[side][:4]
            values = observed.get((before(owner) if phase=='before' else owner,origin,kind),[])
            ordinal = n if mode=='each' else 0
            if ordinal>=len(values): raise ValueError(error)
            original, value = values[ordinal], comparison[side]
            if mode=='each' and rule['predicate']:
                checkpoint(report,original,owner[2],rule[side][4] if len(rule[side])>4 else rule['predicate'],n+1)
            unchanged = not changed if rule['policy']=='contracts' and side=='left' else n==0 if rule['policy']=='variant' and side=='right' else not owner[2].endswith('.p002') if rule['policy']=='staging' and side=='left' else True
            if type(value) is not dict or set(value)!={'source','site','kind','page','ok'} or any(type(value[k]) is not int for k in ('source','page')) or any(value[k]!=original[k] for k in ('source','site','kind','page')) or type(value['ok']) is not bool or value['ok']!=unchanged or original['at_ns']>at:
                raise ValueError(error)
            operands.append(original)
        if rule['policy']!='contracts':
            fresh = 0 if rule['left'][2]=='each' else 1
            if operands[1-fresh]['source']>=operands[fresh]['source']: raise ValueError(error)
        occurrences[owner,site] = n+1
        previous = at
    if any(comparisons.values()): raise ValueError(error)


def validate_primary(report, inventory):
    from tracer_history import _auxiliary_states
    error='original primary predicate checkpoint mismatch'
    expected=[]
    for case in report['cases']:
        spec=next(s for s in inventory['cases'] if s['id']==case['id'])
        sites=list(spec['assertions'])
        if case['id'].startswith('seed_cases.c001.') and report['mode']=='targeted' and report['plan']['name'].startswith('seed.') and report['plan']['name']!='seed.all':sites=[s for s in sites if s!='seed_cases.a005']
        if 'variants' in spec:sites=list(spec['variants']['sequences'][case['branches'][spec['variants']['branch']]])
        if 'optional' in spec and case['branches'][spec['optional']['branch']]=='locked':sites.insert(sites.index(spec['optional']['after'])+1,spec['optional']['site'])
        if 'dynamic' in spec:
            dynamic=spec['dynamic'];at=sites.index(dynamic['site']);sites=[s for s in sites if s!=dynamic['site']];sites[at:at]=[dynamic['site']]*report['domains'][dynamic['domain']]['count']
        counts={}
        for site in sites:
            counts[site]=counts.get(site,0)+1
            expected.append((case['id'],f'{site}.i{counts[site]:03}'))
    rows=report.get('primary_history');events=report['helper_history'];states=_auxiliary_states(events)
    if type(rows) is not list or len(rows)!=len(expected):raise ValueError(error)
    previous=0
    for row,(case,identity) in zip(rows,expected):
        if type(row) is not dict or set(row)!={'case','id','at_ns','history_cursor'} or type(row['at_ns']) is not int or type(row['history_cursor']) is not int:raise ValueError(error)
        at,cursor=row['at_ns'],row['history_cursor']
        if not 0<=cursor<len(states) or not previous<=at<=report['duration_ns']:raise ValueError(error)
        owner=states[cursor][0]
        if row['case']!=case or row['id']!=identity or owner is None or owner[1:]!=('inside',case) or cursor and events[cursor-1]['at_ns']>at or cursor<len(events) and events[cursor]['at_ns']<at:raise ValueError(error)
        previous=at


def checkpoint(report, original, case, predicate, instance, checks=()):
    error='original file source checkpoint/window mismatch'
    rows=report.get('primary_history');identity=f'{predicate}.i{instance:03}'
    if type(rows) is not list:raise ValueError(error)
    index=next((i for i,r in enumerate(rows) if r['case']==case and r['id']==identity),None)
    if index is None:raise ValueError(error)
    target=rows[index]
    lower=rows[index-1]['at_ns'] if index and rows[index-1]['case']==case else next(c['start_ns'] for c in report['cases'] if c['id']==case)
    cursor,until=original['history_cursor'],target['history_cursor'];events=report['helper_history'];at=original['at_ns']
    if not lower<=at<=target['at_ns'] or not 0<=cursor<=until<=len(events) or until-cursor!=len(checks) or any(e['event']!='check' or type(c) is not str or e['id']!=c for e,c in zip(events[cursor:until],checks)):raise ValueError(error)
    if cursor and events[cursor-1]['at_ns']>at or cursor<len(events) and events[cursor]['at_ns']<at:raise ValueError(error)
    if original['kind']=='browser.store':checkpoint(report,report['file_captures'][original['parent']-1],case,predicate,instance,checks)
