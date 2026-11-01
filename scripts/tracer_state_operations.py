"""Independent original source-call requirements for State operations."""

ERROR = 'original State operation source/instance/operand census mismatch'


def _assertions(spec, actual, report):
    sites = list(spec['assertions'])
    if spec['id'].startswith('seed_cases.c001.') and report['mode'] == 'targeted' and report['plan']['name'].startswith('seed.') and report['plan']['name'] != 'seed.all':
        sites = [s for s in sites if s != 'seed_cases.a005']
    if 'variants' in spec:
        variant = spec['variants']
        sites = list(variant['sequences'][actual['branches'][variant['branch']]])
    if 'optional' in spec:
        optional = spec['optional']
        branch = actual['branches'][optional['branch']]
        if branch == 'locked': sites.insert(sites.index(optional['after'])+1, optional['site'])
        elif branch != 'unopened': raise ValueError(ERROR)
    if 'dynamic' in spec:
        dynamic = spec['dynamic']; domain = report['domains'][dynamic['domain']]
        if not 2 <= domain['count'] <= domain['bound']: raise ValueError(ERROR)
        at = sites.index(dynamic['site']); sites = [s for s in sites if s != dynamic['site']]
        sites[at:at] = [dynamic['site']]*domain['count']
    counts, result = {}, []
    for site in sites:
        counts[site] = counts.get(site,0)+1
        result.append(f'{site}.i{counts[site]:03}')
    return result


def _pattern(pattern, identity):
    return identity.startswith(pattern[:-1]) if pattern.endswith('*') else pattern == identity


def validate(report, inventory):
    from tracer_history import _observer_sources
    rules = inventory['state_operation_rules']
    specs = {c['id']:c for c in inventory['cases']}
    execution = list(specs) if report['mode']=='full' else report['plan']['expected_execution']
    actual = {c['id']:c for c in report['cases']}
    required = []
    for rule in rules:
        if type(rule) is not list or len(rule)!=11:
            raise ValueError(ERROR)
        source, site, kind, scenario, patterns, phase, anchor, mode, order, role, script_count = rule
        if any(type(s) is not str for s in (source,site,kind,scenario,phase,anchor,role)) or kind not in ('run','collect','goal.drive','goal.turn') or type(patterns) is not list or not patterns or any(type(p) is not str or not any(_pattern(p,c) for c in specs) for p in patterns) or phase not in ('inside','before_case') or not (mode in ('all','odd','even') if type(mode) is str else type(mode) is list and bool(mode) and all(type(n) is int and n>0 for n in mode)) or type(order) is not int or order<0 or role not in ('tracer','served','invocation') or type(script_count) is not int or script_count<0:
            raise ValueError(ERROR)
        for case_index, identity in enumerate(execution):
            if not any(_pattern(p,identity) for p in patterns):continue
            spec=specs[identity]
            ordinal=0; matched=0
            for anchor_index, assertion in enumerate(_assertions(spec,actual[identity],report)):
                if assertion.rsplit('.i',1)[0]!=anchor:continue
                ordinal+=1
                include = mode=='all' or mode=='odd' and ordinal%2==1 or mode=='even' and ordinal%2==0 if type(mode) is str else ordinal in mode
                if include:
                    matched+=1
                    required.append(dict(case_index=case_index,phase=phase,anchor_index=anchor_index,order=order,instance=matched,spec=spec,rule=rule,anchor=assertion))
            if not matched:raise ValueError(ERROR+': missing source anchor '+source)
    required.sort(key=lambda r:(r['case_index'],r['phase']=='inside',r['anchor_index'],r['order']))
    observed=[(i,r) for i,r in enumerate(report['state_inputs']['operations']) if r['kind']!='reload']
    if len(observed)!=len(required):raise ValueError(ERROR+': missing/extra non-reload invocation')
    if inventory['state_operation_pending'] and inventory['coverage']['complete'] is not False:raise ValueError(ERROR+': unresolved operation domain')
    states,pages,_=_observer_sources(report,inventory)
    invocations,stack=[0],[]
    for e in report['helper_history']:
        if e['event']=='scenario_start':stack.append(e['invocation'])
        elif e['event']=='scenario_end':stack.pop()
        invocations.append(stack[-1] if stack else 0)
    identities=set();result=[]
    primary=report['primary_history']
    for (index,row),want in zip(observed,required,strict=True):
        source,site,kind,scenario,patterns,phase,anchor,mode,order,role,script_count=want['rule']
        identity=want['spec']['id']; case_index=want['case_index']; before=phase=='before_case'
        previous=execution[case_index-1] if case_index else ''
        cursor,until=row['start_cursor'],row['end_cursor']
        owner=states[cursor][0]
        invocation=want['spec']['invocation']
        selected_role=('served' if invocation==2 else 'tracer') if role=='invocation' else role
        descriptor=(source,identity,want['instance'])
        if row['site']!=site or row['kind']!=kind or row['case']!=(None if before else identity) or owner!=(scenario,'after' if before else 'inside',previous if before else identity) or invocations[cursor]!=invocation or states[until][0]!=owner or invocations[until]!=invocation or row['page']!=pages[cursor].get(selected_role) or row['script_items']!=script_count or descriptor in identities:
            raise ValueError(ERROR+': '+source)
        identities.add(descriptor)
        if before:
            lower=actual[previous]['end_ns'] if previous else 0; upper=actual[identity]['start_ns']
        else:
            position=next(i for i,p in enumerate(primary) if p['case']==identity and p['id']==want['anchor'])
            lower=primary[position-1]['at_ns'] if position and primary[position-1]['case']==identity else actual[identity]['start_ns']
            upper=primary[position]['at_ns']
        if not lower<=row['start_ns']<=row['end_ns']<=upper:raise ValueError(ERROR+': source checkpoint '+source)
        if kind in ('goal.drive','goal.turn'):
            _session(report,row,source,case_index,execution,want['instance'],states,invocations)
        elif row['session'] is not None:raise ValueError(ERROR)
        result.append(dict(source=source,case=identity,instance=want['instance'],index=index))
    return result


def _session(report,row,source,case_index,execution,instance,states,invocations):
    successor=source=='goal.drive.successor';manual=source=='goal.authority.turn'
    kind='rebind' if successor else 'query'
    captures=report['goal_rebind_inputs' if successor else 'goal_session_inputs']
    target='goal_cases.c001.p001' if manual else execution[case_index]
    index=execution.index(target);previous=execution[index-1] if index else ''
    cursor=row['start_cursor'];scope=states[cursor][0][0];invocation=invocations[cursor]
    matching=[]
    for i,capture in enumerate(captures):
        c=capture['start_cursor'];owner=states[c][0]
        if owner and owner[0]==scope and invocations[c]==invocation and (owner[1]=='after' and owner[2]==previous if successor or manual else owner[1]=='inside' and owner[2]==target):matching.append((i,capture))
    n=0 if successor or manual else instance-1
    if not 0<=n<len(matching):raise ValueError(ERROR)
    index,capture=matching[n]
    operand=row['session']
    if type(operand) is not dict or set(operand)!={'kind','source'} or type(operand['source']) is not int or operand!={'kind':kind,'source':index+1} or capture['page']!=row['page'] or capture['worker']!=row['worker'] or capture['end_ns']>row['start_ns']:
        raise ValueError(ERROR+': original goal session')
