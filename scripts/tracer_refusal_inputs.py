"""Independent setup and binding refusal input domains and original operation order."""
KINDS=('setup.approve','setup.answer','setup.run','setup.collect','setup.message','binding.bind')


def _policy(kind,case,n):
    site=case.rsplit('.p',1)[0]
    if kind=='binding.bind' and site=='binding_cases.c001':
        return ('second_binding',True) if n==1 else ('invalid_binding',True) if 2<=n<=4 else None
    if kind=='setup.approve' and site=='setup_cases.c001':
        return {1:('locked_approval',True),2:('seed_backup_approval',True)}.get(n)
    if kind=='setup.answer' and site=='setup_cases.c004' and n==1: return 'second_answer',True
    if kind in ('setup.run','setup.collect') and site=='setup_cases.c003' and 1<=n<=6: return 'invalid_request',True
    if kind=='setup.message' and site=='setup_cases.c003' and 1<=n<=6: return 'malformed_page',False
    return None


def validate(report,key):
    from tracer_history import _observer_sources
    error='original file before/operation/after window mismatch'
    rules=key['file_refusal_operation_sources']
    if type(rules) is not dict or any(v not in ('ceremony','boundary','second_answer','binding') for v in rules.values()): raise ValueError(error)
    selected=None if report['mode']=='full' else report['plan']['expected_execution']
    required={}
    for case in key['cases']:
        if selected is not None and case['id'] not in selected: continue
        program=rules.get(case['site_id'])
        if program is None: continue
        required[(case['site_id'].split('.')[0]+'.run','inside',case['id'],case['invocation'])]=['setup.approve']*2 if program=='ceremony' else ['setup.run','setup.collect']*6+['setup.message']*6 if program=='boundary' else ['binding.bind']*4 if program=='binding' else ['setup.answer']
    states,pages,_=_observer_sources(report,key)
    invocations,stack=[0],[]
    for event in report['helper_history']:
        if event['event']=='scenario_start': stack.append(event['invocation'])
        elif event['event']=='scenario_end': stack.pop()
        invocations.append(stack[-1] if stack else 0)
    observed,ordinals={},{}
    for row in report['file_requests']:
        if row['kind'] not in KINDS: continue
        cursor,kind=row['start_cursor'],row['kind']
        owner=states[cursor][0]
        if owner is None: raise ValueError(error)
        context=(*owner,invocations[cursor])
        observed.setdefault(context,[]).append(kind)
        index=(context,kind);ordinals[index]=ordinals.get(index,0)+1
        policy=_policy(kind,owner[2],ordinals[index])
        if policy is None: raise ValueError(error)
        domain,refused=policy
        role='served' if context[3]==2 else 'tracer'
        if owner[:2]!=(owner[2].split('.')[0]+'.run','inside') or row['page']!=pages[cursor].get(role) or row['input_source'] is not None or row['domain']!=domain or row['input_ok'] is not True or row['refused'] is not refused or row['response_ok'] is not True: raise ValueError(error)
    if observed!=required: raise ValueError(error+': static refusal operation source program')
