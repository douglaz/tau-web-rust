"""Independent source-slot and original helper correspondence for reloads."""

ERROR='original reload source/helper/receiver correspondence mismatch'

def validate(report,key):
    from tracer_history import _observer_sources
    requirements=key if report['mode']=='full' else report['plan']
    roots={};expected=0
    for row in requirements['invocation_root_sequences']:
        tokens,sources=row['tokens'],row['reload_sources']
        if len(tokens)!=len(sources):raise ValueError(ERROR)
        for token,source in zip(tokens,sources,strict=True):
            if source is not None:
                if token!='call:runtime.worker' or source not in key['state_reload_sites']:raise ValueError(ERROR)
                expected+=1
        expected+=sum(d['active'] is True and d['contracts'] is True for d in row['prepare_domains'])
        owner=(row['scenario'],row['owner'],row['case'] or '',row['invocation'])
        if owner in roots:raise ValueError(ERROR)
        roots[owner]=row
    states,_,workers=_observer_sources(report,key)
    invocations,scenarios=[0],[]
    for event in report['helper_history']:
        if event['event']=='scenario_start':scenarios.append(event['invocation'])
        elif event['event']=='scenario_end':scenarios.pop()
        invocations.append(scenarios[-1] if scenarios else 0)
    positions,prepares,stack,required={},{},[],[]
    events=report['helper_history']
    for index,event in enumerate(events):
        if event['event']=='call_start' or event['event']=='check' and not stack:
            source=None;prepare_reload=False
            if not stack:
                owner=(*states[index][0],invocations[index])
                if owner not in roots:raise ValueError(ERROR)
                row=roots[owner]
                position=positions.get(owner,0)
                token='check:'+event['id'] if event['event']=='check' else 'call:'+event['kind']
                if position>=len(row['tokens']) or row['tokens'][position]!=token:raise ValueError(ERROR)
                source=row['reload_sources'][position];positions[owner]=position+1
                if event.get('kind')=='binding.prepare':
                    ordinal=prepares.get(owner,0);domain=row['prepare_domains'][ordinal];prepares[owner]=ordinal+1
                    prepare_reload=domain['active'] is True and domain['contracts'] is True
            elif event.get('kind')=='runtime.worker' and stack[-1]['kind']=='binding.prepare':
                if not stack[-1]['prepare_reload']:raise ValueError(ERROR)
                source=key['state_prepare_reload_site']
            if event['event']=='call_start':stack.append(dict(call=event['call'],start=index,kind=event['kind'],source=source,prepare_reload=prepare_reload))
        elif event['event']=='call_end':
            frame=stack.pop()
            if frame['call']!=event['call']:raise ValueError(ERROR)
            if frame['source'] is not None:
                if frame['kind']!='runtime.worker':raise ValueError(ERROR)
                required.append((frame['source'],frame['start'],index))
    if stack or len(required)!=expected or any(positions.get(o,0)!=len(r['tokens']) for o,r in roots.items()):raise ValueError(ERROR)
    operations=report['state_inputs']['operations'];consumed=set()
    for source,start,end in required:
        matching=[(i,op) for i,op in enumerate(operations) if op['kind']=='reload' and op['start_cursor']==start]
        if len(matching)!=1:raise ValueError(ERROR+': '+source)
        index,op=matching[0]
        if op['site']!=source or op['page']!=events[start]['page'] or op['worker']!=workers[start].get(op['page']) or op['successor']!=workers[end+1].get(op['page']) or op['end_cursor']!=end+1 or op['start_ns']>events[start]['at_ns'] or op['end_ns']<events[end]['at_ns'] or index in consumed:raise ValueError(ERROR+': '+source)
        consumed.add(index)
        kind={'declaration_cases.rs::reload#1':'declaration.prepare','delivery_cases.rs::reload#1':'delivery.prepare'}.get(source)
        if kind is not None:
            matching=[c for c in report['observer_calls'] if c['kind']==kind and c['page']==op['page'] and c['start_ns']<=op['start_ns']<=op['end_ns']<=c['end_ns']]
            if len(matching)!=1:raise ValueError(ERROR)
        if source=='main.rs::reload#18':
            matching=[i for i in report['settle_inputs'] if i['empty'] is False and i['page']==op['page'] and i['worker']==op['worker'] and i['start_ns']<=op['start_ns']<=op['end_ns']<=i['end_ns']]
            if len(matching)!=1:raise ValueError(ERROR)
    if any(op['kind']=='reload' and i not in consumed for i,op in enumerate(operations)):raise ValueError(ERROR+': unmatched reload')
    for source in report['settle_inputs']:
        matching=[op for op in operations if op['kind']=='reload' and op['site']=='main.rs::reload#18' and source['start_ns']<=op['start_ns']<=op['end_ns']<=source['end_ns']]
        if len(matching)!=int(source['empty'] is False):raise ValueError(ERROR)
