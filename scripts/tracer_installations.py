"""Consume every original store installation against independent source placements."""


def validate(report, key, consumed):
    from tracer_history import _observer_sources, _same_json
    error = 'original installation source/operand/placement mismatch'
    requirements = key if report['mode']=='full' else report['plan']
    execution = [c['id'] for c in key['cases']] if report['mode']=='full' else requirements['expected_execution']
    states, pages, _ = _observer_sources(report, key)
    events, captures, puts = report['helper_history'], report['file_captures'], report['file_uses']['puts']
    for row in puts:
        p=row['provenance']
        if type(p) is not dict or set(p)!={'empty','control','contracts'} or type(p['empty']) is not bool:raise ValueError(error)
        for field in ('control','contracts'):
            v=p[field]
            if v is not None and (type(v) is not dict or set(v)!=({'source','reader','ok'} if field=='contracts' else {'source','ok'}) or field=='contracts' and (type(v['reader']) is not int or v['reader']<1) or type(v['source']) is not int or v['source']<1 or type(v['ok']) is not bool):raise ValueError(error)
    stack, invocations, scopes, roots, children, ends = [], [0], [], {}, {}, {}
    for n,event in enumerate(events):
        if event['event']=='scenario_start':scopes.append(event['invocation'])
        elif event['event']=='scenario_end':scopes.pop()
        invocations.append(scopes[-1] if scopes else 0)
        if event['event']=='call_start':
            if stack:children.setdefault(stack[-1],[]).append(n)
            else:
                owner=states[n+1][0]
                roots.setdefault((*owner,invocations[n+1]),[]).append(n)
            stack.append(event['call'])
        elif event['event']=='call_end':
            if not stack or stack.pop()!=event['call']:raise ValueError(error)
            ends[event['call']]=n
        elif event['event']=='check' and not stack:
            owner=states[n+1][0]
            roots.setdefault((*owner,invocations[n+1]),[]).append(n)
    def original(site,kind,scope,invocation,instance=1):
        candidates=[]
        for capture in captures:
            cursor=capture['history_cursor'];owner=states[cursor][0]
            if capture['site']==site and capture['kind']==kind and owner and (scope=='@unique' or owner[0]==scope and invocations[cursor]==invocation):candidates.append(capture)
        if type(instance) is not int or instance<1 or instance>len(candidates) or scope=='@unique' and len(candidates)!=1:raise ValueError(error)
        return candidates[instance-1]
    def consume(cursor,page,operand,provenance,earliest):
        matching=[(n,p) for n,p in enumerate(puts) if p['history_cursor']==cursor]
        if len(matching)!=1 or matching[0][0] in consumed:raise ValueError(error)
        n,row=matching[0]
        if row['page']!=page or not _same_json(row['input'],operand) or not _same_json(row['provenance'],provenance) or not earliest<=row['at_ns']<=events[cursor]['at_ns']:raise ValueError(error)
        consumed.add(n)
    def capture_put(cursor,page,capture):
        if events[cursor]['event']!='call_start' or events[cursor]['kind']!='runtime.worker' or events[cursor]['page']!=page or capture['ok'] is not True:raise ValueError(error)
        operand={k:capture[k] for k in ('site','source','kind','page')};operand['ok']=True
        # A saved empty capture is valid; private provenance must still match its exact capture.
        matching=[p for p in puts if p['history_cursor']==cursor]
        if len(matching)!=1:raise ValueError(error)
        provenance=dict(empty=matching[0]['provenance']['empty'],control=None,contracts=None)
        consume(cursor,page,operand,provenance,capture['at_ns'])
    def local_cases(scope,invocation,descendant=False):
        family=scope.split('.')[0]+'.'
        return [c['id'] for c in key['cases'] if c['id'] in execution and c['invocation']==invocation and (c['site_id'].startswith(family) or descendant and c['site_id'].startswith(('goal_admission_cases.','declaration_cases.','delivery_cases.')))]
    def anchor(scope,invocation,pattern):
        if pattern not in ('@last','@entry','@last_descendant'):return pattern
        cases=local_cases(scope,invocation,pattern=='@last_descendant')
        if not cases:return None
        if pattern!='@entry':return cases[-1]
        index=execution.index(cases[0]);return execution[index-1] if index else ''
    root_rows=requirements['invocation_root_sequences']
    for scope,invocation,phase,pattern,positions,descriptor in key['file_installation_rules']:
        if descriptor[0] not in ('capture','empty','control'):raise ValueError(error)
        wanted=anchor(scope,invocation,pattern)
        for row in root_rows:
            if row['scenario']!=scope or row['invocation']!=invocation or row['owner']!=phase:continue
            case=row['case'] or ''
            if wanted is None or not (case==wanted or wanted.endswith('.*') and case.startswith(wanted[:-1])):continue
            context=(scope,phase,case,invocation)
            actual=roots.get(context,[])
            for ordinal,position in enumerate(positions):
                if type(position) is not int or not 0<=position<len(row['tokens']) or row['tokens'][position]!='call:runtime.worker' or position>=len(actual):raise ValueError(error)
                cursor=actual[position];page=events[cursor]['page']
                if descriptor[0]=='capture':
                    capture=original(descriptor[1],descriptor[2],scope,invocation,descriptor[3][ordinal])
                    capture_put(cursor,page,capture)
                elif descriptor[0]=='empty':
                    consume(cursor,page,dict(site='',source=None,kind='unbound',page=None,ok=False),dict(empty=True,control=None,contracts=None),0)
                else:
                    number=descriptor[1];capture=original('file.main.dump.013','browser.store',scope,invocation)
                    operand={k:capture[k] for k in ('site','source','kind','page')};operand['ok']=number==1
                    consume(cursor,page,operand,dict(empty=False,control=dict(source=number,ok=True),contracts=None),capture['at_ns'])
    # Existing independent root programs locate each reset's second reload.
    for row in root_rows:
        scope=row['scenario'];context=(scope,row['owner'],row['case'] or '',row['invocation']);tokens=row['tokens'];actual=roots.get(context,[])
        if row['owner']=='after' and scope in ('lifecycle_cases.run','lifecycle_cases.selected','lifecycle_repairs.run'):
            site='file.lifecycle_cases.build.001';kind='constructor'
            if scope=='lifecycle_cases.selected':site,kind='file.lifecycle_cases.dump.007','browser.store'
            elif scope=='lifecycle_repairs.run' and requirements['scenario_scopes'].get('lifecycle_cases.repair_cases'):site,kind='file.lifecycle_cases.dump.009','browser.store'
            for n in range(1,len(tokens)):
                if tokens[n-1:n+1]==['call:runtime.worker']*2:
                    cursor=actual[n];capture_put(cursor,events[cursor]['page'],original(site,kind,'@unique',1))
        if row['owner']=='after' and scope=='session_end_cases.run':
            for n in range(2,len(tokens)):
                if tokens[n-2:n+1]==['call:runtime.worker','check:session-end.previous_ssh.closed','call:runtime.worker']:
                    at=execution.index(row['case'])+1 if row['case'] in execution else 0
                    upcoming=execution[at] if at<len(execution) else None
                    site='file.session_end_cases.build.002' if upcoming in ('session_end_cases.c002.p004','session_end_cases.c002.p005') else 'file.session_end_cases.build.001'
                    cursor=actual[n];capture_put(cursor,events[cursor]['page'],original(site,'constructor','@unique',1))
            if row['case']==anchor(scope,row['invocation'],'@last'):
                cursor=actual[1];capture_put(cursor,events[cursor]['page'],original('file.session_end_cases.dump.002','browser.store',scope,row['invocation']))
        preparation=0
        for position,token in enumerate(tokens):
            if token!='call:binding.prepare':continue
            domain=row['prepare_domains'][preparation];preparation+=1
            if domain['active'] is not True or domain['contracts'] is not True:continue
            cursor=actual[position];parent=events[cursor];end=ends[parent['call']]
            workers=[n for n in children.get(parent['call'],[]) if events[n]['kind']=='runtime.worker']
            original_files=[c for c in captures if c['site']=='file.binding_cases.dump.001' and c['kind']=='browser.store' and cursor<c['history_cursor']<end]
            if len(workers)!=1 or len(original_files)!=1:raise ValueError(error)
            at=workers[0];capture=original_files[0];page=parent['page']
            if events[at]['page']!=page or capture['page']!=page:raise ValueError(error)
            operand={k:capture[k] for k in ('site','source','kind','page')};operand['ok']=False
            readers=[(n,r) for n,r in enumerate(report['reader_roots'],1) if r['site']=='reader.call.binding.contracts_source' and cursor<r['history_cursor']<end and _same_json(r['file_input'],dict(operand,ok=True))]
            if len(readers)!=1:raise ValueError(error)
            reader_id,reader=readers[0]
            matching=[p for p in puts if p['history_cursor']==at]
            if len(matching)!=1 or reader['end_ns']>matching[0]['at_ns']:raise ValueError(error)
            consume(at,page,operand,dict(empty=False,control=None,contracts=dict(source=capture['source'],reader=reader_id,ok=True)),capture['at_ns'])
    for source in report.get('settle_inputs',[]):
        if not any(a and b for a,b in source['input']):continue
        matching=[c for c in captures if c['site']=='file.main.build.008' and c['kind']=='constructor' and source['start_ns']<=c['at_ns']<=source['end_ns']]
        if len(matching)!=1:raise ValueError(error)
        capture=matching[0];capture_put(capture['history_cursor'],source['page'],capture)
    if report['mode']=='targeted' and requirements['name'].startswith('inference.'):
        capture=original('file.main.build.001','constructor','main.run',1)
        cursors=[n for n,e in enumerate(events) if e['event']=='scenario_start' and e['id']=='inference_cases.run']
        if len(cursors)!=1:raise ValueError(error)
        cursor=cursors[0];operand={k:capture[k] for k in ('site','source','kind','page')};operand['ok']=True
        consume(cursor,pages[cursor]['tracer'],operand,dict(empty=False,control=None,contracts=None),capture['at_ns'])
    if consumed!=set(range(len(puts))):raise ValueError(error+': unmatched installation')
    for row in puts:
        cursor=row['history_cursor'];event=events[cursor]
        if event['event']=='scenario_start' and event['id']=='inference_cases.run':
            if row['input']['site']!='file.main.build.001' or row['end_ns']>event['at_ns']:raise ValueError(error)
            continue
        if event['event']!='call_start' or event['kind']!='runtime.worker':raise ValueError(error)
        matching=[o for o in report['state_inputs']['operations'] if o['kind']=='reload' and o['page']==row['page'] and o['start_cursor']==cursor and o['end_cursor']==ends[event['call']]+1]
        if len(matching)!=1 or row['end_ns']>matching[0]['start_ns']:raise ValueError(error+': installation did not finish before reload')

