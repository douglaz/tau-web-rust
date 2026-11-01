"""Independent consumer of serial helper ownership and readiness history."""


def validate_page_queries(report, inventory):
    error='original page query/value/predicate provenance mismatch'
    rows=report.get('page_query_inputs')
    if type(rows) is not list:raise ValueError(error)
    expected=[]
    for call, owner in enumerate(report['observer_calls'],1):
        kind=inventory['page_query_sources'].get(owner['site'])
        if kind is not None:
            if kind not in ('true','two'):raise ValueError(error)
            expected.extend((call,owner,kind,poll) for poll in owner['polls'])
    if len(rows)!=len(expected):raise ValueError(error)
    fields={'source','call','attempt','kind','page','start_ns','end_ns','history_cursor','query_ok','ready','used_ns','operand_ok','comparison_ns','comparison_count','comparison_result'}
    previous=0
    for index,(row,(call,owner,kind,poll)) in enumerate(zip(rows,expected),1):
        if type(row) is not dict or set(row)!=fields or any(type(row[k]) is not int for k in ('source','call','attempt','page','start_ns','end_ns','used_ns','history_cursor','comparison_ns','comparison_count')) or type(row['ready']) is not bool or type(row['comparison_result']) is not bool:raise ValueError(error)
        if row['source']!=index or row['call']!=call or row['attempt']!=poll['attempt'] or row['kind']!=kind or row['page']!=owner['page'] or row['history_cursor']!=poll['start_cursor'] or row['history_cursor']!=poll['end_cursor'] or row['query_ok'] is not True or row['operand_ok'] is not True or row['comparison_count']!=1 or row['comparison_result']!=row['ready'] or not row['end_ns']<=row['comparison_ns']<=row['used_ns'] or row['ready']!=poll['ready'] or not max(previous,poll['start_ns'])<=row['start_ns']<=row['end_ns']<=row['used_ns']<=poll['end_ns']:raise ValueError(error)
        previous=row['used_ns']


def validate_history(report, inventory):
    try:
        _validate_history(report, inventory)
    except (IndexError, KeyError, TypeError, AttributeError) as error:
        raise ValueError("invalid helper caller/history structure") from error


def _validate_history(report, inventory):
    events = report.get("helper_history")
    if not isinstance(events, list):
        raise ValueError("missing helper caller/history")
    schemas = {
        "scenario_start": {"id", "invocation"}, "scenario_end": {"id", "invocation"},
        "case_start": {"id"}, "case_end": {"id"},
        "call_start": {"call", "kind", "page", "worker"}, "call_end": {"call"},
        "worker_selected": {"call", "worker", "operand_ok"},
        "predicate": {"call", "id", "ok"},
        "logical_check": {"id", "instance", "ok"},
        "check": {"id", "instance", "ordinal"}, "poll": {"call", "ready"},
        "attempt": {"call", "ordinal"}, "retry": {"call"},
        "prepare_input": {"call", "active", "classes"},
        "contracts": {"call", "changed"}, "pass": {"call", "needed"},
        "binding_input": {"call", "slot", "bound"},
    }
    calls, scenarios = [], []
    ready, counts = {}, {}
    roots = {}
    preparations = {}
    requirements = inventory if report["mode"] == "full" else report["plan"]
    page_rows = {(row["scenario"], row["owner"], row["case"] or "", row["invocation"]): row for row in requirements["invocation_root_sequences"]}
    page_roles, born_pages = {}, set()
    case = None
    call_count = worker_count = case_count = scope_count = check_count = previous = 0

    def root_token(token):
        anchor = case["id"] if case is not None else report["cases"][case_count - 1]["id"] if case_count else ""
        key = (scenarios[-1][0], "inside" if case is not None else "after", anchor, scenarios[-1][2])
        roots.setdefault(key, []).append(token)
        return key

    for event in events:
        kind = event.get("event")
        if kind not in schemas or set(event) != schemas[kind] | {"event", "at_ns"}:
            raise ValueError("invalid helper history schema")
        at = event["at_ns"]
        if type(at) is not int or not previous <= at <= report["duration_ns"]:
            raise ValueError("helper history order/time mismatch")
        previous = at
        if "call" in event and (type(event["call"]) is not int or event["call"] < 1):
            raise ValueError("invalid helper caller ordinal schema")
        if kind == "scenario_start":
            if calls or case is not None:
                raise ValueError("scenario boundary crosses active case/helper")
            scenarios.append((event["id"], at, event["invocation"]))
        elif kind == "scenario_end":
            if calls or case is not None:
                raise ValueError("scenario boundary crosses active case/helper")
            identity, start, invocation = scenarios.pop()
            if event["id"] != identity or event["invocation"] != invocation or not _same_json(report["scenario_spans"][scope_count], {"id": identity, "invocation": invocation, "start_ns": start, "end_ns": at}):
                raise ValueError("scenario caller/history mismatch")
            scope_count += 1
        elif kind == "case_start":
            if case is not None or calls:
                raise ValueError("overlapping case/helper history")
            case = report["cases"][case_count]
            source_case = next((c for c in inventory['cases'] if c['id'] == case['id']), None)
            if not scenarios or not source_case or source_case['invocation'] != scenarios[-1][2] or event["id"] != case["id"] or case["start_ns"] != at or not scenarios or not scenarios[-1][0].startswith(case["site_id"].split(".")[0] + "."):
                raise ValueError("case caller/history owner mismatch")
        elif kind == "case_end":
            if case is None or calls or case["id"] != event["id"] or case["end_ns"] != at:
                raise ValueError("case caller/history boundary mismatch")
            case = None
            case_count += 1
        elif kind == "call_start":
            call_count += 1
            owner = None
            name, page, worker = event["kind"], event["page"], event["worker"]
            if not scenarios or type(event["call"]) is not int or event["call"] != call_count or type(page) is not int or page < 1 or type(worker) is not int or worker < 0:
                raise ValueError("helper caller ordinal/page mismatch")
            if name not in {"runtime.worker", "runtime.settled", "runtime.submit", "binding.prepare", "binding.fixture_class.ready", "binding.page.bound"}:
                raise ValueError("unknown helper caller")
            if name == "runtime.worker" and worker != 0:
                raise ValueError("worker creation has a foreign selected owner")
            if name.startswith("binding.") and ready.get(page) != worker:
                raise ValueError("binding before its worker readiness or foreign worker owner")
            if name in {"binding.fixture_class.ready", "binding.page.bound"} and (not calls or calls[-1]["kind"] != "binding.prepare" or calls[-1]["page"] != page):
                raise ValueError("binding wait outside owning preparation")
            if name == "runtime.submit" and ready.get(page) != worker:
                raise ValueError("submission before page worker readiness")
            if name == "runtime.settled":
                expected = calls[-1]["worker"] if calls and calls[-1]["kind"] == "runtime.worker" else ready.get(page)
                if worker != expected or worker == 0:
                    raise ValueError("store observation has a foreign worker owner")
            if calls:
                if name == "binding.prepare":
                    raise ValueError("preparation outside source root caller")
                if calls[-1]["page"] != page:
                    raise ValueError("helper transplanted across page owner")
                calls[-1]["steps"].append("call:" + name)
            else:
                anchor = case["id"] if case is not None else report["cases"][case_count - 1]["id"] if case_count else ""
                key = (scenarios[-1][0], "inside" if case is not None else "after", anchor, scenarios[-1][2])
                position = len(roots.get(key, []))
                row = page_rows.get(key, {})
                operations = row.get("page_operations", [])
                if position >= len(operations) or type(operations[position]) is not str:
                    raise ValueError("missing source page lineage occurrence")
                operation = operations[position]
                if operation.startswith("new:"):
                    if name != "runtime.worker" or page != len(born_pages) + 1 or page in born_pages:
                        raise ValueError("source page lineage birth mismatch")
                    born_pages.add(page)
                    page_roles[operation[4:]] = page
                elif page_roles.get(operation) != page:
                    raise ValueError("source page lineage relationship mismatch")
                owner = root_token("call:" + name)
            counts[name] = counts.get(name, 0) + 1
            calls.append({"id": call_count, "kind": name, "page": page, "worker": worker,
                          "steps": [], "polls": [], "poll_times": [], "attempt_times": [], "attempts": 0, "input": None, "contracts": None,
                          "pass": None, "bindings": []})
            calls[-1]["owner"] = owner if name == "binding.prepare" else None
        elif kind == "call_end":
            frame = calls.pop()
            if frame["id"] != event["call"]:
                raise ValueError("helper caller/history crossing")
            validate_frame(frame)
            if frame["owner"] is not None:
                preparations.setdefault(frame["owner"], []).append({
                    "active": frame["input"]["active"], "classes": frame["input"]["classes"],
                    "contracts": frame["contracts"], "pass": frame["pass"], "bindings": frame["bindings"],
                })
        elif kind == 'logical_check':
            if calls or type(event['id']) is not str or type(event['instance']) is not str or event['ok'] is not True:
                raise ValueError('original logical predicate failed or crossed a helper frame')
        elif kind == "predicate":
            if not calls or calls[-1]['kind']!='binding.prepare' or calls[-1]['id']!=event['call'] or event['ok'] is not True or event['id'] not in ('binding.prepare.setup_array','binding.prepare.machine_name'):
                raise ValueError('helper logical predicate mismatch')
            calls[-1]['steps'].append('predicate:'+event['id'])
        elif kind == "worker_selected":
            frame = calls[-1]
            worker_count += 1
            if type(event["call"]) is not int or type(event["worker"]) is not int or event['operand_ok'] is not True or frame["kind"] != "runtime.worker" or frame["id"] != event["call"] or event["worker"] != worker_count or not frame["polls"] or frame["polls"][-1] is not True:
                raise ValueError("worker selection history mismatch")
            frame["worker"] = worker_count
            frame["steps"].append("selected")
        elif kind == "check":
            check = report["prerequisites"][check_count]
            check_count += 1
            identity = check["id"]
            if type(event["ordinal"]) is not int or event["id"] != identity or event["instance"] != check["instance"] or event["ordinal"] != check_count or not scenarios:
                raise ValueError("prerequisite caller/history order mismatch")
            owner = {"runtime.worker.ready": "runtime.worker", "runtime.store.ready_nontransient": "runtime.settled", "runtime.store.not_failed": "runtime.settled", "binding.fixture_class.ready": identity, "binding.page.bound": identity, "binding.pass.allocation_identity": "binding.prepare"}.get(identity)
            if owner is not None and (not calls or calls[-1]["kind"] != owner):
                raise ValueError("prerequisite outside independently expected owning call")
            if calls:
                calls[-1]["steps"].append("check:" + identity)
                if identity == "runtime.worker.ready":
                    ready[calls[-1]["page"]] = calls[-1]["worker"]
            else:
                root_token("check:" + identity)
        else:
            frame = calls[-1]
            if type(event["call"]) is not int or frame["id"] != event["call"]:
                raise ValueError("helper input foreign caller")
            if kind == "attempt":
                if type(event["ordinal"]) is not int or event["ordinal"] != frame["attempts"] + 1 or frame["attempts"] >= 300:
                    raise ValueError("invalid independent poll attempt domain")
                frame["attempts"] += 1
                frame["attempt_times"].append(at)
                frame["steps"].append("attempt")
            elif kind == "retry":
                if frame["kind"] != "runtime.worker" or not frame["polls"] or frame["polls"][-1] is not True:
                    raise ValueError("invalid worker retry history")
                frame["steps"].append("retry")
            elif kind == "poll":
                frame["poll_times"].append(at)
                if type(event["ready"]) is not bool:
                    raise ValueError("invalid helper poll result")
                frame["polls"].append(event["ready"])
                frame["steps"].append("poll")
            elif frame["kind"] != "binding.prepare":
                raise ValueError("inapplicable helper input")
            elif kind == "binding_input":
                if type(event["slot"]) is not int or event["slot"] != len(frame["bindings"]) + 1 or type(event["bound"]) is not bool:
                    raise ValueError("binding input domain mismatch")
                frame["bindings"].append(event["bound"])
                frame["steps"].append("binding_input")
            else:
                key = {"prepare_input": "input", "contracts": "contracts", "pass": "pass"}[kind]
                if frame[key] is not None:
                    raise ValueError("duplicate helper input")
                value = event if kind == "prepare_input" else event["changed" if kind == "contracts" else "needed"]
                if kind != "prepare_input" and type(value) is not bool:
                    raise ValueError("invalid helper applicability")
                frame[key] = value
                frame["steps"].append(key)
    if calls or scenarios or case is not None or case_count != len(report["cases"]) or scope_count != len(report["scenario_spans"]) or check_count != len(report["prerequisites"]):
        raise ValueError("incomplete helper caller/history")
    for name, identity in [("runtime.worker", "runtime.worker.ready"), ("runtime.settled", "runtime.store.ready_nontransient"), ("binding.fixture_class.ready", "binding.fixture_class.ready"), ("binding.page.bound", "binding.page.bound")]:
        if counts.get(name, 0) != report["prerequisite_requests"].get(identity, 0):
            raise ValueError("missing logical helper call/history")
    requirements = inventory if report["mode"] == "full" else report["plan"]
    expected = {(row["scenario"], row["owner"], row["case"] or "", row["invocation"]): row["tokens"] for row in requirements["invocation_root_sequences"]}
    if len(expected) != len(requirements["invocation_root_sequences"]) or roots != expected:
        raise ValueError("source caller/history owner sequence mismatch")
    expected_preparations = {}
    for row in requirements["invocation_root_sequences"]:
        domains = row.get("prepare_domains")
        if not isinstance(domains, list) or len(domains) != row["tokens"].count("call:binding.prepare"):
            raise ValueError("missing/invalid source preparation domains")
        if domains:
            expected_preparations[(row["scenario"], row["owner"], row["case"] or "", row["invocation"])] = domains
    if preparations != expected_preparations:
        raise ValueError("source preparation applicability/history mismatch")


def validate_frame(frame):
    name, polls = frame["kind"], frame["polls"]
    if frame["attempts"] != len(polls):
        raise ValueError("helper polling grammar mismatch: independent attempt domain")
    if name in {"runtime.worker", "runtime.settled", "binding.fixture_class.ready", "binding.page.bound"}:
        if not 1 <= len(polls) <= 300 or polls[-1] is not True or name != "runtime.worker" and any(polls[:-1]):
            raise ValueError("helper predicate poll/termination history incomplete")
    if name == "runtime.worker":
        if not frame["worker"]:
            raise ValueError("worker selection missing")
        expected = []
        for index, ready in enumerate(polls):
            expected += ["attempt", "poll"]
            if index + 1 < len(polls) and ready:
                expected += ["retry"]
        expected += ["selected", "call:runtime.settled", "check:runtime.worker.ready"]
    elif name == "runtime.settled":
        expected = [step for _ in polls for step in ["attempt", "check:runtime.store.not_failed", "poll"]] + ["check:runtime.store.ready_nontransient"]
    elif name == "runtime.submit":
        expected = ["call:runtime.settled"]
    elif name.startswith("binding.") and name != "binding.prepare":
        expected = [step for _ in polls for step in ["attempt", "poll"]] + ["check:" + name]
    elif name == "binding.prepare":
        data = frame["input"]
        if data is None or type(data["active"]) is not bool:
            raise ValueError("missing independent preparation input")
        expected = ["input"]
        if not data["active"]:
            if data["classes"] is not None and (not isinstance(data["classes"], list) or any(type(value) is not bool for value in data["classes"])):
                raise ValueError("invalid inactive preparation domain")
            if frame["contracts"] is not None or frame["pass"] is not None or frame["bindings"]:
                raise ValueError("inactive preparation has later inputs")
        else:
            classes = data["classes"]
            if not isinstance(classes, list) or any(type(value) is not bool for value in classes) or frame["contracts"] is None:
                raise ValueError("invalid preparation machine domain")
            expected += ['predicate:binding.prepare.setup_array']
            for value in classes:
                if value: expected += ['predicate:binding.prepare.machine_name','call:binding.fixture_class.ready']
            expected += ["contracts"]
            if frame["contracts"]:
                expected += ["call:runtime.worker", "call:runtime.submit"]
            if not classes:
                if frame["pass"] is not None or frame["bindings"]:
                    raise ValueError("empty preparation has page inputs")
            else:
                if frame["pass"] is None or len(frame["bindings"]) != len(classes):
                    raise ValueError("incomplete preparation binding domain")
                expected += ["pass"]
                if frame["pass"]:
                    expected += ["check:binding.pass.allocation_identity"]
                for bound in frame["bindings"]:
                    expected += ["binding_input"]
                    if not bound:
                        expected += ["call:binding.page.bound"]
    else:
        raise ValueError("unknown helper grammar")
    if expected != frame["steps"]:
        raise ValueError("helper caller/history grammar mismatch: " + name)
    interval = 100_000_000 if name in ('runtime.worker', 'runtime.settled') else 50_000_000
    if any(not ready and frame['attempt_times'][index + 1] - frame['poll_times'][index] < interval for index, ready in enumerate(polls[:-1])):
        raise ValueError('helper original failed-attempt observation window shortened')


def validate_file_shapes(report):
    error = 'original encrypted reader input provenance mismatch'
    captures, events = report.get('file_captures'), report.get('helper_history')
    if type(captures) is not list or type(events) is not list:
        raise ValueError(error)
    states = _auxiliary_states(events)
    invocations, stack = [0], []
    for event in events:
        if event['event'] == 'scenario_start': stack.append(event['invocation'])
        elif event['event'] == 'scenario_end': stack.pop()
        invocations.append(stack[-1] if stack else 0)
    previous = (0, 0)
    for index, capture in enumerate(captures):
        if set(capture) != {'source','kind','site','page','parent','ok','case','at_ns','history_cursor'} or type(capture['source']) is not int or capture['source'] != index+1 or capture['ok'] is not True or type(capture['site']) is not str:
            raise ValueError(error)
        at, cursor = capture['at_ns'], capture['history_cursor']
        if type(at) is not int or type(cursor) is not int or not previous[0] <= at <= report['duration_ns'] or not previous[1] <= cursor <= len(events):
            raise ValueError(error)
        kind, page, parent = capture['kind'], capture['page'], capture['parent']
        if type(page) is not int or page < 0:
            raise ValueError(error)
        if kind == 'browser.dump':
            if type(page) is not int or page < 1 or parent is not None:
                raise ValueError(error)
        elif kind == 'browser.store':
            if type(parent) is not int or not 1 <= parent <= index or captures[parent-1]['kind'] != 'browser.dump' or captures[parent-1]['page'] != page or captures[parent-1]['site'] != capture['site']:
                raise ValueError(error)
        elif kind == 'constructor':
            if page != 0 or parent is not None:
                raise ValueError(error)
        else:
            raise ValueError(error)
        previous = (at,cursor)
    for read in report.get('reader_roots',[]):
        value = read.get('file_input')
        if type(value) is not dict or set(value) != {'source','kind','site','page','ok'} or type(value['source']) is not int or type(value['page']) is not int or not 1 <= value['source'] <= len(captures):
            raise ValueError(error)
        origin = captures[value['source']-1]
        if read['site'] in ('reader.call.hold.legacy_source', 'reader.call.hold.unreachable_source'):
            cursor = origin['history_cursor']
            if origin['kind'] != 'constructor' or origin['site'] != 'hold.initial' or (states[cursor][0] is None or states[cursor][0][:2] != ('hold_cases.run','after') or states[cursor][0][2].startswith('hold_cases.')) or invocations[cursor] != 1 or sum(c['kind']=='constructor' and c['site']=='hold.initial' for c in captures) != 1:
                raise ValueError(error)
        elif origin['kind'] != 'browser.store':
            raise ValueError(error)
        if read['site'] == 'reader.call.seed.failed_completion_baseline':
            owner = states[origin['history_cursor']][0]
            if origin['site'] != 'seed.failed_append.baseline' or owner is None or owner[:2] != ('seed_cases.run','inside') or origin['case'] != owner[2] or type(read.get('history_cursor')) is not int or not 0 <= read['history_cursor'] < len(states) or states[read['history_cursor']][0] != owner:
                raise ValueError(error)
        if value['ok'] is not True or value['page'] != origin['page'] or value['kind'] != origin['kind'] or value['site'] != origin['site'] or origin['at_ns'] > read['start_ns']:
            raise ValueError(error)


def validate_file_inputs(report, inventory):
    validate_file_shapes(report)
    error = 'original file source checkpoint/page/window mismatch'
    sources = validate_reader_callers(report, inventory)
    states, pages, _ = _observer_sources(report, inventory)
    events, captures = report['helper_history'], report['file_captures']
    invocations, stack, starts, prepares_started = [0], [], {}, [0]
    for index, event in enumerate(events):
        if event['event'] == 'scenario_start': stack.append(event['invocation'])
        elif event['event'] == 'scenario_end': stack.pop()
        invocations.append(stack[-1] if stack else 0)
        owner = states[index+1][0]
        if event['event'] == 'call_start' and event['kind'] == 'binding.prepare':
            starts[owner] = starts.get(owner, 0) + 1
        prepares_started.append(starts.get(owner, 0))
    used, occurrences = set(), {}
    for read, source in zip(report['reader_roots'], sources):
        rule = inventory['file_read_sources'].get(source['site'])
        if type(rule) is not list or not 2 <= len(rule) <= 3:
            raise ValueError(error)
        site, window = rule[:2]
        original = captures[read['file_input']['source']-1]
        cursor, end = original['history_cursor'], read['history_cursor']
        if original['site'] != site or cursor > end or invocations[cursor] != source['invocation']:
            raise ValueError(error)
        owner = states[cursor][0]
        if window == 'initial':
            if original['kind'] != 'constructor' or owner is None or owner[:2] != (source['owner'][0], 'after') or owner[2].startswith('hold_cases.'):
                raise ValueError(error)
            continue
        role = 'served' if (source['owner'][0] in ('seed_cases.run','setup_cases.run','binding_cases.run','mode_cases.run') and source['invocation'] == 2 or source['site'] == 'reader.call.main.leakage' and source['owner'][2] == 'main.c022.p001') else 'tracer'
        if source['prepare'] is not None:
            calls = []
            for event in events[:cursor]:
                if event['event'] == 'call_start': calls.append(event)
                elif event['event'] == 'call_end': calls.pop()
            if not calls or calls[-1]['kind'] != 'binding.prepare':
                raise ValueError(error)
            page = calls[-1]['page']
        else:
            page = pages[cursor].get(role)
        if page is None or original['page'] != page or owner != source['owner']:
            raise ValueError(error)
        occurrence_key=(source['owner'],source['invocation'],source['site'],source['prepare'])
        occurrence=occurrences[occurrence_key]=occurrences.get(occurrence_key,0)+1
        if len(rule)==3:
            import tracer_file_domains
            anchor=rule[2]
            if type(anchor) is not dict or set(anchor)-{'before_check','after_observer','checks_before_primary'}:raise ValueError(error)
            if 'before_check' in anchor:
                predicate=anchor['before_check']
                checks=anchor.get('checks_before_primary',[])
                if type(checks) is not list:raise ValueError(error)
                tracer_file_domains.checkpoint(report,original,source['owner'][2],predicate,occurrence,checks)
                target=next(r for r in report['primary_history'] if r['case']==source['owner'][2] and r['id']==f'{predicate}.i{occurrence:03}')
                if read['end_ns']>target['at_ns']:raise ValueError(error)
            if 'after_observer' in anchor:
                matches=[c for c in report['observer_calls'] if c['site']==anchor['after_observer'] and states[c['end_cursor']][0]==source['owner'] and invocations[c['end_cursor']]==source['invocation']]
                if len(matches)!=1 or matches[0]['end_ns']>original['at_ns']:raise ValueError(error)
        if window == 'current':
            if cursor != end or original['source'] in used:
                raise ValueError(error)
            used.add(original['source'])
        elif window == 'baseline':
            if source['site'] != 'reader.call.seed.failed_completion_baseline' or prepares_started[cursor] != 0:
                raise ValueError(error)
        elif window == 'reload':
            depth, roots = 0, []
            for event in events[cursor:end]:
                if event['event'] == 'call_start':
                    if depth == 0: roots.append(event['kind'])
                    depth += 1
                elif event['event'] == 'call_end' and depth > 0: depth -= 1
                elif event['event'] in ('scenario_start','scenario_end','case_start','case_end'):
                    raise ValueError(error)
            if depth or roots != ['runtime.worker','runtime.submit']:
                raise ValueError(error)
        else:
            raise ValueError(error)
    validate_file_constructors(report, inventory, sources)
    validate_file_controls(report)
    validate_blob_sources(report, inventory)
    import tracer_file_domains
    tracer_file_domains.validate(report, inventory)


def validate_blob_sources(report, inventory):
    error='original scan reference query/name provenance mismatch'
    required=report['mode']=='full' or 'lifecycle_cases.c001.p001' in report['plan']['expected_execution']
    sources=report.get('blob_sources')
    if type(sources) is not list or len(sources)!=int(required):raise ValueError(error)
    states,pages,workers=_observer_sources(report,inventory)
    for row in sources:
        if type(row) is not dict or set(row)!={'source','page','worker','start_ns','end_ns','history_cursor','case','ok','named'} or any(type(row[k]) is not int for k in ('source','page','worker','start_ns','end_ns','history_cursor','named')):raise ValueError(error)
        cursor=row['history_cursor']
        if not 0<=cursor<len(states):raise ValueError(error)
        page=pages[cursor].get('tracer')
        if row['source']!=1 or row['named']!=1 or row['ok'] is not True or page is None or row['page']!=page or row['worker']!=workers[cursor].get(page) or row['case']!='lifecycle_cases.c001.p001' or states[cursor][0]!=('lifecycle_cases.run','inside','lifecycle_cases.c001.p001') or not 0<=row['start_ns']<=row['end_ns']<=report['duration_ns']:raise ValueError(error)


def validate_file_controls(report):
    error='original cryptographic refusal input/use domain mismatch'
    selected=report['mode']=='full' or 'main.c015.p001' in report['plan']['expected_execution']
    value=report.get('file_controls')
    if type(value) is not dict or set(value)!={'captures','uses'} or type(value['captures']) is not list or type(value['uses']) is not list or len(value['captures'])!=(5 if selected else 0) or len(value['uses'])!=len(value['captures']): raise ValueError(error)
    states=_auxiliary_states(report['helper_history'])
    invocations, stack = [0], []
    for event in report['helper_history']:
        if event['event']=='scenario_start':stack.append(event['invocation'])
        elif event['event']=='scenario_end':stack.pop()
        invocations.append(stack[-1] if stack else 0)
    files=report['file_captures']; previous=0
    for index,(capture,used) in enumerate(zip(value['captures'],value['uses']),1):
        if type(capture) is not dict or set(capture)!={'source','kind','base','foreign','ok','at_ns','history_cursor','case'} or type(used) is not dict or set(used)!={'source','ok','at_ns','history_cursor','case'} or type(capture['source']) is not int or type(used['source']) is not int or capture['source']!=index or used['source']!=index or capture['kind']!=('wrong_passphrase','salt','ciphertext','foreign_record','version')[index-1] or capture['ok'] is not True or used['ok'] is not True: raise ValueError(error)
        if type(capture['base']) is not int or not 1<=capture['base']<=len(files):raise ValueError(error)
        base=files[capture['base']-1]
        if (base['site'],base['kind'],base['case'])!=('file.main.dump.013','browser.store','main.c015.p001') or base['at_ns']>capture['at_ns']:raise ValueError(error)
        if index==4:
            if type(capture['foreign']) is not int or not 1<=capture['foreign']<=len(files):raise ValueError(error)
            foreign=files[capture['foreign']-1]
            if (foreign['site'],foreign['kind'],foreign['case'])!=('file.main.build.007','constructor','main.c015.p001') or foreign['at_ns']>capture['at_ns']:raise ValueError(error)
        elif capture['foreign'] is not None:raise ValueError(error)
        for row in (capture,used):
            if type(row['at_ns']) is not int or type(row['history_cursor']) is not int or not 0<=row['history_cursor']<len(states):raise ValueError(error)
            cursor=row['history_cursor']
            if row['case']!='main.c015.p001' or states[cursor]!=(('main.run','inside','main.c015.p001'),None) or invocations[cursor]!=1 or row['at_ns']>report['duration_ns']:raise ValueError(error)
        if not previous<=used['at_ns'] or capture['at_ns']>used['at_ns']:raise ValueError(error)
        previous=used['at_ns']


def validate_file_constructors(report, inventory, readers):
    error = 'original constructor source invocation/domain mismatch'
    execution = [c['id'] for c in inventory['cases']] if report['mode'] == 'full' else report['plan']['expected_execution']
    auxiliary = _auxiliary_constructors(report, inventory)
    expected = {}
    for rule in inventory['file_constructor_sources']:
        site, kind, target = rule[:3]
        def add(owner, count=1):
            expected.setdefault(owner, []).extend([site]*count)
        if kind == 'reader':
            for source in readers:
                if source['site'] == target: add(source['owner']+(source['invocation'],))
        elif kind == 'aux':
            for owner, domains in auxiliary.items():
                for invocation, domain in domains:
                    if domain['caller'].startswith(target): add(owner+(invocation,))
        elif kind == 'case':
            for case in inventory['cases']:
                if case['site_id'] != target or case['id'] not in execution: continue
                position, anchor = rule[3], case['id']
                if position == 'before':
                    index = execution.index(anchor)
                    position, anchor = 'after', execution[index-1] if index else ''
                add((target.split('.')[0]+'.run',position,anchor,case['invocation']),rule[4])
        elif kind == 'cleanup':
            case = next((c for c in reversed(inventory['cases']) if c['site_id'].startswith(target.split('.')[0]+'.') and c['id'] in execution), None)
            if case: add((target,'after',case['id'],case['invocation']))
        else:
            raise ValueError(error)
    for owner, sites in expected.items():
        if owner[1] != 'inside': continue
        order=inventory['file_constructor_order'].get(owner[2].rsplit('.p',1)[0])
        if order is not None:
            if any(site not in order for site in sites):raise ValueError(error)
            sites.sort(key=order.index)
    states, invocations, stack = _auxiliary_states(report['helper_history']), [0], []
    for event in report['helper_history']:
        if event['event'] == 'scenario_start': stack.append(event['invocation'])
        elif event['event'] == 'scenario_end': stack.pop()
        invocations.append(stack[-1] if stack else 0)
    for capture in report['file_captures']:
        if capture['kind'] != 'constructor': continue
        cursor = capture['history_cursor']
        owner = states[cursor][0]
        want = expected.get(owner+(invocations[cursor],), []) if owner else []
        if not want or capture['site'] != want.pop(0) or capture['case'] != (owner[2] if owner[1] == 'inside' else None):
            raise ValueError(error)
    if any(expected.values()): raise ValueError(error)


def validate_settle_inputs(report, inventory):
    error = 'original conditional disposition input/domain mismatch'
    execution = [c['id'] for c in inventory['cases']] if report['mode'] == 'full' else report['plan']['expected_execution']
    required = {}
    for site, target, position in inventory['settle_call_rules']:
        for case in inventory['cases']:
            if case['site_id'] != target or case['id'] not in execution: continue
            anchor, phase = case['id'], position
            if position == 'before':
                index = execution.index(anchor)
                phase, anchor = 'after', execution[index-1] if index else ''
            required.setdefault((target.split('.')[0]+'.run', phase, anchor, case['invocation']), []).append(site)
    states, pages, workers = _observer_sources(report, inventory)
    events = report['helper_history']
    invocations, stack = [0], []
    for event in events:
        if event['event'] == 'scenario_start': stack.append(event['invocation'])
        elif event['event'] == 'scenario_end': stack.pop()
        invocations.append(stack[-1] if stack else 0)
    fields = {'source','site','page','worker','input','empty_tests','empty','dispositions','constructor_uses','reader_origin','puts','start_ns','end_ns','start_cursor','end_cursor','ok'}
    previous = 0
    if type(report.get('settle_inputs')) is not list: raise ValueError(error)
    for index, value in enumerate(report['settle_inputs'], 1):
        if type(value) is not dict or set(value) != fields or any(type(value[k]) is not int for k in ('source','page','worker','empty_tests','dispositions','constructor_uses','start_ns','end_ns','start_cursor','end_cursor')):
            raise ValueError(error)
        start, end, cursor, until = (value[k] for k in ('start_ns','end_ns','start_cursor','end_cursor'))
        if not previous <= start <= end <= report['duration_ns'] or not 0 <= cursor <= until < len(states): raise ValueError(error)
        owner = states[cursor][0]
        want = required.get(owner+(invocations[cursor],), []) if owner else []
        domain = value['input']
        if type(domain) is not list or any(type(row) is not list or len(row)!=2 or any(type(v) is not bool for v in row) for row in domain): raise ValueError(error)
        empty = not any(first and second for first, second in domain)
        page = pages[cursor].get('tracer')
        if not want or value['site'] != want.pop(0) or value['source']!=index or value['ok'] is not True or page is None or value['page']!=page or value['worker']!=workers[cursor].get(page) or value['empty_tests']!=1 or type(value['empty']) is not bool or value['empty']!=empty or value['dispositions']!=int(not empty) or value['constructor_uses']!=int(not empty) or states[until][0]!=owner or invocations[until]!=invocations[cursor]:
            raise ValueError(error)
        if cursor and events[cursor-1]['at_ns']>start or cursor<len(events) and events[cursor]['at_ns']<start or until and events[until-1]['at_ns']>end or until<len(events) and events[until]['at_ns']<end: raise ValueError(error)
        captures = [c for c in report['file_captures'] if start<=c['at_ns']<=end and c['site'] in ('file.main.dump.017','file.main.build.008')]
        reads = [r for r in report['reader_roots'] if r['site']=='reader.call.settle_unresolved.disposition_source' and start<=r['start_ns']<=end]
        puts = value['puts']
        if type(puts) is not list: raise ValueError(error)
        if empty:
            if cursor!=until or captures or reads or value['reader_origin'] is not None or puts: raise ValueError(error)
        else:
            if [c['kind'] for c in captures]!=['browser.dump','browser.store','constructor'] or len(reads)!=1 or reads[0]['file_input']['source']!=captures[1]['source'] or reads[0]['end_ns']>captures[2]['at_ns']: raise ValueError(error)
            if type(value['reader_origin']) is not int or reads[0]['instance']!=f'reader.read.i{value["reader_origin"]:03}':raise ValueError(error)
            if len(puts)!=1 or type(puts[0]) is not dict or set(puts[0])!={'input','page','at_ns','history_cursor'}:raise ValueError(error)
            put=puts[0]
            operand=dict(site='file.main.build.008',source=captures[2]['source'],kind='constructor',page=0,ok=True)
            if not _same_json(put['input'],operand) or type(put['page']) is not int or put['page']!=page or type(put['history_cursor']) is not int or put['history_cursor']!=cursor or type(put['at_ns']) is not int or not captures[2]['at_ns']<=put['at_ns']<=min(end,events[cursor]['at_ns']):raise ValueError(error)
            depth, roots = 0, []
            for event in events[cursor:until]:
                if event['event']=='call_start':
                    if depth==0: roots.append(event['kind'])
                    depth+=1
                elif event['event']=='call_end' and depth: depth-=1
            if depth or roots!=['runtime.worker','runtime.submit','binding.prepare']: raise ValueError(error)
        previous=end
    if any(required.values()): raise ValueError(error)


def validate_reader_roots(report, inventory):
    reads = report.get("reader_roots")
    if not isinstance(reads, list):
        raise ValueError("missing reader root completions")
    previous = 0
    for index, read in enumerate(reads, 1):
        if set(read) != {"instance", "site", "history_cursor", "file_input", "numeric_files", "guards", "event_domains", "semantic_guards", "start_ns", "end_ns", "auxiliary_inputs", "auxiliary_guards"} or read["instance"] != f"reader.read.i{index:03}":
            raise ValueError("invalid reader root schema/instance")
        start, end, numeric = read["start_ns"], read["end_ns"], read["numeric_files"]
        if type(start) is not int or type(end) is not int or not previous <= start <= end <= report["duration_ns"]:
            raise ValueError("reader root timing mismatch")
        previous = end
        if type(numeric) is not int or numeric < 0 or not isinstance(read["guards"], list) or len(read["guards"]) != 16 + 12 * numeric:
            raise ValueError("reader root assertion inventory mismatch: input-domain cardinality")
        expected = ["reader.envelope.lookup", "reader.envelope.json", "reader.envelope.constant.iterations", "reader.envelope.constant.kdf", "reader.envelope.constant.purpose", "reader.envelope.constant.version", "reader.envelope.id",
                    "reader.b64.text.salt", "reader.b64.decode.salt", "reader.b64.text.nonce", "reader.b64.decode.nonce", "reader.b64.text.wrapped_key", "reader.b64.decode.wrapped_key"]
        expected += ["reader.nonce.length", "reader.aead.open", "reader.data_key.length"]
        expected += ["reader.file.number"] * numeric
        record = ["reader.record.contiguous", "reader.record.json", "reader.record.header", "reader.record.type",
                  "reader.b64.text.nonce", "reader.b64.decode.nonce", "reader.b64.text.ciphertext", "reader.b64.decode.ciphertext",
                  "reader.nonce.length", "reader.aead.open", "reader.record.plaintext_json"]
        expected += record * numeric
        counts = {}
        for guard, identity in zip(read["guards"], expected):
            counts[identity] = counts.get(identity, 0) + 1
            if set(guard) != {"id", "instance", "ok"} or guard["id"] != identity or guard["instance"] != f"{identity}.i{counts[identity]:03}" or guard["ok"] is not True:
                raise ValueError("reader root assertion inventory mismatch: predicate identity/order")
        validate_semantic(read, inventory)
    validate_reader_callers(report, inventory)


def validate_reader_callers(report, inventory):
    """Expand source caller obligations before looking at completed readers."""
    requirements = inventory if report['mode'] == 'full' else report['plan']
    execution = [c['id'] for c in inventory['cases']] if report['mode'] == 'full' else requirements['expected_execution']
    direct = {}
    for rule in sorted(inventory['reader_caller_rules'], key=lambda r: r['within_owner_order']):
        include, anchor = rule['include_if'], rule['case']
        if 'case' in include:
            if include['case'] not in execution:
                continue
        elif 'any_module' in include or 'any_site' in include:
            prefix = include.get('any_module', include.get('any_site')) + '.'
            anchor = next((c for c in execution if c.startswith(prefix)), None)
            if anchor is None:
                continue
        elif 'scenario' in include:
            if include['scenario'] not in requirements['scenario_scopes']:
                continue
            anchor = next(c for c in execution if c.startswith(rule['scenario'].split('.')[0] + '.'))
        else:
            raise ValueError('invalid independent reader caller rule')
        invocation = next(c['invocation'] for c in inventory['cases'] if c['id'] == anchor)
        position = rule['position']
        if position == 'before':
            index = execution.index(anchor)
            position, anchor = 'after', execution[index - 1] if index else ''
        key = (rule['scenario'], position, anchor)
        direct.setdefault(key, []).append((rule['site'], rule['after_prepare'], rule['role'], invocation))
    expected_prepares = {}
    for row in requirements['helper_owner_sequences']:
        owner = (row['scenario'], row['owner'], row['case'] or '')
        for ordinal, domain in enumerate(row['prepare_domains'], 1):
            sites = []
            if domain['active']:
                sites.append('reader.call.binding.contracts_source')
                if domain['classes']:
                    sites.append('reader.call.binding.opened_source')
                    if domain['pass']:
                        sites.append('reader.call.binding.allocated_pass_source')
            if sites:
                expected_prepares[(owner, ordinal)] = sites
    prepare_invocations, ordinals = {}, {}
    for row in requirements['invocation_root_sequences']:
        owner = (row['scenario'], row['owner'], row['case'] or '')
        for _ in row['prepare_domains']:
            ordinal = ordinals.get(owner, 0) + 1
            ordinals[owner] = ordinal
            prepare_invocations[(owner, ordinal)] = row['invocation']
    scenarios, calls, invocations = [], [], []
    case, previous = None, ''
    starts, completed, observed, prepared = {}, {}, {}, {}
    events, cursor = report['helper_history'], 0
    sources = []

    def owner_key():
        if not scenarios:
            raise ValueError('reader without source scenario')
        return (scenarios[-1], 'inside' if case is not None else 'after', case if case is not None else previous)

    for read in report['reader_roots']:
        while cursor < len(events) and events[cursor]['at_ns'] <= read['start_ns']:
            event = events[cursor]
            cursor += 1
            kind = event['event']
            if kind == 'scenario_start':
                scenarios.append(event['id'])
                invocations.append(event['invocation'])
            elif kind == 'scenario_end':
                scenarios.pop()
                invocations.pop()
            elif kind == 'case_start':
                case = event['id']
            elif kind == 'case_end':
                previous, case = event['id'], None
            elif kind == 'call_start':
                owner, ordinal = owner_key(), 0
                if event['kind'] == 'binding.prepare':
                    starts[owner] = ordinal = starts.get(owner, 0) + 1
                calls.append((event['kind'], owner, ordinal))
            elif kind == 'call_end':
                name, owner, _ = calls.pop()
                if name == 'binding.prepare':
                    completed[owner] = completed.get(owner, 0) + 1
        if cursor < len(events) and events[cursor]['at_ns'] < read['end_ns']:
            raise ValueError('reader crosses source caller/history boundary')
        if read.get('history_cursor') != cursor or type(read.get('history_cursor')) is not int:
            raise ValueError('reader source cursor mismatch')
        invocation = invocations[-1] if invocations else 0
        if calls:
            name, owner, ordinal = calls[-1]
            if name != 'binding.prepare':
                raise ValueError('reader outside required parent call')
            parent = (owner, ordinal)
            n = prepared.get(parent, 0)
            want = expected_prepares.get(parent, [])
            if n >= len(want) or read['site'] != want[n] or prepare_invocations.get(parent) != invocation:
                raise ValueError('missing/extra/duplicate reader parent-role completion')
            sources.append({'site': want[n], 'owner': owner, 'role': 'only', 'prepare': ordinal, 'invocation': invocation})
            prepared[parent] = n + 1
        else:
            owner = owner_key()
            n, want = observed.get(owner, 0), direct.get(owner, [])
            if n >= len(want) or (read['site'], completed.get(owner, 0)) != want[n][:2] or want[n][3] != invocation:
                raise ValueError('reader source caller/order/prepare history mismatch: ' + read['site'])
            sources.append({'site': want[n][0], 'owner': owner, 'role': want[n][2], 'prepare': None, 'invocation': invocation})
            observed[owner] = n + 1
    if any(observed.get(k, 0) != len(v) for k, v in direct.items()) or any(prepared.get(k, 0) != len(v) for k, v in expected_prepares.items()):
        raise ValueError('missing/extra whole reader call: source caller obligations')
    return sources


def _same_json(left, right):
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(_same_json(v, right[k]) for k, v in left.items())
    if isinstance(left, list):
        return len(left) == len(right) and all(_same_json(a, b) for a, b in zip(left, right))
    return left == right


def _domain_matches(value, schema, definitions, depth=0):
    if depth > 100:
        return False
    if type(schema) is bool:
        return schema
    if '$ref' in schema:
        prefix = '#/$defs/'
        reference = schema['$ref']
        return isinstance(reference, str) and reference.startswith(prefix) and reference[len(prefix):] in definitions and _domain_matches(value, definitions[reference[len(prefix):]], definitions, depth + 1)
    if 'anyOf' in schema:
        return any(_domain_matches(value, choice, definitions, depth + 1) for choice in schema['anyOf'])
    if 'const' in schema and not _same_json(value, schema['const']):
        return False
    if 'enum' in schema and not any(_same_json(value, choice) for choice in schema['enum']):
        return False
    kind = schema.get('type')
    if kind == 'null':
        return value is None
    if kind == 'boolean':
        return type(value) is bool
    if kind == 'string':
        return type(value) is str
    if kind == 'integer':
        return type(value) is int and value >= 0
    if kind == 'object':
        if type(value) is not dict or not set(schema.get('required', [])) <= value.keys():
            return False
        properties = schema['properties']
        return all(k in properties and _domain_matches(v, properties[k], definitions, depth + 1) for k, v in value.items())
    if kind == 'array':
        if type(value) is not list or len(value) < schema.get('minItems', 0) or 'maxItems' in schema and len(value) > schema['maxItems']:
            return False
        prefix = schema.get('prefixItems', [])
        return all(_domain_matches(v, prefix[i] if i < len(prefix) else schema.get('items', False), definitions, depth + 1) for i, v in enumerate(value))
    return kind is None and ('const' in schema or 'enum' in schema)


def _semantic_expand(node, domain, rules, context, result, limit, depth=0):
    if depth > 100:
        raise ValueError('semantic grammar nesting exceeds bound')
    if 'guard' in node:
        if len(result) >= limit:
            raise ValueError('semantic assertion inventory mismatch: cardinality')
        result.append((node['guard'], context.copy()))
    elif 'seq' in node:
        for child in node['seq']:
            _semantic_expand(child, domain, rules, context, result, limit, depth + 1)
    elif 'call' in node:
        target = domain if node['at'] == '' else domain[node['at']]
        _semantic_expand(rules[node['call']], target, rules, context, result, limit, depth + 1)
    elif 'each' in node:
        items = domain[node['each']]
        if type(items) is not list or len(items) > limit:
            raise ValueError('invalid semantic input array/bound')
        for index, item in enumerate(items):
            context.append({'slot': node['slot'], 'index': index})
            _semantic_expand(node['do'], item, rules, context, result, limit, depth + 1)
            context.pop()
    elif 'scope' in node:
        if type(node['index']) is not int or node['index'] < 0:
            raise ValueError('invalid fixed source input occurrence')
        context.append({'slot': node['scope'], 'index': node['index']})
        _semantic_expand(node['do'], domain, rules, context, result, limit, depth + 1)
        context.pop()
    elif 'if' in node:
        flag = domain[node['if']]
        if type(flag) is not bool:
            raise ValueError('invalid semantic input boolean')
        _semantic_expand(node['then'] if flag else node['else'], domain, rules, context, result, limit, depth + 1)
    elif 'switch' in node:
        alias = domain[node['switch']]
        if type(alias) is not str or alias not in node['cases']:
            raise ValueError('unknown semantic input alternative')
        _semantic_expand(node['cases'][alias], domain, rules, context, result, limit, depth + 1)
    else:
        raise ValueError('invalid semantic grammar operator')


def validate_semantic(read, inventory):
    domains, guards = read.get('event_domains'), read.get('semantic_guards')
    if type(domains) is not list or len(domains) != read['numeric_files']:
        raise ValueError('semantic event/history invocation domain mismatch')
    if type(guards) is not list:
        raise ValueError('missing semantic predicate completions')
    definitions = inventory['semantic_domain_schemas']
    expected = []
    for index, domain in enumerate(domains):
        if not _domain_matches(domain, definitions['semantic.record'], definitions):
            raise ValueError('semantic input domain schema mismatch')
        for rule, field in [('reader.event', 'event'), ('inference.history', 'inference'), ('reader.mode_history', 'modes'), ('declaration.history', 'declaration'), ('delivery.history', 'delivery')]:
            context = [{'slot': 'reader.record', 'index': index}, {'slot': rule, 'index': 0}]
            _semantic_expand(inventory['semantic_rules'][rule], domain[field], inventory['semantic_rules'], context, expected, len(guards))
    if len(guards) != len(expected):
        raise ValueError('semantic assertion inventory mismatch: cardinality')
    counts = {}
    for guard, (identity, context) in zip(guards, expected):
        counts[identity] = counts.get(identity, 0) + 1
        if type(guard) is not dict or set(guard) != {'id', 'instance', 'ok', 'context'} or guard['id'] != identity or guard['instance'] != f'{identity}.i{counts[identity]:03}' or guard['ok'] is not True or not _same_json(guard['context'], context):
            raise ValueError('semantic assertion inventory mismatch: ' + identity)


def _auxiliary_states(events):
    """Caller state at every cursor, derived from validated execution history."""
    scenarios, calls, starts = [], [], {}
    case, previous = None, ''
    result = [(None, None)]
    for event in events:
        kind = event['event']
        if kind == 'scenario_start':
            scenarios.append(event['id'])
        elif kind == 'scenario_end':
            scenarios.pop()
        elif kind == 'case_start':
            case = event['id']
        elif kind == 'case_end':
            previous, case = event['id'], None
        elif kind == 'call_start':
            ordinal = None
            if event['kind'] == 'binding.prepare':
                owner = (scenarios[-1], 'inside' if case else 'after', case or previous)
                ordinal = starts[owner] = starts.get(owner, 0) + 1
            calls.append(ordinal)
        elif kind == 'call_end':
            calls.pop()
        owner = (scenarios[-1], 'inside' if case else 'after', case or previous) if scenarios else None
        result.append((owner, next((p for p in reversed(calls) if p is not None), None)))
    return result


def _auxiliary_constructors(report, inventory):
    requirements = inventory if report['mode'] == 'full' else report['plan']
    execution = [c['id'] for c in inventory['cases']] if report['mode'] == 'full' else requirements['expected_execution']
    result = {}
    for rule in sorted(inventory['auxiliary_constructor_rules'], key=lambda r: r['within_owner_order']):
        include, anchor, position = rule['include_if'], rule['case'], rule['position']
        if 'case' in include:
            if include['case'] not in execution:
                continue
        elif 'any_module' in include or 'any_site' in include:
            prefix = include.get('any_module', include.get('any_site')) + '.'
            anchor = next((c for c in execution if c.startswith(prefix)), None)
            if anchor is None:
                continue
        elif 'scenario' in include:
            if include['scenario'] not in requirements['scenario_scopes']:
                continue
            anchor = next(c for c in execution if c.startswith(rule['scenario'].split('.')[0] + '.'))
        elif 'targeted_plan_prefix' in include:
            if report['mode'] != 'targeted' or not requirements['name'].startswith(include['targeted_plan_prefix']):
                continue
        else:
            raise ValueError('invalid constructor source rule')
        invocation = 1 if not anchor and rule['scenario'] == 'main.run' else next(c['invocation'] for c in inventory['cases'] if c['id'] == anchor)
        if position == 'before':
            index = execution.index(anchor)
            position, anchor = 'after', execution[index - 1] if index else ''
        result.setdefault((rule['scenario'], position, anchor), []).append((invocation, {'caller': rule['caller'], 'roster': rule['roster']}))
    return result


def _auxiliary_root(source, read, requirements):
    """Source program selection precedes expansion of completed auxiliary guards."""
    site, owner, raw = source['site'], source['owner'], read['auxiliary_inputs']
    count, records = read['numeric_files'], raw['records']
    backups = [i for i, r in enumerate(records) if r['backup']]
    backup_good = False
    if site in ('reader.call.seed.collision_completion', 'reader.call.seed.completion'):
        backup_good = count == 2 and backups == [1]
    elif site in ('reader.call.seed.mismatch_absence', 'reader.call.seed.failed_completion_absence'):
        backup_good = count == 1 and not backups
    elif site == 'reader.call.seed.completion_reopened':
        backup_good = backups == [1] and count == (5 if owner[2] in ('seed_cases.c003.p001', 'seed_cases.c003.p002') else 2 if owner[2] in ('seed_cases.c003.p003', 'seed_cases.c003.p004') else -1)
    elif site == 'reader.call.seed.redisplay_completion':
        backup_good = count >= 3 and backups == [1, count - 1]
    final_opened, relay_key, keys, expected_pass = False, False, [], None
    if source['prepare'] is not None:
        row = next(r for r in requirements['helper_owner_sequences'] if (r['scenario'], r['owner'], r['case'] or '') == owner)
        preparation = row['prepare_domains'][source['prepare'] - 1]
        machines = len(preparation.get('classes') or [])
        served = (owner == ('main.run', 'inside', 'main.c001.p001') or owner[0] == 'binding_cases.run' and owner[2].endswith('.p002') or owner == ('mode_cases.run', 'after', 'mode_cases.c001.p001'))
        enrol = not (owner == ('main.run', 'inside', 'main.c012.p001') and source['prepare'] == 1)
        if preparation['active'] and machines:
            pass_birth = preparation['pass']
            needs_relay = not served and enrol
            final_opened = site == ('reader.call.binding.allocated_pass_source' if pass_birth else 'reader.call.binding.opened_source')
            if final_opened:
                keys = [{'key': 'machine.first'}] + ([{'key': 'machine.second'}] if machines >= 2 else [])
                relay_key = needs_relay
            if site == 'reader.call.binding.opened_source':
                expected_pass = int(not pass_birth and needs_relay)
            elif site == 'reader.call.binding.allocated_pass_source' and pass_birth:
                expected_pass = 1
    key = {'fixture': 'machine.first', 'fixture_other': 'machine.second'}.get(source['role'], 'unknown')
    machine_index_records = []
    for record in records:
        found = any(entry['key']==key for entry in record['machine_entries'])
        machine_index_records.append({'found':found})
        if found: break
    return {
        'site': site, 'record_domain': 'complete' if len(records) == count else 'unknown',
        'backup_domain': 'complete' if backup_good else 'unknown',
        'pass_domain': 'complete' if expected_pass == sum(r['pass'] for r in records) else 'unknown',
        'records': records, 'three': [{}, {}, {}], 'setup_entries': [{}, {}],
        'final_opened': final_opened, 'machine_keys': keys, 'relay_key': relay_key,
        'relay': {'key': 'pass.first'}, 'machine_first': {'key': 'machine.first'},
        'key': key, 'machine_index_records': machine_index_records,
        'displayed': raw['displayed'], 'earlier_search': raw['earlier_search'], 'earlier': raw['earlier'],
        'nonseed_records': [{} for _ in range(max(0, count - 1))],
        'tracer': site == 'reader.call.main.leakage' and owner[2] == 'main.c022.p002',
    }


def _auxiliary_guards(report, inventory, guards, rule, domain, start, end, owner, prepare, states):
    if type(guards) is not list:
        raise ValueError('missing auxiliary predicate completions')
    expected = []
    _semantic_expand(inventory['semantic_rules'][rule], domain, inventory['semantic_rules'], [], expected, len(guards))
    if len(guards) != len(expected):
        raise ValueError('auxiliary assertion inventory mismatch: cardinality')
    counts, previous, events = {}, start, report['helper_history']
    for guard, (identity, context) in zip(guards, expected):
        counts[identity] = counts.get(identity, 0) + 1
        if type(guard) is not dict or set(guard) != {'id', 'instance', 'ok', 'context', 'at_ns', 'history_cursor'}:
            raise ValueError('invalid auxiliary predicate schema')
        at, cursor = guard['at_ns'], guard['history_cursor']
        if type(at) is not int or type(cursor) is not int or not 0 <= cursor < len(states) or not previous <= at <= end:
            raise ValueError('invalid auxiliary predicate timing/cursor')
        if guard['id'] != identity or guard['instance'] != f'{identity}.i{counts[identity]:03}' or guard['ok'] is not True or not _same_json(guard['context'], context) or states[cursor] != (owner, prepare) or cursor and events[cursor - 1]['at_ns'] > at or cursor < len(events) and events[cursor]['at_ns'] < at:
            raise ValueError('auxiliary predicate/caller/input/history mismatch: ' + identity)
        previous = at


def validate_auxiliary(report, inventory):
    _validate_leakage_capture(report,inventory)
    sources = validate_reader_callers(report, inventory)
    requirements = inventory if report['mode'] == 'full' else report['plan']
    definitions, constructors = inventory['semantic_domain_schemas'], _auxiliary_constructors(report, inventory)
    states, duration = _auxiliary_states(report['helper_history']), report['duration_ns']
    standalone = report.get('auxiliary_calls')
    if type(standalone) is not list:
        raise ValueError('missing standalone auxiliary completions')
    invocation_states, stack = [0], []
    for event in report['helper_history']:
        if event['event'] == 'scenario_start': stack.append(event['invocation'])
        elif event['event'] == 'scenario_end': stack.pop()
        invocation_states.append(stack[-1] if stack else 0)
    previous, preview = 0, None
    for call in standalone:
        if type(call) is not dict or set(call) != {'site', 'domain', 'guards', 'start_ns', 'end_ns', 'history_cursor'}:
            raise ValueError('invalid standalone auxiliary schema')
        start, end, cursor = call['start_ns'], call['end_ns'], call['history_cursor']
        if type(start) is not int or type(end) is not int or type(cursor) is not int or not 0 <= cursor < len(states) or not previous <= start <= end <= duration:
            raise ValueError('standalone auxiliary timing/cursor mismatch')
        previous, (owner, prepare) = end, states[cursor]
        events = report['helper_history']
        if prepare is not None or any(e['event'] == 'call_start' and e['kind'] == 'binding.prepare' and states[i][0] == owner for i, e in enumerate(events[:cursor])) or cursor and events[cursor - 1]['at_ns'] > start or cursor < len(events) and events[cursor]['at_ns'] < end:
            raise ValueError('standalone auxiliary source preparation/history mismatch')
        if call['site'] == 'reader.aux.constructor':
            expected = constructors.get(owner, [])
            if not expected:
                raise ValueError('missing/extra constructor source caller')
            invocation, domain = expected.pop(0)
            if invocation_states[cursor] != invocation:
                raise ValueError("constructor source invocation mismatch")
            if not _same_json(call['domain'], domain) or not _domain_matches(domain, definitions['reader.aux.constructor'], definitions):
                raise ValueError('constructor source caller/parameter mismatch')
            source_root = {
                'reader.aux.call.main.no_pin_setup': 'reader.call.main.pre_no_pin',
                'reader.aux.call.main.no_pass_setup': 'reader.call.main.pre_no_pass',
                'reader.aux.call.hold.setup': 'reader.call.hold.original',
                'reader.aux.call.mode.setup': 'reader.call.mode.original',
                'reader.aux.call.inference.sent_read_setup': 'reader.call.inference.sent_read_original',
                'reader.aux.call.session_end.setup': 'reader.call.session_end.original',
                'reader.aux.call.lifecycle.setup': 'reader.call.lifecycle.original',
            }.get(domain['caller'])
            if source_root:
                index = next((i for i, s in enumerate(sources) if s['site'] == source_root and s['owner'] == owner and s['invocation'] == invocation_states[cursor]), None)
                if index is None or report['reader_roots'][index]['end_ns'] > start or index + 1 < len(sources) and report['reader_roots'][index + 1]['start_ns'] < end:
                    raise ValueError('constructor source reader chronology mismatch')
            rule = 'reader.aux.constructor'
        elif call['site'] == 'reader.aux.main_displayed':
            execution = [c['id'] for c in inventory['cases']] if report['mode'] == 'full' else requirements['expected_execution']
            if 'main.c022.p001' not in execution:
                raise ValueError('displayed source outside selection')
            index = execution.index('main.c022.p001')
            if invocation_states[cursor] != 1 or preview is not None or owner != ('main.run', 'after', execution[index - 1] if index else '') or not _domain_matches(call['domain'], definitions['reader.aux.preview'], definitions):
                raise ValueError('displayed input source domain mismatch')
            rule, domain, preview = 'reader.aux.main_displayed', call['domain'], call['domain']['displayed']
        else:
            raise ValueError('unknown standalone auxiliary source')
        _auxiliary_guards(report, inventory, call['guards'], rule, domain, start, end, owner, prepare, states)
    if any(constructors.values()) or any(c['id'] == 'main.c022.p001' for c in report['cases']) != (preview is not None):
        raise ValueError('missing whole standalone auxiliary source caller')
    for read_index, (read, source) in enumerate(zip(report['reader_roots'], sources)):
        raw = read['auxiliary_inputs']
        if not _domain_matches(raw, definitions['reader.aux.raw'], definitions):
            raise ValueError('auxiliary raw input schema mismatch')
        if source['site'] == 'reader.call.inference.reload_revoke' and raw['reload_revoke'] not in ('absent', 'pending', 'finished') or source['site'] != 'reader.call.inference.reload_revoke' and raw['reload_revoke'] is not None:
            raise ValueError('auxiliary source conditional input mismatch')
        if source['site'] == 'reader.call.inference.reload_revoke':
            cases = [c for c in report['cases'] if 'reload-revoke' in c['branches']]
            if len(cases) != 1 or cases[0]['branches']['reload-revoke'] != raw['reload_revoke']:
                raise ValueError('reload assertion branch differs from original raw input domain')
        leakage = source['site'] == 'reader.call.main.leakage'
        if len(raw['records']) != read['numeric_files'] or leakage and not _same_json(preview, raw['displayed']) or not leakage and (raw['displayed'] or raw['earlier_search'] or raw['earlier'] != 'unknown'):
            raise ValueError('auxiliary original input domain mismatch')
        domain = _auxiliary_root(source, read, requirements)
        if not _domain_matches(domain, definitions['reader.aux.root_domain'], definitions):
            raise ValueError('invalid auxiliary source domain')
        _auxiliary_guards(report, inventory, read['auxiliary_guards'], 'reader.aux.root', domain, read['end_ns'], report['reader_roots'][read_index + 1]['start_ns'] if read_index + 1 < len(sources) else duration, source['owner'], source['prepare'], states)


def validate_preflight(value, full, inventory):
    if type(value) is not dict or set(value) != {'schema', 'duration_ns', 'auxiliary_calls', 'served_checks'} or type(value['schema']) is not int or value['schema'] != 1 or type(value['duration_ns']) is not int or value['duration_ns'] < 0 or type(value['auxiliary_calls']) is not list or len(value['auxiliary_calls']) != int(full):
        raise ValueError('preflight auxiliary source/schema mismatch')
    domain = {'phrases': [{'roles': [{'keys': [{'key': 'machine.first'}, {'key': 'machine.second'}]}, {'keys': [{'key': 'pass.first'}, {'key': 'pass.second'}]}]} for _ in range(5)]}
    for call in value['auxiliary_calls']:
        if type(call) is not dict or set(call) != {'site', 'domain', 'guards', 'start_ns', 'end_ns', 'history_cursor'} or call['site'] != 'reader.aux.absence' or type(call['history_cursor']) is not int or call['history_cursor'] != 0 or not _same_json(call['domain'], domain):
            raise ValueError('preflight auxiliary source/input mismatch')
        start, end = call['start_ns'], call['end_ns']
        if type(start) is not int or type(end) is not int or not 0 <= start <= end <= value['duration_ns']:
            raise ValueError('invalid preflight auxiliary bounds')
        _auxiliary_guards({'helper_history': []}, inventory, call['guards'], 'reader.aux.absence', domain, start, end, None, None, [(None, None)])
    _validate_served_checks(value, full, inventory)


def _validate_served_checks(value, full, inventory, served=None):
    from pathlib import Path
    from html.parser import HTMLParser
    error = 'mandatory served-check predicate/input/order mismatch'
    calls = value.get('served_checks')
    if type(calls) is not list or len(calls) != (2 if full else 0):
        raise ValueError(error)
    if not full:
        return
    root = Path(__file__).resolve().parent.parent
    served = Path(served) if served is not None else root/'dist/served'
    html = (root/'www/index.html').read_bytes()
    if (served/'index.html').read_bytes() != html:
        raise ValueError('served page differs from its build source')
    def guard(identity, **context):
        return {'id':identity, 'context':context, 'ok':True}
    absence = [guard('checks.served.required_files')]
    def files(directory):
        result = 0
        for path in directory.iterdir():
            if path.is_symlink(): raise ValueError('nonregular served-check input')
            if path.is_dir(): result += files(path)
            elif path.is_file(): result += 1
            else: raise ValueError('nonregular served-check input')
        return result
    for file in range(files(served)):
        absence.append(guard('checks.absence.file_source', file=file))
        for needle in range(len(inventory['served_check_sources']['absence_needles'])):
            absence.append(guard('checks.absence.needle_absent', file=file, needle=needle))
    absence.append(guard('checks.absence.clear'))
    csp = [guard('checks.served.required_files'),guard('checks.csp.page_source')]
    class Domain(HTMLParser):
        def __init__(self):
            super().__init__(); self.meta=0; self.policies=[]
        def handle_starttag(self, tag, attrs):
            if tag != 'meta': return
            csp.append(guard('checks.csp.meta_closed', meta=self.meta))
            attrs=dict(attrs)
            if attrs.get('http-equiv', '').lower() == 'content-security-policy':
                csp.append(guard('checks.csp.meta_content', meta=self.meta))
                self.policies.append(attrs.get('content'))
            self.meta+=1
    domain=Domain(); domain.feed(html.decode())
    if len(domain.policies)!=1 or type(domain.policies[0]) is not str:
        raise ValueError('unmapped source CSP syntax')
    csp += [guard('checks.csp.single_policy'),guard('checks.csp.before_script')]
    for directive, _ in enumerate(part for part in domain.policies[0].split(';') if part.split()):
        csp.append(guard('checks.csp.unique_directive', directive=directive))
    csp.append(guard('checks.csp.exact_policy'))
    previous=0
    # The artifact identity includes sorted source-relative paths, modes and bytes.
    import hashlib, os
    paths=[]
    def enumerate_files(directory):
        for path in directory.iterdir():
            if path.is_symlink(): raise ValueError('nonregular served-check input')
            if path.is_dir(): enumerate_files(path)
            elif path.is_file(): paths.append(path)
            else: raise ValueError('nonregular served-check input')
    enumerate_files(served)
    digest=hashlib.sha256(b'tau-tracer-tree-v2\0')
    for path in sorted(paths):
        data=path.read_bytes();digest.update(os.fsencode(path.relative_to(served)));digest.update(b'\0file\0');digest.update(len(data).to_bytes(8,'little'));digest.update((path.stat().st_mode & 0o777).to_bytes(4,'little'));digest.update(data)
    identity=digest.hexdigest()
    for call, kind, guards in zip(calls, ('absence','csp'), (absence,csp)):
        if type(call) is not dict or set(call)!={'kind','input','input_after','start_ns','end_ns','guards'} or call['kind']!=kind or call['input']!=identity or call['input_after']!=identity or any(type(call[k]) is not int for k in ('start_ns','end_ns')) or not previous<=call['start_ns']<=call['end_ns']<=value['duration_ns'] or not _same_json(call['guards'],guards):
            raise ValueError(error)
        previous=call['end_ns']


def _observer_sources(report, inventory):
    requirements = inventory if report['mode'] == 'full' else report['plan']
    states = _auxiliary_states(report['helper_history'])
    pages, workers, call_pages, positions = {}, {}, {}, {}
    page_states, worker_states, depth = [{}], [{}], 0
    rows = {(r['scenario'], r['owner'], r['case'] or ''): r for r in requirements['helper_owner_sequences']}
    for index, event in enumerate(report['helper_history']):
        event_type = event['event']
        if event_type == 'call_start':
            call_pages[event['call']] = event['page']
            if depth == 0:
                owner = states[index + 1][0]
                position = positions.get(owner, 0)
                operation = rows[owner]['page_operations'][position]
                if operation.startswith('new:'):
                    role = operation[4:]
                    if role == 'tracer' and role in pages and pages[role] != event['page'] and owner == ('main.run', 'inside', 'main.c020.p001'):
                        pages['prior_tracer_at_main_c020_birth'] = pages[role]
                    pages[role] = event['page']
                positions[owner] = position + 1
            depth += 1
        elif event_type == 'call_end':
            depth -= 1
        elif event_type == 'check' and depth == 0:
            owner = states[index + 1][0]
            positions[owner] = positions.get(owner, 0) + 1
        elif event_type == 'worker_selected':
            workers[call_pages[event['call']]] = event['worker']
        page_states.append(pages.copy())
        worker_states.append(workers.copy())
    return states, page_states, worker_states


def _observer_expected(report, inventory):
    rows = inventory['invocation_observer_sequences'] if report['mode'] == 'full' else report['plan']['invocation_observer_sequences']
    result = {}
    for row in rows:
        calls = []
        for node in row['calls']:
            if node.get('if') == 'reload_raw_revoke_absent':
                reads = [r for r in report['reader_roots'] if r['site'] == 'reader.call.inference.reload_revoke']
                if len(reads) != 1 or reads[0]['auxiliary_inputs'].get('reload_revoke') not in ('absent', 'pending', 'finished'):
                    raise ValueError('missing observer independent revoke domain')
                if reads[0]['auxiliary_inputs']['reload_revoke'] == 'absent':
                    calls.append(node['then'])
            else:
                calls.append(node)
        key = (row['scenario'], row['owner'], row['case'] or '')
        result.setdefault(key, []).extend(dict(node, invocation=row["invocation"]) for node in calls)
    if report['mode'] != 'full' and report['plan']['name'] in ('hold.union', 'inference.session-end.selection'):
        execution = report['plan']['expected_execution']
        for row in inventory['direct_observer_source_rows']:
            if row['case'] not in execution:
                continue
            position, case = row['position'], row['case']
            if position == 'before':
                index = execution.index(case)
                position, case = 'after', execution[index - 1] if index else ''
            calls = result.setdefault((row['scenario'], position, case), [])
            offset = len(calls)
            for field, shift in (('before_existing_site', 0), ('after_existing_site', 1)):
                if field in row:
                    matches = [i for i, node in enumerate(calls) if node.get('site') in row[field].split('|')]
                    if len(matches) != 1:
                        raise ValueError('missing source direct observer interleave anchor')
                    offset = matches[0] + shift
                    break
            calls[offset:offset] = [dict(node, invocation=1) for node in row['calls']]
    return result


def _causal_positions(report):
    states = _auxiliary_states(report['helper_history'])
    positions, depth, result = {}, 0, [(0, True)]
    for index, event in enumerate(report['helper_history']):
        if event['event']=='call_start':
            depth += 1
        elif event['event']=='call_end':
            depth -= 1
            if depth==0:
                owner=states[index][0]
                positions[owner]=positions.get(owner,0)+1
        elif event['event']=='check' and depth==0:
            owner=states[index+1][0]
            positions[owner]=positions.get(owner,0)+1
        result.append((positions.get(states[index+1][0],0),depth==0))
    return result


def _causal_expected(report, inventory):
    execution=[c['id'] for c in inventory['cases']] if report['mode']=='full' else report['plan']['expected_execution']
    result={}
    for row in inventory['causal_observer_sources']:
        if row['position']=='cleanup':
            result.setdefault(('', 'cleanup', ''),[]).extend(row['calls'])
            continue
        if row['case'] not in execution:
            continue
        index=execution.index(row['case'])
        owner=(row['scenario'],'after',execution[index-1] if index else '') if row['position']=='before' else (row['scenario'],row['position'],row['case'])
        result.setdefault(owner,[]).extend(row['calls'])
    return {owner:sorted(calls,key=lambda c:c['root_start']) for owner,calls in result.items()}


def _validate_original_inputs(report):
    def fail():
        raise ValueError('original input capture/use/lifetime mismatch')
    events=report.get('original_input_history');calls=report['observer_calls']
    if type(report.get('original_unbound_inputs')) is not int or report['original_unbound_inputs']!=0 or type(events) is not list:
        fail()
    states=_auxiliary_states(report['helper_history']);positions=_causal_positions(report)
    sources=[];uses={};consumed=set();current=None;retired=None;previous=0
    for event_index,e in enumerate(events):
        if type(e) is not dict or type(e.get('at_ns')) is not int or not previous<=e['at_ns']<=report['duration_ns'] or type(e.get('history_cursor')) is not int or not 0<=e['history_cursor']<len(states) or type(e.get('source')) is not int:
            fail()
        at=e['at_ns'];cursor=e['history_cursor'];source=e['source'];previous=at
        history_events=report['helper_history']
        if (cursor and history_events[cursor-1]['at_ns']>at) or (cursor<len(history_events) and history_events[cursor]['at_ns']<at):
            fail()
        if retired is not None and (e.get('event')!='capture' or e.get('kind')!='session'):
            fail()
        if e.get('event')=='capture':
            if set(e)!={'event','source','kind','site','call','ok','query','at_ns','history_cursor'} or source!=len(sources)+1 or e['ok'] is not True or (retired is not None and retired!=source):
                fail()
            retired=None
            if e['kind']=='session':
                if current is not None or type(e['call']) is not int or not 1<=e['call']<=len(calls):
                    fail()
                c=calls[e['call']-1];q=e['query'];start=c['start_cursor']
                if c['kind'] not in ('declaration.prepare','delivery.prepare') or e['site']!=c['site'] or not c['start_ns']<=at<=c['end_ns'] or type(q) is not dict or set(q)!={'at_ns','history_cursor','queries'}:
                    fail()
                if type(q['at_ns']) is not int or type(q['history_cursor']) is not int or not 0<=q['history_cursor']<=cursor or not c['start_ns']<=q['at_ns']<=at or states[cursor][0]!=states[start][0] or positions[cursor]!=(positions[start][0]+(3 if c['kind']=='declaration.prepare' else 2),True):
                    fail()
                query_call=next((child for child in calls if child['parent']==e['call'] and child['kind']=='declaration.prepare.binding'),None) if c['kind']=='declaration.prepare' else c
                if query_call is None or not query_call['polls'] or query_call['polls'][-1]['ready'] is not True or not query_call['polls'][-1]['start_ns']<=q['at_ns']<=query_call['polls'][-1]['end_ns']:
                    fail()
                queries=q['queries'];polls=query_call['polls']
                if type(queries) is not list or len(queries)!=len(polls):
                    fail()
                for query,poll in zip(queries,polls):
                    if type(query) is not dict or set(query)!={'at_ns','history_cursor','present'} or type(query['at_ns']) is not int or type(query['history_cursor']) is not int or type(query['present']) is not bool or query['present']!=poll['ready'] or not poll['start_ns']<=query['at_ns']<=poll['end_ns'] or not poll['start_cursor']<=query['history_cursor']<=poll['end_cursor']:
                        fail()
                if not queries or queries[-1]['at_ns']!=q['at_ns'] or queries[-1]['history_cursor']!=q['history_cursor']:
                    fail()
                uses.setdefault(e['call'],[]).append('produce_session');current=source
            elif e['kind'] not in ('files','declaration','measurement') or e['call'] is not None or e['query'] is not None:
                fail()
            sources.append(e)
        elif e.get('event')=='use':
            if set(e)!={'event','source','kind','site','call','ok','at_ns','history_cursor'} or e['ok'] is not True or not 1<=source<=len(sources) or type(e['call']) is not int or not 1<=e['call']<=len(calls):
                fail()
            cap=sources[source-1];c=calls[e['call']-1]
            if e['kind']!=cap['kind'] or e['site']!=c['site'] or not c['start_ns']<=at<=c['end_ns'] or cursor!=c['start_cursor'] or (c['polls'] and at>c['polls'][0]['start_ns']):
                fail()
            if e['kind']=='session':
                if current!=source:
                    fail()
            else:
                cc=cap['history_cursor'];start=c['start_cursor']
                if source in consumed or cap['site']!=c['site'] or cap['at_ns']>c['start_ns'] or cc>start or states[cc][0]!=states[start][0] or positions[cc]!=positions[start]:
                    fail()
                consumed.add(source)
            uses.setdefault(e['call'],[]).append(e['kind'])
        elif e.get('event')=='retire':
            if set(e)!={'event','source','next','at_ns','history_cursor'} or current!=source or source in consumed or retired is not None or (e['next'] is not None and type(e['next']) is not int):
                fail()
            if e['next'] is None:
                if event_index+1!=len(events) or cursor+1!=len(states) or any(c['end_ns']>at for c in calls):
                    fail()
            elif e['next']!=len(sources)+1:
                fail()
            consumed.add(source);current=None;retired=e['next']
        else:
            fail()
    if current is not None or retired is not None or len(consumed)!=len(sources):
        fail()
    for index,c in enumerate(calls,1):
        expected={'declaration.prepare':['files','produce_session'],'delivery.prepare':['declaration','produce_session'],'delivery.check':['measurement','session'],'declaration.prepare.goal_card':['session'],'declaration.wait_card':['session'],'declaration.wait_proposal_or_outcome':['session'],'declaration.outcome':['session']}.get(c['kind'],[])
        if uses.pop(index,[])!=expected:
            fail()
    if uses:
        fail()


def _validate_counter_inputs(report,inventory):
    def fail():
        raise ValueError('original counter baseline/dispatch/use history mismatch')
    rows={
        'inference.held_completion.wait':('inference_cases.run','inference_cases.c005.p001',0,0),
        'inference.late_mint.wait':('inference_cases.run','inference_cases.c009.p001',1,1),
        'inference.withheld_sweep.wait':('inference_cases.run','inference_cases.c011.p001',2,3),
        'lifecycle.boundaries.wait_completion':('lifecycle_cases.run','lifecycle_cases.c004.p001',0,0),
        'lifecycle.aggregate_cap.wait_completion':('lifecycle_cases.run','lifecycle_cases.c009.p001',0,0),
    }
    sources=report.get('counter_inputs');calls=report['observer_calls'];expected=[(i,c) for i,c in enumerate(calls,1) if c['kind']=='inference.wait_count']
    if type(report.get('counter_unbound_inputs')) is not int or report['counter_unbound_inputs']!=0 or type(sources) is not list or len(sources)!=len(expected):
        fail()
    states,pages,workers=_observer_sources(report,inventory);positions=_causal_positions(report)
    history_events=report['helper_history']
    def within(cursor,at):
        return type(cursor)is int and type(at)is int and 0<=cursor<=len(history_events) and (not cursor or history_events[cursor-1]['at_ns']<=at) and (cursor==len(history_events) or history_events[cursor]['at_ns']>=at)
    previous=0
    for index,(s,(call_index,c)) in enumerate(zip(sources,expected),1):
        if type(s) is not dict or set(s)!={'source','site','path_ok','capture','bindings','triggers','uses','matches'} or type(s['source']) is not int or s['source']!=index or s['site']!=c['site'] or s['path_ok'] is not True or s['site'] not in rows:
            fail()
        scenario,case,cap_pos,use_pos=rows[s['site']]
        if s['site']=='lifecycle.boundaries.wait_completion' and states[c['start_cursor']][0][0]=='lifecycle_cases.selected':
            scenario='lifecycle_cases.selected'
        owner=(scenario,'inside',case);cap=s['capture'];b=s['bindings'];t=s['triggers'];u=s['uses']
        if type(cap) is not dict or set(cap)!={'start_ns','end_ns','history_cursor'} or any(type(cap[k]) is not int for k in cap) or not previous<=cap['start_ns']<=cap['end_ns'] or not 0<=cap['history_cursor']<len(states) or states[cap['history_cursor']][0]!=owner or positions[cap['history_cursor']]!=(cap_pos,True):
            fail()
        if any(type(v) is not list or len(v)!=1 for v in (b,t,u)):
            fail()
        b,t,u=b[0],t[0],u[0]
        if any(type(v)is not dict for v in (b,t,u)):
            fail()
        if not within(cap['history_cursor'],cap['start_ns']) or not within(cap['history_cursor'],cap['end_ns']) or not within(b.get('history_cursor'),b.get('at_ns')) or not within(t.get('start_cursor'),t.get('start_ns')) or not within(t.get('end_cursor'),t.get('end_ns')) or not within(u.get('history_cursor'),u.get('at_ns')):
            fail()
        if type(b) is not dict or set(b)!={'ok','at_ns','history_cursor'} or b['ok'] is not True or type(b['at_ns']) is not int or type(b['history_cursor']) is not int or b['history_cursor']!=cap['history_cursor'] or type(t) is not dict or set(t)!={'worker','page','ok','start_ns','end_ns','start_cursor','end_cursor'} or t['ok'] is not True or any(type(t[k]) is not int for k in ('worker','page','start_ns','end_ns','start_cursor','end_cursor')) or not cap['end_ns']<=b['at_ns']<=t['start_ns']<=t['end_ns']<=c['start_ns']:
            fail()
        tc,ec=t['start_cursor'],t['end_cursor'];page=t['page'];worker=t['worker']
        if not 0<=tc<=ec<len(states) or states[tc][0]!=owner or states[ec][0]!=owner or positions[tc]!=(cap_pos,True) or positions[ec]!=(use_pos,True) or pages[tc].get('tracer')!=page or pages[ec].get('tracer')!=page or workers[tc].get(page)!=worker or workers[ec].get(page)!=worker:
            fail()
        if type(u) is not dict or set(u)!={'call','ok','at_ns','history_cursor'} or u['ok'] is not True or any(type(u[k]) is not int for k in ('call','at_ns','history_cursor')) or u['call']!=call_index or u['history_cursor']!=c['start_cursor'] or not c['start_ns']<=u['at_ns']<=c['end_ns'] or states[c['start_cursor']][0]!=owner or positions[c['start_cursor']]!=(use_pos,True):
            fail()
        matches=s['matches'];polls=c['polls']
        if type(matches) is not list or len(matches)!=len(polls) or not polls or u['at_ns']>polls[0]['start_ns']:
            fail()
        for m,p in zip(matches,polls):
            if type(m)is not dict or not within(m.get('history_cursor'),m.get('start_ns')) or not within(m.get('history_cursor'),m.get('end_ns')):
                fail()
            if type(m) is not dict or set(m)!={'attempt','ok','ready','start_ns','end_ns','history_cursor'} or any(type(m[k]) is not int for k in ('attempt','start_ns','end_ns','history_cursor')) or m['ok'] is not True or type(m['ready']) is not bool or m['ready']!=p['ready'] or m['attempt']!=p['attempt'] or not p['start_ns']<=m['start_ns']<=m['end_ns']<=p['end_ns'] or m['history_cursor']!=p['start_cursor']:
                fail()
        previous=c['end_ns']


def _validate_session_operands(report,inventory):
    def fail():
        raise ValueError('original dynamic session source/trigger/operand mismatch')
    supported=('lifecycle.hidden_goal.done','lifecycle_repairs.document.pending_cleared','lifecycle_repairs.source_append.completed')
    rows=report.get('session_operands');calls=report['observer_calls'];expected=[(i,c)for i,c in enumerate(calls,1)if c['site']in supported]
    if type(report.get('session_operand_unbound'))is not int or report['session_operand_unbound']!=0 or type(rows)is not list or len(rows)!=len(expected):
        fail()
    states,pages,workers=_observer_sources(report,inventory);positions=_causal_positions(report);events=report['helper_history'];previous=0
    for index,(row,(call_index,c))in enumerate(zip(rows,expected),1):
        hidden=c['site']=='lifecycle.hidden_goal.done';cp=0 if hidden else 6;bp=0 if hidden else 7;up=8 if c['site']=='lifecycle_repairs.document.pending_cleared' else bp;owner=states[c['start_cursor']][0]
        def check(cursor,at,pos):
            if type(cursor)is not int or type(at)is not int or not 0<=cursor<len(states) or states[cursor][0]!=owner or positions[cursor]!=(pos,True) or (cursor and events[cursor-1]['at_ns']>at) or (cursor<len(events) and events[cursor]['at_ns']<at):
                fail()
            return cursor
        if type(row)is not dict or set(row)!={'source','site','capture','selections','triggers','uses','queries','predicates'} or type(row['source'])is not int or row['source']!=index or row['site']!=c['site']:
            fail()
        cap=row['capture']
        if type(cap)is not dict or set(cap)!={'worker','page','ok','start_ns','end_ns','start_cursor','end_cursor'} or cap['ok']is not True or any(type(cap[k])is not int for k in set(cap)-{'ok'}):
            fail()
        cursor=check(cap['start_cursor'],cap['start_ns'],cp);last=check(cap['end_cursor'],cap['end_ns'],cp);page=cap['page'];worker=cap['worker']
        if not previous<=cap['start_ns']<=cap['end_ns'] or cursor!=last or pages[cursor].get('tracer')!=page or workers[cursor].get(page)!=worker or any(type(row[k])is not list or len(row[k])!=1 for k in ('selections','triggers','uses')):
            fail()
        b=row['selections'][0];t=row['triggers'][0];u=row['uses'][0]
        if type(b)is not dict or set(b)!={'ok','at_ns','history_cursor'} or b['ok']is not True or type(t)is not dict or set(t)!={'page','ok','start_ns','end_ns','start_cursor','end_cursor'} or t['ok']is not True or any(type(t[k])is not int for k in set(t)-{'ok'}) or type(u)is not dict or set(u)!={'call','at_ns','history_cursor'} or any(type(u[k])is not int for k in u):
            fail()
        check(b['history_cursor'],b['at_ns'],bp);tc=check(t['start_cursor'],t['start_ns'],bp);ec=check(t['end_cursor'],t['end_ns'],bp)
        if not cap['end_ns']<=b['at_ns']<=t['start_ns']<=t['end_ns']<=c['start_ns'] or t['page']!=page or tc!=ec or u['call']!=call_index or u['history_cursor']!=c['start_cursor'] or positions[c['start_cursor']]!=(up,True) or not c['start_ns']<=u['at_ns']<=c['end_ns']:
            fail()
        if hidden:
            recorded=[r for r in calls if r['site']=='lifecycle.hidden_goal.recorded' and states[r['start_cursor']][0]==owner]
            if len(recorded)!=1 or t['end_ns']>recorded[0]['start_ns'] or recorded[0]['end_ns']>c['start_ns']:
                fail()
        queries=row['queries'];predicates=row['predicates'];polls=c['polls']
        if type(queries)is not list or type(predicates)is not list or len(queries)!=len(polls) or len(predicates)!=len(polls) or not polls or u['at_ns']>polls[0]['start_ns']:
            fail()
        for q,r,p in zip(queries,predicates,polls):
            if type(q)is not dict or set(q)!={'attempt','ok','start_ns','end_ns','history_cursor'} or type(r)is not dict or set(r)!={'attempt','ok','ready','at_ns','history_cursor'} or q['ok']is not True or r['ok']is not True or type(r['ready'])is not bool or r['ready']!=p['ready'] or any(type(q[k])is not int for k in ('attempt','start_ns','end_ns','history_cursor')) or any(type(r[k])is not int for k in ('attempt','at_ns','history_cursor')) or q['attempt']!=p['attempt'] or r['attempt']!=p['attempt'] or not p['start_ns']<=q['start_ns']<=q['end_ns']<=r['at_ns']<=p['end_ns'] or q['history_cursor']!=p['start_cursor'] or r['history_cursor']!=p['start_cursor']:
                fail()
        previous=c['end_ns']


def _validate_key_inputs(report,inventory):
    def fail():
        raise ValueError('original key capture/trigger/lifetime/operand mismatch')
    rows=report.get('key_inputs');cases=report['cases'];calls=report['observer_calls'];names=('inference_cases.c006.p001','inference_cases.c007.p004','inference_cases.c008.p001','inference_cases.c008.p002');expected=[(i,c)for i,c in enumerate(cases)if c['id']in names]
    if type(report.get('key_unbound_inputs'))is not int or report['key_unbound_inputs']!=0 or type(rows)is not list or len(rows)!=len(expected):
        fail()
    states,pages,workers=_observer_sources(report,inventory);positions=_causal_positions(report);events=report['helper_history'];previous=0
    for index,(row,(case_index,case))in enumerate(zip(rows,expected),1):
        core=case['id']==names[0];reload=case['id']==names[1];site='inference.core_sweep.wait' if core else 'inference.reload_sweep.wait' if reload else 'inference.crash_sweep.wait';inside=('inference_cases.run','inside',case['id']);capture_owner=inside if core else ('inference_cases.run','after',cases[case_index-1]['id']);cap_pos=0 if core else 5 if reload else 4
        def point(cursor,at,owner,pos):
            if type(cursor)is not int or type(at)is not int or not 0<=cursor<len(states) or states[cursor][0]!=owner or positions[cursor]!=(pos,True) or (cursor and events[cursor-1]['at_ns']>at) or (cursor<len(events) and events[cursor]['at_ns']<at):
                fail()
            return cursor
        if type(row)is not dict or set(row)!={'source','site','capture','bindings','triggers','uses','matches','ids','terminal_inputs','terminal_matches','final_uses','borrows','retirements'} or type(row['source'])is not int or row['source']!=index or row['site']!=site:
            fail()
        cap=row['capture']
        if type(cap)is not dict or set(cap)!={'ok','worker','page','start_ns','end_ns','start_cursor','end_cursor'} or cap['ok']is not True or any(type(cap[k])is not int for k in set(cap)-{'ok'}):
            fail()
        cc=point(cap['start_cursor'],cap['start_ns'],capture_owner,cap_pos);ec=point(cap['end_cursor'],cap['end_ns'],capture_owner,cap_pos);page=cap['page'];worker=cap['worker']
        if not previous<=cap['start_ns']<=cap['end_ns'] or cc!=ec or pages[cc].get('tracer')!=page or workers[cc].get(page)!=worker or (not core and cap['end_ns']>case['start_ns']) or (core and cap['start_ns']<case['start_ns']) or any(type(row[k])is not list or len(row[k])!=1 for k in ('bindings','triggers','retirements')):
            fail()
        b=row['bindings'][0];t=row['triggers'][0];r=row['retirements'][0]
        if type(b)is not dict or set(b)!={'ok','at_ns','history_cursor'} or b['ok']is not True or type(t)is not dict or set(t)!={'kind','ok','worker','page','start_ns','end_ns','start_cursor','end_cursor'} or t['ok']is not True or any(type(t[k])is not int for k in ('worker','page','start_ns','end_ns','start_cursor','end_cursor')):
            fail()
        point(b['history_cursor'],b['at_ns'],inside if reload else capture_owner,1 if reload else cap_pos);tc=point(t['start_cursor'],t['start_ns'],inside,0);point(t['end_cursor'],t['end_ns'],inside,int(reload))
        if t['kind']!=('crash' if core else 'reload' if reload else 'page-crash') or t['worker']!=worker or t['page']!=page or pages[tc].get('tracer')!=page or workers[tc].get(page)!=worker or not cap['end_ns']<=t['start_ns']<=t['end_ns'] or (reload and t['end_ns']>b['at_ns']) or (not reload and not cap['end_ns']<=b['at_ns']<=t['start_ns']):
            fail()
        branch=case['branches'].get('reload-revoke') if reload else None
        if reload and branch not in ('absent','pending','finished'):
            fail()
        reason='used' if not reload or branch=='absent' else branch;used=reason=='used';uses=row['uses'];matches=row['matches'];wait=[(i,c)for i,c in enumerate(calls,1)if c['site']==site and states[c['start_cursor']][0]==inside]
        if type(uses)is not list or type(matches)is not list or len(wait)!=int(used) or len(uses)!=int(used):
            fail()
        last=max(t['end_ns'],b['at_ns'])
        if used:
            call_index,c=wait[0];u=uses[0];point(c['start_cursor'],c['start_ns'],inside,4)
            if type(u)is not dict or set(u)!={'call','ok','at_ns','history_cursor'} or u['ok']is not True or any(type(u[k])is not int for k in ('call','at_ns','history_cursor')) or u['call']!=call_index or u['history_cursor']!=c['start_cursor'] or c['start_ns']<last or u['at_ns']<c['start_ns']:
                fail()
            polls=c['polls']
            if len(matches)!=len(polls) or not polls or u['at_ns']>polls[0]['start_ns']:
                fail()
            for m,p in zip(matches,polls):
                if type(m)is not dict or set(m)!={'call','attempt','ok','ready','start_ns','end_ns','history_cursor'} or any(type(m[k])is not int for k in ('call','attempt','start_ns','end_ns','history_cursor')) or m['call']!=u['call'] or m['attempt']!=p['attempt'] or m['ok']is not True or type(m['ready'])is not bool or m['ready']!=p['ready'] or not p['start_ns']<=m['start_ns']<=m['end_ns']<=p['end_ns'] or m['history_cursor']!=p['start_cursor']:
                    fail()
            last=c['end_ns']
        elif matches:
            fail()
        ids=row['ids']
        if type(ids)is not list or len(ids)!=int(core or reload):
            fail()
        if ids:
            id=ids[0]
            if type(id)is not dict or set(id)!={'ok','at_ns','history_cursor'} or id['ok']is not True:
                fail()
            point(id['history_cursor'],id['at_ns'],inside,4 if core else 1)
            if (core and id['at_ns']<last) or (reload and not t['end_ns']<=id['at_ns']<=b['at_ns']):
                fail()
            if core:
                last=id['at_ns']
        inputs=row['terminal_inputs'];terminal=row['terminal_matches']
        if type(inputs)is not list or type(terminal)is not list or len(inputs)!=int(core):
            fail()
        if core:
            found=[(i,c)for i,c in enumerate(calls,1)if c['site']=='inference.core.revoke_terminal' and states[c['start_cursor']][0]==inside]
            if len(found)!=1:
                fail()
            ci,c=found[0];u=inputs[0]
            if type(u)is not dict or set(u)!={'call','at_ns','history_cursor'} or any(type(u[k])is not int for k in u) or u['call']!=ci or u['history_cursor']!=c['start_cursor'] or last>c['start_ns'] or u['at_ns']<c['start_ns'] or len(terminal)!=len(c['polls']) or not c['polls'] or u['at_ns']>c['polls'][0]['start_ns']:
                fail()
            for m,p in zip(terminal,c['polls']):
                if type(m)is not dict or set(m)!={'attempt','ok','ready','at_ns','history_cursor'} or any(type(m[k])is not int for k in ('attempt','at_ns','history_cursor')) or m['ok']is not True or type(m['ready'])is not bool or m['ready']!=p['ready'] or m['attempt']!=p['attempt'] or not p['start_ns']<=m['at_ns']<=p['end_ns'] or m['history_cursor']!=p['start_cursor']:
                    fail()
            last=c['end_ns']
        elif terminal:
            fail()
        borrows=row['borrows'];borrow_positions=[0] if core else [1,4] if reload else [0,4] if case['id']=='inference_cases.c008.p001' else [0,1,4]
        if type(borrows)is not list or len(borrows)!=len(borrow_positions):
            fail()
        prior_borrow=t['end_ns']
        for borrow,position in zip(borrows,borrow_positions):
            if type(borrow)is not dict or set(borrow)!={'ok','at_ns','history_cursor'} or borrow['ok']is not True:
                fail()
            point(borrow['history_cursor'],borrow['at_ns'],inside,position)
            if borrow['at_ns']<prior_borrow or (reload and position==1 and borrow['at_ns']<b['at_ns']) or (position==4 and borrow['at_ns']<last):
                fail()
            prior_borrow=borrow['at_ns']
        fs=row['final_uses']
        if type(fs)is not list or len(fs)!=1:
            fail()
        f=fs[0]
        if type(f)is not dict or set(f)!={'kind','ok','start_ns','end_ns','start_cursor','end_cursor'} or f['ok']is not True or f['kind']!=('core-status' if core else 'expiry' if reload else 'crash-status'):
            fail()
        point(f['start_cursor'],f['start_ns'],inside,4);point(f['end_cursor'],f['end_ns'],inside,4)
        if not max(last,prior_borrow)<=f['start_ns']<=f['end_ns'] or type(r)is not dict or set(r)!={'reason','at_ns','history_cursor'} or r['reason']!=reason:
            fail()
        point(r['history_cursor'],r['at_ns'],inside,4)
        if not f['end_ns']<=r['at_ns']<=case['end_ns']:
            fail()
        previous=r['at_ns']


def _validate_displayed_words(report, inventory):
    error = 'original displayed phrase capture census/receiver/window mismatch'
    calls = report.get('observer_calls')
    captures = report.get('displayed_word_captures')
    if type(calls)is not list or type(captures)is not list:
        raise ValueError(error)
    expected = [(index+1, call) for index, call in enumerate(calls) if call.get('kind')=='seed.phrase']
    if len(captures)!=len(expected):
        raise ValueError(error)
    previous = (0, 0)
    for capture, (identity, call) in zip(captures, expected):
        if type(capture)is not dict or set(capture)!={'call','page','ok','at_ns','history_cursor'}:
            raise ValueError(error)
        if any(type(capture[key])is not int or capture[key]<0 for key in ('call','page','at_ns','history_cursor')) or capture['ok']is not True:
            raise ValueError(error)
        at, cursor = capture['at_ns'], capture['history_cursor']
        if capture['call']!=identity or capture['page']!=call.get('page') or any(type(call.get(key))is not int for key in ('page','start_ns','end_ns','start_cursor','end_cursor')) or not call['start_ns']<=at<=call['end_ns'] or not call['start_cursor']<=cursor<=call['end_cursor'] or at<previous[0] or cursor<previous[1]:
            raise ValueError(error)
        previous = (at, cursor)
    domains = inventory['displayed_phrase_comparisons']
    for rule in domains.values():
        if type(rule) is not dict or set(rule) != {'operands', 'predicate', 'partner'} or type(rule['operands']) is not list or len(rule['operands']) > 2 or any(type(o) is not str for o in rule['operands']) or (type(rule['predicate']) is not str if rule['operands'] else rule['predicate'] is not None):
            raise ValueError(error)
        partner=rule['partner']
        if partner is not None and partner != ['collision'] and not (type(partner) is list and len(partner)==3 and partner[0]=='reader' and all(type(v) is str for v in partner[1:])): raise ValueError(error)

    expected_uses = []
    for index, call in enumerate(calls):
        if call['kind'] != 'seed.phrase': continue
        case = next((c for c in report['cases'] if c['start_ns'] <= call['start_ns'] <= call['end_ns'] <= c['end_ns']), None)
        rule = domains.get(call['site'])
        if case is None or rule is None: raise ValueError(error)
        sources = []
        for operand in rule['operands']:
            source = index if operand == 'self' else next((i for i in range(index-1, -1, -1) if calls[i]['site'] == operand and calls[i]['start_ns'] >= case['start_ns']), None)
            if source is None: raise ValueError(error)
            sources.append(source+1)
        for n, source in enumerate(sources):
            expected_uses.append((source, sources[1-n] if len(sources) == 2 else None, call, case, rule['predicate'], rule['partner']))
    uses, history = report.get('displayed_word_uses'), report['helper_history']
    if type(uses) is not list or len(uses) != len(expected_uses): raise ValueError(error)
    previous = (0, 0)
    for use, (source, other, call, case, predicate, reader) in zip(uses, expected_uses):
        fields = {'call', 'other', 'partner', 'result', 'ok', 'case', 'at_ns', 'history_cursor', 'predicate', 'instance', 'check_ns', 'check_cursor'}
        if type(use) is not dict or set(use) != fields or any(type(use[k]) is not int for k in ('call', 'at_ns', 'history_cursor', 'instance', 'check_ns', 'check_cursor')) or (use['other'] is not None and type(use['other']) is not int): raise ValueError(error)
        checked = next((p for p in report['primary_history'] if p['case'] == case['id'] and p['id'] == f'{predicate}.i001'), None)
        if checked is None: raise ValueError(error)
        at, cursor = use['at_ns'], use['history_cursor']
        expected_partner = None
        if reader is not None and reader[0]=='collision':
            original=next((c for c in inventory['cases'] if c['id']==case['id'] and c['site_id']=='seed_cases.c001'),None)
            if original is None: raise ValueError(error)
            family=[c['id'] for c in inventory['cases'] if c['site_id']==original['site_id'] and c['invocation']==original['invocation']]
            expected_partner=dict(kind='collision',index=family.index(case['id'])+1,ok=True)
        elif reader is not None:
            roots = [(n, r) for n, r in enumerate(report['reader_roots'], 1) if r['site'] == reader[1] and r['start_ns'] >= case['start_ns'] and r['end_ns'] <= at]
            if len(roots) != 1: raise ValueError(error)
            expected_partner = dict(kind='reader',source=roots[0][0], site=reader[2], ok=True)
        if use['call'] != source or use['other'] != other or not _same_json(use['partner'], expected_partner) or use['result'] is not True or use['ok'] is not True or use['case'] != case['id'] or use['predicate'] != predicate or use['instance'] != 1 or use['check_ns'] != checked['at_ns'] or use['check_cursor'] != checked['history_cursor'] or not call['end_ns'] <= at <= checked['at_ns'] <= case['end_ns'] or not call['end_cursor'] <= cursor <= checked['history_cursor'] or not 1 <= cursor < len(history) or not history[cursor-1]['at_ns'] <= at <= history[cursor]['at_ns'] or at < previous[0] or cursor < previous[1]: raise ValueError(error)
        previous = at, cursor


def validate_observers(report, inventory):
    _validate_logical_checks(report,inventory)
    if not _same_json(report.get("aggregator_inputs"), {"registrations":1,"unmatched":0}):
        raise ValueError("original aggregator receiver mismatch")
    if not _same_json(report.get('observer_unbound_arguments'), {'values':[],'triggers':[],'workers':0,'goal_ends':0,'document_sessions':0,'document_queries':0}):
        raise ValueError('unbound original source argument capture or trigger')
    if type(report.get('causal_unbound_jobs')) is not int or report['causal_unbound_jobs']!=0:
        raise ValueError('unbound causal job input/dispatch/producer')
    _validate_runtime_inputs(report, inventory)
    _validate_submissions(report, inventory)
    _validate_displayed_words(report, inventory)
    calls = report.get('observer_calls')
    if type(calls) is not list:
        raise ValueError('missing serial observer completions')
    use_calls=[i+1 for i,c in enumerate(calls) if c.get('kind') in ('job.wait_launch','job.wait_end') or c.get('site')=='job.mismatch.start_observed']
    if not _same_json(report.get('causal_use_calls'),use_calls):
        raise ValueError('causal job source use multiplicity/order mismatch')
    expected = _observer_expected(report, inventory)
    causal_expected = _causal_expected(report, inventory)
    positions = _causal_positions(report)
    job_producers = {}
    class_inputs = []
    goal_end_inputs = []
    prior_inputs = report.get('observer_prior_inputs')
    if type(prior_inputs) is not list:
        raise ValueError('missing original initial view inputs')
    prior_used = set()
    argument_groups = {}
    argument_group_sites = {}
    argument_events = []
    states, pages, workers = _observer_sources(report, inventory)
    from tracer_seed_operations import validate as validate_seed_operations
    validate_seed_operations(report, inventory, states, pages, workers)
    visited = set()
    events, duration = report['helper_history'], report['duration_ns']

    def cursor(value, at, owner):
        cleanup=owner==('', 'cleanup', '')
        if type(value) is not int or not 0 <= value < len(states) or (states[value][0] is not None if cleanup else states[value][0]!=owner) or value and events[value - 1]['at_ns'] > at or value < len(events) and events[value]['at_ns'] < at:
            raise ValueError('observer source caller/history mismatch')
        if cleanup:
            phase=next((p for p in report['timings'] if p['phase']=='cleanup'),None)
            if phase is None or value!=len(events) or not phase['start_ns']<=at<=phase['end_ns']:
                raise ValueError('cleanup observer outside original phase')
        return value

    def document_query(queries,node,owner,low,high,query_cursor):
        if type(queries)is not list or len(queries)!=1:
            raise ValueError('original document counter query multiplicity mismatch')
        query=queries[0]
        fields={'kind','value','receiver_ok','start_ns','end_ns','start_cursor','end_cursor'}
        if type(query)is not dict or set(query)!=fields or any(type(query[k])is not int or not 0<=query[k]<=18446744073709551615 for k in fields-{'kind','receiver_ok'}):
            raise ValueError('invalid original document counter query schema')
        kind='closes' if node['site']=='goal.document.connection_closed' else 'requests'
        if query['kind']!=kind or query['receiver_ok']is not True or not low<=query['start_ns']<=query['end_ns']<=high or query['start_cursor']!=query_cursor or query['end_cursor']!=query_cursor:
            raise ValueError('original document counter receiver/role/window mismatch')
        cursor(query['start_cursor'],query['start_ns'],owner);cursor(query['end_cursor'],query['end_ns'],owner)
        return query['value']

    def job_receiver(value,owner,position,query):
        keys={'worker','page','worker_ok','at_ns','history_cursor'} | ({'end_ns','end_cursor'} if query else {'input_ok'})
        if type(value) is not dict or set(value)!=keys or any(type(value[k]) is not int for k in keys-{'worker_ok','input_ok'}) or value['worker_ok'] is not True or not query and value['input_ok'] is not True:
            raise ValueError('invalid causal job source input schema')
        at=value['at_ns'];where=cursor(value['history_cursor'],at,owner);page=value['page']
        if positions[where]!=(position,True) or pages[where].get('tracer')!=page or workers[where].get(page)!=value['worker']:
            raise ValueError('causal job source receiver/history mismatch')
        if query:
            cursor(value['end_cursor'],value['end_ns'],owner)
            if value['end_ns']<at or value['end_cursor']!=value['history_cursor']:
                raise ValueError('causal baseline query crosses source history')
        return at,where

    def direct_operand(call,node,owner):
        site=node['site']
        if site=='goal.document.connection_closed':
            inputs=call['causal_input']
            if type(inputs) is not list or len(inputs)!=1 or not _same_json(call['causal_result'],[]) or not _same_json(call['causal_matches'],[]):
                raise ValueError('original end dispatch multiplicity mismatch')
            input=inputs[0];n=len(goal_end_inputs);ledger=report.get('goal_end_inputs')
            if type(input) is not dict or set(input)!={'source','worker','page','input_ok','start_ns','end_ns','start_cursor','end_cursor'} or any(type(input[k]) is not int for k in set(input)-{'input_ok'}) or input['input_ok'] is not True or input['source']!=n+1 or type(ledger) is not list or n>=len(ledger) or not _same_json(ledger[n],input):
                raise ValueError('original end dispatch source mismatch')
            goal_end_inputs.append(input)
            start,end=input['start_ns'],input['end_ns'];where=cursor(input['start_cursor'],start,owner);last=cursor(input['end_cursor'],end,owner);page=input['page'];worker=input['worker']
            prior=[c for c in calls if c['site']=='goal.document.active_sent' and states[c['start_cursor']][0]==owner]
            if len(prior)!=1 or not prior[0]['end_ns']<=start<=end<=call['start_ns'] or input['start_cursor']!=prior[0]['end_cursor'] or where!=last or input['end_cursor']!=call['start_cursor'] or pages[where].get('tracer')!=page or workers[where].get(page)!=worker or call['page']!=page or call['argument_triggers'][0]['worker']!=worker:
                raise ValueError('original end dispatch source order mismatch')
            return True
        if site not in ('setup.class.answer_applied','main.writer.holder_and_waiter'):
            return False
        inputs=call['causal_input']
        if type(inputs) is not list or len(inputs)!=1 or not _same_json(call['causal_result'],[]):
            raise ValueError('original direct operand capture multiplicity mismatch')
        input=inputs[0]
        if site=='setup.class.answer_applied':
            if type(input) is not dict or set(input)!={'source','machine','answer','page','start_ns','end_ns','start_cursor','end_cursor','selector_ok'} or any(type(input[k]) is not int for k in ('source','page','start_ns','end_ns','start_cursor','end_cursor')) or input['machine']!=node['domain']['machine'] or input['answer']!=node['domain']['answer'] or input['selector_ok'] is not True:
                raise ValueError('original class answer dispatch input mismatch')
            index=len(class_inputs)
            triggers=report.get('class_inputs')
            if type(triggers) is not list or input['source']!=index+1 or index>=len(triggers) or not _same_json(triggers[index],input):
                raise ValueError('original class trigger multiplicity/order mismatch')
            class_inputs.append(input)
            start,end=input['start_ns'],input['end_ns']
            where=cursor(input['start_cursor'],start,owner)
            cursor(input['end_cursor'],end,owner)
            if not 0<=start<=end<=call['start_ns'] or input['start_cursor']!=input['end_cursor'] or input['end_cursor']!=call['start_cursor'] or pages[where].get(node['page_role'])!=input['page']:
                raise ValueError('original class dispatch source lineage mismatch')
        else:
            if type(input) is not dict or set(input)!={'at_ns','history_cursor','worker','page','worker_ok'} or any(type(input[k]) is not int for k in ('at_ns','history_cursor','worker','page')) or input['worker_ok'] is not True:
                raise ValueError('invalid original holder Worker capture')
            at=input['at_ns'];where=cursor(input['history_cursor'],at,owner);start_cursor=call['start_cursor'];page=input['page']
            if where>=len(events):
                raise ValueError('holder capture without original page birth')
            event=events[where]
            if positions[where]!=(0,True) or positions[start_cursor]!=(1,True) or event['event']!='call_start' or event['kind']!='runtime.worker' or event['at_ns']<at or pages[where].get('tracer')!=page or workers[where].get(page)!=input['worker'] or call['page']!=page:
                raise ValueError('original holder Worker capture/birth lineage mismatch')
        matches=call['causal_matches'];polls=call['polls']
        if type(matches) is not list or len(matches)!=len(polls):
            raise ValueError('original direct operand use multiplicity mismatch')
        name='class_machine' if site=='setup.class.answer_applied' else 'holder'
        for value,poll in zip(matches,polls):
            if type(value) is not dict or set(value)!={'name','ok','ready','attempt','at_ns','history_cursor'} or any(type(value[k]) is not int for k in ('attempt','at_ns','history_cursor')) or value['name']!=name or value['ok'] is not True or type(value['ready']) is not bool:
                raise ValueError('invalid original direct operand use schema')
            at=value['at_ns'];cursor(value['history_cursor'],at,owner)
            if value['ready'] is not poll['ready'] or value['attempt']!=poll['attempt'] or not poll['start_ns']<=at<=poll['end_ns']:
                raise ValueError('original direct operand predicate/attempt mismatch')
        return True

    def job_input(index,call,node,owner):
        if direct_operand(call,node,owner):
            return
        kind=node['kind'];marker=node['site']=='job.mismatch.start_observed';inputs=call['causal_input'];results=call['causal_result']
        if kind=='fixture.ssh_ended' or node['site']=='session.closed.ssh':
            if not _same_json(inputs,[]) or not _same_json(results,[]):
                raise ValueError('unexpected original SSH counter input')
            matches=call['causal_matches'];polls=call['polls']
            if type(matches)is not list or len(matches)!=2*len(polls):
                raise ValueError('original SSH counter multiplicity mismatch')
            for index,poll in enumerate(polls):
                prior=poll['start_ns'];values=[]
                for input,field in zip(matches[index*2:index*2+2],('ended','accepted') if kind=='fixture.ssh_ended' else ('accepted','ended')):
                    if type(input)is not dict or set(input)!={'name','attempt','field','role','receiver_ok','value','at_ns','history_cursor'} or input['name']!='ssh_counter' or input['field']!=field or input['role']!=(node['domain']['fixture'] if kind=='fixture.ssh_ended' else 'primary') or input['receiver_ok']is not True or any(type(input[k])is not int for k in ('attempt','value','at_ns','history_cursor')) or not 0<=input['value']<=4294967295 or input['attempt']!=poll['attempt'] or not prior<=input['at_ns']<=poll['end_ns'] or input['history_cursor']!=poll['start_cursor']:
                        raise ValueError('original SSH counter receiver/window/order mismatch')
                    prior=input['at_ns'];values.append(input['value'])
                if poll['ready']!=(values[0]==values[1]):
                    raise ValueError('original SSH ended/accepted comparison mismatch')
            return
        if kind=='fixture.wait':
            if not _same_json(inputs,[]) or not _same_json(results,[]):
                raise ValueError('unexpected original fixture predicate inputs')
            matches=call['causal_matches'];polls=call['polls']
            if type(matches)is not list or len(matches)!=len(polls):
                raise ValueError('original fixture predicate multiplicity mismatch')
            from tracer_fixture_predicates import replay
            for input,poll in zip(matches,polls):
                if type(input)is not dict or set(input)!={'name','operands','ready','attempt','at_ns','history_cursor'} or input['name']!='fixture_predicate' or type(input['ready'])is not bool or any(type(input[k])is not int for k in ('attempt','at_ns','history_cursor')):
                    raise ValueError('invalid original fixture predicate schema')
                at=input['at_ns'];cursor(input['history_cursor'],at,owner)
                if input['attempt']!=poll['attempt'] or not poll['start_ns']<=at<=poll['end_ns'] or input['history_cursor']!=poll['start_cursor']:
                    raise ValueError('original fixture predicate receiver/window/order mismatch')
                ready=replay(node['site'],input['operands'])
                if input['ready']is not ready or poll['ready']is not ready:
                    raise ValueError('original fixture whole predicate mismatch')
            return
        if type(inputs) is not list or type(results) is not list:
            raise ValueError('missing causal input/producer captures')
        if kind not in ('job.wait_launch','job.wait_end') and not marker:
            if inputs or results or call['causal_matches']!=[]:
                raise ValueError('unexpected causal job operands')
            return
        launch=kind=='job.wait_launch'
        if len(inputs)!=1 or len(results)!=int(launch):
            raise ValueError('causal job capture/producer write multiplicity mismatch')
        input=inputs[0];produced=results[0] if results else None
        keys={'source','source_job','occurrence','origin','capture','trigger','input_ok'} | (set() if launch else {'producer'})
        if type(input) is not dict or set(input)!=keys or input['input_ok'] is not True or type(input['source']) is not int or type(input['occurrence']) is not int or input['source_job']!=node['source_job'] or input['occurrence']!=node['occurrence']:
            raise ValueError('causal job original input/occurrence mismatch')
        source=input['source'];holding=node['source_job']=='goal_admission.holding_job'
        if launch or holding:
            if source!=len(job_producers)+1:
                raise ValueError('causal job source multiplicity/order mismatch')
            position=node['root_start']
            capture,_=job_receiver(input['capture'],owner,position,True)
            trigger,_=job_receiver(input['trigger'],owner,position-1 if holding else position,False)
            capture_end=input['capture']['end_ns'];start=call['start_ns']
            same_receiver=input['capture']['page']==input['trigger']['page'] and input['capture']['worker']==input['trigger']['worker']
            correct_lineage=(trigger<=capture and capture_end<=start and input['origin']=='holding') if holding else (capture_end<=trigger<=start and input['origin']==node['previous_origin'])
            if not same_receiver or not correct_lineage:
                raise ValueError('causal job original capture/dispatch lineage mismatch')
            value=input['producer'] if holding else produced
            if type(value) is not dict or set(value)!={'source','call','at_ns','history_cursor','input_ok'} or any(type(value[k]) is not int for k in ('source','at_ns','history_cursor')) or value['source']!=source or value['input_ok'] is not True:
                raise ValueError('invalid causal job original producer schema')
            if (value['call'] is not None or produced is not None) if holding else (type(value['call']) is not int or value['call']!=index+1):
                raise ValueError('invalid causal job original producer schema')
            at=value['at_ns'];where=cursor(value['history_cursor'],at,owner)
            low,high=(capture_end,start) if holding else (call['polls'][-1]['end_ns'],call['end_ns'])
            if not low<=at<=high or positions[where]!=(position,True):
                raise ValueError('causal job producer crosses original observation')
            job_producers[source]=({'source_job':node['source_job'],'occurrence':node['occurrence']},value)
        else:
            if source not in job_producers:
                raise ValueError('job end without original admitted producer')
            origin,result=job_producers[source]
            if input['origin']!='launch' or input['source_job']!=origin['source_job'] or input['occurrence']!=origin['occurrence'] or not _same_json(input['producer'],result) or input['capture'] is not None or input['trigger'] is not None or produced is not None or result['at_ns']>call['start_ns']:
                raise ValueError('job end original producer/identity lineage mismatch')
        matches=call['causal_matches']
        if type(matches) is not list:
            raise ValueError('missing causal job predicate operands')
        offset=0;previous=call['start_ns']
        for poll in call['polls']:
            names=('candidate','newer','contains') if launch else ('marker',) if marker else ('ended','exit')
            result=False
            for ordinal,name in enumerate(names):
                if ordinal and not result:
                    break
                if offset>=len(matches):
                    raise ValueError('missing causal job short-circuit operand')
                value=matches[offset];offset+=1
                if type(value) is not dict or set(value)!={'name','ok','ready','attempt','at_ns','history_cursor'} or type(value['name']) is not str or value['ok'] is not True or type(value['ready']) is not bool or any(type(value[k]) is not int for k in ('attempt','at_ns','history_cursor')):
                    raise ValueError('invalid causal job operand schema')
                at=value['at_ns'];cursor(value['history_cursor'],at,owner)
                if value['name']!=name or value['attempt']!=poll['attempt'] or not max(previous,poll['start_ns'])<=at<=poll['end_ns']:
                    raise ValueError('causal job original operand/attempt mismatch')
                previous=at;result=value['ready']
            if poll['ready'] is not result:
                raise ValueError('causal job whole original predicate mismatch')
        if offset!=len(matches):
            raise ValueError('extra causal job predicate operands')

    def validate_call(index, node, owner, parent, depth=0):
        if depth > 100 or type(index) is not int or not 0 <= index < len(calls) or index in visited:
            raise ValueError('invalid/duplicate observer instance')
        visited.add(index)
        call = calls[index]
        fields = {'site', 'kind', 'domain', 'domain_captures', 'argument_domains', 'argument_triggers', 'argument_matches', 'causal_input', 'causal_result', 'causal_matches', 'page', 'parent', 'children', 'polls', 'facts', 'inputs', 'page_inputs', 'start_ns', 'end_ns', 'start_cursor', 'end_cursor'}
        if type(call) is not dict or set(call) != fields:
            raise ValueError('invalid observer invocation schema')
        start, end, kind = call['start_ns'], call['end_ns'], node['kind']
        if type(start) is not int or type(end) is not int or not 0 <= start <= end <= duration or call['site'] != node['site'] or call['kind'] != kind or not _same_json(call['domain'], node['domain']) or not _same_json(call['parent'], parent):
            raise ValueError('observer source invocation/parameter mismatch: ' + node['site'])
        position = cursor(call['start_cursor'], start, owner)
        end_position = cursor(call['end_cursor'], end, owner)
        if 'root_start' in node and (positions[position]!=(node['root_start'],True) or positions[end_position]!=(node['root_end'],True)):
            raise ValueError('causal observer original helper position mismatch')
        if type(call['domain_captures']) is not int or call['domain_captures'] != int(kind == 'setup.approve'):
            raise ValueError('observer input capture multiplicity mismatch')
        if kind.startswith(('inference.','fixture.')) or kind in ('job.wait_end','session.closed'):
            if call['page'] is not None:
                raise ValueError('fixture observer has an invented browser input')
        elif type(call['page']) is not int or node['page_role'] not in pages[position] or call['page'] != pages[position][node['page_role']]:
            raise ValueError('observer source page lineage mismatch')
        if node.get('page_input_phase') == 'after_false':
            matches = [(i, p) for i, p in enumerate(prior_inputs) if type(p) is dict and p.get('site') == node['site'] and _same_json(p.get('end_cursor'), call['start_cursor'])]
            if len(matches) != 1:
                raise ValueError('missing/extra original initial view input')
            index, value = matches[0]
            if index in prior_used:
                raise ValueError('reused original initial view input')
            prior_used.add(index)
            if set(value) != {'site','page','view_source','start_ns','end_ns','start_cursor','end_cursor'} or type(value['site']) is not str or any(type(value[k]) is not int for k in ('page','view_source','start_ns','end_ns','start_cursor','end_cursor')):
                raise ValueError('invalid original initial view schema')
            at, done = value['start_ns'], value['end_ns']
            position = cursor(value['start_cursor'], at, owner)
            cursor(value['end_cursor'], done, owner)
            if not 0 <= at <= done <= start or value['start_cursor'] != value['end_cursor'] or pages[position].get(node['page_role']) != value['page']:
                raise ValueError('original initial view source input mismatch')
        bounded = {'seed.wait_stage', 'setup.approve', 'declaration.prepare.binding', 'declaration.prepare.goal_card', 'declaration.wait_card', 'declaration.wait_proposal_or_outcome', 'declaration.outcome', 'delivery.prepare', 'delivery.check', 'delivery.card'}
        bound = 300 if kind in bounded else 100 if kind in ('inference.wait_count', 'inference.wait_refused') else 300 if kind=='job.wait_launch' else 1000 if kind=='job.wait_end' else 0
        if kind in ('serial.observation','fixture.wait','fixture.ssh_ended'):
            bound = node['domain']['bound']
        polls = call['polls']
        if type(polls) is not list or not bound and polls or bound and not 1 <= len(polls) <= bound:
            raise ValueError('observer source attempt domain mismatch')
        previous = start
        for number, poll in enumerate(polls, 1):
            if type(poll) is not dict or set(poll) != {'attempt', 'ready', 'start_ns', 'end_ns', 'start_cursor', 'end_cursor'}:
                raise ValueError('invalid observer attempt schema')
            at, done = poll['start_ns'], poll['end_ns']
            interval = 50_000_000 if kind in ('seed.wait_stage', 'setup.approve', 'inference.wait_count', 'inference.wait_refused') else 10_000_000 if kind in ('job.wait_launch','job.wait_end') else 20_000_000
            if kind in ('serial.observation','fixture.wait','fixture.ssh_ended'):
                interval = node['domain']['false_sleep_ms'] * 1_000_000
            if number > 1 and type(at) is int and at - previous < interval:
                raise ValueError('observer original failed-attempt observation window shortened')
            ready_valid = poll['ready'] == (number == len(polls))
            if kind in ('serial.observation','fixture.wait','fixture.ssh_ended'):
                ready_valid = poll['ready'] is False if number < len(polls) else poll['ready'] is True or (node['domain']['requires_ready'] is False and len(polls) == bound)
            if type(at) is not int or type(done) is not int or not previous <= at <= done <= end or type(poll['attempt']) is not int or poll['attempt'] != number or type(poll['ready']) is not bool or not ready_valid:
                raise ValueError('observer predicate/attempt/termination mismatch')
            cursor(poll['start_cursor'], at, owner)
            cursor(poll['end_cursor'], done, owner)
            previous = done
        if kind in ('serial.observation','fixture.wait','fixture.ssh_ended') and polls[-1]['ready'] is False and end - polls[-1]['end_ns'] < node['domain']['false_sleep_ms'] * 1_000_000:
            raise ValueError('observer original exhausted-attempt sleep shortened')
        inputs = call['inputs']
        count = len(polls) + 1 if kind in ('setup.approve', 'delivery.check') else len(polls) if kind in ('declaration.prepare.binding', 'delivery.prepare','job.wait_launch') else 1 if kind in ('declaration.prepare', 'declaration.wait_card') else 0
        if kind == 'serial.observation':
            count = len(polls) * node['worker_inputs_per_poll']
        if type(inputs) is not list or len(inputs) != count:
            raise ValueError('observer original worker input multiplicity mismatch')
        previous = start
        for number, value in enumerate(inputs):
            if type(value) is not dict or set(value) != {'worker', 'page', 'at_ns', 'history_cursor'} or any(type(value[k]) is not int for k in value):
                raise ValueError('invalid observer worker input schema')
            at = value['at_ns']
            position = cursor(value['history_cursor'], at, owner)
            if not previous <= at <= end or pages[position].get(node['page_role']) != value['page'] or workers[position].get(value['page']) != value['worker']:
                raise ValueError('observer actual source worker/page input mismatch')
            poll_index = number - 1 if kind in ('setup.approve', 'delivery.check') else number if kind in ('declaration.prepare.binding', 'delivery.prepare','job.wait_launch') else None
            if kind == 'serial.observation':
                poll_index = number // node['worker_inputs_per_poll']
            if poll_index is not None and poll_index >= 0:
                if not polls[poll_index]['start_ns'] <= at <= polls[poll_index]['end_ns']:
                    raise ValueError('observer input outside original attempt')
            elif kind in ('setup.approve', 'delivery.check') and at > polls[0]['start_ns'] or kind == 'declaration.wait_card' and at < polls[-1]['end_ns']:
                raise ValueError('observer initial/final input chronology mismatch')
            previous = at
        page_inputs = call['page_inputs']
        expected_inputs = []
        if kind == 'serial.observation':
            for number, poll in enumerate(polls):
                if node['page_input_phase'] == 'before_predicate' or poll['ready'] is False:
                    expected_inputs.extend((number, spec) for spec in node['page_inputs_per_poll'])
        if type(page_inputs) is not list or len(page_inputs) != len(expected_inputs):
            raise ValueError('original page query input multiplicity mismatch')
        previous_page_input = start
        for value, (number, spec) in zip(page_inputs, expected_inputs):
            if type(value) is not dict or set(value) != {'slot','page','at_ns','history_cursor'} or type(value['slot']) is not str or any(type(value[k]) is not int for k in ('page','at_ns','history_cursor')):
                raise ValueError('invalid original page query input schema')
            at = value['at_ns']
            position = cursor(value['history_cursor'], at, owner)
            if value['slot'] != spec['slot'] or not previous_page_input <= at <= end or pages[position].get(spec['page_role']) != value['page']:
                raise ValueError('original page query source input mismatch')
            poll = polls[number]
            if node['page_input_phase'] == 'before_predicate':
                low, high = poll['start_ns'], poll['end_ns']
            else:
                low = poll['end_ns'] + node['domain']['false_sleep_ms'] * 1_000_000
                high = polls[number + 1]['start_ns'] if number + 1 < len(polls) else end
            if not low <= at <= high:
                raise ValueError('original page query crosses source observation window')
            previous_page_input = at
        document=node['site'] in ('goal.document.pending_sent','goal.document.active_sent','goal.document.connection_closed')
        names = node.get('argument_names', [])
        domains, triggers, matches = call['argument_domains'], call['argument_triggers'], call['argument_matches']
        if any(type(value) is not list for value in (domains,triggers,matches)) or len(domains)!=len(names) or len(triggers)!=int(bool(names)):
            raise ValueError('original source argument capture multiplicity mismatch')
        if triggers:
            trigger=triggers[0]
            trigger_fields={'at_ns','history_cursor','page','worker','order'}
            if node['site']=='hold.writer.read_completed':
                trigger_fields.add('dispatch_ok')
            else:
                trigger_fields.update(('dispatch_ok','session_source','session_capture'))
            if type(trigger) is not dict or set(trigger)!=trigger_fields or any(type(trigger[key]) is not int for key in ('at_ns','history_cursor','page','worker','order')) or node['site']=='hold.writer.read_completed' and trigger['dispatch_ok'] is not True:
                raise ValueError('invalid original source argument trigger schema')
            if node['site']!='hold.writer.read_completed':
                execution=[c['id'] for c in inventory['cases']] if report['mode']=='full' else report['plan']['expected_execution']
                documents=[id for id in ('goal_cases.c009.p001','goal_cases.c011.p001') if id in execution]
                target='goal_cases.c009.p001' if node['site']=='goal.document.pending_sent' else 'goal_cases.c011.p001'
                capture=trigger['session_capture']
                if trigger['dispatch_ok'] is not True or type(trigger['session_source'])is not int or trigger['session_source']!=documents.index(target)+1 or type(capture)is not dict or set(capture)!={'at_ns','history_cursor','worker','page','worker_ok','query'} or capture['worker_ok']is not True or any(type(capture[k])is not int for k in ('at_ns','history_cursor','worker','page','query')) or capture['worker']!=trigger['worker'] or capture['page']!=trigger['page'] or capture['history_cursor']!=trigger['history_cursor'] or capture['at_ns']>trigger['at_ns']:
                    raise ValueError('original goal document dispatch payload/source mismatch')
                queries=report['goal_session_inputs']
                if not 1<=capture['query']<=len(queries): raise ValueError('missing original goal document session query')
                query=queries[capture['query']-1]
                if query['end_ns']!=capture['at_ns'] or query['end_cursor']!=capture['history_cursor'] or query['worker']!=capture['worker'] or query['page']!=capture['page'] or query['document']!=('pending' if target=='goal_cases.c009.p001' else 'active'):
                    raise ValueError('original goal document query/capture mismatch')
                cursor(capture['history_cursor'],capture['at_ns'],owner)
            at=trigger['at_ns'];position=cursor(trigger['history_cursor'],at,owner)
            if at>start or trigger['history_cursor']!=call['start_cursor'] or pages[position].get(node['page_role'])!=trigger['page'] or workers[position].get(trigger['page'])!=trigger['worker']:
                raise ValueError('original source argument trigger lineage mismatch')
            group=(owner,node['argument_trigger_group'])
            if group in argument_groups and not _same_json(argument_groups[group],trigger):
                raise ValueError('original source argument trigger group changed')
            argument_groups[group]=trigger
            argument_group_sites.setdefault(group,[]).append(call['site'])
            for domain,name in zip(domains,names):
                if type(domain) is not dict or set(domain)!={'name','captures'} or domain['name']!=name or type(domain['captures']) is not list or len(domain['captures'])!=1:
                    raise ValueError('original source argument origin schema mismatch')
                capture=domain['captures'][0]
                if type(capture) is not dict or set(capture)!={'at_ns','history_cursor','order','input'} or any(type(capture[key]) is not int for key in ('at_ns','history_cursor','order')):
                    raise ValueError('invalid source argument capture schema')
                cursor(capture['history_cursor'],capture['at_ns'],owner)
                if node['site']!='hold.writer.read_completed' and trigger['session_capture']['at_ns']>capture['at_ns']:
                    raise ValueError('original document session query follows counter capture')
                if capture['at_ns']>at or capture['history_cursor']!=trigger['history_cursor'] or not 0<=capture['order']<trigger['order']:
                    raise ValueError('original source argument capture is not before its source trigger')
                value=capture['input']
                if node['site']=='hold.writer.read_completed':
                    if type(value) is not dict or set(value)!={'worker','page','query_ok','receiver_ok','start_ns','start_cursor'} or any(type(value[key]) is not int for key in ('worker','page','start_ns','start_cursor')) or value['query_ok'] is not True or value['receiver_ok'] is not True:
                        raise ValueError('invalid original completed-read baseline query schema')
                    position=cursor(value['start_cursor'],value['start_ns'],owner)
                    if value['start_ns']>capture['at_ns'] or value['start_cursor']!=capture['history_cursor'] or pages[position].get(node['page_role'])!=value['page'] or workers[position].get(value['page'])!=value['worker']:
                        raise ValueError('original completed-read baseline query lineage mismatch')
                elif document:
                    if type(value)is not dict or set(value)!={'value','queries'} or type(value['value'])is not int:
                        raise ValueError('invalid original document counter baseline schema')
                    observed=document_query(value['queries'],node,owner,trigger['session_capture']['at_ns'],capture['at_ns'],capture['history_cursor'])
                    if value['value']!=observed:
                        raise ValueError('original document counter baseline substitution')
                elif value is not None:
                    raise ValueError('unexpected source argument query input')
                argument_events.append((capture['order'],capture['at_ns'],{'case':owner[2],'kind':'capture','site':call['site'],'name':name}))
        if len(matches)!=len(polls)*len(names):
            raise ValueError('original source argument use multiplicity mismatch')
        for match_index,value in enumerate(matches):
            poll,name=polls[match_index//len(names)],names[match_index%len(names)]
            keys={'name','ok','ready','attempt','at_ns','history_cursor'} | ({'observed','before','queries'} if document else set())
            if type(value) is not dict or set(value)!=keys or type(value['name']) is not str or type(value['ok']) is not bool or type(value['ready']) is not bool or any(type(value[key]) is not int for key in ('attempt','at_ns','history_cursor')):
                raise ValueError('invalid original source argument use schema')
            cursor(value['history_cursor'],value['at_ns'],owner)
            if value['name']!=name or value['ok'] is not True or value['ready'] is not poll['ready'] or value['attempt']!=poll['attempt'] or not poll['start_ns']<=value['at_ns']<=poll['end_ns']:
                raise ValueError('original source argument use/attempt mismatch')
            if document:
                observed=document_query(value['queries'],node,owner,poll['start_ns'],value['at_ns'],value['history_cursor'])
                baseline=domains[match_index%len(names)]['captures'][0]['input']['value']
                if type(value['observed'])is not int or type(value['before'])is not int or value['observed']!=observed or value['before']!=baseline or value['ready']is not (observed>baseline):
                    raise ValueError('original document counter whole predicate mismatch')
        job_input(index,call,node,owner)
        fact_ids = {'seed.reenter': 'field_cleared', 'declaration.prepare.confirmation': 'confirmed', 'inference.wait_count': 'counter_input', 'inference.wait_refused': 'key_input', 'declaration.prepare.goal_card': 'session_input', 'declaration.wait_card': 'session_input', 'declaration.wait_proposal_or_outcome': 'session_input', 'declaration.outcome': 'session_input', 'delivery.check': 'session_input'}
        facts = [{'id': fact_ids[kind], 'ok': True}] if kind in fact_ids else []
        if kind in ('job.wait_end','fixture.wait','fixture.ssh_ended','fixture.settle','session.closed'):
            facts = [{'id':'fixture_input','ok':True}]
        if kind == 'seed.reenter':
            facts = [{'id': 'words_input', 'ok': True}, {'id': 'field_cleared', 'ok': True}]
        if kind == 'declaration.prepare':
            facts = [{'id': 'files_input', 'ok': True}, {'id': 'account_absent', 'ok': True}]
        if kind == 'delivery.check':
            facts = [{'id': 'measurement_input', 'ok': True}, {'id': 'session_input', 'ok': True}]
        if kind == 'delivery.prepare':
            facts = [{'id': 'declaration_input', 'ok': True}]
        if not _same_json(call['facts'], facts):
            raise ValueError('observer original predicate completion mismatch')
        children = call['children']
        if type(children) is not list or len(children) != len(node['children']):
            raise ValueError('missing/extra observer child invocation')
        previous = start
        for child, child_node in zip(children, node['children']):
            if type(child) is not int or not 1 <= child <= len(calls):
                raise ValueError('invalid observer child ordinal')
            actual = calls[child - 1]
            if type(actual.get('start_ns')) is not int or type(actual.get('end_ns')) is not int or not previous <= actual['start_ns'] <= actual['end_ns'] <= end:
                raise ValueError('observer child chronology mismatch')
            validate_call(child - 1, child_node, owner, index + 1, depth + 1)
            previous = actual['end_ns']
        if kind == 'declaration.prepare' and not calls[children[0] - 1]['end_ns'] <= inputs[0]['at_ns'] <= calls[children[1] - 1]['start_ns']:
            raise ValueError('declaration account input crosses original binding/confirmation history')

    invocation_states, invocation_stack = [0], []
    for event in events:
        if event['event'] == 'scenario_start':
            invocation_stack.append(event['invocation'])
        elif event['event'] == 'scenario_end':
            invocation_stack.pop()
        invocation_states.append(invocation_stack[-1] if invocation_stack else 0)
    previous = 0
    for index, call in enumerate(calls):
        if type(call) is not dict or 'parent' not in call:
            raise ValueError('invalid observer root schema')
        if call['parent'] is not None:
            continue
        position = call.get('start_cursor')
        if type(position) is not int or not 0 <= position < len(states):
            raise ValueError('invalid observer root cursor')
        owner = states[position][0]
        if owner is None and call.get('kind')=='fixture.ssh_ended' and position==len(events):
            owner=('', 'cleanup', '')
        source_expected = causal_expected if type(call.get('kind')) is str and (call['kind'].startswith(('job.','fixture.')) or call['kind'] in ('session.closed','main.lock_command')) else expected
        want = source_expected.get(owner, [])
        if not want:
            raise ValueError('missing/extra observer root caller')
        node = want.pop(0)
        finish = call.get('end_cursor')
        invocation = invocation_states[position]
        if type(finish) is not int or not 0 <= finish < len(invocation_states) or invocation_states[finish] != invocation or ('invocation' in node and node['invocation'] != invocation):
            raise ValueError('observer source invocation mismatch')
        if type(call.get('start_ns')) is not int or call['start_ns'] < previous:
            raise ValueError('observer root execution order mismatch')
        validate_call(index, node, owner, None)
        previous = call['end_ns']
    if len(prior_used) != len(prior_inputs):
        raise ValueError('extra original initial view input')
    if any(first['end_ns'] > second['start_ns'] for first, second in zip(prior_inputs, prior_inputs[1:])):
        raise ValueError('original initial view input order mismatch')
    if len(visited) != len(calls) or any(expected.values()) or any(causal_expected.values()):
        raise ValueError('missing/extra whole serial observer invocation')
    execution={c['id'] for c in inventory['cases']} if report['mode']=='full' else set(report['plan']['expected_execution'])
    for edge in inventory['causal_order_edges']:
        if edge['case'] not in execution:
            continue
        source_owner=(edge['scenario'],'inside',edge['case'])
        first=[c for c in calls if c['site']==edge['before'] and states[c['start_cursor']][0]==source_owner]
        second=[c for c in calls if c['site']==edge['after'] and states[c['start_cursor']][0]==source_owner]
        if len(first)!=1 or len(second)!=1 or first[0]['end_ns']>second[0]['start_ns']:
            raise ValueError('causal observer original cross-family order mismatch')
    if type(report.get('class_inputs')) is not list or len(report['class_inputs'])!=len(class_inputs):
        raise ValueError('extra original class dispatch capture')
    if type(report.get('goal_end_inputs')) is not list or len(report['goal_end_inputs'])!=len(goal_end_inputs):
        raise ValueError('extra original end dispatch')
    _validate_original_inputs(report)
    _validate_counter_inputs(report,inventory)
    _validate_session_operands(report,inventory)
    _validate_key_inputs(report,inventory)
    from tracer_fixture_inputs import validate as validate_fixture_inputs
    validate_fixture_inputs(report,inventory,states,positions,pages,workers)
    for (owner,group), trigger in argument_groups.items():
        argument_events.append((trigger['order'],trigger['at_ns'],{'case':owner[2],'kind':'trigger','group':group,'sites':argument_group_sites[(owner,group)]}))
    argument_events.sort(key=lambda value:value[0])
    execution = {case['id'] for case in inventory['cases']} if report['mode']=='full' else set(report['plan']['expected_execution'])
    source_events = [dict(event,case=row['case']) for row in inventory['argument_source_events'] if row['case'] in execution for event in row['events']]
    if len(argument_events)!=len(source_events):
        raise ValueError('original source argument event multiplicity mismatch')
    previous=0
    for index, ((order,at,event), expected_event) in enumerate(zip(argument_events,source_events),1):
        if order!=index or not _same_json(event,expected_event) or at<previous:
            raise ValueError('original source argument event order/broadcast mismatch')
        previous=at


def _validate_submissions(report, inventory):
    default_unlock = report['mode'] != 'full' and report['plan']['name'] == 'inference.session-end.selection'
    rows = inventory['submission_sources'] if report['mode'] == 'full' else [] if default_unlock else report['plan']['submission_sources']
    kinds = {((r['scenario'], r['owner'], r['case'] or ''), int(position)): kind for r in rows for position, kind in r['kinds'].items()}
    roles = {((r['scenario'], r['owner'], r['case'] or ''), int(position)): role for r in rows for position, role in r['roles'].items()}
    events, positions, stack, expected = report['helper_history'], {}, [], []
    states = _auxiliary_states(events)
    for index, event in enumerate(events):
        if event['event'] == 'call_start':
            owner, root = states[index + 1][0], not stack
            if event['kind'] == 'runtime.submit':
                role = roles.get((owner, positions.get(owner, 0)), 'store.primary' if default_unlock else None) if root else _prepare_passphrase(owner)
                if role is None:
                    raise ValueError('missing independent submission passphrase role')
                if root:
                    kind = kinds.get((owner, positions.get(owner, 0)), 'unlock' if default_unlock else None)
                    if kind is None:
                        raise ValueError('missing independent submission kind')
                else:
                    if stack[-1] != 'binding.prepare':
                        raise ValueError('submission outside original parent')
                    kind = 'unlock'
                if index + 1 >= len(events):
                    raise ValueError('incomplete submission')
                expected.append((event['call'], kind, role, index + 1, event['at_ns'], events[index + 1]['at_ns']))
            if root:
                positions[owner] = positions.get(owner, 0) + 1
            stack.append(event['kind'])
        elif event['event'] == 'call_end':
            stack.pop()
        elif event['event'] == 'check' and not stack:
            owner = states[index + 1][0]
            positions[owner] = positions.get(owner, 0) + 1
    actual = report.get('submissions')
    if type(actual) is not list or len(actual) != len(expected):
        raise ValueError('missing/extra/duplicate submission field observation')
    for row, (call, kind, role, cursor, start, end) in zip(actual, expected):
        if type(row) is not dict or set(row) != {'call', 'kind', 'passphrase_role', 'cleared', 'at_ns', 'history_cursor'} or type(row['call']) is not int or row['call'] != call or row['kind'] != kind or row['passphrase_role'] != role or type(row['history_cursor']) is not int or row['history_cursor'] != cursor or type(row['cleared']) is not bool or type(row['at_ns']) is not int or not start <= row['at_ns'] <= end:
            raise ValueError('submission original parameter/field/history mismatch')
    for case in report['cases']:
        if case['site_id'] == 'main.c022' and any(s['at_ns'] <= case['start_ns'] and s['cleared'] is not True for s in actual):
            raise ValueError('submission field history contradicts original aggregate assertion')
    # Preserve the original accumulator and later aggregate Case's failure semantics.


def _prepare_passphrase(owner):
    return 'store.served' if owner == ('main.run', 'inside', 'main.c001.p001') or owner[0] == 'binding_cases.run' and owner[2].endswith('.p002') or owner == ('mode_cases.run', 'after', 'mode_cases.c001.p001') else 'store.primary'


def _validate_runtime_inputs(report, inventory):
    _validate_worker_exclusions(report)
    _validate_second_worker(report, inventory)
    _validate_goal_sessions(report, inventory)
    canonical = inventory if report['mode'] == 'full' else None if report['plan']['name'] in ('hold.union', 'inference.session-end.selection') else report['plan']
    requirements = inventory if report['mode'] == 'full' else report['plan']
    arguments = {((r['scenario'], r['owner'], r['case'] or ''), int(position)): parameters for r in canonical['runtime_source_domains'] for position, parameters in r['arguments'].items()} if canonical is not None else {}
    source_rows = {(r['scenario'], r['owner'], r['case'] or ''): r for r in requirements['helper_owner_sequences']}
    states, events = _auxiliary_states(report['helper_history']), report['helper_history']
    positions, stack, worker_arguments, expected, bindings = {}, [], {}, [], []
    for index, event in enumerate(events):
        if event['event'] == 'call_start':
            kind, identity = event['kind'], event['call']
            owner, root = states[index + 1][0], not stack
            position = positions.get(owner, 0)
            parameters = None
            if kind == 'binding.prepare':
                parameters = {'passphrase_role': _prepare_passphrase(owner)}
            elif kind in ('runtime.worker', 'runtime.settled') and root:
                parameters = arguments.get((owner, position))
                if parameters is None and canonical is None:
                    operation = source_rows[owner]['page_operations'][position]
                    parameters = {'old': 'none' if operation.startswith('new:') else 'source_entry_current', 'in_use': False} if kind == 'runtime.worker' else {'in_use': False}
                if parameters is None:
                    raise ValueError('missing original runtime argument occurrence')
            elif kind == 'runtime.worker':
                if not stack or stack[-1][1] != 'binding.prepare':
                    raise ValueError('runtime worker outside original parent')
                parameters = {'old': 'source_entry_current', 'in_use': False}
            elif kind == 'runtime.settled':
                if not stack:
                    raise ValueError('settled input without parent')
                parent, parent_kind = stack[-1]
                if parent_kind == 'runtime.worker':
                    parameters = {'in_use': worker_arguments[parent]}
                elif parent_kind == 'runtime.submit':
                    parameters = {'in_use': False}
                else:
                    raise ValueError('settled outside original parameter parent')
            if parameters is not None:
                if kind == 'runtime.worker':
                    worker_arguments[identity] = parameters['in_use']
                if index + 1 >= len(events):
                    raise ValueError('incomplete runtime input')
                expected.append((identity, parameters, index + 1, event['at_ns'], events[index + 1]['at_ns']))
            if root:
                positions[owner] = position + 1
            stack.append((identity, kind))
        elif event['event'] == 'call_end':
            stack.pop()
        elif event['event'] == 'check' and not stack:
            owner = states[index + 1][0]
            positions[owner] = positions.get(owner, 0) + 1
        elif event['event'] == 'binding_input':
            role = {1: 'machine.first', 2: 'machine.second', 3: 'machine.unpinned'}.get(event['slot'])
            if role is None:
                raise ValueError('unsupported source binding role')
            bindings.append((event['call'], event['slot'], role, index, events[index - 1]['at_ns'], event['at_ns']))
    actual = report.get('runtime_inputs')
    if type(actual) is not list or len(actual) != len(expected):
        raise ValueError('missing/extra/duplicate runtime argument occurrence')
    for row, (identity, parameters, cursor, start, end) in zip(actual, expected):
        if type(row) is not dict or set(row) != {'call', 'parameters', 'at_ns', 'history_cursor'} or any(type(row[k]) is not int for k in ('call', 'at_ns', 'history_cursor')) or row['call'] != identity or not _same_json(row['parameters'], parameters) or row['history_cursor'] != cursor or not start <= row['at_ns'] <= end:
            raise ValueError('original runtime parameter/caller/history mismatch')
    actual = report.get('binding_inputs')
    if type(actual) is not list or len(actual) != len(bindings):
        raise ValueError('missing/extra/duplicate binding role occurrence')
    for row, (identity, slot, role, cursor, start, end) in zip(actual, bindings):
        if type(row) is not dict or set(row) != {'call', 'slot', 'role', 'at_ns', 'history_cursor'} or any(type(row[k]) is not int for k in ('call', 'slot', 'at_ns', 'history_cursor')) or row['call'] != identity or row['slot'] != slot or row['role'] != role or row['history_cursor'] != cursor or not start <= row['at_ns'] <= end:
            raise ValueError('original binding parameter/role/occurrence/history mismatch')


def _validate_worker_exclusions(report):
    error = 'original Worker exclusion operand/caller/history mismatch'
    events = report['helper_history']
    workers, expected = {}, []
    for index, event in enumerate(events):
        if event['event'] == 'call_start' and event['kind'] == 'runtime.worker':
            workers[event['call']] = event['page']
        if event['event'] == 'poll' and event['call'] in workers:
            before = events[index - 1] if index else {}
            if before.get('event') != 'attempt' or before.get('call') != event['call']:
                raise ValueError(error)
            expected.append((index, event, workers[event['call']], before))
    actual = report.get('worker_exclusions')
    if type(actual) is not list or len(actual) != len(expected):
        raise ValueError(error)
    for row, (cursor, event, page, before) in zip(actual, expected):
        if type(row) is not dict or set(row) != {'call', 'page', 'ok', 'ready', 'at_ns', 'history_cursor'} or any(type(row[key]) is not int for key in ('call', 'page', 'at_ns', 'history_cursor')) or row['call'] != event['call'] or row['page'] != page or row['ok'] is not True or type(row['ready']) is not bool or row['ready'] != event['ready'] or row['history_cursor'] != cursor or not before['at_ns'] <= row['at_ns'] <= event['at_ns']:
            raise ValueError(error)


def _validate_second_worker(report, inventory):
    error = 'original second Worker query/branch/receiver/history mismatch'
    expected = [c for c in report['cases'] if c['site_id'] == 'lifecycle_cases.c001']
    actual = report.get('second_worker_inputs')
    if type(actual) is not list or len(actual) != len(expected):
        raise ValueError(error)
    states, pages, workers = _observer_sources(report, inventory)
    events = report['helper_history']
    for row, case in zip(actual, expected):
        keys = {'worker','page','receiver_ok','locked','start_ns','end_ns','start_cursor','end_cursor'}
        if type(row) is not dict or set(row) != keys or any(type(row[k]) is not int for k in keys-{'locked','receiver_ok'}) or type(row['locked']) is not bool or row['receiver_ok'] is not True:
            raise ValueError(error)
        start, end, before, after, page = (row[k] for k in ('start_ns','end_ns','start_cursor','end_cursor','page'))
        if not 0 < before == after < len(events) or not case['start_ns'] <= start <= end <= case['end_ns'] or not events[before-1]['at_ns'] <= start <= end <= events[after]['at_ns'] or pages[before].get('temporary') != page or row['worker'] < 1 or workers[before].get(page) != row['worker'] or states[before][0] is None or states[before][0][1:] != ('inside',case['id']) or case['branches']['second-worker'] != ('locked' if row['locked'] else 'unopened'):
            raise ValueError(error)


def _validate_goal_sessions(report, inventory):
    error='original goal session query/source/receiver/history mismatch'
    requirements=inventory if report['mode']=='full' else report['plan']
    wanted={}
    for row in requirements['helper_owner_sequences']:
        if row['scenario'] not in ('goal_cases.run','goal_admission_cases.run'): continue
        owner=(row['scenario'],row['owner'],row['case'] or '')
        for index,token in enumerate(row['tokens']):
            if token!='call:binding.prepare' or row['case']=='goal_cases.c012.p001' and index==2: continue
            wanted[(owner,index+1)]={'goal_cases.c009.p001':'pending','goal_cases.c011.p001':'active'}.get(row['case'])
    count=len(wanted)
    states,pages,workers=_observer_sources(report,inventory)
    positions=_causal_positions(report)
    events=report['helper_history']; stack=[]; expected=[]
    for index,event in enumerate(events):
        if event['event']=='call_start': stack.append(event)
        elif event['event']=='call_end':
            start=stack.pop()
            if not stack and start['kind']=='binding.prepare':
                key=(states[index][0],positions[index+1][0])
                if key in wanted: expected.append((index+1,start['page'],wanted.pop(key)))
    actual=report.get('goal_session_inputs')
    if wanted or type(actual) is not list or len(actual)!=count or len(expected)!=count: raise ValueError(error)
    previous=0
    for row,(cursor,page,document) in zip(actual,expected):
        keys={'worker','page','receiver_ok','query_ok','present','document','start_ns','end_ns','start_cursor','end_cursor'}
        if type(row) is not dict or set(row)!=keys or any(type(row[k]) is not int for k in keys-{'receiver_ok','query_ok','present','document'}): raise ValueError(error)
        start,end=row['start_ns'],row['end_ns']
        if row['start_cursor']!=cursor or row['end_cursor']!=cursor or row['page']!=page or row['receiver_ok'] is not True or row['query_ok'] is not True or row['present'] is not True or row['document']!=document or workers[cursor].get(page)!=row['worker'] or pages[cursor].get('tracer')!=page or not previous<=start<=end or not cursor<len(events) or not events[cursor-1]['at_ns']<=start<=end<=events[cursor]['at_ns']: raise ValueError(error)
        previous=end


def _validate_logical_checks(report,inventory):
    error='original logical predicate/source/instance/order mismatch'
    requirements=inventory if report['mode']=='full' else report['plan']
    execution=[case['id'] for case in inventory['cases']] if report['mode']=='full' else requirements['expected_execution']
    rows=[]
    for order,row in enumerate(inventory['logical_predicate_sources']):
        if row['case'] not in execution: continue
        index=execution.index(row['case']);before=row['position']=='before'
        scenario=row['scenario'];selected=scenario.removesuffix('.run')+'.selected'
        if selected in requirements['scenario_scopes']:scenario=selected
        owner=(scenario,'after' if before else 'inside',execution[index-1] if before and index else '' if before else execution[index])
        rows.append((index,not before,order,owner,row['predicates']))
    expected={}
    for _,_,_,owner,predicates in sorted(rows):expected.setdefault(owner,[]).extend(predicates)
    states=_auxiliary_states(report['helper_history']);positions={};instances={};total=0
    for index,event in enumerate(report['helper_history']):
        if event['event']!='logical_check': continue
        owner=states[index][0];position=positions.get(owner,0)
        if owner not in expected or position>=len(expected[owner]):raise ValueError(error)
        identity=expected[owner][position];positions[owner]=position+1;total+=1;instances[identity]=instances.get(identity,0)+1
        if event['id']!=identity or event['instance']!=f"{identity}.i{instances[identity]:03}" or event['ok'] is not True: raise ValueError(error)
    if total!=sum(len(ids) for ids in expected.values()):raise ValueError(error)


def _validate_leakage_capture(report,inventory):
    error='original leakage history snapshot/source/capture census mismatch'
    execution=[case['id'] for case in inventory['cases']] if report['mode']=='full' else report['plan']['expected_execution']
    index=execution.index('main.c022.p001') if 'main.c022.p001' in execution else None
    captures=report.get('leakage_input_captures')
    uses=report.get('leakage_input_uses')
    if type(captures) is not list or len(captures)!=int(index is not None):raise ValueError(error)
    if type(uses) is not list or len(uses)!=len(captures):raise ValueError(error)
    if index is None:return
    capture=captures[0]
    if type(capture) is not dict or set(capture)!={'start_ns','end_ns','history_cursor','ok'} or any(type(capture[k]) is not int for k in ('start_ns','end_ns','history_cursor')) or capture['ok'] is not True or not index:raise ValueError(error)
    start,end,cursor=capture['start_ns'],capture['end_ns'],capture['history_cursor']
    states=_auxiliary_states(report['helper_history']);positions=_causal_positions(report);events=report['helper_history']
    preview=next((c for c in report['auxiliary_calls'] if c['site']=='reader.aux.main_displayed'),None)
    use=uses[0]
    if type(use) is not dict or set(use)!={'source','ok','at_ns','history_cursor'} or any(type(use[k]) is not int for k in ('source','at_ns','history_cursor')) or use['source']!=1 or use['ok'] is not True or use['history_cursor']!=cursor or preview is None or not end<=use['at_ns']<=preview['start_ns']:raise ValueError(error)
    if not 0<cursor<len(events) or not start<=end or states[cursor][0]!=('main.run','after',execution[index-1]) or not positions[cursor][1] or not events[cursor-1]['at_ns']<=start<=end<=events[cursor]['at_ns'] or preview is None or end>preview['start_ns']:raise ValueError(error)
