"""Check actual timing emissions independently of the Rust supervisor."""
import json

MAX_NS = 9_007_199_254_740_991
MAX_CLOCK_NS = (1 << 64) - 1


def _number(value, maximum=MAX_NS):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError('invalid printed timing schema/bounds/order')
    return value


def _fields(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        raise ValueError('invalid printed timing schema')


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('invalid printed timing schema')
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=_pairs)


class Output:
    def __init__(self):
        self.records = []
        self.evidence = None
        self.last_end = 0

    def observe(self, line):
        if line.startswith('TRACER_EVIDENCE '):
            if self.evidence is not None:
                raise ValueError('duplicate timing evidence boundary')
            self.evidence = len(self.records)
        for prefix, kind in (('TRACER_TIMING', 'phase'), ('TRACER_CASE_TIMING', 'case'), ('TRACER_GROUP_TIMING', 'group')):
            if not line.startswith(prefix):
                continue
            if not line.startswith(prefix + ' '):
                raise ValueError('invalid printed timing schema')
            value = decode(line[len(prefix)+1:])
            identifier = 'phase' if kind == 'phase' else 'id'
            fields = {identifier, 'start_ns', 'end_ns'}
            if kind == 'group':
                fields.add('invocation')
                if type(value.get('invocation')) is not int or value['invocation'] < 1:
                    raise ValueError('invalid printed scenario invocation')
            if type(value) is dict and 'status' in value:
                fields.add('status')
                if value['status'] not in ('failed', 'incomplete') or type(value['status']) is not str:
                    raise ValueError('invalid printed timing status')
            _fields(value, fields)
            if type(value[identifier]) is not str or kind == 'phase' and value[identifier] not in ('fixtures', 'browser', 'groups', 'cleanup', 'execution'):
                raise ValueError('invalid printed timing phase/identity')
            start, end = _number(value['start_ns']), _number(value['end_ns'])
            if start > end or end < self.last_end:
                raise ValueError('invalid printed timing schema/bounds/order')
            self.last_end = end
            self.records.append((kind, value))

    def validate(self, report):
        phases = [value for kind, value in self.records if kind == 'phase']
        cases = [value for kind, value in self.records if kind == 'case']
        groups = [value for kind, value in self.records if kind == 'group']
        expected_cases = [{key: case[key] for key in ('id', 'start_ns', 'end_ns')} for case in report['cases']]
        if len(phases) != 5 or cases != expected_cases or groups != report['scenario_spans'] or self.evidence != len(self.records)-1:
            raise ValueError('printed timing coverage/placement mismatch')
        if phases[:4] != report['timings']:
            raise ValueError('printed phase timing differs from execution report')
        execution = phases[4]
        if self.records[:2] != [('phase', phases[0]), ('phase', phases[1])] or self.records[-1] != ('phase', execution) or set(execution) != {'phase', 'start_ns', 'end_ns'} or execution['phase'] != 'execution' or execution['start_ns'] > phases[0]['start_ns'] or execution['end_ns'] < report['duration_ns']:
            raise ValueError('printed execution timing envelope mismatch')
        for kind, value in self.records:
            if kind != 'phase' and not phases[2]['start_ns'] <= value['start_ns'] <= value['end_ns'] <= phases[2]['end_ns']:
                raise ValueError('printed case/group outside original groups phase')


def build(value, name, start, end, actual_exit):
    _fields(value, ('schema', 'phase', 'start_ns', 'end_ns', 'exit'))
    if type(value['schema']) is not int or value['schema'] != 1 or value['phase'] != 'prepare_' + name or type(value['exit']) is not int or value['exit'] != actual_exit:
        raise ValueError('invalid build timing schema/exit')
    # Build receipts use the host's absolute monotonic clock, not a run duration.
    before = _number(value['start_ns'], MAX_CLOCK_NS)
    after = _number(value['end_ns'], MAX_CLOCK_NS)
    if not start <= before <= after <= end:
        raise ValueError('invalid build timing bounds/placement')


def preparation(value, actual_exits, admitted_mode):
    _fields(value, ('schema', 'mode', 'phases', 'duration_ns'))
    if type(value['schema']) is not int or value['schema'] != 1 or value['mode'] not in ('full', 'targeted') or type(value['phases']) is not list or not 1 <= len(value['phases']) <= 3:
        raise ValueError('invalid preparation timing schema')
    if value['mode']!=admitted_mode:
        raise ValueError('preparation mode differs from admission')
    if type(actual_exits)is not list or len(actual_exits)!=len(value['phases']) or any(type(code)is not int for code in actual_exits):
        raise ValueError('invalid preparation actual exit census')
    duration = _number(value['duration_ns'])
    previous = 0
    for phase, name in zip(value['phases'], ('prepare_served', 'prepare_tracer', 'execute_through_cleanup')):
        _fields(phase, ('phase', 'start_ns', 'end_ns', 'exit'))
        start, end = _number(phase['start_ns']), _number(phase['end_ns'])
        if phase['phase'] != name or type(phase['exit']) is not int or not -255 <= phase['exit'] <= 255 or not previous <= start <= end <= duration:
            raise ValueError('invalid preparation timing bounds/exit/order')
        previous = end
    if any(phase['exit']!=code for phase,code in zip(value['phases'],actual_exits)) or any(phase['exit']!=0 for phase in value['phases'][:-1]):
        raise ValueError('preparation timing differs from actual exit/order')
    # Validate the bytes that will be printed, including strict key/type handling.
    serialized = json.dumps(value)
    if decode(serialized) != value:
        raise ValueError('invalid preparation timing serialization')
    return serialized
