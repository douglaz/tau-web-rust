"""Independent replay of the original fixture predicates' finite operands."""


def _fields(value, names):
    if type(value) is not dict or set(value) != set(names):
        raise ValueError('invalid original fixture predicate operand schema')


def _number(value):
    if type(value) is not int or not 0 <= value <= 18446744073709551615:
        raise ValueError('invalid original fixture predicate count')
    return value


def _boolean(value):
    if type(value) is not bool:
        raise ValueError('invalid original fixture predicate Boolean')
    return value


def _array(value):
    if type(value) is not list:
        raise ValueError('invalid original fixture predicate sequence')
    return value


def _any(values, length):
    if len(values) > length or True in values and values.index(True) != len(values)-1 or True not in values and len(values) != length:
        raise ValueError('original fixture predicate iterator/short-circuit mismatch')
    return bool(values and values[-1])


def replay(site, operands):
    if site in ('fixture.settle.wait', 'main.lock_command.socket_closed', 'seed.redisplay.socket_closed', 'session.network.client_packet', 'session.rekey.client_packet'):
        packet = 'client_packet' in site
        if packet:
            _slice(operands, ('total', 'from', 'length', 'visits'))
        else:
            _fields(operands, ('receiver_ok', 'ended', 'length', 'visits'))
            _receiver(operands)
            if type(operands['ended']) is not bool or operands['ended'] != (site != 'fixture.settle.wait'):
                raise ValueError('original fixture socket predicate parameter mismatch')
        allowed = ('destination', 'binary', 'other') if packet else ('close', 'ended', 'other')
        values = []
        for event in _array(operands['visits']):
            if type(event) is not str or event not in allowed:
                raise ValueError('invalid fixture event alias')
            values.append(event != 'other' if packet else event == 'close' or site != 'fixture.settle.wait' and event == 'ended')
        return _any(values, _number(operands['length']))
    if site in ('main.crash.running_exec', 'main.lock_command.exec', 'seed.redisplay.running_exec'):
        _fields(operands, ('receiver_ok', 'length', 'steps', 'command_ok'))
        _receiver(operands)
        if operands['command_ok'] is not True:
            raise ValueError('original lock command operand mismatch')
        steps = _array(operands['steps'])
        if len(steps) != 5:
            raise ValueError('invalid fixture exec parse stages')
        reached = _number(operands['length']) == 1
        for step in steps:
            if reached:
                reached = _boolean(step)
            elif step is not None:
                raise ValueError('original fixture exec short-circuit mismatch')
        return reached
    if site in ('hold.stop.reading', 'hold.evidence.actual_read', 'hold.evidence.later_read'):
        _fields(operands, ('receiver_ok', 'required', 'total', 'prefixes', 'length'))
        _receiver(operands)
        if _number(operands['required']) != (2 if site == 'hold.stop.reading' else 1):
            raise ValueError('original fixture read predicate parameter mismatch')
        total = _number(operands['total'])
        prefixes = [_boolean(value) for value in _array(operands['prefixes'])]
        if total == 0:
            if prefixes:
                raise ValueError('empty fixture read iterated')
            ready = False
        else:
            ready = not _any([not value for value in prefixes], total)
        if ready:
            length = _number(operands['length'])
            if length != total:
                raise ValueError('original fixture read count changed')
            return length == (2 if site == 'hold.stop.reading' else 1)
        if operands['length'] is not None:
            raise ValueError('original fixture read count evaluated after failure')
        return False
    if site == 'session.closed.relay':
        _slice(operands, ('total', 'from', 'length', 'events', 'visits'))
        events = _array(operands['events'])
        if len(events) != _number(operands['length']):
            raise ValueError('original relay first-pass multiplicity mismatch')
        identities = {}
        connections = set()
        for event in events:
            _array(event)
            if len(event) != 2:
                raise ValueError('invalid original relay connection operand')
            identity = _number(event[0])
            ordinal = identities.setdefault(identity, len(identities))
            if ordinal != identity:
                raise ValueError('noncanonical relay identity equivalence class')
            if type(event[1]) is not str or event[1] not in ('challenge', 'held', 'ended', 'close', 'other'):
                raise ValueError('invalid original relay event')
            if event[1] in ('challenge', 'held'):
                connections.add(identity)
        visits = _array(operands['visits'])
        if len(visits) > len(events):
            raise ValueError('extra original relay visits')
        values = []
        for visit, event in zip(visits, events):
            _array(visit)
            member = event[0] in connections
            terminal = event[1] in ('ended', 'close') if member else None
            if len(visit) != 2 or type(visit[0]) is not bool or visit[0] is not member or visit[1] is not terminal:
                raise ValueError('original relay membership/termination mismatch')
            values.append(member and terminal is True)
        return _any(values, len(events))
    if site == 'inference.sent_read.exec':
        _fields(operands, ('length', 'baseline', 'last'))
        baseline, length = _number(operands['baseline']), _number(operands['length'])
        if baseline < 18446744073709551615 and length == baseline + 1:
            return _boolean(operands['last'])
        if operands['last'] is not None:
            raise ValueError('original sent-read short-circuit mismatch')
        return False
    if site == 'lifecycle.hidden.job_launched':
        _fields(operands, ('length', 'visits', 'fixture'))
        if operands['fixture'] != 'primary':
            raise ValueError('original lifecycle job fixture mismatch')
        return _any([_boolean(value) for value in _array(operands['visits'])], _number(operands['length']))
    if site in ('session.network.stage_reached', 'session.rekey.stage_reached'):
        _fields(operands, ('value',))
        return _boolean(operands['value'])
    if site == 'session.cold_probe.sent':
        _fields(operands, ('length', 'visits', 'baseline'))
        if len(_array(operands['visits'])) != _number(operands['length']):
            raise ValueError('original probe iterator multiplicity mismatch')
        count = 0
        for row in _array(operands['visits']):
            _array(row)
            if len(row) != 2:
                raise ValueError('invalid original probe operands')
            if _boolean(row[0]):
                count += _boolean(row[1])
            elif row[1] is not None:
                raise ValueError('original probe short-circuit mismatch')
        return count > _number(operands['baseline'])
    if site in ('session.cold_probe.revoke', 'session.revoke_control.sent'):
        _fields(operands, ('length', 'visits'))
        values = []
        for row in _array(operands['visits']):
            _array(row)
            if len(row) != 3:
                raise ValueError('invalid original revoke operands')
            if _boolean(row[0]):
                if _boolean(row[1]):
                    ready = _boolean(row[2])
                else:
                    if row[2] is not None:
                        raise ValueError('original revoke body short-circuit mismatch')
                    ready = False
            else:
                if row[1] is not None or row[2] is not None:
                    raise ValueError('original revoke method short-circuit mismatch')
                ready = False
            values.append(ready)
        return _any(values, _number(operands['length']))
    raise ValueError('unknown original fixture predicate site')


def _slice(operands, names):
    _fields(operands, names)
    total, start, length = (_number(operands[key]) for key in ('total', 'from', 'length'))
    if start > total or total-start != length:
        raise ValueError('original fixture slice cursor/domain mismatch')


def _receiver(operands):
    if operands['receiver_ok'] is not True:
        raise ValueError('original fixture predicate receiver mismatch')
