"""Closed, bounded publication. Raw captures are local and never copied into this packet."""
import hashlib
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time

LIMIT = 64 * 1024
PHASES = {'supervisor', 'preflight', 'provenance', 'execution', 'fixtures', 'browser',
          'groups', 'cleanup', 'report', 'validation'}
STAGES = {'admission', 'identity', 'prepare_served', 'prepare_tracer', 'native_build',
          'native_execution', 'validation', 'preparation_report', 'finished'}
CLASSES = {'check', 'prerequisite', 'setup', 'execution', 'cleanup', 'report',
           'validation', 'spawn', 'forwarding', 'wait', 'retention',
           'capture_flush', 'capture_digest', 'capture_receipt'}


def fields(value, names):
    if type(value) is not dict or set(value) != set(names):
        raise ValueError('diagnostic schema')


def integer(value, maximum=(1 << 64)-1):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError('diagnostic number')
    return value


def digest(value, length=64):
    if type(value) is not str or not re.fullmatch('[0-9a-f]{' + str(length) + '}', value):
        raise ValueError('diagnostic hash')
    return value


def decode(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError('duplicate diagnostic field')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs)


class Directory:
    """Open every component without following links; operate through the pinned descriptor."""
    def __init__(self, path, create=False):
        path = Path(path)
        if not path.is_absolute() or '..' in path.parts:
            raise ValueError('noncanonical diagnostic directory')
        self.fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
        try:
            for component in path.parts[1:]:
                if create:
                    try:
                        os.mkdir(component, 0o700, dir_fd=self.fd)
                    except FileExistsError:
                        pass
                next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                  dir_fd=self.fd)
                os.close(self.fd)
                self.fd = next_fd
            if os.fstat(self.fd).st_uid != os.geteuid():
                raise ValueError('foreign diagnostic directory')
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def file(self, name):
        if self.fd is None:
            raise ValueError('closed diagnostic directory')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
        meta = os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.geteuid() or meta.st_nlink != 1:
            os.close(fd)
            raise ValueError('unsafe diagnostic input')
        return os.fdopen(fd, 'rb')

    def read(self, name, limit=8192):
        with self.file(name) as stream:
            raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise OverflowError('diagnostic input bound')
        return decode(raw)

    def hash(self, name):
        result = hashlib.sha256()
        with self.file(name) as stream:
            for chunk in iter(lambda: stream.read(65536), b''):
                result.update(chunk)
        return result.hexdigest()

    def write(self, name, raw, staging=None):
        if self.fd is None:
            raise ValueError('closed diagnostic directory')
        try:
            with self.file(name):
                pass
        except FileNotFoundError:
            pass
        source = self if staging is None else staging
        if source.fd is None:
            raise ValueError('closed diagnostic staging directory')
        temporary = '.tracer-' + name + '-' + secrets.token_hex(16)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=source.fd)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.rename(temporary, name, src_dir_fd=source.fd, dst_dir_fd=self.fd)
        finally:
            try:
                os.unlink(temporary, dir_fd=source.fd)
            except FileNotFoundError:
                pass


def missing(state='missing'):
    return {'state': state}


def available(value):
    return {'state': 'available', 'value': value}


def select(directory, name, validator):
    try:
        return available(validator(directory.read(name)))
    except FileNotFoundError:
        return missing()
    except OverflowError:
        return missing('truncated')
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, RecursionError):
        return missing('untrusted')


def waited(value):
    fields(value, ('schema', 'state', 'code', 'signal'))
    if type(value['schema']) is not int or value['schema'] != 1 or value['state'] not in ('waited', 'unavailable'):
        raise ValueError('invalid waited status')
    code, signal = value['code'], value['signal']
    if code is not None:
        integer(code, 255)
    if signal is not None:
        integer(signal, 127)
        if signal == 0:
            raise ValueError('invalid signal')
    if value['state'] == 'unavailable' and (code is not None or signal is not None) or code is not None and signal is not None or value['state'] == 'waited' and code is None and signal is None:
        raise ValueError('inconsistent waited status')
    return dict(value)


def actual_exit(code):
    if code is None:
        return {'schema': 1, 'state': 'unavailable', 'code': None, 'signal': None}
    if type(code) is not int or not -127 <= code <= 255:
        raise ValueError('invalid actual exit')
    return waited({'schema': 1, 'state': 'waited', 'code': code if code >= 0 else None,
                   'signal': -code if code < 0 else None})


def publication_owner(target, invocation):
    # Liveness data stays outside the one-file public publication.
    owner = target.read('tracer-diagnostics-owner.json')
    fields(owner, ('schema', 'invocation', 'driver_pid'))
    if type(owner['schema']) is not int or owner['schema'] != 1 or owner['invocation'] != invocation:
        raise ValueError('foreign publication owner')
    digest(owner['invocation'])
    if integer(owner['driver_pid'], (1 << 31)-1) == 0:
        raise ValueError('invalid publication owner')
    return owner


class Publication:
    def __init__(self, root):
        self.root = Path(root)
        self.invocation = secrets.token_hex(32)
        self.started = time.monotonic_ns()
        self.native_pid = None
        self.catalogue = None
        self.prerequisites = None
        self.packet = {'schema': 1, 'invocation': self.invocation, 'packet_state': 'partial',
                       'driver': {'stage': 'admission', 'status': 'active', 'at_ns': 0},
                       'outcomes': {name: actual_exit(None) for name in
                                    ('served_build', 'tracer_build', 'native_build', 'native', 'validation', 'driver')},
                       'capture': missing('unavailable'), 'first_failure': missing(),
                       'context': missing(), 'native_context': missing(), 'driver_failure': missing(),
                       'execution': actual_exit(None), 'identity': missing(),
                       'receipt': missing(), 'preflight': missing(),
                       'timing': missing(), 'preparation': missing()}
        # Hold ownership through child reaping and the last packet write. Displayed
        # terminal status does not release it; close (or process death) does.
        self.staging = Directory(self.root / 'target', create=True)
        try:
            try:
                fcntl.flock(self.staging.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ValueError('publication invocation still active') from None
            self.prepare()
        except BaseException:
            self.staging.close()
            raise

    def prepare(self):
        with Directory(self.root / 'target', create=True) as target:
            try:
                os.mkdir('tracer-diagnostics', 0o700, dir_fd=target.fd)
            except FileExistsError:
                with Directory(self.path.parent) as old:
                    if set(os.listdir(old.fd)) - {'packet.json'}:
                        raise ValueError('unexpected publication files')
                    try:
                        previous = old.read('packet.json', LIMIT)
                        if type(previous) is not dict or type(previous.get('schema')) is not int or previous['schema'] != 1:
                            raise ValueError('foreign publication packet')
                        digest(previous['invocation'])
                        publication_owner(target, previous['invocation'])
                        fields(previous['driver'], ('stage', 'status', 'at_ns'))
                        if previous['driver']['stage'] not in STAGES or previous['driver']['status'] not in ('active', 'succeeded', 'failed', 'cancelled', 'unavailable'):
                            raise ValueError('invalid publication status')
                        integer(previous['driver']['at_ns'])
                        os.unlink('packet.json', dir_fd=old.fd)
                    except FileNotFoundError:
                        pass
                os.rmdir('tracer-diagnostics', dir_fd=target.fd)
                os.mkdir('tracer-diagnostics', 0o700, dir_fd=target.fd)
            target.write('tracer-diagnostics-owner.json', json.dumps(
                {'schema': 1, 'invocation': self.invocation, 'driver_pid': os.getpid()}).encode())
        self.directory = Directory(self.path.parent)
        self.inode = os.fstat(self.directory.fd).st_ino
        try:
            self.publish()
        except BaseException:
            self.directory.close()
            raise

    @property
    def path(self):
        return self.root / 'target/tracer-diagnostics/packet.json'

    def close(self):
        self.directory.close()
        self.staging.close()

    def publish(self):
        # Refuse a replaced directory or an adjacent file before any packet update.
        with Directory(self.path.parent) as current:
            if os.fstat(current.fd).st_ino != self.inode or set(os.listdir(current.fd)) - {'packet.json'}:
                raise ValueError('foreign publication destination')
        raw = json.dumps(self.packet, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'
        if len(raw) > LIMIT:
            self.packet['timing'] = missing('truncated')
            self.packet['preparation'] = missing('truncated')
            self.packet['packet_state'] = 'truncated'
            raw = json.dumps(self.packet, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'
        if len(raw) > LIMIT:
            raise ValueError('packet exceeds bound')
        self.directory.write('packet.json', raw, self.staging)

    def stage(self, stage, status='active'):
        if stage not in STAGES or status not in ('active', 'failed', 'succeeded', 'cancelled', 'unavailable'):
            raise ValueError('invalid driver diagnostic stage')
        self.packet['driver'] = {'stage': stage, 'status': status,
                                 'at_ns': time.monotonic_ns() - self.started}
        self.publish()

    def fail(self, category):
        if category not in ('admission', 'identity', 'build', 'spawn', 'forwarding', 'validation', 'report', 'cancelled', 'retention'):
            raise ValueError('invalid driver failure class')
        if self.packet['driver_failure']['state'] != 'available':
            self.packet['driver_failure'] = available({'schema': 1, 'stage': self.packet['driver']['stage'],
                                                       'class': category, 'at_ns': time.monotonic_ns() - self.started})
            self.publish()

    def outcome(self, name, code):
        if name not in self.packet['outcomes']:
            raise ValueError('unknown diagnostic outcome')
        self.packet['outcomes'][name] = actual_exit(code)
        self.publish()

    def finish(self, result, cancelled):
        # Finalized means the packet is ready, not that its producer has exited.
        # A later signal or interpreter shutdown can still change our exit. Only
        # an external waiter could establish that outcome; leave it unavailable.
        # Publish status and outcome together so a failed write stays partial.
        self.packet['packet_state'] = 'finalized'
        self.packet['driver'] = {
            'stage': 'finished' if result == 0 else self.packet['driver']['stage'],
            'status': 'cancelled' if cancelled else 'unavailable' if result == 0 else 'failed',
            'at_ns': time.monotonic_ns() - self.started}
        self.packet['outcomes']['driver'] = actual_exit(None)
        self.publish()

    def identifiers(self, inventory, prerequisites):
        self.catalogue = {case['id']: set(case['assertions']) for case in inventory['cases']}
        for case in inventory['cases']:
            if 'variants' in case:
                for sites in case['variants']['sequences'].values():
                    self.catalogue[case['id']].update(sites)
            if 'optional' in case:
                self.catalogue[case['id']].add(case['optional']['site'])
        # False-only source check in lock_during_command's two callers. It is
        # deliberately absent from the successful completion inventory.
        for case in ('main.c017.p001', 'main.c018.p001'):
            if case in self.catalogue:
                self.catalogue[case].add('main.a122')
        self.prerequisites = set(prerequisites) | set(inventory['dynamic_prerequisites'])

    def context(self, value):
        fields(value, ('schema', 'at_ns', 'phase', 'case', 'status'))
        if type(value['schema']) is not int or value['schema'] != 1 or value['phase'] not in PHASES or value['status'] not in ('active', 'succeeded', 'failed'):
            raise ValueError('invalid diagnostic context')
        integer(value['at_ns'])
        if value['case'] is not None and (self.catalogue is None or value['case'] not in self.catalogue):
            raise ValueError('unknown catalogue case')
        return dict(value)

    def failure(self, value):
        fields(value, ('schema', 'at_ns', 'phase', 'case', 'kind', 'class', 'instance'))
        self.context({key: value[key] for key in ('schema', 'at_ns', 'phase', 'case')} | {'status': 'failed'})
        kind, category, instance = value['kind'], value['class'], value['instance']
        if category not in CLASSES or kind not in ('primary', 'prerequisite', 'execution'):
            raise ValueError('unknown failure class')
        if kind == 'execution':
            if instance is not None or category in ('check', 'prerequisite'):
                raise ValueError('invented assertion')
        else:
            if type(instance) is not str or len(instance) > 180:
                raise ValueError('invalid instance')
            site, occurrence = instance.rsplit('.i', 1)
            if not occurrence.isascii() or not occurrence.isdigit() or not 1 <= int(occurrence) <= 999999 or f'{int(occurrence):03}' != occurrence:
                raise ValueError('invalid instance occurrence')
            if kind == 'primary' and (category != 'check' or value['case'] is None or site not in self.catalogue[value['case']]):
                raise ValueError('foreign primary instance')
            if kind == 'prerequisite' and (category not in ('prerequisite', 'cleanup') or self.prerequisites is None or site not in self.prerequisites):
                raise ValueError('foreign prerequisite instance')
        return dict(value)

    def identity(self, value):
        # Explicitly select hashes and booleans, never the entire provenance object.
        result = {key: digest(value[key], 40 if key == 'spec' else 64)
                  for key in ('source', 'spec', 'binary', 'served', 'tracer')}
        result['validation_contracts'] = {key: digest(value['validation_contracts'][key])
                                         for key in ('native_producer_and_validator', 'shell_driver_and_validator')}
        flags = value['preconditions']
        result['preconditions'] = {key: digest(flags[key]) for key in ('chrome', 'chrome_version')}
        for key in ('fresh_profile', 'serial', 'local_fixtures', 'declaration_witnesses'):
            if type(flags[key]) is not bool:
                raise ValueError('invalid precondition')
            result['preconditions'][key] = flags[key]
        return result

    def collect(self):
        if self.native_pid is None:
            return
        path = self.root / 'target/tracer-evidence' / f'{self.native_pid}-{self.invocation}'
        for key in ('first_failure', 'context', 'native_context', 'identity', 'receipt', 'preflight'):
            self.packet[key] = missing()
        self.packet['execution'] = actual_exit(None)
        try:
            with Directory(path) as capture:
                owner = capture.read('owner.json')
                if owner != {'schema': 1, 'driver': os.getpid(), 'supervisor': self.native_pid,
                             'invocation': self.invocation} or type(owner['schema']) is not int or type(owner['driver']) is not int or type(owner['supervisor']) is not int:
                    raise ValueError('foreign diagnostic supervisor')
                self.packet['capture'] = available(True)
                self.packet['first_failure'] = select(capture, 'first-failure.json', self.failure)
                self.packet['context'] = select(capture, 'status.json', self.context)
                self.packet['native_context'] = select(capture, 'native-status.json', self.context)
                execution = select(capture, 'supervisor.json', waited)
                self.packet['execution'] = execution['value'] if execution['state'] == 'available' else actual_exit(None)
                self.packet['identity'] = select(capture, 'identity.json', self.identity)
                def receipt(value):
                    fields(value, ('code', 'success', 'log', 'preflight'))
                    if value['code'] is not None:
                        integer(value['code'], 255)
                    if type(value['success']) is not bool or value['success'] != (value['code'] == 0):
                        raise ValueError('invalid receipt exit')
                    for name in ('log', 'preflight'):
                        if digest(value[name]) != capture.hash('execution.log' if name == 'log' else 'preflight.json'):
                            raise ValueError('receipt digest mismatch')
                    return {key: value[key] for key in ('code', 'success', 'log', 'preflight')}
                self.packet['receipt'] = select(capture, 'exit.json', receipt)
                def preflight(value):
                    if type(value) is not dict or type(value.get('schema')) is not int or value['schema'] != 1:
                        raise ValueError('invalid preflight')
                    return {'duration_ns': integer(value['duration_ns']), 'sha256': capture.hash('preflight.json')}
                self.packet['preflight'] = select(capture, 'preflight.json', preflight)
        except FileNotFoundError:
            self.packet['capture'] = missing()
        except (OSError, ValueError, KeyError, TypeError, UnicodeError, RecursionError, OverflowError):
            self.packet['capture'] = missing('untrusted')
            for key in ('first_failure', 'context', 'native_context', 'identity', 'receipt', 'preflight'):
                self.packet[key] = missing('untrusted')
            self.packet['execution'] = actual_exit(None)
        self.publish()

    def timing(self, records):
        # Only the five fixed phase timings; case/group records can be large and remain local.
        result = []
        try:
            for kind, value in records:
                if kind != 'phase':
                    continue
                keys = {'phase', 'start_ns', 'end_ns'}
                if 'status' in value:
                    keys.add('status')
                fields(value, keys)
                if value['phase'] not in PHASES or value.get('status', 'complete') not in ('complete', 'failed', 'incomplete'):
                    raise ValueError('invalid timing')
                if integer(value['start_ns']) > integer(value['end_ns']):
                    raise ValueError('invalid timing order')
                result.append(dict(value))
                if len(result) > 5:
                    raise OverflowError('timing bound')
            self.packet['timing'] = available(result) if result else missing()
        except OverflowError:
            self.packet['timing'] = missing('truncated')
        except (ValueError, KeyError, TypeError):
            self.packet['timing'] = missing('untrusted')
        self.publish()

    def preparation(self, phases, duration):
        result = []
        for phase in phases:
            fields(phase, ('phase', 'start_ns', 'end_ns', 'exit'))
            if phase['phase'] not in ('prepare_served', 'prepare_tracer', 'execute_through_cleanup') or integer(phase['start_ns']) > integer(phase['end_ns']):
                raise ValueError('invalid preparation record')
            result.append({key: phase[key] for key in ('phase', 'start_ns', 'end_ns')} | {'exit': actual_exit(phase['exit'])})
        if len(result) > 3:
            self.packet['preparation'] = missing('truncated')
        else:
            self.packet['preparation'] = available({'phases': result, 'duration_ns': integer(duration)})
        self.publish()


def github_output(name, value):
    """Only fixed output names and validated values cross the runner-output boundary."""
    if name == 'diagnostic_invocation':
        if value != '':
            digest(value)
    elif name != 'ready' or value not in ('true', 'false'):
        raise ValueError('invalid runner output')
    destination = os.environ.get('GITHUB_OUTPUT')
    if destination is None:
        return
    path = Path(destination)
    with Directory(path.parent) as parent:
        fd = os.open(path.name, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=parent.fd)
        with os.fdopen(fd, 'ab') as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_nlink != 1:
                raise ValueError('unsafe runner output')
            stream.write((name + '=' + value + '\n').encode())


def verify_packet(root, invocation):
    """Admission for upload, including a cancelled step's partial current packet."""
    digest(invocation)
    root = Path(root)
    with Directory(root / 'target/tracer-diagnostics') as directory:
        if set(os.listdir(directory.fd)) != {'packet.json'}:
            raise ValueError('unexpected publication files')
        packet = directory.read('packet.json', LIMIT)
    required = {'schema', 'invocation', 'packet_state', 'driver', 'outcomes',
                'capture', 'first_failure', 'context', 'native_context', 'driver_failure',
                'execution', 'identity', 'receipt', 'preflight', 'timing', 'preparation'}
    fields(packet, required | ({'inputs'} if 'inputs' in packet else set()))
    if type(packet['schema']) is not int or packet['schema'] != 1 or packet['invocation'] != invocation or packet['packet_state'] not in ('partial', 'finalized', 'truncated'):
        raise ValueError('foreign publication packet')
    with Directory(root / 'target') as target:
        publication_owner(target, invocation)
    fields(packet['driver'], ('stage', 'status', 'at_ns'))
    if packet['driver']['stage'] not in STAGES or packet['driver']['status'] not in ('active', 'failed', 'succeeded', 'cancelled', 'unavailable'):
        raise ValueError('invalid driver state')
    integer(packet['driver']['at_ns'])
    fields(packet['outcomes'], ('served_build', 'tracer_build', 'native_build', 'native', 'validation', 'driver'))
    for outcome in packet['outcomes'].values():
        waited(outcome)
    waited(packet['execution'])
    import tracer_requirements
    inventory = tracer_requirements.read(root / 'tracer/inventory.json')
    validator = object.__new__(Publication)
    validator.identifiers(inventory, tracer_requirements.prerequisite_counts(inventory))

    def optional(key, check):
        value = packet[key]
        if type(value) is not dict or value.get('state') not in ('available', 'missing', 'untrusted', 'truncated', 'unavailable'):
            raise ValueError('invalid metadata availability')
        fields(value, ('state', 'value') if value['state'] == 'available' else ('state',))
        if value['state'] == 'available':
            check(value['value'])

    def capture(value):
        if value is not True:
            raise ValueError('invalid capture availability')

    def identity(value):
        fields(value, ('source', 'spec', 'binary', 'served', 'tracer', 'validation_contracts', 'preconditions'))
        fields(value['validation_contracts'], ('native_producer_and_validator', 'shell_driver_and_validator'))
        fields(value['preconditions'], ('chrome', 'chrome_version', 'fresh_profile', 'serial', 'local_fixtures', 'declaration_witnesses'))
        validator.identity(value)

    def receipt(value):
        fields(value, ('code', 'success', 'log', 'preflight'))
        if value['code'] is not None:
            integer(value['code'], 255)
        if type(value['success']) is not bool or value['success'] != (value['code'] == 0):
            raise ValueError('invalid receipt status')
        digest(value['log'])
        digest(value['preflight'])

    def preflight(value):
        fields(value, ('duration_ns', 'sha256'))
        integer(value['duration_ns'])
        digest(value['sha256'])

    def timing(value):
        if type(value) is not list or len(value) > 5:
            raise ValueError('invalid timing count')
        for phase in value:
            fields(phase, {'phase', 'start_ns', 'end_ns'} | ({'status'} if 'status' in phase else set()))
            if phase['phase'] not in ('fixtures', 'browser', 'groups', 'cleanup', 'execution') or phase.get('status', 'complete') not in ('complete', 'failed', 'incomplete') or integer(phase['start_ns']) > integer(phase['end_ns']):
                raise ValueError('invalid timing record')

    def preparation(value):
        fields(value, ('phases', 'duration_ns'))
        integer(value['duration_ns'])
        if type(value['phases']) is not list or len(value['phases']) > 3:
            raise ValueError('invalid preparation count')
        for phase in value['phases']:
            fields(phase, ('phase', 'start_ns', 'end_ns', 'exit'))
            if phase['phase'] not in ('prepare_served', 'prepare_tracer', 'execute_through_cleanup') or integer(phase['start_ns']) > integer(phase['end_ns']):
                raise ValueError('invalid preparation phase')
            waited(phase['exit'])

    def driver_failure(value):
        fields(value, ('schema', 'stage', 'class', 'at_ns'))
        if type(value['schema']) is not int or value['schema'] != 1 or value['stage'] not in STAGES or value['class'] not in ('admission', 'identity', 'build', 'spawn', 'forwarding', 'validation', 'report', 'cancelled', 'retention'):
            raise ValueError('invalid driver failure')
        integer(value['at_ns'])

    for key, check in (('capture', capture), ('first_failure', validator.failure),
                       ('context', validator.context), ('native_context', validator.context),
                       ('identity', identity), ('receipt', receipt), ('preflight', preflight),
                       ('timing', timing), ('preparation', preparation), ('driver_failure', driver_failure)):
        optional(key, check)
    if 'inputs' in packet:
        inputs = packet['inputs']
        fields(inputs, ('source', 'inventory', 'validation_contracts'))
        digest(inputs['source'])
        digest(inputs['inventory'])
        fields(inputs['validation_contracts'], ('native_producer_and_validator', 'shell_driver_and_validator'))
        for value in inputs['validation_contracts'].values():
            digest(value)
    return packet


if __name__ == '__main__':
    import sys
    try:
        github_output('ready', 'false')
        verify_packet(Path(__file__).resolve().parent.parent, os.environ.get('DIAGNOSTIC_INVOCATION'))
        github_output('ready', 'true')
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, RecursionError, OverflowError):
        print('diagnostic packet unavailable or refused', file=sys.stderr)
        sys.exit(1)
