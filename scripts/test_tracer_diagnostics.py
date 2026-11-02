#!/usr/bin/env python3
"""Retention controls establish mechanics, never coverage or historical diagnosis."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import re
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

sys.dont_write_bytecode = True
import tracer_diagnostics as diagnostics
import tracer_requirements

spec = importlib.util.spec_from_file_location('tracer_driver', Path(__file__).with_name('tracer-driver.py'))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
ROOT = Path(__file__).resolve().parent.parent


class Retention(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / 'tracer').mkdir()
        (self.root / 'tracer/inventory.json').write_bytes((ROOT / 'tracer/inventory.json').read_bytes())
        self.publication = diagnostics.Publication(self.root)
        inventory = tracer_requirements.read(ROOT / 'tracer/inventory.json')
        self.publication.identifiers(inventory, tracer_requirements.prerequisite_counts(inventory))
        self.publication.native_pid = 123
        self.capture = self.root / 'target/tracer-evidence' / ('123-' + self.publication.invocation)
        self.capture.mkdir(parents=True)
        self.write('owner.json', {'schema': 1, 'driver': os.getpid(), 'supervisor': 123,
                                 'invocation': self.publication.invocation})

    def tearDown(self):
        self.publication.close()
        self.temporary.cleanup()

    def write(self, name, value):
        (self.capture / name).write_text(json.dumps(value))

    def packet(self):
        packet = json.loads(self.publication.path.read_bytes())
        self.assertLessEqual(self.publication.path.stat().st_size, diagnostics.LIMIT)
        self.assertEqual({p.name for p in self.publication.path.parent.iterdir()}, {'packet.json'})
        self.assertNotIn('SENTINEL', self.publication.path.read_text())
        self.assertNotIn('pid', self.publication.path.read_text().lower())
        return packet

    def first(self, **changes):
        return dict(schema=1, at_ns=17, phase='groups', case='main.c001.p001',
                    kind='primary', **{'class': 'check'}, instance='main.a001.i001') | changes

    def test_no_forwarding_no_summary_preserves_first_and_actual_exit(self):
        self.write('first-failure.json', self.first())
        self.write('status.json', dict(schema=1, at_ns=29, phase='cleanup', case='main.c001.p001', status='failed'))
        self.write('supervisor.json', dict(schema=1, state='waited', code=23, signal=None))
        (self.capture / 'execution.log').write_text('SENTINEL opaque error and raw report')
        (self.capture / 'profile').mkdir()
        (self.capture / 'profile/secret').write_text('SENTINEL')
        self.publication.collect()
        packet = self.packet()
        self.assertEqual(packet['first_failure']['value'], self.first())
        self.assertEqual(packet['context']['value']['phase'], 'cleanup')
        self.assertEqual(packet['execution']['code'], 23)
        self.assertEqual(packet['receipt']['state'], 'missing')

    def test_exact_prerequisite_and_cleanup_classes(self):
        for failure in [self.first(kind='prerequisite', **{'class': 'prerequisite'}, instance='runtime.worker.ready.i003'),
                        self.first(kind='execution', **{'class': 'cleanup'}, instance=None)]:
            self.write('first-failure.json', failure)
            self.publication.collect()
            self.assertEqual(self.packet()['first_failure']['value'], failure)

    def test_terminated_child_context_does_not_invent_failure(self):
        child = subprocess.run(['/bin/sh', '-c', 'kill -TERM $$'], check=False)
        self.assertEqual(child.returncode, -signal.SIGTERM)
        self.write('supervisor.json', diagnostics.actual_exit(child.returncode))
        self.write('status.json', dict(schema=1, at_ns=3, phase='groups', case='main.c001.p001', status='active'))
        self.publication.collect()
        packet = self.packet()
        self.assertEqual(packet['execution']['signal'], signal.SIGTERM)
        self.assertIsNone(packet['execution']['code'])
        self.assertEqual(packet['first_failure'], {'state': 'missing'})
        self.assertEqual(packet['context']['value']['status'], 'active')

    def test_foreign_owner_and_stale_capture_are_never_accepted(self):
        for field, value in [('supervisor', 124), ('driver', os.getpid()+1), ('invocation', '0'*64)]:
            with self.subTest(field=field):
                self.write('owner.json', dict(schema=1, driver=os.getpid(), supervisor=123,
                                             invocation=self.publication.invocation) | {field: value})
                self.write('first-failure.json', self.first())
                self.publication.collect()
                self.assertEqual(self.packet()['capture'], {'state': 'untrusted'})
                self.assertEqual(self.packet()['first_failure'], {'state': 'untrusted'})

    def test_symlink_directory_leaf_fifo_and_hardlink_refuse(self):
        self.write('first-failure.json', self.first())
        self.write('secret', self.first(instance='SENTINEL'))
        for kind in ('symlink', 'fifo', 'hardlink'):
            with self.subTest(kind=kind):
                path = self.capture / 'first-failure.json'
                path.unlink()
                if kind == 'symlink':
                    path.symlink_to(self.capture / 'secret')
                elif kind == 'fifo':
                    os.mkfifo(path)
                else:
                    os.link(self.capture / 'secret', path)
                self.publication.collect()
                self.assertEqual(self.packet()['first_failure'], {'state': 'untrusted'})
        real = self.capture.with_name('foreign')
        self.capture.rename(real)
        self.capture.symlink_to(real, target_is_directory=True)
        self.publication.collect()
        self.assertEqual(self.packet()['capture'], {'state': 'untrusted'})

    def test_publication_refuses_symlink_parent_leaf_and_extra_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'target').symlink_to(self.root / 'target', target_is_directory=True)
            with self.assertRaises(OSError):
                diagnostics.Publication(root)
        self.publication.path.unlink()
        self.publication.path.symlink_to(self.capture / 'secret')
        with self.assertRaises(OSError):
            self.publication.publish()
        self.publication.path.unlink()
        (self.publication.path.parent / 'excluded').write_text('SENTINEL')
        with self.assertRaises(ValueError):
            self.publication.publish()

    def test_reject_opaque_strings_and_bound_oversized_records(self):
        mutations = [dict(phase='SENTINEL'), dict(case='SENTINEL'), dict(instance='main.a001.i001SENTINEL'),
                     dict(kind='SENTINEL'), {'class': 'SENTINEL'}, dict(at_ns=True),
                     dict(instance='main.a099.i001'), dict(description='SENTINEL')]
        for mutation in mutations:
            self.write('first-failure.json', self.first(**mutation))
            self.publication.collect()
            self.assertEqual(self.packet()['first_failure']['state'], 'untrusted')
        (self.capture / 'first-failure.json').write_text('SENTINEL'*10000)
        self.publication.collect()
        self.assertEqual(self.packet()['first_failure']['state'], 'truncated')
        self.publication.timing([('phase', dict(phase='groups', start_ns=1, end_ns=2))]*6)
        self.assertEqual(self.packet()['timing']['state'], 'truncated')

    def test_identity_and_preflight_are_explicit_projections(self):
        value = {key: 'a'*(40 if key == 'spec' else 64) for key in ('source', 'spec', 'binary', 'served', 'tracer')}
        value['validation_contracts'] = {key: 'b'*64 for key in ('native_producer_and_validator', 'shell_driver_and_validator')}
        value['preconditions'] = dict(chrome='c'*64, chrome_version='d'*64, fresh_profile=True,
                                      serial=True, local_fixtures=True, declaration_witnesses=False,
                                      opaque='SENTINEL')
        value['opaque'] = 'SENTINEL'
        self.write('identity.json', value)
        self.write('preflight.json', dict(schema=1, duration_ns=12, secret='SENTINEL'))
        self.publication.collect()
        packet = self.packet()
        self.assertEqual(packet['identity']['state'], 'available')
        self.assertEqual(set(packet['preflight']['value']), {'duration_ns', 'sha256'})
        self.assertNotIn('opaque', packet['identity']['value']['preconditions'])
        self.assertFalse(packet['identity']['value']['preconditions']['declaration_witnesses'])

    def test_malformed_optional_shapes_do_not_hide_valid_neighbors(self):
        self.write('first-failure.json', self.first())
        self.write('supervisor.json', diagnostics.actual_exit(23))
        self.publication.outcome('native', 1)
        for value in ([], None, 1, True, 'SENTINEL', {}, {'schema': True},
                      {'schema': 1}, {'schema': 1, 'duration_ns': []},
                      {'schema': 1, 'duration_ns': -1}, {'schema': 1, 'duration_ns': 3}):
            for name in ('preflight.json', 'identity.json', 'status.json', 'native-status.json', 'exit.json'):
                with self.subTest(name=name, value=value):
                    self.write(name, value)
                    self.publication.collect()
                    packet = diagnostics.verify_packet(self.root, self.publication.invocation)
                    self.assertEqual(packet['first_failure'], diagnostics.available(self.first()))
                    self.assertEqual(packet['execution'], diagnostics.actual_exit(23))
                    self.assertEqual(packet['outcomes']['native'], diagnostics.actual_exit(1))
                    key = {'identity.json': 'identity', 'preflight.json': 'preflight',
                           'status.json': 'context', 'native-status.json': 'native_context',
                           'exit.json': 'receipt'}[name]
                    self.assertEqual(packet[key]['state'], 'available' if name == 'preflight.json' and value == {'schema': 1, 'duration_ns': 3} else 'untrusted')
                    (self.capture / name).unlink()

    def test_error_only_primary_identity_is_limited_to_real_callers(self):
        for case in ('main.c017.p001', 'main.c018.p001', 'main.c001.p001'):
            self.write('first-failure.json', self.first(case=case, instance='main.a122.i001'))
            self.publication.collect()
            packet = diagnostics.verify_packet(self.root, self.publication.invocation)
            self.assertEqual(packet['first_failure']['state'], 'untrusted' if case == 'main.c001.p001' else 'available')

    def test_private_owner_binding_and_public_pid_rejection(self):
        packet = self.packet()
        owner_path = self.root / 'target/tracer-diagnostics-owner.json'
        owner = json.loads(owner_path.read_text())
        self.assertEqual(owner['driver_pid'], os.getpid())
        self.assertNotIn('driver_pid', packet)
        owner_path.write_text(json.dumps(owner | {'invocation': '0'*64}))
        with self.assertRaises(ValueError):
            diagnostics.verify_packet(self.root, self.publication.invocation)
        with self.assertRaises(ValueError):
            diagnostics.Publication(self.root)
        owner_path.write_text(json.dumps(owner))
        packet['driver_pid'] = os.getpid()
        self.publication.path.write_text(json.dumps(packet))
        with self.assertRaises(ValueError):
            diagnostics.verify_packet(self.root, self.publication.invocation)

    def test_consecutive_failure_success_and_live_neighbor(self):
        self.write('first-failure.json', self.first())
        self.publication.collect()
        with self.assertRaisesRegex(ValueError, 'still active'):
            diagnostics.Publication(self.root)
        old_invocation = self.publication.invocation
        self.publication.stage('validation', 'failed')
        self.publication.close()
        self.publication = diagnostics.Publication(self.root)
        self.publication.outcome('driver', 0)
        self.publication.stage('finished', 'succeeded')
        packet = self.packet()
        self.assertNotEqual(packet['invocation'], old_invocation)
        self.assertEqual(packet['first_failure'], {'state': 'missing'})
        self.assertEqual(packet['execution']['state'], 'unavailable')
        self.assertEqual(packet['driver']['status'], 'succeeded')

    def test_unknown_exit_is_not_zero(self):
        self.assertEqual(diagnostics.actual_exit(None)['state'], 'unavailable')
        for value in [True, '0', -128, 256]:
            with self.assertRaises(ValueError):
                diagnostics.actual_exit(value)
        self.publication.collect()
        self.assertEqual(self.packet()['execution']['state'], 'unavailable')

    def test_admission_and_spawn_failures_leave_early_stage(self):
        for failure in ('admission', 'spawn'):
            # main's boundary publishes even when no preparation report can be formed.
            self.publication.stage('admission', 'failed')
            self.publication.close()
            with patch.object(driver, 'ROOT', self.root), \
                 patch.object(driver.sys, 'argv', ['tracer.sh', 'full']), \
                 patch.object(driver, 'run', side_effect=ValueError('SENTINEL') if failure == 'admission' else OSError('SENTINEL')), \
                 contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(driver.main(), 1)
            packet = json.loads((self.root / 'target/tracer-diagnostics/packet.json').read_text())
            self.assertEqual(packet['driver']['status'], 'failed')
            self.assertEqual(packet['outcomes']['native']['state'], 'unavailable')
            self.assertNotIn('SENTINEL', json.dumps(packet))
            self.publication = diagnostics.Publication(self.root)

    def test_real_fixture_no_stdout_and_nonzero_exit_is_retained(self):
        binary = self.root / 'target/debug/tracer'
        binary.parent.mkdir()
        # This process fixture models the native boundary, not an application check.
        binary.write_text('#!' + sys.executable + "\n" + r"""
import json, os
from pathlib import Path
invocation = os.environ['_TAU_DIAGNOSTIC_INVOCATION']
capture = Path('target/tracer-evidence') / (str(os.getpid()) + '-' + invocation)
capture.mkdir(parents=True)
values = {
 'owner.json': dict(schema=1, driver=os.getppid(), supervisor=os.getpid(), invocation=invocation),
 'first-failure.json': dict(schema=1, at_ns=1, phase='browser', case=None, kind='execution', **{'class':'setup'}, instance=None),
 'status.json': dict(schema=1, at_ns=2, phase='cleanup', case=None, status='failed'),
 'supervisor.json': dict(schema=1, state='waited', code=19, signal=None),
}
for name, value in values.items():
 (capture/name).write_text(json.dumps(value))
(capture/'raw.log').write_text('SENTINEL')
os._exit(19)
""")
        binary.chmod(0o700)
        with patch.object(driver, 'ROOT', self.root), \
             patch.dict(os.environ, {'CARGO_TARGET_DIR': str(self.root / 'target')}), \
             patch.object(driver, 'native_build', return_value=0), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            native, validation = driver.execute('full', [], None, {}, 'synthetic', self.publication)
        self.assertEqual((native, validation), (19, 1))
        packet = self.packet()
        self.assertEqual(packet['outcomes']['native']['code'], 19)
        self.assertEqual(packet['outcomes']['validation']['code'], 1)
        self.assertEqual(packet['first_failure']['value']['class'], 'setup')
        self.assertIsNone(packet['first_failure']['value']['instance'])
        self.assertEqual(packet['execution']['code'], 19)

    def test_closed_directory_cannot_fall_back_to_cwd(self):
        self.publication.directory.close()
        with self.assertRaisesRegex(ValueError, 'closed'):
            self.publication.directory.write('packet.json', b'SENTINEL')

    def test_upload_admission_rejects_stale_unsafe_and_extra_fields(self):
        self.publication.collect()
        diagnostics.verify_packet(self.root, self.publication.invocation)
        with self.assertRaises(ValueError):
            diagnostics.verify_packet(self.root, '0'*64)
        original = self.publication.path.read_bytes()
        for mutation in ('extra', 'description', 'status', 'hash', 'pid'):
            packet = json.loads(original)
            if mutation == 'extra':
                packet['SENTINEL'] = True
            elif mutation == 'description':
                packet['first_failure'] = diagnostics.available(self.first(description='SENTINEL'))
            elif mutation == 'status':
                packet['driver']['status'] = 'SENTINEL'
            elif mutation == 'pid':
                packet['driver_pid'] = os.getpid()
            else:
                packet['preflight'] = diagnostics.available(dict(duration_ns=2, sha256='SENTINEL'))
            self.publication.path.write_text(json.dumps(packet))
            with self.assertRaises(ValueError):
                diagnostics.verify_packet(self.root, self.publication.invocation)
        self.publication.path.write_bytes(original + b' '*diagnostics.LIMIT)
        with self.assertRaises(OverflowError):
            diagnostics.verify_packet(self.root, self.publication.invocation)
        self.publication.path.unlink()
        self.publication.path.symlink_to(self.capture / 'secret')
        with self.assertRaises(OSError):
            diagnostics.verify_packet(self.root, self.publication.invocation)

    def test_cancelled_step_retains_current_packet_and_early_output(self):
        self.publication.stage('admission', 'failed')
        self.publication.close()
        output = self.root / 'runner-output'
        output.touch()
        def cancelled(publication):
            publication.stage('native_execution')
            os.kill(os.getpid(), signal.SIGTERM)
        with patch.object(driver, 'ROOT', self.root), \
             patch.dict(os.environ, {'GITHUB_OUTPUT': str(output)}), \
             patch.object(driver, 'run', side_effect=cancelled), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(driver.main(), 143)
        invocation = output.read_text().strip().splitlines()[-1].split('=')[1]
        packet = diagnostics.verify_packet(self.root, invocation)
        self.assertEqual(packet['driver']['status'], 'cancelled')
        self.assertEqual(packet['execution']['state'], 'unavailable')
        self.assertEqual(packet['first_failure'], {'state': 'missing'})
        self.publication = diagnostics.Publication(self.root)

    def test_refused_invocation_clears_any_earlier_runner_output(self):
        output = self.root / 'runner-output'
        output.write_text('diagnostic_invocation=' + self.publication.invocation + '\n')
        # A live neighbor must retain its files, and cannot become this step's artifact.
        with patch.object(driver, 'ROOT', self.root), \
             patch.dict(os.environ, {'GITHUB_OUTPUT': str(output)}), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(driver.main(), 1)
        self.assertEqual(output.read_text().splitlines()[-1], 'diagnostic_invocation=')
        self.assertEqual(json.loads(self.publication.path.read_text())['invocation'], self.publication.invocation)

    def test_keyboard_interrupt_waits_for_actual_child_exit(self):
        class Diagnostic:
            def __init__(self):
                self.observed = []
            def publish(self):
                pass
            def collect(self):
                pass
            def outcome(self, name, code):
                self.observed.append((name, diagnostics.actual_exit(code)))
        diagnostic = Diagnostic()
        child = None
        try:
            with self.assertRaises(KeyboardInterrupt):
                with driver.observed_child([sys.executable, '-c',
                     'import time; print("ready",flush=True); time.sleep(0.7); raise SystemExit(23)'],
                     diagnostic, 'native', stdout=subprocess.PIPE, text=True) as child:
                    self.assertEqual(child.stdout.readline(), 'ready\n')
                    raise KeyboardInterrupt
            self.assertEqual(diagnostic.observed, [('native', diagnostics.actual_exit(23))])
        finally:
            if child is not None:
                child.wait()

    def test_cancelled_native_build_keeps_actual_waited_exit(self):
        self.publication.stage('admission', 'failed')
        self.publication.close()
        real_popen = subprocess.Popen
        children, timers = [], []
        def launch(command, **_kwargs):
            self.assertEqual(command, ['cargo', 'build', '--locked', '-p', 'tracer'])
            child = real_popen([sys.executable, '-c',
                'import signal,time; signal.signal(signal.SIGTERM,lambda *_:None); print("ready",flush=True); time.sleep(0.7); raise SystemExit(23)'],
                stdout=subprocess.PIPE, text=True)
            children.append(child)
            self.assertEqual(child.stdout.readline(), 'ready\n')
            timer = threading.Timer(0.05, lambda: os.kill(os.getpid(), signal.SIGTERM))
            timers.append(timer)
            timer.start()
            return child
        def run(publication):
            publication.stage('native_build')
            return driver.native_build(publication)
        try:
            with patch.object(driver, 'ROOT', self.root), \
                 patch.object(driver, 'run', side_effect=run), \
                 patch.object(driver.subprocess, 'Popen', side_effect=launch), \
                 contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(driver.main(), 143)
        finally:
            for timer in timers:
                timer.join()
            exits = [child.wait() for child in children]
        self.assertEqual(exits, [23])
        packet = json.loads((self.root / 'target/tracer-diagnostics/packet.json').read_text())
        self.assertEqual(packet['outcomes']['native_build'], diagnostics.actual_exit(23))
        self.assertEqual(packet['driver']['status'], 'cancelled')
        self.assertEqual(packet['first_failure'], {'state': 'missing'})

    def test_spawn_failure_is_observed_before_any_child_receipt(self):
        with patch.object(driver, 'ROOT', self.root), \
             patch.object(driver.subprocess, 'Popen', side_effect=OSError('SENTINEL')), \
             self.assertRaises(OSError):
            driver.execute('full', [], None, {}, 'synthetic', self.publication)
        packet = self.packet()
        self.assertEqual(packet['driver_failure']['value']['class'], 'spawn')
        self.assertEqual(packet['driver_failure']['value']['stage'], 'native_build')
        self.assertEqual(packet['outcomes']['native_build']['state'], 'unavailable')

    def test_native_build_status_forwarding_error_is_not_a_spawn(self):
        class LostOutput(io.StringIO):
            def write(self, text):
                if text.startswith('TRACER_NATIVE_BUILD_EXIT'):
                    raise OSError('SENTINEL')
                return super().write(text)
        with patch.object(driver, 'native_build', return_value=0), \
             contextlib.redirect_stdout(LostOutput()), self.assertRaises(OSError):
            driver.execute('full', [], None, {}, 'synthetic', self.publication)
        first = self.packet()['driver_failure']
        self.assertEqual(first['value']['class'], 'forwarding')
        self.assertEqual(first['value']['stage'], 'native_build')
        self.assertEqual(self.packet()['outcomes']['native_build'], diagnostics.actual_exit(0))
        self.assertEqual(self.packet()['outcomes']['native']['state'], 'unavailable')
        self.publication.fail('validation')
        self.assertEqual(self.packet()['driver_failure'], first)

    def test_failed_native_build_precedes_status_forwarding_failure(self):
        class LostOutput(io.StringIO):
            def write(self, text):
                if text.startswith('TRACER_NATIVE_BUILD_EXIT'):
                    raise OSError('SENTINEL')
                return super().write(text)
        with patch.object(driver, 'native_build', return_value=7), \
             contextlib.redirect_stdout(LostOutput()), self.assertRaises(OSError):
            driver.execute('full', [], None, {}, 'synthetic', self.publication)
        packet = self.packet()
        first = packet['driver_failure']
        self.assertEqual(first['value']['class'], 'build')
        self.assertEqual(first['value']['stage'], 'native_build')
        self.assertEqual(packet['outcomes']['native_build'], diagnostics.actual_exit(7))
        self.assertEqual(packet['outcomes']['native']['state'], 'unavailable')
        self.publication.fail('validation')
        self.assertEqual(self.packet()['driver_failure'], first)

    def test_process_output_failure_keeps_honest_eventual_driver_status(self):
        harness = r'''
import importlib.util, subprocess, sys
from pathlib import Path
sys.dont_write_bytecode = True
sys.path.insert(0, sys.argv[1])
spec = importlib.util.spec_from_file_location('driver', Path(sys.argv[1])/'tracer-driver.py')
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
driver.ROOT = Path(sys.argv[2])
mode = sys.argv[3]
def run(publication):
    publication.stage('prepare_served')
    with driver.observed_child([sys.executable, '-c', 'raise SystemExit(7)'],
                               publication, 'served_build') as child:
        assert child.wait() == 7
    publication.stage('preparation_report')
    if mode == 'diagnostic':
        publication.fail('build')
        return 7
    driver.forward(publication, 'TRACER_PREPARATION SENTINEL', flush=mode == 'preparation')
    return 0
driver.run = run
sys.exit(driver.main())
'''
        self.publication.stage('admission', 'failed')
        self.publication.close()
        for device in ('broken_pipe', 'full'):
            for mode in ('preparation', 'buffered', 'diagnostic'):
                with self.subTest(device=device, mode=mode):
                    if device == 'broken_pipe':
                        read_fd, write_fd = os.pipe()
                        os.close(read_fd)
                        failed_stream = os.fdopen(write_fd, 'wb')
                    else:
                        failed_stream = open('/dev/full', 'wb')
                    with failed_stream:
                        result = subprocess.run([sys.executable, '-c', harness, str(ROOT / 'scripts'), str(self.root), mode],
                            stdout=failed_stream if mode != 'diagnostic' else subprocess.PIPE,
                            stderr=failed_stream if mode == 'diagnostic' else subprocess.PIPE,
                            check=False, timeout=10)
                    self.assertNotEqual(result.returncode, 0)
                    packet = json.loads(self.publication.path.read_text())
                    diagnostics.verify_packet(self.root, packet['invocation'])
                    outcome = packet['outcomes']['driver']
                    if outcome['state'] == 'waited':
                        self.assertEqual(outcome, diagnostics.actual_exit(result.returncode))
                    else:
                        self.assertEqual(outcome, diagnostics.actual_exit(None))
                    self.assertEqual(packet['outcomes']['served_build'], diagnostics.actual_exit(7))
                    self.assertEqual(packet['driver']['status'], 'failed')
                    self.assertEqual(packet['driver_failure']['value']['class'], 'build' if mode == 'diagnostic' else 'forwarding')
                    self.assertEqual(packet['driver_failure']['value']['stage'], 'preparation_report')
                    self.assertEqual(packet['first_failure'], diagnostics.missing())
                    self.assertNotIn('SENTINEL', json.dumps(packet))
        self.publication = diagnostics.Publication(self.root)

    def test_cancellation_reaches_execution_descendant(self):
        harness = r'''
import importlib.util, sys
from pathlib import Path
sys.dont_write_bytecode = True
sys.path.insert(0, sys.argv[1])
spec = importlib.util.spec_from_file_location('driver', Path(sys.argv[1])/'tracer-driver.py')
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
driver.ROOT = Path(sys.argv[2])
executor = r"""
import os, signal, sys, time
from pathlib import Path
root = Path(sys.argv[1])
def cancelled(signum, _frame):
    (root/'execution-stopped').write_text(str(signum))
    raise SystemExit(0)
for sig in (signal.SIGTERM, signal.SIGINT):
    signal.signal(sig, cancelled)
(root/'execution-ready').write_text(str(os.getpid()))
while True:
    time.sleep(0.01)
"""
supervisor = r"""
import subprocess, sys, time
child = subprocess.Popen([sys.executable, '-c', sys.argv[2], sys.argv[1]],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
child.wait()
"""
def run(publication):
    publication.stage('native_execution')
    with driver.observed_child([sys.executable, '-c', supervisor, str(driver.ROOT), executor],
                               publication, 'native', stdout=-1, stderr=-1) as child:
        (driver.ROOT/'supervisor-ready').write_text(str(child.pid))
        return child.wait()
driver.run = run
sys.exit(driver.main())
'''
        self.publication.stage('admission', 'failed')
        self.publication.close()
        for signum in (signal.SIGTERM, signal.SIGINT):
            with self.subTest(signal=signum):
                ready = self.root / 'execution-ready'
                stopped = self.root / 'execution-stopped'
                supervisor_ready = self.root / 'supervisor-ready'
                for path in (ready, stopped, supervisor_ready):
                    path.unlink(missing_ok=True)
                execution_pid = None
                with subprocess.Popen([sys.executable, '-c', harness, str(ROOT / 'scripts'), str(self.root)],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
                    try:
                        deadline = time.monotonic() + 10
                        while not ready.exists() or not supervisor_ready.exists():
                            self.assertIsNone(process.poll())
                            self.assertLess(time.monotonic(), deadline)
                            time.sleep(0.01)
                        execution_pid = int(ready.read_text())
                        supervisor_pid = int(supervisor_ready.read_text())
                        self.assertIn(str(self.root).encode(), Path(f'/proc/{execution_pid}/cmdline').read_bytes())
                        self.assertEqual(os.getpgid(execution_pid), supervisor_pid)
                        self.assertNotEqual(os.getpgrp(), supervisor_pid)
                        process.send_signal(signum)
                        stdout, stderr = process.communicate(timeout=10)
                        self.assertEqual(process.returncode, 128 + signum, (stdout, stderr))
                        deadline = time.monotonic() + 2
                        while not stopped.exists() and time.monotonic() < deadline:
                            time.sleep(0.01)
                        self.assertTrue(stopped.exists(), 'execution descendant did not receive cancellation')
                        self.assertEqual(int(stopped.read_text()), signum)
                        packet = json.loads(self.publication.path.read_text())
                        diagnostics.verify_packet(self.root, packet['invocation'])
                        self.assertEqual(packet['driver']['status'], 'cancelled')
                        self.assertEqual(packet['driver_failure']['value']['class'], 'cancelled')
                        self.assertEqual(packet['first_failure'], diagnostics.missing())
                    finally:
                        if execution_pid is not None:
                            command = Path(f'/proc/{execution_pid}/cmdline')
                            if command.exists() and command.read_bytes():
                                self.assertIn(str(self.root).encode(), command.read_bytes())
                                with contextlib.suppress(ProcessLookupError):
                                    os.kill(execution_pid, signal.SIGKILL)
        self.publication = diagnostics.Publication(self.root)

    def test_cancellation_owns_publication_until_delayed_child_is_reaped(self):
        harness = r'''
import importlib.util, sys
from pathlib import Path
sys.dont_write_bytecode = True
sys.path.insert(0, sys.argv[1])
spec = importlib.util.spec_from_file_location('driver', Path(sys.argv[1])/'tracer-driver.py')
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
driver.ROOT = Path(sys.argv[2])
program = r"""
import os, signal, sys, time
from pathlib import Path
root = Path(sys.argv[1])
signal.signal(signal.SIGTERM, lambda *_: None)
(root/'child-ready').write_text(str(os.getpid()))
deadline = time.monotonic() + 15
while not (root/'release-child').exists():
    if time.monotonic() >= deadline:
        raise SystemExit(24)
    time.sleep(0.01)
raise SystemExit(23)
"""
def run(publication):
    publication.stage('prepare_served')
    with driver.observed_child([sys.executable, '-c', program, str(driver.ROOT)],
                               publication, 'served_build') as child:
        return child.wait()
driver.run = run
sys.exit(driver.main())
'''
        self.publication.stage('admission', 'failed')
        self.publication.close()
        with subprocess.Popen([sys.executable, '-c', harness, str(ROOT / 'scripts'), str(self.root)],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
            try:
                deadline = time.monotonic() + 10
                ready = self.root / 'child-ready'
                while not ready.exists():
                    self.assertIsNone(process.poll())
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.01)
                child_pid = int(ready.read_text())
                self.assertIn(str(self.root).encode(), Path(f'/proc/{process.pid}/cmdline').read_bytes())
                self.assertIn(str(self.root).encode(), Path(f'/proc/{child_pid}/cmdline').read_bytes())
                process.send_signal(signal.SIGTERM)
                while True:
                    original = self.publication.path.read_bytes()
                    packet = json.loads(original)
                    if packet['driver']['status'] == 'cancelled':
                        break
                    self.assertIsNone(process.poll())
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.01)
                self.assertIsNone(process.poll())
                self.assertEqual(packet['outcomes']['served_build'], diagnostics.actual_exit(None))
                self.assertTrue(Path(f'/proc/{child_pid}').exists())
                owner_path = self.root / 'target/tracer-diagnostics-owner.json'
                owner = owner_path.read_bytes()
                with self.assertRaisesRegex(ValueError, 'still active'):
                    competitor = diagnostics.Publication(self.root)
                    competitor.close()
                self.assertEqual(self.publication.path.read_bytes(), original)
                self.assertEqual(owner_path.read_bytes(), owner)
                diagnostics.verify_packet(self.root, packet['invocation'])
            finally:
                (self.root / 'release-child').touch()
                stdout, stderr = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 143, (stdout, stderr))
        final = json.loads(self.publication.path.read_text())
        diagnostics.verify_packet(self.root, packet['invocation'])
        self.assertEqual(final['outcomes']['served_build'], diagnostics.actual_exit(23))
        self.assertEqual(final['outcomes']['driver'], diagnostics.actual_exit(None))
        self.assertEqual(final['driver']['status'], 'cancelled')
        self.assertEqual(final['driver_failure'], packet['driver_failure'])
        self.assertEqual(final['driver_failure']['value']['class'], 'cancelled')
        self.assertEqual(final['first_failure'], diagnostics.missing())
        self.publication = diagnostics.Publication(self.root)
        fresh = self.packet()
        self.assertNotEqual(fresh['invocation'], final['invocation'])
        self.assertEqual(fresh['driver_failure'], diagnostics.missing())
        self.assertEqual(fresh['first_failure'], diagnostics.missing())
        self.assertEqual(fresh['outcomes']['served_build'], diagnostics.actual_exit(None))

    def test_terminal_handler_boundary_retains_real_cancellation(self):
        harness = r'''
import importlib.util, os, signal, sys
from pathlib import Path
sys.dont_write_bytecode = True
sys.path.insert(0, sys.argv[1])
spec = importlib.util.spec_from_file_location('driver', Path(sys.argv[1])/'tracer-driver.py')
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
driver.ROOT = Path(sys.argv[2])
original = signal.getsignal(signal.SIGTERM)
install = signal.signal
injected = False
def boundary(sig, handler):
    global injected
    if sig == signal.SIGTERM and handler == original and not injected:
        injected = True
        os.kill(os.getpid(), signal.SIGTERM)
    return install(sig, handler)
driver.signal.signal = boundary
def run(publication):
    publication.outcome('served_build', 7)
    if sys.argv[3] == 'earlier':
        publication.packet['first_failure'] = driver.tracer_diagnostics.available(dict(
            schema=1, at_ns=17, phase='groups', case='main.c001.p001',
            kind='primary', **{'class': 'check'}, instance='main.a001.i001'))
        publication.packet['execution'] = driver.tracer_diagnostics.actual_exit(23)
        publication.fail('build')
        return 7
    return 0
driver.run = run
sys.exit(driver.main())
'''
        self.publication.close()
        for mode in ('success', 'earlier'):
            with self.subTest(mode=mode):
                result = subprocess.run([sys.executable, '-c', harness, str(ROOT / 'scripts'),
                                         str(self.root), mode], capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 143, result.stderr)
                self.assertNotIn(b'closed diagnostic directory', result.stderr)
                packet = self.packet()
                diagnostics.verify_packet(self.root, packet['invocation'])
                self.assertEqual(packet['outcomes']['driver'], diagnostics.actual_exit(None))
                self.assertEqual(packet['outcomes']['served_build'], diagnostics.actual_exit(7))
                self.assertEqual(packet['driver']['status'], 'cancelled')
                self.assertEqual(packet['driver_failure']['value']['class'],
                                 'build' if mode == 'earlier' else 'cancelled')
                self.assertEqual(packet['first_failure'],
                                 diagnostics.available(self.first()) if mode == 'earlier' else diagnostics.missing())
                self.assertEqual(packet['execution'], diagnostics.actual_exit(23 if mode == 'earlier' else None))
        self.publication = diagnostics.Publication(self.root)

    def test_after_real_terminal_methods_keep_eventual_driver_exit_unavailable(self):
        harness = r'''
import importlib.util, os, signal, subprocess, sys
from pathlib import Path
sys.dont_write_bytecode = True
sys.path.insert(0, sys.argv[1])
spec = importlib.util.spec_from_file_location('driver', Path(sys.argv[1])/'tracer-driver.py')
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
driver.ROOT = Path(sys.argv[2])
method, signum, mode = sys.argv[3], int(sys.argv[4]), sys.argv[5]
real = getattr(driver.tracer_diagnostics.Publication, method)
def boundary(publication, *args):
    result = real(publication, *args)
    os.kill(os.getpid(), signum)
    return result
setattr(driver.tracer_diagnostics.Publication, method, boundary)
def run(publication):
    if mode == 'earlier':
        child = subprocess.run([sys.executable, '-c', 'raise SystemExit(23)'])
        publication.packet['execution'] = driver.tracer_diagnostics.actual_exit(child.returncode)
        publication.packet['first_failure'] = driver.tracer_diagnostics.available(dict(
            schema=1, at_ns=17, phase='groups', case='main.c001.p001',
            kind='primary', **{'class': 'check'}, instance='main.a001.i001'))
        publication.outcome('native', child.returncode)
        publication.fail('validation')
        return child.returncode
    return 0
driver.run = run
sys.exit(driver.main())
'''
        self.publication.close()
        for method in ('finish', 'close'):
            for signum in (signal.SIGTERM, signal.SIGINT):
                for mode in ('success', 'earlier'):
                    with self.subTest(method=method, signal=signum, mode=mode):
                        result = subprocess.run(
                            [sys.executable, '-c', harness, str(ROOT / 'scripts'),
                             str(self.root), method, str(signum), mode],
                            capture_output=True, timeout=10)
                        self.assertEqual(result.returncode, -signum, result.stderr)
                        self.assertNotIn(b'closed diagnostic directory', result.stderr)
                        packet = self.packet()
                        diagnostics.verify_packet(self.root, packet['invocation'])
                        self.assertEqual(packet['packet_state'], 'finalized')
                        self.assertEqual(packet['outcomes']['driver'], diagnostics.actual_exit(None))
                        self.assertNotEqual(packet['driver']['status'], 'succeeded')
                        self.assertEqual(packet['first_failure'],
                                         diagnostics.available(self.first()) if mode == 'earlier' else diagnostics.missing())
                        for outcome in (packet['execution'], packet['outcomes']['native']):
                            self.assertEqual(outcome, diagnostics.actual_exit(23 if mode == 'earlier' else None))
                        if mode == 'earlier':
                            self.assertEqual(packet['driver_failure']['value']['class'], 'validation')
        self.publication = diagnostics.Publication(self.root)

    def test_terminal_write_failure_keeps_coherent_partial_packet(self):
        harness = r'''
import importlib.util, json, sys
from pathlib import Path
sys.dont_write_bytecode = True
sys.path.insert(0, sys.argv[1])
spec = importlib.util.spec_from_file_location('driver', Path(sys.argv[1])/'tracer-driver.py')
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
driver.ROOT = Path(sys.argv[2])
write = driver.tracer_diagnostics.Directory.write
def terminal_write(directory, name, raw, staging=None):
    if name == 'packet.json' and sys.argv[3] != 'success':
        packet = json.loads(raw)
        if packet['packet_state'] == 'finalized':
            raise OSError('SENTINEL_FINAL_WRITE')
    return write(directory, name, raw, staging)
driver.tracer_diagnostics.Directory.write = terminal_write
def run(publication):
    if sys.argv[3] == 'earlier':
        publication.packet['first_failure'] = driver.tracer_diagnostics.available(dict(
            schema=1, at_ns=17, phase='groups', case='main.c001.p001',
            kind='primary', **{'class': 'check'}, instance='main.a001.i001'))
        publication.packet['execution'] = driver.tracer_diagnostics.actual_exit(23)
        publication.outcome('served_build', 7)
        publication.fail('build')
        return 7
    return 0
driver.run = run
sys.exit(driver.main())
'''
        self.publication.close()
        for mode, expected in (('fault', 1), ('earlier', 7), ('success', 0)):
            with self.subTest(mode=mode):
                result = subprocess.run([sys.executable, '-c', harness, str(ROOT / 'scripts'),
                                         str(self.root), mode], capture_output=True, timeout=10)
                self.assertEqual(result.returncode, expected, result.stderr)
                packet = self.packet()
                diagnostics.verify_packet(self.root, packet['invocation'])
                if mode == 'success':
                    self.assertEqual(packet['packet_state'], 'finalized')
                    self.assertEqual(packet['driver']['status'], 'unavailable')
                    self.assertEqual(packet['outcomes']['driver'], diagnostics.actual_exit(None))
                else:
                    self.assertEqual(packet['packet_state'], 'partial')
                    self.assertNotEqual(packet['driver']['status'], 'succeeded')
                    self.assertEqual(packet['outcomes']['driver'], diagnostics.actual_exit(None))
                    self.assertIn(b'diagnostic retention unavailable', result.stderr)
                if mode == 'earlier':
                    self.assertEqual(packet['outcomes']['served_build'], diagnostics.actual_exit(7))
                    self.assertEqual(packet['driver_failure']['value']['class'], 'build')
                    self.assertEqual(packet['first_failure'], diagnostics.available(self.first()))
                    self.assertEqual(packet['execution'], diagnostics.actual_exit(23))
        self.publication = diagnostics.Publication(self.root)

    def test_flush_failure_does_not_displace_an_earlier_event(self):
        class LostFlush(io.StringIO):
            def flush(self):
                raise OSError('SENTINEL')
        for earlier in (False, True):
            with self.subTest(earlier=earlier):
                self.publication.packet['driver_failure'] = diagnostics.missing()
                self.publication.stage('preparation_report')
                if earlier:
                    self.publication.fail('build')
                with contextlib.redirect_stdout(LostFlush()), self.assertRaises(OSError):
                    driver.forward(self.publication, 'TRACER_PREPARATION {}', flush=True)
                self.assertEqual(self.packet()['driver_failure']['value']['class'], 'build' if earlier else 'forwarding')

    def test_pipe_capture_error_keeps_forwarding_class_and_waited_exit(self):
        class LostPipe:
            def __iter__(self):
                raise OSError('SENTINEL')
        child = Mock(pid=123, stdout=LostPipe(), returncode=0)
        child.__enter__ = Mock(return_value=child)
        child.__exit__ = Mock(return_value=False)
        with patch.object(driver, 'ROOT', self.root), \
             patch.object(driver, 'native_build', return_value=0), \
             patch.object(driver.subprocess, 'Popen', return_value=child), \
             contextlib.redirect_stdout(io.StringIO()), self.assertRaises(OSError):
            driver.execute('full', [], None, {}, 'synthetic', self.publication)
        packet = self.packet()
        self.assertEqual(packet['driver_failure']['value']['class'], 'forwarding')
        self.assertEqual(packet['driver_failure']['value']['stage'], 'native_execution')
        self.assertEqual(packet['outcomes']['native'], diagnostics.actual_exit(0))

    def test_process_driver_exit_is_separate_from_preparation_signal(self):
        # A real preparation process emits its bounded timing, then exits or is
        # signalled. Observe the driver's eventual OS status independently.
        harness = r'''
import json, os, signal, subprocess, sys, time
from pathlib import Path
sys.dont_write_bytecode = True
sys.path.insert(0, sys.argv[1])
import importlib.util
spec = importlib.util.spec_from_file_location('driver', Path(sys.argv[1])/'tracer-driver.py')
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
driver.ROOT = Path(sys.argv[2])
mode = sys.argv[3]
driver.sys.argv = ['tracer.sh', 'full']
driver.admit = lambda *_: {}
driver.source_paths = lambda *_: []
driver.tree_hash = lambda *_args, **_kwargs: 'a'*64
driver.validation_contracts = lambda *_: {key:'b'*64 for key in ('native_producer_and_validator', 'shell_driver_and_validator')}
real_popen = subprocess.Popen
def launch(command, **kwargs):
    assert command == ['scripts/build-web.sh', 'served']
    code = -signal.SIGTERM if mode == 'signal' else 7
    program = "import json,os,signal,time; now=time.monotonic_ns(); print('TRACER_BUILD_TIMING '+json.dumps(dict(schema=1,phase='prepare_served',start_ns=now,end_ns=now,exit="+str(code)+")),flush=True); "
    program += 'os.kill(os.getpid(),signal.SIGTERM)' if code < 0 else 'raise SystemExit(7)'
    return real_popen([sys.executable, '-c', program], **kwargs)
driver.subprocess.Popen = launch
if mode == 'cancelled':
    driver.run = lambda *_: signal.raise_signal(signal.SIGTERM)
sys.exit(driver.main())
'''
        self.publication.stage('admission', 'failed')
        self.publication.close()
        for mode, expected in (('signal', 241), ('nonzero', 7), ('cancelled', 143)):
            with self.subTest(mode=mode):
                result = subprocess.run([sys.executable, '-c', harness, str(ROOT / 'scripts'), str(self.root), mode],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
                self.assertEqual(result.returncode, expected, result.stderr.decode())
                packet = json.loads((self.root / 'target/tracer-diagnostics/packet.json').read_text())
                diagnostics.verify_packet(self.root, packet['invocation'])
                self.assertEqual(packet['outcomes']['driver'], diagnostics.actual_exit(None))
                self.assertEqual(packet['outcomes']['served_build'], diagnostics.actual_exit(-signal.SIGTERM if mode == 'signal' else 7 if mode == 'nonzero' else None))
                self.assertEqual(packet['driver']['status'], 'cancelled' if mode == 'cancelled' else 'failed')
                self.assertNotIn('SENTINEL', json.dumps(packet))
        self.publication = diagnostics.Publication(self.root)

    def test_preparation_forwarding_error_keeps_its_original_stage_and_class(self):
        class LostOutput(io.StringIO):
            def reconfigure(self, **_kwargs):
                pass
            def write(self, _text):
                raise OSError('SENTINEL')
        self.publication.stage('admission', 'failed')
        self.publication.close()
        inventory = tracer_requirements.read(ROOT / 'tracer/inventory.json')
        child = Mock(pid=123, stdout=io.StringIO('SENTINEL opaque build output\n'), returncode=0)
        child.wait.return_value = 0
        child.__enter__ = Mock(return_value=child)
        child.__exit__ = Mock(return_value=False)
        contracts = {name: 'a'*64 for name in ('native_producer_and_validator', 'shell_driver_and_validator')}
        with patch.object(driver, 'ROOT', self.root), \
             patch.object(driver.sys, 'argv', ['tracer.sh', 'full']), \
             patch.object(driver, 'admit', return_value={}), \
             patch.object(driver, 'read_inventory', return_value=inventory), \
             patch.object(driver, 'source_paths', return_value=[]), \
             patch.object(driver, 'tree_hash', return_value='b'*64), \
             patch.object(driver, 'validation_contracts', return_value=contracts), \
             patch.object(driver.subprocess, 'Popen', return_value=child), \
             contextlib.redirect_stdout(LostOutput()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(driver.main(), 1)
        packet = json.loads((self.root / 'target/tracer-diagnostics/packet.json').read_text())
        self.assertEqual(packet['driver_failure']['value']['class'], 'forwarding')
        self.assertEqual(packet['driver_failure']['value']['stage'], 'prepare_served')
        self.assertEqual(packet['driver']['stage'], 'preparation_report')
        self.assertEqual(packet['outcomes']['served_build'], diagnostics.actual_exit(0))
        self.assertNotIn('SENTINEL', json.dumps(packet))

    def test_workflow_failed_cancelled_skipped_and_success(self):
        workflow = (ROOT / '.github/workflows/ci.yml').read_text()
        self.assertIn("always() && (steps.tracer.outcome == 'failure' || steps.tracer.outcome == 'cancelled')", workflow)
        self.assertIn('path: target/tracer-diagnostics/packet.json', workflow)
        self.assertIn('tracer-failure-${{ github.run_id }}-${{ github.run_attempt }}', workflow)
        self.assertIn('retention-days: 7', workflow)
        self.assertNotIn('continue-on-error', workflow)
        conditions = re.findall(r"if: \$\{\{ (always\(\).*steps.tracer.outcome.*) \}\}", workflow)
        self.assertEqual(len(conditions), 2)
        for outcome in ('failure', 'cancelled', 'success', 'skipped', ''):
            for ready in ('true', ''):
                expression = conditions[1].replace('always()', 'True').replace('steps.tracer.outcome', repr(outcome)).replace('steps.tracer-diagnostics.outputs.ready', repr(ready)).replace('&&', 'and').replace('||', 'or')
                self.assertEqual(eval(expression, {'__builtins__': {}}), outcome in {'failure', 'cancelled'} and ready == 'true')


if __name__ == '__main__':
    unittest.main()
