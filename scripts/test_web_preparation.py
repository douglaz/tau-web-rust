#!/usr/bin/env python3
"""Build/publication regression controls; compiled controls are recorded separately."""
import errno
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import web_preparation as preparation

ROOT = Path(__file__).resolve().parent.parent


class PinWatch(unittest.TestCase):
    def test_soft_reset_rechecks_pin_in_ordinary_linked_and_packed_repositories(self):
        # Compile the real build script against disposable refs and the local
        # specification. No checkout or ref in the source repository is changed.
        with tempfile.TemporaryDirectory() as temporary:
            scratch = Path(temporary)
            environment = dict(os.environ, CARGO_TARGET_DIR=str(scratch / 'target'))

            def git(root, *arguments):
                return subprocess.check_output(
                    ['git', '-c', 'user.name=Allan Douglas', '-c',
                     'user.email=allandouglas@gmail.com', '-C', str(root), *arguments],
                    env=environment, stderr=subprocess.STDOUT, text=True).strip()

            def clone_spec(root):
                git(root, 'clone', '--shared', '--separate-git-dir',
                    str(scratch / ('spec-git-' + root.name)), str(ROOT / 'spec'), 'spec')
                git(root / 'spec', 'checkout', '--detach', pin)

            pin = git(ROOT / 'spec', 'rev-parse', 'HEAD')
            for mode in ('ordinary', 'linked', 'packed'):
                with self.subTest(mode=mode):
                    repository = scratch / mode
                    repository.mkdir()
                    git(repository, 'init', '-b', 'main')
                    (repository / 'Cargo.toml').write_text(
                        '[workspace]\n[package]\nname="pin-watch"\nversion="0.0.0"\n'
                        'edition="2024"\n[build-dependencies]\ntoml="1"\n')
                    (repository / 'src').mkdir()
                    (repository / 'src/lib.rs').write_text('')
                    for name in ('build.rs', 'session_gate.rs', 'Cargo.lock'):
                        shutil.copyfile(ROOT / name, repository / name)
                    clone_spec(repository)
                    different_pin = git(repository / 'spec', 'commit-tree', 'HEAD^{tree}',
                                        '-p', pin, '-m', 'Different specification pin')
                    git(repository, 'add', 'Cargo.toml', 'Cargo.lock', 'src',
                        'build.rs', 'session_gate.rs', 'spec')
                    git(repository, 'commit', '-m', 'Pin watch fixture')
                    original = git(repository, 'rev-parse', 'HEAD')
                    git(repository, 'update-index', '--cacheinfo', f'160000,{different_pin},spec')
                    tree = git(repository, 'write-tree')
                    changed = git(repository, 'commit-tree', tree, '-p', original,
                                  '-m', 'Different specification pin')
                    git(repository, 'reset', '--mixed', original)
                    root = repository
                    if mode == 'linked':
                        root = scratch / 'linked-checkout'
                        git(repository, 'worktree', 'add', '-b', 'linked', str(root), original)
                        (root / 'spec').rmdir()
                        clone_spec(root)
                    if mode == 'packed':
                        git(repository, 'pack-refs', '--all', '--prune')

                    def build(expected):
                        result = subprocess.run(['cargo', 'build', '--offline'], cwd=root,
                                                env=environment, capture_output=True, text=True)
                        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                        return result.stdout + result.stderr

                    build(0)
                    git(root, 'reset', '--soft', changed)
                    self.assertIn('spec/ is checked out at', build(101))
                    git(root, 'reset', '--soft', original)
                    build(0)
                    generated = list((scratch / 'target').glob('debug/build/pin-watch-*/out/pinned.rs'))
                    self.assertTrue(generated)
                    timestamps = {path: path.stat().st_mtime_ns for path in generated}
                    build(0)
                    self.assertEqual({path: path.stat().st_mtime_ns for path in generated}, timestamps,
                                     'unchanged repository must retain the warm build')


class Preparation(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        for name in ('scripts', 'www', 'bin'):
            (self.root / name).mkdir()
        for name in ('web_preparation.py', 'build-web.sh'):
            shutil.copyfile(ROOT / 'scripts' / name, self.root / 'scripts' / name)
        (self.root / 'Cargo.lock').write_text('name = "wasm-bindgen"\nversion = "0.2.127"\n')
        for name in ('index.html', 'boot.js', 'worker.js'):
            (self.root / 'www' / name).write_text(name)
        self.program('cargo', '''
import os, pathlib, sys
if os.environ.get('FAIL_CARGO'): raise SystemExit(23)
args=sys.argv[1:]
assert args[:7] == ['build','--locked','--release','-p','tau-web','--target','wasm32-unknown-unknown']
variant='tracer' if '--features' in args else 'served'
target=pathlib.Path(args[args.index('--target-dir')+1])
assert target.name==variant
path=target/'wasm32-unknown-unknown/release/tau_web.wasm'
path.parent.mkdir(parents=True,exist_ok=True)
path.write_text(variant)
''')
        self.program('wasm-bindgen', '''
import os, pathlib, sys, time
if sys.argv[1:]==['--version']:
    print('wasm-bindgen '+os.environ.get('CLI_VERSION','0.2.127')); raise SystemExit(0)
out=pathlib.Path(sys.argv[sys.argv.index('--out-dir')+1]); out.mkdir()
variant=pathlib.Path(sys.argv[-1]).read_text()
(out/'tau_web_bg.wasm').write_text(variant)
if os.environ.get('PAUSE'):
    marker=pathlib.Path(os.environ['PAUSE']); marker.write_text(str(os.getpid()))
    while not marker.with_suffix('.release').exists(): time.sleep(.01)
if os.environ.get('FAIL_BINDGEN'): raise SystemExit(29)
(out/'tau_web.js').write_text(variant)
''')
        self.env = dict(os.environ, PATH=str(self.root / 'bin') + os.pathsep + os.environ['PATH'])
        self.env.pop('CARGO_TARGET_DIR', None)
        self.env.pop(preparation.LOCK_FD, None)
        self.children = []

    def tearDown(self):
        for child in self.children:
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=10)
        self.temporary.cleanup()

    def program(self, name, text):
        path = self.root / 'bin' / name
        path.write_text('#!' + sys.executable + '\n' + text)
        path.chmod(0o755)

    def start(self, variant='served', **changes):
        child = subprocess.Popen(['/bin/bash', 'scripts/build-web.sh', variant], cwd=self.root,
                                 env=self.env | changes, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.children.append(child)
        return child

    def finish(self, child, expected=0):
        out, err = child.communicate(timeout=15)
        self.assertEqual(child.returncode, expected, err.decode())
        records = [json.loads(line.removeprefix('TRACER_BUILD_TIMING '))
                   for line in out.decode().splitlines() if line.startswith('TRACER_BUILD_TIMING ')]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]['exit'], expected)
        self.assertLessEqual(records[0]['start_ns'], records[0]['end_ns'])

    def wait_marker(self, marker):
        deadline = time.monotonic() + 10
        while not marker.exists():
            if time.monotonic() > deadline: self.fail('preparation did not reach bindgen')
            time.sleep(.01)

    def bundle(self, variant):
        root = self.root / 'dist' / variant
        self.assertFalse(root.is_symlink())
        self.assertEqual(root.stat().st_mode & 0o777, root.parent.stat().st_mode & 0o777)
        self.assertEqual((root / 'pkg/tau_web_bg.wasm').read_text(), variant)
        self.assertEqual((root / 'pkg/tau_web.js').read_text(), variant)
        for name in ('index.html', 'boot.js', 'worker.js'):
            self.assertEqual((root / name).read_text(), name)

    def test_default_relative_and_absolute_roots_consume_requested_variant(self):
        for target in (None, 'custom relative', str(self.root / 'absolute target')):
            with self.subTest(target=target):
                changes = {} if target is None else {'CARGO_TARGET_DIR': target}
                for variant in ('served', 'tracer', 'served', 'tracer'):
                    self.finish(self.start(variant, **changes))
                    self.bundle(variant)
                outer = self.root / (target or 'target')
                self.assertTrue((outer / 'web/served/wasm32-unknown-unknown/release/tau_web.wasm').is_file())
                self.assertFalse((outer / 'debug').exists())

    def test_failure_status_and_previous_complete_output(self):
        self.finish(self.start())
        for settings, code in (({'FAIL_CARGO': '1'}, 23), ({'FAIL_BINDGEN': '1'}, 29),
                               ({'CLI_VERSION': '0.0.0'}, 1)):
            self.finish(self.start(**settings), code)
            self.bundle('served')
        self.finish(self.start('tracer', FAIL_BINDGEN='1'), 29)
        self.assertFalse((self.root / 'dist/tracer').exists())
        self.finish(self.start('tracer'))
        self.bundle('tracer')

    def test_same_and_cross_variant_overlap_waits_before_consumption(self):
        for variant in ('served', 'tracer'):
            with self.subTest(variant=variant):
                self.finish(self.start())
                marker = self.root / ('pause-' + variant)
                first = self.start(PAUSE=str(marker))
                self.wait_marker(marker)
                second = self.start(variant)
                time.sleep(.15)
                self.assertIsNone(second.poll())
                self.bundle('served')
                marker.with_suffix('.release').touch()
                self.finish(first)
                self.finish(second)
                self.bundle(variant)

    def test_interruption_does_not_publish_partial_and_recovers(self):
        self.finish(self.start())
        for signum, expected in ((signal.SIGTERM, 143), (signal.SIGKILL, -9)):
            marker = self.root / ('interrupt-' + str(signum))
            child = self.start(PAUSE=str(marker))
            self.wait_marker(marker)
            child.send_signal(signum)
            if signum == signal.SIGKILL:
                # The binding child survives a killed parent and must retain
                # both locks until it has finished consuming the wasm.
                successor = self.start('tracer')
                time.sleep(.15)
                self.assertIsNone(successor.poll())
                self.bundle('served')
                marker.with_suffix('.release').touch()
                child.communicate(timeout=15)
                self.assertEqual(child.returncode, expected)
                self.finish(successor)
            else:
                self.finish(child, expected)
            self.bundle('served')
            self.finish(self.start())
            self.bundle('served')

    def test_shared_target_consumption_lock_across_different_destinations(self):
        marker = self.root / 'shared-pause'
        first = self.start(PAUSE=str(marker), CARGO_TARGET_DIR=str(self.root / 'shared'))
        self.wait_marker(marker)
        other = self.root / 'other'
        other.mkdir()
        for name in ('scripts', 'www'):
            shutil.copytree(self.root / name, other / name)
        shutil.copyfile(self.root / 'Cargo.lock', other / 'Cargo.lock')
        child = subprocess.Popen(['/bin/bash', 'scripts/build-web.sh', 'served'], cwd=other,
                                 env=self.env | {'CARGO_TARGET_DIR': str(self.root / 'shared')},
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.children.append(child)
        time.sleep(.15)
        self.assertIsNone(child.poll())
        self.assertFalse((other / 'dist/served').exists())
        marker.with_suffix('.release').touch()
        self.finish(first)
        self.finish(child)

    def test_driver_descriptor_holds_publication_until_consumer_finishes(self):
        with preparation.preparation_lock(self.root) as lock:
            child = subprocess.Popen(['/bin/bash', 'scripts/build-web.sh', 'served'], cwd=self.root,
                                     env=self.env | {preparation.LOCK_FD: str(lock)}, pass_fds=(lock,),
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.children.append(child)
            self.finish(child)
            competitor = self.start('tracer')
            time.sleep(.15)
            self.assertIsNone(competitor.poll())
            self.bundle('served')
        self.finish(competitor)
        self.bundle('tracer')

    def test_copy_and_publication_failure_preserve_destination(self):
        self.finish(self.start())
        with patch.dict(os.environ, self.env, clear=True), preparation.preparation_lock(self.root) as lock:
            with patch.object(preparation.shutil, 'copyfile', side_effect=OSError('copy failed')):
                with self.assertRaisesRegex(OSError, 'copy failed'):
                    preparation.build(self.root, 'served', lock)
            self.bundle('served')
            with patch.object(preparation.ctypes, 'CDLL') as library:
                library.return_value.renameat2.return_value = -1
                with patch.object(preparation.ctypes, 'get_errno', return_value=errno.EIO):
                    with self.assertRaises(OSError): preparation.build(self.root, 'served', lock)
            self.bundle('served')
        self.finish(self.start())

    def test_foreign_inherited_descriptor_refused(self):
        with (self.root / 'foreign').open('w') as foreign:
            child = subprocess.Popen(['/bin/bash', 'scripts/build-web.sh', 'served'], cwd=self.root,
                                     env=self.env | {preparation.LOCK_FD: str(foreign.fileno())},
                                     pass_fds=(foreign.fileno(),), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.children.append(child)
            self.finish(child, 1)
        self.assertFalse((self.root / 'dist/served').exists())

    def test_driver_preparation_clock_includes_wait_for_artifacts(self):
        marker = self.root / 'driver-clock'
        program = r'''
import importlib.util, json, sys
from pathlib import Path
from unittest.mock import Mock
sys.dont_write_bytecode = True
sys.path.insert(0, sys.argv[1])
spec = importlib.util.spec_from_file_location('driver', Path(sys.argv[1])/'tracer-driver.py')
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
driver.ROOT = Path(sys.argv[2])
driver.admit = lambda *_: {}
clock = driver.time.monotonic_ns
def started():
    value = clock()
    (driver.ROOT/'driver-clock').write_text(str(value))
    return value
driver.time.monotonic_ns = started
def prepared(diagnostic, arguments, mode, selected, lock, start):
    print(json.dumps({'elapsed_ns': clock()-start}), flush=True)
    return 0
driver.run_prepared = prepared
driver.sys.argv = ['tracer.sh', 'full']
raise SystemExit(driver.run(Mock()))
'''
        with preparation.preparation_lock(self.root):
            child = subprocess.Popen([sys.executable, '-B', '-c', program,
                                      str(ROOT / 'scripts'), str(self.root)],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.children.append(child)
            self.wait_marker(marker)
            time.sleep(.2)
            self.assertIsNone(child.poll())
        out, err = child.communicate(timeout=15)
        self.assertEqual(child.returncode, 0, err.decode())
        self.assertGreaterEqual(json.loads(out)['elapsed_ns'], 100_000_000)


if __name__ == '__main__':
    unittest.main()
