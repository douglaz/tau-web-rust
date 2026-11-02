#!/usr/bin/env python3
"""Prepare the two web variants without replacing a reader's inputs."""
import contextlib
import ctypes
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time


LOCK_FD = "TAU_WEB_PREPARATION_FD"


@contextlib.contextmanager
def preparation_lock(root, inherited=False):
    """The driver retains this lock through validation and all artifact reads.

    A build child duplicates the same open description. Never LOCK_UN here:
    closing the last descriptor releases ownership, including after a kill.
    """
    path = root / "dist/.web-preparation.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    if inherited and LOCK_FD in os.environ:
        fd = os.dup(int(os.environ[LOCK_FD]))
        if (os.fstat(fd).st_dev, os.fstat(fd).st_ino) != (path.stat().st_dev, path.stat().st_ino):
            os.close(fd)
            raise ValueError("web preparation lock descriptor differs from destination")
    else:
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o666)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield fd
    finally:
        os.close(fd)


def publish(stage, destination):
    """One rename publishes the entire ordinary directory, even on replacement.

    Linux renameat2 exchange leaves the previous complete output at stage. A
    failure before the exchange preserves it at destination. A killed process
    can leave a hidden staging directory, never a partial active bundle.
    """
    if not destination.exists():
        os.rename(stage, destination)
        return
    if destination.is_symlink() or not destination.is_dir():
        raise ValueError("web destination must be an ordinary directory")
    libc = ctypes.CDLL(None, use_errno=True)
    exchange = libc.renameat2
    exchange.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    exchange.restype = ctypes.c_int
    if exchange(-100, os.fsencode(stage), -100, os.fsencode(destination), 2):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), str(destination))


def command(arguments, descriptors=()):
    # Reap an interrupted child before releasing its consumption lock.
    with subprocess.Popen(arguments, pass_fds=descriptors) as child:
        try:
            code = child.wait()
        except BaseException:
            with contextlib.suppress(ProcessLookupError):
                child.terminate()
            child.wait()
            raise
    if code:
        raise subprocess.CalledProcessError(code, arguments)


def build(root, variant, lock):
    locked = re.search(r'^name = "wasm-bindgen"\nversion = "([^"]+)"',
                       (root / "Cargo.lock").read_text(), re.MULTILINE).group(1)
    cli = subprocess.check_output(["wasm-bindgen", "--version"], text=True).split()[1]
    if cli != locked:
        raise ValueError(f"wasm-bindgen CLI is {cli}, Cargo.lock pins the crate at {locked}")
    target = Path(os.environ.get("CARGO_TARGET_DIR") or "target")
    if not target.is_absolute():
        target = root / target
    target = target / "web" / variant
    target.mkdir(parents=True, exist_ok=True)
    # Cargo's own lock ends when cargo exits. Extend protection through bindgen
    # for worktrees sharing an explicit Cargo target root.
    with (target / ".web-consumption.lock").open("a") as consumption:
        fcntl.flock(consumption, fcntl.LOCK_EX)
        features = ["--features", "tracer"] if variant == "tracer" else []
        command(["cargo", "build", "--locked", "--release", "-p", "tau-web",
                 "--target", "wasm32-unknown-unknown", "--target-dir", str(target), *features],
                (lock, consumption.fileno()))
        with tempfile.TemporaryDirectory(prefix=f".{variant}-", dir=root / "dist") as temporary:
            # Keep generation private, but publish a directory with mkdir's
            # normal umask-derived permissions rather than tempfile's 0700.
            stage = Path(temporary) / "bundle"
            stage.mkdir()
            command(["wasm-bindgen", "--target", "web", "--no-typescript", "--out-dir",
                     str(stage / "pkg"), str(target / "wasm32-unknown-unknown/release/tau_web.wasm")],
                    (lock, consumption.fileno()))
            for name in ("index.html", "boot.js", "worker.js"):
                shutil.copyfile(root / "www" / name, stage / name)
            publish(stage, root / "dist" / variant)
    print(f"built dist/{variant}")


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("served", "tracer"):
        print("usage: scripts/build-web.sh served|tracer", file=sys.stderr)
        return 2
    variant = sys.argv[1]
    started = time.monotonic_ns()
    code = 1
    def interrupted(signum, _frame):
        raise SystemExit(128 + signum)
    previous = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        root = Path(__file__).resolve().parent.parent
        with preparation_lock(root, inherited=True) as lock:
            build(root, variant, lock)
        code = 0
    except subprocess.CalledProcessError as error:
        code = error.returncode if error.returncode >= 0 else 128 - error.returncode
    except (OSError, ValueError, AttributeError) as error:
        print(f"web preparation failed: {error}", file=sys.stderr)
    except SystemExit as error:
        code = error.code
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        print("TRACER_BUILD_TIMING " + json.dumps({
            "schema": 1, "phase": "prepare_" + variant,
            "start_ns": started, "end_ns": time.monotonic_ns(), "exit": code,
        }), flush=True)
    return code


if __name__ == "__main__":
    sys.exit(main())
