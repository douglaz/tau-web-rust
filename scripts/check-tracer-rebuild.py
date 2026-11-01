#!/usr/bin/env python3
"""Exercise normal Cargo source-identity rebuilding on source-set changes."""
import os
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parent.parent


def check(stale=False):
    environment = {key: value for key, value in os.environ.items()
                   if key != "CHROME" and not key.startswith("TAU_TRACER_")}
    target = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
    if not target.is_absolute():
        target = ROOT / target
    command = [str(target / "debug/tracer")] if stale else ["cargo", "run", "--locked", "-p", "tracer", "--"]
    result = subprocess.run(
        command + ["targeted",
         "dist/served", "dist/tracer", "TAU_TRACER_MODE_CASE=all"],
        cwd=ROOT, env=environment, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, check=False,
    )
    print(result.stdout, end="")
    expected = "source differs from the compiled tracer" if stale else "FAIL: CHROME is not set"
    if result.returncode != 1 or expected not in result.stdout:
        raise RuntimeError("normal rebuild did not reach the current-input precondition")
    if not stale and "source differs from the compiled tracer" in result.stdout:
        raise RuntimeError("normal rebuild retained a stale source identity")


def main():
    check()
    for directory in [ROOT, ROOT / "docs", ROOT / ".github"]:
        descriptor, name = tempfile.mkstemp(prefix="tracer-rebuild-", suffix=".txt", dir=directory)
        path = Path(name)
        try:
            with os.fdopen(descriptor, "w") as stream:
                stream.write("source-set rebuild regression\n")
            check(stale=True)
            check()
            path.write_text("changed source bytes\n")
            check(stale=True)
            check()
        finally:
            # mkstemp created this exact path; no pre-existing file is removed.
            path.unlink()
        check(stale=True)
        check()
    # A tracked deletion has a distinct source marker until its exact bytes return.
    path = ROOT / "docs/spec-66762f1-uptake.md"
    descriptor, name = tempfile.mkstemp(prefix="tracer-rebuild-saved-", dir=ROOT / "target")
    os.close(descriptor)
    backup = Path(name)
    moved = False
    try:
        path.rename(backup)
        moved = True
        check(stale=True)
        check()
    finally:
        if moved:
            if path.exists():
                raise RuntimeError(f"preserving unexpected replacement and original at {backup}")
            backup.rename(path)
        else:
            backup.unlink()
    check(stale=True)
    check()
    print("source-set rebuild checks passed")


if __name__ == "__main__":
    main()
