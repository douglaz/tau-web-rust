#!/usr/bin/env python3
"""Artifact identity refuses entries that cannot be hashed as regular files."""
import hashlib
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location(
    "tracer_driver", Path(__file__).with_name("tracer-driver.py")
)
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class ArtifactIdentity(unittest.TestCase):
    def test_nested_regular_files_include_names_modes_and_bytes(self):
        with tempfile.TemporaryDirectory(dir="/var/tmp") as temporary:
            root = Path(temporary)
            (root / "pkg").mkdir()
            (root / "empty").mkdir()
            files = [("index.html", b"page", 0o644), ("pkg/app.wasm", b"wasm", 0o600)]
            expected = hashlib.sha256(b"tau-tracer-tree-v2\0")
            for name, data, mode in files:
                path = root / name
                path.write_bytes(data)
                path.chmod(mode)
                expected.update(os.fsencode(name) + b"\0file\0")
                expected.update(len(data).to_bytes(8, "little"))
                expected.update(mode.to_bytes(4, "little"))
                expected.update(data)
            self.assertEqual(driver.artifact_hash(root), expected.hexdigest())
            (root / "pkg/app.wasm").chmod(0o644)
            self.assertNotEqual(driver.artifact_hash(root), expected.hexdigest())

    def test_nonregular_entries_are_refused(self):
        for kind in ["directory-link", "file-link", "dangling-link", "fifo"]:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(dir="/var/tmp") as temporary:
                root = Path(temporary)
                (root / "pkg").mkdir()
                (root / "pkg/app.wasm").write_bytes(b"wasm")
                entry = root / "pkg/unsupported"
                if kind == "fifo":
                    os.mkfifo(entry)
                else:
                    target = {"directory-link": root, "file-link": root / "pkg/app.wasm",
                              "dangling-link": root / "absent"}[kind]
                    entry.symlink_to(target)
                with self.assertRaisesRegex(ValueError, "nonregular artifact identity input"):
                    driver.artifact_hash(root)

    def test_root_symlink_is_refused(self):
        with tempfile.TemporaryDirectory(dir="/var/tmp") as temporary:
            root = Path(temporary)
            (root / "real").mkdir()
            (root / "real/app.wasm").write_bytes(b"wasm")
            (root / "link").symlink_to(root / "real", target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "nonregular artifact identity input"):
                driver.artifact_hash(root / "link")

    def test_empty_artifact_is_refused(self):
        with tempfile.TemporaryDirectory(dir="/var/tmp") as temporary:
            with self.assertRaisesRegex(ValueError, "empty artifact directory"):
                driver.artifact_hash(Path(temporary))


if __name__ == "__main__":
    unittest.main()
