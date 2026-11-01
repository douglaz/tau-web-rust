#!/usr/bin/env python3
"""Partial execution labels retain the supervisor and receipt boundary."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location(
    "tracer_driver", Path(__file__).with_name("tracer-driver.py")
)
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class PartialCompletion(unittest.TestCase):
    def test_labels_require_boolean_coverage_and_keep_targeted_diagnostic(self):
        self.assertEqual(driver.success_verdict("full", {"coverage": {"complete": False}}),
                         "TRACER PARTIAL PASS (coverage.complete=false)")
        self.assertEqual(driver.success_verdict("full", {"coverage": {"complete": True}}),
                         "TRACER PASS")
        self.assertEqual(driver.success_verdict("targeted", {"coverage": {"complete": False}}),
                         "TARGETED PASS")
        for value in [None, 0, 1, "false"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                driver.success_verdict("full", {"coverage": {"complete": value}})

    def test_partial_publication_requires_native_validation_and_intact_receipt(self):
        # This isolates publication, with the substantive validators tested separately.
        # The synthetic receipt supplies no browser execution or coverage credit.
        for fault in [None, "complete-label", "targeted-label", "duplicate-label",
                      "no-label", "native-failure", "validator-failure", "changed-log",
                      "changed-preflight", "changed-exit"]:
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                capture = root / "target/tracer-evidence/123-test"
                capture.mkdir(parents=True)
                report = {"provenance": {"source": "synthetic"}}
                preflight = {}
                log = "TRACER_EVIDENCE " + json.dumps(report) + "\n"
                (capture / "execution.log").write_text(log)
                (capture / "preflight.json").write_text(json.dumps(preflight))
                (capture / "identity.json").write_text(json.dumps(report["provenance"]))
                receipt = {"code": 0, "success": True,
                           "log": driver.file_hash(capture / "execution.log"),
                           "preflight": driver.file_hash(capture / "preflight.json")}
                (capture / "exit.json").write_text(json.dumps(receipt))
                if fault == "changed-log":
                    (capture / "execution.log").write_text(log + "altered\n")
                if fault == "changed-preflight":
                    (capture / "preflight.json").write_text('{"altered":true}')
                if fault == "changed-exit":
                    (capture / "exit.json").write_text(json.dumps(dict(receipt, code=1, success=False)))
                verdict = "TRACER PARTIAL PASS (coverage.complete=false)\n"
                if fault == "complete-label":
                    verdict = "TRACER PASS\n"
                if fault == "targeted-label":
                    verdict = "TARGETED PASS\n"
                if fault == "duplicate-label":
                    verdict *= 2
                if fault == "no-label":
                    verdict = ""
                output = ("evidence capture: " + str(capture) + "\n"
                          'TRACER_EXIT {"code":0,"success":true}\n'
                          'TRACER_PREFLIGHT {}\n' + log + verdict)
                child = Mock(pid=123, stdout=io.StringIO(output))
                child.wait.return_value = 1 if fault == "native-failure" else 0
                child.__enter__ = Mock(return_value=child)
                child.__exit__ = Mock(return_value=False)
                with patch.object(driver, "ROOT", root), \
                     patch.object(driver.subprocess, "run", return_value=Mock(returncode=0)), \
                     patch.object(driver.subprocess, "Popen", return_value=child), \
                     patch.object(driver.tracer_timing, "Output"), \
                     patch.object(driver, "validate", side_effect=ValueError("invalid evidence")
                                  if fault == "validator-failure" else None) as validate, \
                     contextlib.redirect_stdout(io.StringIO()), \
                     contextlib.redirect_stderr(io.StringIO()):
                    native, validation = driver.execute("full", [], None,
                                                       {"coverage": {"complete": False}}, "synthetic")
                self.assertEqual(validation, 0 if fault is None else 1)
                if fault is None:
                    self.assertEqual(native, 0)
                    validate.assert_called_once()


if __name__ == "__main__":
    unittest.main()
