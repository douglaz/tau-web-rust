#!/usr/bin/env python3
"""Admit before preparation; record monotonic preparation and actual child exits."""
import json
import math
import hashlib
import os
from pathlib import Path
import subprocess
import shutil
import stat
import sys
import time
import importlib.util
import signal
import contextlib
import tracer_diagnostics

ROOT = Path(__file__).resolve().parent.parent
sys.dont_write_bytecode = True
import tracer_timing
import tracer_requirements
import web_preparation
_history_spec = importlib.util.spec_from_file_location("tracer_history", ROOT / "scripts/tracer_history.py")
_history = importlib.util.module_from_spec(_history_spec)
_history_spec.loader.exec_module(_history)


def evidence(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate evidence JSON field")
            result[key] = value
        return result
    def constant(_):
        raise ValueError("nonfinite evidence JSON number")
    def finite(raw_number):
        value = float(raw_number)
        if not math.isfinite(value):
            raise ValueError("nonfinite evidence JSON number")
        return value
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant, parse_float=finite)


def read_inventory():
    return tracer_requirements.read(ROOT / "tracer/inventory.json")


def file_hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree_hash(root, paths, source=False):
    digest = hashlib.sha256(b"tau-tracer-tree-v2\0")
    for path in sorted(set(paths)):
        digest.update(os.fsencode(path.relative_to(root)))
        digest.update(b"\0")
        if source and not path.is_symlink() and not path.exists():
            digest.update(b"absent\0")
            continue
        if path.is_symlink() or not path.is_file():
            raise ValueError("nonregular identity input")
        data = path.read_bytes()
        digest.update(b"file\0")
        digest.update(len(data).to_bytes(8, "little"))
        digest.update((path.stat().st_mode & 0o777).to_bytes(4, "little"))
        digest.update(data)
    return digest.hexdigest()


def artifact_hash(root):
    if not stat.S_ISDIR(root.lstat().st_mode):
        raise ValueError("nonregular artifact identity input")
    paths = []

    def walk(directory):
        for path in directory.iterdir():
            kind = path.lstat().st_mode
            if stat.S_ISDIR(kind):
                walk(path)
            elif stat.S_ISREG(kind):
                paths.append(path)
            else:
                raise ValueError("nonregular artifact identity input")

    walk(root)
    if not paths:
        raise ValueError("empty artifact directory")
    return tree_hash(root, paths)


def source_paths(root):
    paths = []
    environment = {k: v for k, v in os.environ.items() if not k.startswith("GIT")}
    for arguments in [["--cached", "--recurse-submodules"], ["--others", "--exclude-standard"]]:
        names = subprocess.check_output(["git", "--no-replace-objects", "-c", "core.fsmonitor=false", "ls-files", "-z", *arguments], cwd=root, env=environment).split(b"\0")
        for raw in filter(None, names):
            name = os.fsdecode(raw)
            if name.startswith(".beads/"):
                continue
            path = root / name
            if name == "spec" and path.is_dir():
                paths.extend(source_paths(path))
            else:
                paths.append(path)
    return paths


def validation_contracts(root, paths):
    result = {}
    for name, component in (('native_producer_and_validator','tracer'), ('shell_driver_and_validator','scripts')):
        members = [p for p in paths if p.relative_to(root).parts[0] == component]
        if not members:
            raise ValueError('empty validation contract source set')
        result[name] = tree_hash(root, members, source=True)
    return result


def execution_plan(selected, inventory):
    return tracer_requirements.execution_plan(selected, inventory)


def success_verdict(mode, inventory):
    if mode == "targeted":
        return "TARGETED PASS"
    complete = inventory.get("coverage", {}).get("complete")
    if type(complete) is not bool:
        raise ValueError("missing or invalid inventory coverage status")
    return "TRACER PASS" if complete else "TRACER PARTIAL PASS (coverage.complete=false)"


def validate(report, mode, plan, inventory, source, exit_code, census, helpers, preflight):
    """Independent shell-boundary check; no verdict line supplies execution credit."""
    if type(report.get("schema")) is not int or exit_code != 0 or report.get("schema") != 1 or report.get("mode") != mode or report.get("execution_ok") is not True:
        raise ValueError("missing, incomplete or wrong-mode execution evidence")
    if report.get("inventory") != file_hash(ROOT / "tracer/inventory.json"):
        raise ValueError("stale inventory")
    if report.get("domains") != census:
        raise ValueError("fixture census differs from observed mint history")
    paths = source_paths(ROOT)
    current_source = tree_hash(ROOT, paths, source=True)
    if current_source != source or report["provenance"]["source"] != source:
        raise ValueError("source provenance mismatch")
    if report["provenance"].get("validation_contracts") != validation_contracts(ROOT, paths):
        raise ValueError("validation contract provenance mismatch")
    binary = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")) / "debug/tracer"
    if not binary.is_absolute():
        binary = ROOT / binary
    if report["provenance"]["binary"] != file_hash(binary):
        raise ValueError("binary provenance mismatch")
    chrome = Path(shutil.which(os.environ["CHROME"]) or os.environ["CHROME"]).resolve()
    chrome_version = subprocess.check_output([str(chrome), "--version"])
    preconditions = report["provenance"]["preconditions"]
    expected_preconditions = {"chrome": file_hash(chrome), "chrome_version": hashlib.sha256(chrome_version).hexdigest(), "fresh_profile": True, "serial": True, "local_fixtures": True, "declaration_witnesses": "TAU_DECLARATION_WITNESSES" not in os.environ}
    if type(preconditions) is not dict or any(type(preconditions.get(flag)) is not bool for flag in ("fresh_profile", "serial", "local_fixtures", "declaration_witnesses")):
        raise ValueError("invalid precondition provenance schema")
    if preconditions != expected_preconditions or mode == "full" and not expected_preconditions["declaration_witnesses"]:
        raise ValueError("precondition provenance mismatch")
    git_environment = {k: v for k, v in os.environ.items() if not k.startswith("GIT")}
    spec = subprocess.check_output(["git", "--no-replace-objects", "-c", "core.fsmonitor=false", "ls-tree", "HEAD", "spec"], cwd=ROOT, env=git_environment).decode().split()[2]
    if report["provenance"].get("spec") != spec:
        raise ValueError("specification provenance mismatch")
    for variant in ["served", "tracer"]:
        root = ROOT / "dist" / variant
        if report["provenance"][variant] != artifact_hash(root):
            raise ValueError("artifact provenance mismatch")

    if mode == "full":
        if report.get("plan") is not None or report.get("selected") != [] or report.get("support") != [] or report["mandatory"].get("same_browser_policy_command") is not True:
            raise ValueError("targeted evidence cannot qualify as full")
        expected = [c["id"] for c in inventory["cases"]]
    else:
        independently_required = execution_plan(admit("targeted", [], report["plan"]["selection"]), inventory)
        if plan != independently_required:
            raise ValueError("scheduler plan differs from independent projection")
        if report.get("plan") != plan or report.get("selected") != plan["selected"] or report.get("support") != plan["support"]:
            raise ValueError("targeted execution differs from admitted plan")
        expected = plan["expected_execution"]
    catalogue = [{field: case[field] for field in ("id", "site_id", "label", "scenario_id")} for case in inventory["cases"]]
    if report.get("catalogue") != catalogue:
        raise ValueError("executable catalogue differs from independent case key")
    cases = report["cases"]
    if [c["id"] for c in cases] != expected or len(set(expected)) != len(expected):
        raise ValueError("missing/extra/duplicate primary or serial order/history mismatch")
    specs = {c["id"]: c for c in inventory["cases"]}
    for case in cases:
        spec = specs[case["id"]]
        sites = list(spec["assertions"])
        if case["id"].startswith("seed_cases.c001.") and plan and plan["name"].startswith("seed.") and plan["name"] != "seed.all":
            sites = [site for site in sites if site != "seed_cases.a005"]
        if "variants" in spec:
            variants = spec["variants"]
            sites = list(variants["sequences"][case["branches"][variants["branch"]]])
        if "optional" in spec:
            optional = spec["optional"]
            observed = case["branches"][optional["branch"]]
            if observed == "locked":
                sites.insert(sites.index(optional["after"]) + 1, optional["site"])
            elif observed != "unopened":
                raise ValueError("invalid second-worker observation")
        if "dynamic" in spec:
            dynamic = spec["dynamic"]
            domain = report["domains"][dynamic["domain"]]
            if not 2 <= domain["count"] <= domain["bound"]:
                raise ValueError("invalid fixture census")
            at = sites.index(dynamic["site"])
            sites = [s for s in sites if s != dynamic["site"]]
            sites[at:at] = [dynamic["site"]] * domain["count"]
        counts = {}
        checks = []
        for site in sites:
            counts[site] = counts.get(site, 0) + 1
            checks.append(f"{site}.i{counts[site]:03}")
        if case.get("ok") is not True or case.get("site_id") != spec["site_id"] or [a["id"] for a in case["assertions"]] != checks or any(a.get("ok") is not True for a in case["assertions"]):
            raise ValueError("missing/extra/duplicate or failed assertion completion")
    if report["mandatory"].get("cleanup") is not True:
        raise ValueError("cleanup incomplete")
    prerequisites = report.get("prerequisites", [])
    if helpers is None or report.get("prerequisite_requests") != helpers or set(helpers) - set(inventory["dynamic_prerequisites"]):
        raise ValueError("prerequisite request observation mismatch")
    counts = tracer_requirements.prerequisite_counts(inventory if mode == "full" else plan)
    for identity, count in helpers.items():
        if identity in counts and counts[identity] != count:
            raise ValueError("helper request differs from source-derived cardinality")
    counts.update(helpers)
    worker = helpers.get("runtime.worker.ready", 0)
    ready = helpers.get("runtime.store.ready_nontransient", 0)
    polls = helpers.get("runtime.store.not_failed", 0)
    has_main = mode == "full" or "main.c001.p001" in plan["expected_execution"]
    if worker < (2 if mode == "full" else 1) or ready < worker or not ready <= polls <= 300 * ready or has_main and (helpers.get("binding.fixture_class.ready", 0) < 2 or helpers.get("binding.page.bound", 0) < 2):
        raise ValueError("invalid helper applicability/poll bounds")
    observed = {}
    for check in prerequisites:
        identity = check["id"]
        observed[identity] = observed.get(identity, 0) + 1
        if check.get("ok") is not True or check.get("instance") != f"{identity}.i{observed[identity]:03}":
            raise ValueError("failed/duplicate prerequisite instance")
    if any(observed.get(key, 0) != count for key, count in counts.items()) or set(observed) - set(counts):
        raise ValueError("missing/extra/duplicate prerequisite completion")
    _history.validate_history(report, inventory)
    _history.validate_settle_inputs(report, inventory)
    _history.validate_file_inputs(report, inventory)
    import tracer_file_uses
    tracer_file_uses.validate(report, inventory)
    import tracer_file_windows
    tracer_file_windows.validate(report, inventory)
    import tracer_operation_windows
    tracer_operation_windows.validate(report, inventory)
    import tracer_state_inputs
    tracer_state_inputs.validate(report, inventory)
    _history.validate_reader_roots(report, inventory)
    _history.validate_auxiliary(report, inventory)
    _history.validate_observers(report, inventory)
    _history.validate_page_queries(report, inventory)
    import tracer_view_domains
    tracer_view_domains.validate(report, inventory)
    _history.validate_preflight(preflight, mode == "full", inventory)
    if type(report.get("duration_ns")) is not int or report["duration_ns"] < 0:
        raise ValueError("invalid duration schema")
    phases = report["timings"]
    if [p["phase"] for p in phases] != ["fixtures", "browser", "groups", "cleanup"] or any(set(p) != {"phase", "start_ns", "end_ns"} for p in phases):
        raise ValueError("invalid timing schema")
    previous = 0
    for phase in phases:
        if type(phase["start_ns"]) is not int or type(phase["end_ns"]) is not int or not previous <= phase["start_ns"] <= phase["end_ns"] <= report["duration_ns"]:
            raise ValueError("invalid monotonic timing bounds")
        previous = phase["end_ns"]
    previous = phases[2]["start_ns"]
    groups = []
    for case in cases:
        if type(case["start_ns"]) is not int or type(case["end_ns"]) is not int or not previous <= case["start_ns"] <= case["end_ns"] <= phases[2]["end_ns"]:
            raise ValueError("invalid monotonic case bounds")
        previous = case["end_ns"]
        scenario = specs[case["id"]]["scenario_id"]
        if groups and groups[-1]["id"] == scenario:
            groups[-1]["end_ns"] = case["end_ns"]
        else:
            groups.append({"id": scenario, "start_ns": case["start_ns"], "end_ns": case["end_ns"]})
    if not _history._same_json(report.get("group_spans"), groups):
        raise ValueError("group timing identity/order/case bounds mismatch")
    scope_counts = {}
    previous_end = 0
    for scope in report["scenario_spans"]:
        if type(scope) is not dict or set(scope) != {"id", "invocation", "start_ns", "end_ns"} or type(scope["id"]) is not str or type(scope["start_ns"]) is not int or type(scope["end_ns"]) is not int or not phases[2]["start_ns"] <= scope["start_ns"] <= scope["end_ns"] <= phases[2]["end_ns"] or scope["end_ns"] < previous_end:
            raise ValueError("invalid scenario scope timing bounds/order")
        scope_counts[scope["id"]] = scope_counts.get(scope["id"], 0) + 1
        if type(scope["invocation"]) is not int or scope["invocation"] != scope_counts[scope["id"]]:
            raise ValueError("scenario invocation identity mismatch")
        previous_end = scope["end_ns"]
    scope_requirements = inventory["scenario_scopes"] if mode == "full" else plan["scenario_scopes"]
    scope_order = [name for name in inventory["scope_order"] for _ in range(scope_requirements.get(name, 0))]
    if [scope["id"] for scope in report["scenario_spans"]] != scope_order:
        raise ValueError("scenario invocation order/multiplicity mismatch")
    if scope_counts != (inventory["scenario_scopes"] if mode == "full" else plan["scenario_scopes"]):
        raise ValueError("missing/extra/duplicate scenario timing")
    for case in cases:
        owner = case["site_id"].split(".")[0] + "."
        if not any(s["invocation"] == specs[case["id"]]["invocation"] and s["id"].startswith(owner) and s["start_ns"] <= case["start_ns"] <= case["end_ns"] <= s["end_ns"] for s in report["scenario_spans"]):
            raise ValueError("case outside scenario scope")

_ACTIVE_CHILD = None


@contextlib.contextmanager
def observed_child(command, diagnostic, outcome, **kwargs):
    global _ACTIVE_CHILD
    child = None
    try:
        try:
            # Isolate every invocation child so cancellation also reaches its
            # execution descendants before terminal diagnostics are published.
            process = subprocess.Popen(command, start_new_session=True, **kwargs)
        except OSError:
            if diagnostic:
                diagnostic.fail("spawn")
            raise
        with process as child:
            _ACTIVE_CHILD = child
            if diagnostic and outcome == 'native':
                diagnostic.native_pid = child.pid
                diagnostic.publish()
            yield child
    finally:
        try:
            # Popen's KeyboardInterrupt path waits only briefly. Reap the child
            # before publishing its outcome, including a slow cancellation.
            if child is not None and child.returncode is None:
                child.wait()
        finally:
            _ACTIVE_CHILD = None
            if child is not None and diagnostic:
                diagnostic.outcome(outcome, child.returncode)
                if outcome == 'native':
                    diagnostic.collect()


def native_build(diagnostic):
    with observed_child(["cargo", "build", "--locked", "-p", "tracer"], diagnostic,
                        "native_build", cwd=ROOT, stdin=subprocess.DEVNULL) as child:
        return child.wait()


def forward(diagnostic, text, *, file=None, flush=False):
    try:
        print(text, file=file, flush=flush)
    except (OSError, ValueError):
        if diagnostic:
            diagnostic.fail("forwarding")
        raise


def forwarded_lines(child, diagnostic):
    try:
        yield from child.stdout
    except (OSError, ValueError):
        if diagnostic:
            diagnostic.fail("forwarding")
        raise


def execute(mode, arguments, plan, inventory, source, diagnostic=None, artifact_lock=None):
    if diagnostic:
        diagnostic.stage("native_build")
    build_exit = native_build(diagnostic)
    if diagnostic:
        if build_exit:
            diagnostic.fail("build")
        diagnostic.outcome("native_build", build_exit)
    forward(diagnostic, "TRACER_NATIVE_BUILD_EXIT " + json.dumps({"code": build_exit}))
    if build_exit:
        return build_exit, 1
    binary = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")) / "debug/tracer"
    if not binary.is_absolute():
        binary = ROOT / binary
    command = [str(binary), mode, "dist/served", "dist/tracer", *arguments]
    captures, execution_exits = [], []
    execution_exit = None
    reports = []
    preflights = []
    verdicts = []
    malformed = False
    requests = 0
    mints = 0
    census = {}
    helpers = None
    timing_output = tracer_timing.Output()
    timing_error = None
    environment = dict(os.environ)
    if diagnostic:
        diagnostic.stage("native_execution")
        environment['_TAU_DIAGNOSTIC_INVOCATION'] = diagnostic.invocation
        environment['_TAU_DIAGNOSTIC_DRIVER_PID'] = str(os.getpid())
        environment.pop('_TAU_DIAGNOSTIC_CAPTURE', None)
    with observed_child(command, diagnostic, "native", cwd=ROOT, stdout=subprocess.PIPE, text=True, env=environment,
                        pass_fds=() if artifact_lock is None else (artifact_lock,)) as child:
        for line in forwarded_lines(child, diagnostic):
            try:
                timing_output.observe(line)
            except (ValueError, KeyError, TypeError):
                timing_error = "invalid printed timing schema/bounds/order"
            if line.startswith(("TRACER PASS", "TRACER PARTIAL PASS", "TARGETED PASS")):
                verdicts.append(line.strip())
                continue
            try:
                sys.stdout.write(line)
            except (OSError, ValueError):
                if diagnostic:
                    diagnostic.fail("forwarding")
                malformed = True
            if line.startswith("evidence capture: "):
                captures.append(line[len("evidence capture: "):].strip())
            if line.startswith("TRACER_EXIT "):
                try:
                    execution_exits.append(evidence(line[len("TRACER_EXIT "):]))
                except ValueError:
                    malformed = True
            if line.startswith("TRACER_HELPER_REQUESTS "):
                try:
                    if helpers is not None:
                        malformed = True
                    helpers = evidence(line[len("TRACER_HELPER_REQUESTS "):])
                except ValueError:
                    malformed = True
            if line.startswith("TRACER_FIXTURE "):
                try:
                    event = evidence(line[len("TRACER_FIXTURE "):])
                    if event["kind"] == "request":
                        requests += 1
                    elif event["kind"] == "mint" and event["ordinal"] == mints + 1 and mints < requests:
                        mints += 1
                    elif event["kind"] == "census" and event["id"] == "inference-credentials" and not census:
                        census[event["id"]] = {"count": mints + 1, "bound": requests + 1}
                    else:
                        malformed = True
                except (ValueError, KeyError, TypeError):
                    malformed = True
            if line.startswith("TRACER_PREFLIGHT "):
                try:
                    preflights.append(evidence(line[len("TRACER_PREFLIGHT "):]))
                except ValueError:
                    malformed = True
            if line.startswith("TRACER_EVIDENCE "):
                try:
                    reports.append(evidence(line[len("TRACER_EVIDENCE "):]))
                except ValueError:
                    malformed = True
        exit_code = child.wait()
    if diagnostic:
        diagnostic.outcome("native", exit_code)
        diagnostic.collect()
        diagnostic.timing(timing_output.records)
        diagnostic.stage("validation")
    try:
        if len(captures) != 1 or len(execution_exits) != 1:
            raise ValueError("missing/duplicate actual execution receipt")
        capture = Path(os.path.normpath(captures[0]))
        if capture.parent != ROOT / "target/tracer-evidence" or not capture.name.startswith(str(child.pid) + "-") or not stat.S_ISDIR(capture.lstat().st_mode):
            raise ValueError("execution receipt has a foreign supervisor")
        for name in ("exit.json", "identity.json", "execution.log", "preflight.json"):
            if not stat.S_ISREG((capture / name).lstat().st_mode):
                raise ValueError("nonregular execution receipt input")
        receipt = evidence((capture / "exit.json").read_text())
        if set(receipt) != {"code", "success", "log", "preflight"} or type(receipt['code']) is not int or type(receipt['success']) is not bool or execution_exits != [{"code": receipt['code'], "success": receipt['success']}] or receipt['success'] != (receipt['code'] == 0):
            raise ValueError("actual execution exit receipt mismatch")
        execution_exit = receipt['code']
        if receipt['log'] != file_hash(capture / 'execution.log') or receipt['preflight'] != file_hash(capture / 'preflight.json'):
            raise ValueError("execution capture digest mismatch")
        if malformed or len(reports) != 1 or len(preflights) != 1:
            raise ValueError("missing/duplicate/forged execution evidence")
        if evidence((capture / 'identity.json').read_text()) != reports[0]['provenance'] or evidence((capture / 'preflight.json').read_text()) != preflights[0]:
            raise ValueError("execution capture provenance mismatch")
        captured = [evidence(line[len('TRACER_EVIDENCE '):]) for line in (capture / 'execution.log').read_text().splitlines() if line.startswith('TRACER_EVIDENCE ')]
        if captured != reports:
            raise ValueError("forwarded execution evidence differs from actual capture")
        if timing_error is not None:
            raise ValueError(timing_error)
        validate(reports[0], mode, plan, inventory, source, execution_exit, census, helpers, preflights[0])
        timing_output.validate(reports[0])
        required = success_verdict(mode, inventory)
        if exit_code != 0 or verdicts != [required]:
            raise ValueError("native validation failed or missing/duplicate/forged verdict")
    except (ValueError, KeyError, TypeError, OSError) as error:
        if diagnostic:
            diagnostic.fail("validation")
            diagnostic.outcome("validation", 1)
        forward(diagnostic, "evidence refused: " + str(error), file=sys.stderr)
        forward(diagnostic, "TARGETED FAIL" if mode == "targeted" else "TRACER FAIL", file=sys.stderr)
        forward(diagnostic, "TRACER_SHELL_EXIT " + json.dumps({"execution": execution_exit, "native": exit_code, "validation": 1}))
        return exit_code, 1
    if diagnostic:
        diagnostic.outcome("validation", 0)
    forward(diagnostic, "TRACER_SHELL_EXIT " + json.dumps({"execution": execution_exit, "native": exit_code, "validation": 0}))
    return exit_code, 0


def admit(mode, arguments, environment):
    schema = json.loads((ROOT / "tracer/selectors.json").read_text())
    entries = [(k, v) for k, v in environment.items() if k.startswith("TAU_TRACER_")]
    if mode == "full":
        if entries:
            raise ValueError("full admission refuses inherited " + sorted(entries)[0][0])
        if arguments:
            raise ValueError("full admission refuses explicit filtering")
        return {}
    if mode != "targeted":
        raise ValueError("usage: scripts/tracer.sh [full|list|targeted NAME=VALUE ...]")
    for argument in arguments:
        if "=" not in argument:
            raise ValueError("selection must be NAME=VALUE")
        entries.append(tuple(argument.split("=", 1)))
    selected = {}
    cases = json.loads((ROOT / "tracer/inventory.json").read_text())["cases"]
    for name, value in entries:
        if name not in schema:
            raise ValueError("unknown selection: " + name)
        if not value or name in selected:
            raise ValueError("empty or conflicting selection: " + name)
        selected[name] = value
        if name == "TAU_TRACER_SESSION_END":
            labels = [c["label"] for c in cases if c["site_id"].startswith("session_end_cases.")]
            parts = value.split(",")
            if len(set(parts)) != len(parts):
                raise ValueError("duplicate selection: " + name)
            for part in parts:
                if not part or not any(label == part[1:] if part.startswith("=") else part in label for label in labels):
                    raise ValueError("unknown or empty selection: " + name)
        else:
            parts = value.split(",") if name == "TAU_TRACER_HOLD_CASE" else [value]
            if any(part not in schema[name] and "*" not in schema[name] for part in parts) or len(set(parts)) != len(parts) or len(parts) > 1 and "all" in parts:
                raise ValueError("unknown or conflicting selection: " + name)
    roots = ["HOLD_CASE", "SEED_CASE", "SETUP_CASE", "MODE_CASE", "GOALS", "DELIVERY", "INFERENCE"]
    if sum("TAU_TRACER_" + name in selected for name in roots) > 1:
        raise ValueError("conflicting selection groups")
    for child, parent in [("GOAL_CASE", "GOALS"), ("DELIVERY_CASE", "DELIVERY"), ("INFERENCE_PHASE", "INFERENCE"), ("INFERENCE_END", "INFERENCE"), ("SESSION_END", "INFERENCE")]:
        if "TAU_TRACER_" + child in selected and "TAU_TRACER_" + parent not in selected:
            raise ValueError("selection TAU_TRACER_" + child + " requires TAU_TRACER_" + parent)
    if "TAU_TRACER_INFERENCE_END" in selected and "TAU_TRACER_INFERENCE_PHASE" in selected:
        raise ValueError("conflicting inference selections")
    if "TAU_TRACER_SESSION_END" in selected and selected.get("TAU_TRACER_INFERENCE_PHASE") != "session-end":
        raise ValueError("TAU_TRACER_SESSION_END requires the session-end phase")
    if not selected:
        raise ValueError("targeted mode requires a selection")
    return selected


def run(diagnostic):
    # Forward in chunks; assertion lines do not introduce a flush operation.
    try:
        sys.stdout.reconfigure(line_buffering=False, write_through=False)
    except (OSError, ValueError):
        diagnostic.fail("forwarding")
        raise
    arguments = sys.argv[1:]
    mode = arguments.pop(0) if arguments else "full"
    if mode == "list" and not arguments:
        return subprocess.run(["cargo", "run", "--locked", "-p", "tracer", "--", "list"], cwd=ROOT, check=False).returncode
    try:
        selected = admit(mode, arguments, os.environ)
    except ValueError as error:
        diagnostic.fail("admission")
        forward(diagnostic, str(error), file=sys.stderr)
        if mode == "targeted":
            forward(diagnostic, "TARGETED FAIL", file=sys.stderr)
        return 1
    started = time.monotonic_ns()
    diagnostic.stage("identity")
    with web_preparation.preparation_lock(ROOT) as lock:
        return run_prepared(diagnostic, arguments, mode, selected, lock, started)


def run_prepared(diagnostic, arguments, mode, selected, lock, started):
    diagnostic.stage("identity")
    inventory = read_inventory()
    diagnostic.identifiers(inventory, tracer_requirements.prerequisite_counts(inventory))
    try:
        plan = execution_plan(selected, inventory) if mode == "targeted" else None
    except (ValueError, StopIteration) as error:
        diagnostic.fail("admission")
        forward(diagnostic, str(error) or "selection has no reviewed execution plan", file=sys.stderr)
        forward(diagnostic, "TARGETED FAIL", file=sys.stderr)
        return 1
    source = tree_hash(ROOT, source_paths(ROOT), source=True)
    diagnostic.packet['inputs'] = {
        'source': tracer_diagnostics.digest(source),
        'inventory': tracer_diagnostics.digest(file_hash(ROOT / 'tracer/inventory.json')),
        'validation_contracts': {key: tracer_diagnostics.digest(value) for key, value in validation_contracts(ROOT, source_paths(ROOT)).items()}}
    diagnostic.publish()
    phases = []
    actual_exits = []
    final_success = False
    try:
        for name in ["served", "tracer"]:
            diagnostic.stage("prepare_" + name)
            start = time.monotonic_ns()
            build_records = []
            invalid_build_timing = False
            build_environment = dict(os.environ, **{web_preparation.LOCK_FD: str(lock)})
            with observed_child(["scripts/build-web.sh", name], diagnostic, name + "_build", cwd=ROOT, stdout=subprocess.PIPE, text=True,
                                env=build_environment, pass_fds=(lock,)) as child:
                for line in forwarded_lines(child, diagnostic):
                    try:
                        sys.stdout.write(line)
                    except (OSError, ValueError):
                        diagnostic.fail("forwarding")
                        raise
                    if line.startswith("TRACER_BUILD_TIMING"):
                        try:
                            if not line.startswith("TRACER_BUILD_TIMING "):
                                raise ValueError("invalid build timing schema")
                            build_records.append(tracer_timing.decode(line[len("TRACER_BUILD_TIMING "):]))
                        except ValueError:
                            invalid_build_timing = True
                build_exit = child.wait()
            diagnostic.outcome(name + "_build", build_exit)
            if build_exit:
                diagnostic.fail("build")
            actual_exits.append(build_exit)
            end = time.monotonic_ns()
            phases.append({"phase": "prepare_" + name, "start_ns": start - started, "end_ns": end - started, "exit": build_exit})
            if invalid_build_timing or len(build_records) != 1:
                raise ValueError("invalid build timing multiplicity/schema")
            tracer_timing.build(build_records[0], name, start, end, build_exit)
            if build_exit:
                forward(diagnostic, "TARGETED FAIL" if mode == "targeted" else "TRACER FAIL", file=sys.stderr)
                return build_exit
        start = time.monotonic_ns()
        child_exit, validation_exit = execute(mode, arguments, plan, inventory, source, diagnostic, artifact_lock=lock)
        actual_exits.append(child_exit)
        phases.append({"phase": "execute_through_cleanup", "start_ns": start - started, "end_ns": time.monotonic_ns() - started, "exit": child_exit})
        final_success = validation_exit == 0
        return validation_exit
    except (OSError, ValueError, KeyError, TypeError) as error:
        diagnostic.fail("validation")
        forward(diagnostic, "preparation refused: " + str(error), file=sys.stderr)
        forward(diagnostic, "TARGETED FAIL" if mode == "targeted" else "TRACER FAIL", file=sys.stderr)
        return 1
    finally:
        diagnostic.stage("preparation_report")
        diagnostic.preparation(phases, time.monotonic_ns() - started)
        try:
            preparation = tracer_timing.preparation({"schema": 1, "mode": mode, "phases": phases, "duration_ns": time.monotonic_ns() - started}, actual_exits, mode)
        except (ValueError, KeyError, TypeError) as error:
            forward(diagnostic, "preparation refused: " + str(error), file=sys.stderr)
            forward(diagnostic, "TARGETED FAIL" if mode == "targeted" else "TRACER FAIL", file=sys.stderr)
            diagnostic.fail("report")
            diagnostic.stage("preparation_report", "failed")
            raise SystemExit(1) from None
        try:
            forward(diagnostic, "TRACER_PREPARATION " + preparation, flush=True)
            if final_success:
                forward(diagnostic, success_verdict(mode, inventory), flush=True)
        except (OSError, ValueError):
            diagnostic.fail("forwarding")
            raise


def main():
    diagnostic = None
    result = 1
    cancelled = None
    finishing = False
    def interrupted(signum, _frame):
        nonlocal cancelled
        cancelled = signum
        if finishing:
            # Terminal cleanup owns the packet now. Let it publish cancellation
            # after retiring this handler, while ownership is still held.
            raise KeyboardInterrupt
        if _ACTIVE_CHILD is not None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(_ACTIVE_CHILD.pid, signum)
        if diagnostic:
            diagnostic.fail("cancelled")
            diagnostic.collect()
            diagnostic.stage(diagnostic.packet['driver']['stage'], "cancelled")
        raise KeyboardInterrupt
    old_handlers = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        tracer_diagnostics.github_output("diagnostic_invocation", "")
        diagnostic = tracer_diagnostics.Publication(ROOT)
        tracer_diagnostics.github_output("diagnostic_invocation", diagnostic.invocation)
        result = run(diagnostic)
    except KeyboardInterrupt:
        result = 128 + (cancelled or signal.SIGINT)
    except SystemExit as error:
        result = error.code if type(error.code) is int else 1
    except (OSError, ValueError, KeyError, TypeError, StopIteration):
        # Opaque errors stay in local logs. The public record carries the fixed stage only.
        if diagnostic:
            diagnostic.fail("validation")
        print("tracer preparation/execution failed", file=sys.stderr)
        result = 1
    finally:
        finishing = True
        # Retire handlers before terminal publication and descriptor release.
        # A signal at the handoff still changes the result; retry the interrupted
        # restoration so no diagnostic handler outlives the publication.
        for sig, handler in old_handlers.items():
            while True:
                try:
                    signal.signal(sig, handler)
                    break
                except KeyboardInterrupt:
                    result = 128 + (cancelled or signal.SIGINT)
        # sys.exit uses the low byte of an integer. A negative child returncode
        # describes that child's signal, never a signal delivered to this driver.
        result %= 256
        if diagnostic:
            try:
                for stream in (sys.stdout, sys.stderr):
                    try:
                        stream.flush()
                    except (OSError, ValueError):
                        # The interpreter can override sys.exit with 120 if shutdown
                        # retries a failed flush. That eventual exit is unknown.
                        result = result or 1
                        diagnostic.fail("forwarding")
                if result:
                    diagnostic.fail("cancelled" if cancelled else "validation")
                diagnostic.collect()
                if result:
                    try:
                        print("TRACER_DIAGNOSTIC " + json.dumps(diagnostic.packet, separators=(',', ':')), file=sys.stderr, flush=True)
                    except (OSError, ValueError):
                        diagnostic.fail("forwarding")
                diagnostic.finish(result, cancelled)
            except (OSError, ValueError, KeyError, TypeError):
                print("diagnostic retention unavailable", file=sys.stderr)
                result = result or 1
            finally:
                diagnostic.close()
    return result


if __name__ == "__main__":
    sys.exit(main())
